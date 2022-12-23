'''
# Amazon S3 Construct Library

Define an unencrypted S3 bucket.

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyFirstBucket")
```

`Bucket` constructs expose the following deploy-time attributes:

* `bucketArn` - the ARN of the bucket (i.e. `arn:aws:s3:::bucket_name`)
* `bucketName` - the name of the bucket (i.e. `bucket_name`)
* `bucketWebsiteUrl` - the Website URL of the bucket (i.e.
  `http://bucket_name.s3-website-us-west-1.amazonaws.com`)
* `bucketDomainName` - the URL of the bucket (i.e. `bucket_name.s3.amazonaws.com`)
* `bucketDualStackDomainName` - the dual-stack URL of the bucket (i.e.
  `bucket_name.s3.dualstack.eu-west-1.amazonaws.com`)
* `bucketRegionalDomainName` - the regional URL of the bucket (i.e.
  `bucket_name.s3.eu-west-1.amazonaws.com`)
* `arnForObjects(pattern)` - the ARN of an object or objects within the bucket (i.e.
  `arn:aws:s3:::bucket_name/exampleobject.png` or
  `arn:aws:s3:::bucket_name/Development/*`)
* `urlForObject(key)` - the HTTP URL of an object within the bucket (i.e.
  `https://s3.cn-north-1.amazonaws.com.cn/china-bucket/mykey`)
* `virtualHostedUrlForObject(key)` - the virtual-hosted style HTTP URL of an object
  within the bucket (i.e. `https://china-bucket-s3.cn-north-1.amazonaws.com.cn/mykey`)
* `s3UrlForObject(key)` - the S3 URL of an object within the bucket (i.e.
  `s3://bucket/mykey`)

## Encryption

Define a KMS-encrypted bucket:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyEncryptedBucket",
    encryption=s3.BucketEncryption.KMS
)

# you can access the encryption key:
assert(bucket.encryption_key instanceof kms.Key)
```

You can also supply your own key:

```python
# Example automatically generated from non-compiling source. May contain errors.
my_kms_key = kms.Key(self, "MyKey")

bucket = s3.Bucket(self, "MyEncryptedBucket",
    encryption=s3.BucketEncryption.KMS,
    encryption_key=my_kms_key
)

assert(bucket.encryption_key == my_kms_key)
```

Enable KMS-SSE encryption via [S3 Bucket Keys](https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-key.html):

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyEncryptedBucket",
    encryption=s3.BucketEncryption.KMS,
    bucket_key_enabled=True
)
```

Use `BucketEncryption.ManagedKms` to use the S3 master KMS key:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "Buck",
    encryption=s3.BucketEncryption.KMS_MANAGED
)

assert(bucket.encryption_key == null)
```

## Permissions

A bucket policy will be automatically created for the bucket upon the first call to
`addToResourcePolicy(statement)`:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyBucket")
result = bucket.add_to_resource_policy(iam.PolicyStatement(
    actions=["s3:GetObject"],
    resources=[bucket.arn_for_objects("file.txt")],
    principals=[iam.AccountRootPrincipal()]
))
```

If you try to add a policy statement to an existing bucket, this method will
not do anything:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket.from_bucket_name(self, "existingBucket", "bucket-name")

# No policy statement will be added to the resource
result = bucket.add_to_resource_policy(iam.PolicyStatement(
    actions=["s3:GetObject"],
    resources=[bucket.arn_for_objects("file.txt")],
    principals=[iam.AccountRootPrincipal()]
))
```

That's because it's not possible to tell whether the bucket
already has a policy attached, let alone to re-use that policy to add more
statements to it. We recommend that you always check the result of the call:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyBucket")
result = bucket.add_to_resource_policy(iam.PolicyStatement(
    actions=["s3:GetObject"],
    resources=[bucket.arn_for_objects("file.txt")],
    principals=[iam.AccountRootPrincipal()]
))

if not result.statement_added:
    pass
```

The bucket policy can be directly accessed after creation to add statements or
adjust the removal policy.

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyBucket")
bucket.policy.apply_removal_policy(cdk.RemovalPolicy.RETAIN)
```

Most of the time, you won't have to manipulate the bucket policy directly.
Instead, buckets have "grant" methods called to give prepackaged sets of permissions
to other resources. For example:

```python
# Example automatically generated from non-compiling source. May contain errors.
# my_lambda: lambda.Function


bucket = s3.Bucket(self, "MyBucket")
bucket.grant_read_write(my_lambda)
```

Will give the Lambda's execution role permissions to read and write
from the bucket.

## AWS Foundational Security Best Practices

### Enforcing SSL

To require all requests use Secure Socket Layer (SSL):

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "Bucket",
    enforce_sSL=True
)
```

## Sharing buckets between stacks

To use a bucket in a different stack in the same CDK application, pass the object to the other stack:

```python
#
# Stack that defines the bucket
#
class Producer(cdk.Stack):

    def __init__(self, scope, id, *, description=None, env=None, stackName=None, tags=None, synthesizer=None, terminationProtection=None, analyticsReporting=None):
        super().__init__(scope, id, description=description, env=env, stackName=stackName, tags=tags, synthesizer=synthesizer, terminationProtection=terminationProtection, analyticsReporting=analyticsReporting)

        bucket = s3.Bucket(self, "MyBucket",
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
        self.my_bucket = bucket

#
# Stack that consumes the bucket
#
class Consumer(cdk.Stack):
    def __init__(self, scope, id, *, userBucket, description=None, env=None, stackName=None, tags=None, synthesizer=None, terminationProtection=None, analyticsReporting=None):
        super().__init__(scope, id, userBucket=userBucket, description=description, env=env, stackName=stackName, tags=tags, synthesizer=synthesizer, terminationProtection=terminationProtection, analyticsReporting=analyticsReporting)

        user = iam.User(self, "MyUser")
        user_bucket.grant_read_write(user)

producer = Producer(app, "ProducerStack")
Consumer(app, "ConsumerStack", user_bucket=producer.my_bucket)
```

## Importing existing buckets

To import an existing bucket into your CDK application, use the `Bucket.fromBucketAttributes`
factory method. This method accepts `BucketAttributes` which describes the properties of an already
existing bucket:

```python
# Example automatically generated from non-compiling source. May contain errors.
# my_lambda: lambda.Function

bucket = s3.Bucket.from_bucket_attributes(self, "ImportedBucket",
    bucket_arn="arn:aws:s3:::my-bucket"
)

# now you can just call methods on the bucket
bucket.add_event_notification(s3.EventType.OBJECT_CREATED, s3n.LambdaDestination(my_lambda), prefix="home/myusername/*")
```

Alternatively, short-hand factories are available as `Bucket.fromBucketName` and
`Bucket.fromBucketArn`, which will derive all bucket attributes from the bucket
name or ARN respectively:

```python
# Example automatically generated from non-compiling source. May contain errors.
by_name = s3.Bucket.from_bucket_name(self, "BucketByName", "my-bucket")
by_arn = s3.Bucket.from_bucket_arn(self, "BucketByArn", "arn:aws:s3:::my-bucket")
```

The bucket's region defaults to the current stack's region, but can also be explicitly set in cases where one of the bucket's
regional properties needs to contain the correct values.

```python
# Example automatically generated from non-compiling source. May contain errors.
my_cross_region_bucket = s3.Bucket.from_bucket_attributes(self, "CrossRegionImport",
    bucket_arn="arn:aws:s3:::my-bucket",
    region="us-east-1"
)
```

## Bucket Notifications

The Amazon S3 notification feature enables you to receive notifications when
certain events happen in your bucket as described under [S3 Bucket
Notifications] of the S3 Developer Guide.

To subscribe for bucket notifications, use the `bucket.addEventNotification` method. The
`bucket.addObjectCreatedNotification` and `bucket.addObjectRemovedNotification` can also be used for
these common use cases.

The following example will subscribe an SNS topic to be notified of all `s3:ObjectCreated:*` events:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyBucket")
topic = sns.Topic(self, "MyTopic")
bucket.add_event_notification(s3.EventType.OBJECT_CREATED, s3n.SnsDestination(topic))
```

This call will also ensure that the topic policy can accept notifications for
this specific bucket.

Supported S3 notification targets are exposed by the `@aws-cdk/aws-s3-notifications` package.

It is also possible to specify S3 object key filters when subscribing. The
following example will notify `myQueue` when objects prefixed with `foo/` and
have the `.jpg` suffix are removed from the bucket.

```python
# Example automatically generated from non-compiling source. May contain errors.
# my_queue: sqs.Queue

bucket = s3.Bucket(self, "MyBucket")
bucket.add_event_notification(s3.EventType.OBJECT_REMOVED,
    s3n.SqsDestination(my_queue), prefix="foo/", suffix=".jpg")
```

Adding notifications on existing buckets:

```python
# Example automatically generated from non-compiling source. May contain errors.
# topic: sns.Topic

bucket = s3.Bucket.from_bucket_attributes(self, "ImportedBucket",
    bucket_arn="arn:aws:s3:::my-bucket"
)
bucket.add_event_notification(s3.EventType.OBJECT_CREATED, s3n.SnsDestination(topic))
```

When you add an event notification to a bucket, a custom resource is created to
manage the notifications. By default, a new role is created for the Lambda
function that implements this feature. If you want to use your own role instead,
you should provide it in the `Bucket` constructor:

```python
# Example automatically generated from non-compiling source. May contain errors.
# my_role: iam.IRole

bucket = s3.Bucket(self, "MyBucket",
    notifications_handler_role=my_role
)
```

Whatever role you provide, the CDK will try to modify it by adding the
permissions from `AWSLambdaBasicExecutionRole` (an AWS managed policy) as well
as the permissions `s3:PutBucketNotification` and `s3:GetBucketNotification`.
If you’re passing an imported role, and you don’t want this to happen, configure
it to be immutable:

```python
# Example automatically generated from non-compiling source. May contain errors.
imported_role = iam.Role.from_role_arn(self, "role", "arn:aws:iam::123456789012:role/RoleName",
    mutable=False
)
```

> If you provide an imported immutable role, make sure that it has at least all
> the permissions mentioned above. Otherwise, the deployment will fail!

## Block Public Access

Use `blockPublicAccess` to specify [block public access settings](https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html) on the bucket.

Enable all block public access settings:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyBlockedBucket",
    block_public_access=s3.BlockPublicAccess.BLOCK_ALL
)
```

Block and ignore public ACLs:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyBlockedBucket",
    block_public_access=s3.BlockPublicAccess.BLOCK_ACLS
)
```

Alternatively, specify the settings manually:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyBlockedBucket",
    block_public_access=s3.BlockPublicAccess(block_public_policy=True)
)
```

When `blockPublicPolicy` is set to `true`, `grantPublicRead()` throws an error.

## Logging configuration

Use `serverAccessLogsBucket` to describe where server access logs are to be stored.

```python
# Example automatically generated from non-compiling source. May contain errors.
access_logs_bucket = s3.Bucket(self, "AccessLogsBucket")

bucket = s3.Bucket(self, "MyBucket",
    server_access_logs_bucket=access_logs_bucket
)
```

It's also possible to specify a prefix for Amazon S3 to assign to all log object keys.

```python
# Example automatically generated from non-compiling source. May contain errors.
access_logs_bucket = s3.Bucket(self, "AccessLogsBucket")

bucket = s3.Bucket(self, "MyBucket",
    server_access_logs_bucket=access_logs_bucket,
    server_access_logs_prefix="logs"
)
```

## S3 Inventory

An [inventory](https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-inventory.html) contains a list of the objects in the source bucket and metadata for each object. The inventory lists are stored in the destination bucket as a CSV file compressed with GZIP, as an Apache optimized row columnar (ORC) file compressed with ZLIB, or as an Apache Parquet (Parquet) file compressed with Snappy.

You can configure multiple inventory lists for a bucket. You can configure what object metadata to include in the inventory, whether to list all object versions or only current versions, where to store the inventory list file output, and whether to generate the inventory on a daily or weekly basis.

```python
# Example automatically generated from non-compiling source. May contain errors.
inventory_bucket = s3.Bucket(self, "InventoryBucket")

data_bucket = s3.Bucket(self, "DataBucket",
    inventories=[s3.Inventory(
        frequency=s3.InventoryFrequency.DAILY,
        include_object_versions=s3.InventoryObjectVersion.CURRENT,
        destination=s3.InventoryDestination(
            bucket=inventory_bucket
        )
    ), s3.Inventory(
        frequency=s3.InventoryFrequency.WEEKLY,
        include_object_versions=s3.InventoryObjectVersion.ALL,
        destination=s3.InventoryDestination(
            bucket=inventory_bucket,
            prefix="with-all-versions"
        )
    )
    ]
)
```

If the destination bucket is created as part of the same CDK application, the necessary permissions will be automatically added to the bucket policy.
However, if you use an imported bucket (i.e `Bucket.fromXXX()`), you'll have to make sure it contains the following policy document:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InventoryAndAnalyticsExamplePolicy",
      "Effect": "Allow",
      "Principal": { "Service": "s3.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": ["arn:aws:s3:::destinationBucket/*"]
    }
  ]
}
```

## Website redirection

You can use the two following properties to specify the bucket [redirection policy](https://docs.aws.amazon.com/AmazonS3/latest/dev/how-to-page-redirect.html#advanced-conditional-redirects). Please note that these methods cannot both be applied to the same bucket.

### Static redirection

You can statically redirect a to a given Bucket URL or any other host name with `websiteRedirect`:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyRedirectedBucket",
    website_redirect=s3.RedirectTarget(host_name="www.example.com")
)
```

### Routing rules

Alternatively, you can also define multiple `websiteRoutingRules`, to define complex, conditional redirections:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyRedirectedBucket",
    website_routing_rules=[s3.RoutingRule(
        host_name="www.example.com",
        http_redirect_code="302",
        protocol=s3.RedirectProtocol.HTTPS,
        replace_key=s3.ReplaceKey.prefix_with("test/"),
        condition=s3.RoutingRuleCondition(
            http_error_code_returned_equals="200",
            key_prefix_equals="prefix"
        )
    )]
)
```

## Filling the bucket as part of deployment

To put files into a bucket as part of a deployment (for example, to host a
website), see the `@aws-cdk/aws-s3-deployment` package, which provides a
resource that can do just that.

## The URL for objects

S3 provides two types of URLs for accessing objects via HTTP(S). Path-Style and
[Virtual Hosted-Style](https://docs.aws.amazon.com/AmazonS3/latest/dev/VirtualHosting.html)
URL. Path-Style is a classic way and will be
[deprecated](https://aws.amazon.com/jp/blogs/aws/amazon-s3-path-deprecation-plan-the-rest-of-the-story).
We recommend to use Virtual Hosted-Style URL for newly made bucket.

You can generate both of them.

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyBucket")
bucket.url_for_object("objectname") # Path-Style URL
bucket.virtual_hosted_url_for_object("objectname") # Virtual Hosted-Style URL
bucket.virtual_hosted_url_for_object("objectname", regional=False)
```

## Object Ownership

You can use one of following properties to specify the bucket [object Ownership](https://docs.aws.amazon.com/AmazonS3/latest/dev/about-object-ownership.html).

### Object writer

The Uploading account will own the object.

```python
# Example automatically generated from non-compiling source. May contain errors.
s3.Bucket(self, "MyBucket",
    object_ownership=s3.ObjectOwnership.OBJECT_WRITER
)
```

### Bucket owner preferred

The bucket owner will own the object if the object is uploaded with the bucket-owner-full-control canned ACL. Without this setting and canned ACL, the object is uploaded and remains owned by the uploading account.

```python
# Example automatically generated from non-compiling source. May contain errors.
s3.Bucket(self, "MyBucket",
    object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED
)
```

### Bucket owner enforced (recommended)

ACLs are disabled, and the bucket owner automatically owns and has full control over every object in the bucket. ACLs no longer affect permissions to data in the S3 bucket. The bucket uses policies to define access control.

```python
# Example automatically generated from non-compiling source. May contain errors.
s3.Bucket(self, "MyBucket",
    object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED
)
```

## Bucket deletion

When a bucket is removed from a stack (or the stack is deleted), the S3
bucket will be removed according to its removal policy (which by default will
simply orphan the bucket and leave it in your AWS account). If the removal
policy is set to `RemovalPolicy.DESTROY`, the bucket will be deleted as long
as it does not contain any objects.

To override this and force all objects to get deleted during bucket deletion,
enable the`autoDeleteObjects` option.

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyTempFileBucket",
    removal_policy=cdk.RemovalPolicy.DESTROY,
    auto_delete_objects=True
)
```

**Warning** if you have deployed a bucket with `autoDeleteObjects: true`,
switching this to `false` in a CDK version *before* `1.126.0` will lead to
all objects in the bucket being deleted. Be sure to update your bucket resources
by deploying with CDK version `1.126.0` or later **before** switching this value to `false`.

## Transfer Acceleration

[Transfer Acceleration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/transfer-acceleration.html) can be configured to enable fast, easy, and secure transfers of files over long distances:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyBucket",
    transfer_acceleration=True
)
```

To access the bucket that is enabled for Transfer Acceleration, you must use a special endpoint. The URL can be generated using method `transferAccelerationUrlForObject`:

```python
# Example automatically generated from non-compiling source. May contain errors.
bucket = s3.Bucket(self, "MyBucket",
    transfer_acceleration=True
)
bucket.transfer_acceleration_url_for_object("objectname")
```

## Intelligent Tiering

[Intelligent Tiering](https://docs.aws.amazon.com/AmazonS3/latest/userguide/intelligent-tiering.html) can be configured to automatically move files to glacier:

```python
# Example automatically generated from non-compiling source. May contain errors.
s3.Bucket(self, "MyBucket",
    intelligent_tiering_configurations=[s3.IntelligentTieringConfiguration(
        name="foo",
        prefix="folder/name",
        archive_access_tier_time=cdk.Duration.days(90),
        deep_archive_access_tier_time=cdk.Duration.days(180),
        tags=[s3.Tag(key="tagname", value="tagvalue")]
    )]
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
    ResourceProps as _ResourceProps_15a65b4e,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_events import (
    EventPattern as _EventPattern_fe557901,
    IRuleTarget as _IRuleTarget_7a91f454,
    OnEventOptions as _OnEventOptions_8711b8b3,
    Rule as _Rule_334ed2b5,
)
from ..aws_iam import (
    AddToResourcePolicyResult as _AddToResourcePolicyResult_1d0a53ad,
    Grant as _Grant_a7ae64f8,
    IGrantable as _IGrantable_71c4f5de,
    IRole as _IRole_235f5d8e,
    PolicyDocument as _PolicyDocument_3ac34393,
    PolicyStatement as _PolicyStatement_0fe33853,
)
from ..aws_kms import IKey as _IKey_5f11635f


class BlockPublicAccess(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_s3.BlockPublicAccess",
):
    '''
    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        bucket = s3.Bucket(self, "MyBlockedBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL
        )
    '''

    def __init__(
        self,
        *,
        block_public_acls: typing.Optional[builtins.bool] = None,
        block_public_policy: typing.Optional[builtins.bool] = None,
        ignore_public_acls: typing.Optional[builtins.bool] = None,
        restrict_public_buckets: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''
        :param block_public_acls: Whether to block public ACLs.
        :param block_public_policy: Whether to block public policy.
        :param ignore_public_acls: Whether to ignore public ACLs.
        :param restrict_public_buckets: Whether to restrict public access.
        '''
        options = BlockPublicAccessOptions(
            block_public_acls=block_public_acls,
            block_public_policy=block_public_policy,
            ignore_public_acls=ignore_public_acls,
            restrict_public_buckets=restrict_public_buckets,
        )

        jsii.create(self.__class__, self, [options])

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="BLOCK_ACLS")
    def BLOCK_ACLS(cls) -> "BlockPublicAccess":
        return typing.cast("BlockPublicAccess", jsii.sget(cls, "BLOCK_ACLS"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="BLOCK_ALL")
    def BLOCK_ALL(cls) -> "BlockPublicAccess":
        return typing.cast("BlockPublicAccess", jsii.sget(cls, "BLOCK_ALL"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="blockPublicAcls")
    def block_public_acls(self) -> typing.Optional[builtins.bool]:
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "blockPublicAcls"))

    @block_public_acls.setter
    def block_public_acls(self, value: typing.Optional[builtins.bool]) -> None:
        jsii.set(self, "blockPublicAcls", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="blockPublicPolicy")
    def block_public_policy(self) -> typing.Optional[builtins.bool]:
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "blockPublicPolicy"))

    @block_public_policy.setter
    def block_public_policy(self, value: typing.Optional[builtins.bool]) -> None:
        jsii.set(self, "blockPublicPolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ignorePublicAcls")
    def ignore_public_acls(self) -> typing.Optional[builtins.bool]:
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "ignorePublicAcls"))

    @ignore_public_acls.setter
    def ignore_public_acls(self, value: typing.Optional[builtins.bool]) -> None:
        jsii.set(self, "ignorePublicAcls", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="restrictPublicBuckets")
    def restrict_public_buckets(self) -> typing.Optional[builtins.bool]:
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "restrictPublicBuckets"))

    @restrict_public_buckets.setter
    def restrict_public_buckets(self, value: typing.Optional[builtins.bool]) -> None:
        jsii.set(self, "restrictPublicBuckets", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.BlockPublicAccessOptions",
    jsii_struct_bases=[],
    name_mapping={
        "block_public_acls": "blockPublicAcls",
        "block_public_policy": "blockPublicPolicy",
        "ignore_public_acls": "ignorePublicAcls",
        "restrict_public_buckets": "restrictPublicBuckets",
    },
)
class BlockPublicAccessOptions:
    def __init__(
        self,
        *,
        block_public_acls: typing.Optional[builtins.bool] = None,
        block_public_policy: typing.Optional[builtins.bool] = None,
        ignore_public_acls: typing.Optional[builtins.bool] = None,
        restrict_public_buckets: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''
        :param block_public_acls: Whether to block public ACLs.
        :param block_public_policy: Whether to block public policy.
        :param ignore_public_acls: Whether to ignore public ACLs.
        :param restrict_public_buckets: Whether to restrict public access.

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            bucket = s3.Bucket(self, "MyBlockedBucket",
                block_public_access=s3.BlockPublicAccess(block_public_policy=True)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if block_public_acls is not None:
            self._values["block_public_acls"] = block_public_acls
        if block_public_policy is not None:
            self._values["block_public_policy"] = block_public_policy
        if ignore_public_acls is not None:
            self._values["ignore_public_acls"] = ignore_public_acls
        if restrict_public_buckets is not None:
            self._values["restrict_public_buckets"] = restrict_public_buckets

    @builtins.property
    def block_public_acls(self) -> typing.Optional[builtins.bool]:
        '''Whether to block public ACLs.

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-options
        '''
        result = self._values.get("block_public_acls")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def block_public_policy(self) -> typing.Optional[builtins.bool]:
        '''Whether to block public policy.

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-options
        '''
        result = self._values.get("block_public_policy")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def ignore_public_acls(self) -> typing.Optional[builtins.bool]:
        '''Whether to ignore public ACLs.

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-options
        '''
        result = self._values.get("ignore_public_acls")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def restrict_public_buckets(self) -> typing.Optional[builtins.bool]:
        '''Whether to restrict public access.

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-options
        '''
        result = self._values.get("restrict_public_buckets")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BlockPublicAccessOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_s3.BucketAccessControl")
class BucketAccessControl(enum.Enum):
    '''Default bucket access control types.

    :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html
    :exampleMetadata: infused

    Example::

        website_bucket = s3.Bucket(self, "WebsiteBucket",
            website_index_document="index.html",
            public_read_access=True
        )
        
        s3deploy.BucketDeployment(self, "DeployWebsite",
            sources=[s3deploy.Source.asset("./website-dist")],
            destination_bucket=website_bucket,
            destination_key_prefix="web/static",  # optional prefix in destination bucket
            metadata=s3deploy.UserDefinedObjectMetadata(A="1", b="2"),  # user-defined metadata
        
            # system-defined metadata
            content_type="text/html",
            content_language="en",
            storage_class=s3deploy.StorageClass.INTELLIGENT_TIERING,
            server_side_encryption=s3deploy.ServerSideEncryption.AES_256,
            cache_control=[
                s3deploy.CacheControl.set_public(),
                s3deploy.CacheControl.max_age(Duration.hours(1))
            ],
            access_control=s3.BucketAccessControl.BUCKET_OWNER_FULL_CONTROL
        )
    '''

    PRIVATE = "PRIVATE"
    '''Owner gets FULL_CONTROL.

    No one else has access rights.
    '''
    PUBLIC_READ = "PUBLIC_READ"
    '''Owner gets FULL_CONTROL.

    The AllUsers group gets READ access.
    '''
    PUBLIC_READ_WRITE = "PUBLIC_READ_WRITE"
    '''Owner gets FULL_CONTROL.

    The AllUsers group gets READ and WRITE access.
    Granting this on a bucket is generally not recommended.
    '''
    AUTHENTICATED_READ = "AUTHENTICATED_READ"
    '''Owner gets FULL_CONTROL.

    The AuthenticatedUsers group gets READ access.
    '''
    LOG_DELIVERY_WRITE = "LOG_DELIVERY_WRITE"
    '''The LogDelivery group gets WRITE and READ_ACP permissions on the bucket.

    :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html
    '''
    BUCKET_OWNER_READ = "BUCKET_OWNER_READ"
    '''Object owner gets FULL_CONTROL.

    Bucket owner gets READ access.
    If you specify this canned ACL when creating a bucket, Amazon S3 ignores it.
    '''
    BUCKET_OWNER_FULL_CONTROL = "BUCKET_OWNER_FULL_CONTROL"
    '''Both the object owner and the bucket owner get FULL_CONTROL over the object.

    If you specify this canned ACL when creating a bucket, Amazon S3 ignores it.
    '''
    AWS_EXEC_READ = "AWS_EXEC_READ"
    '''Owner gets FULL_CONTROL.

    Amazon EC2 gets READ access to GET an Amazon Machine Image (AMI) bundle from Amazon S3.
    '''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.BucketAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "account": "account",
        "bucket_arn": "bucketArn",
        "bucket_domain_name": "bucketDomainName",
        "bucket_dual_stack_domain_name": "bucketDualStackDomainName",
        "bucket_name": "bucketName",
        "bucket_regional_domain_name": "bucketRegionalDomainName",
        "bucket_website_new_url_format": "bucketWebsiteNewUrlFormat",
        "bucket_website_url": "bucketWebsiteUrl",
        "encryption_key": "encryptionKey",
        "is_website": "isWebsite",
        "notifications_handler_role": "notificationsHandlerRole",
        "region": "region",
    },
)
class BucketAttributes:
    def __init__(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        bucket_arn: typing.Optional[builtins.str] = None,
        bucket_domain_name: typing.Optional[builtins.str] = None,
        bucket_dual_stack_domain_name: typing.Optional[builtins.str] = None,
        bucket_name: typing.Optional[builtins.str] = None,
        bucket_regional_domain_name: typing.Optional[builtins.str] = None,
        bucket_website_new_url_format: typing.Optional[builtins.bool] = None,
        bucket_website_url: typing.Optional[builtins.str] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        is_website: typing.Optional[builtins.bool] = None,
        notifications_handler_role: typing.Optional[_IRole_235f5d8e] = None,
        region: typing.Optional[builtins.str] = None,
    ) -> None:
        '''A reference to a bucket outside this stack.

        :param account: The account this existing bucket belongs to. Default: - it's assumed the bucket belongs to the same account as the scope it's being imported into
        :param bucket_arn: The ARN of the bucket. At least one of bucketArn or bucketName must be defined in order to initialize a bucket ref.
        :param bucket_domain_name: The domain name of the bucket. Default: Inferred from bucket name
        :param bucket_dual_stack_domain_name: The IPv6 DNS name of the specified bucket.
        :param bucket_name: The name of the bucket. If the underlying value of ARN is a string, the name will be parsed from the ARN. Otherwise, the name is optional, but some features that require the bucket name such as auto-creating a bucket policy, won't work.
        :param bucket_regional_domain_name: The regional domain name of the specified bucket.
        :param bucket_website_new_url_format: The format of the website URL of the bucket. This should be true for regions launched since 2014. Default: false
        :param bucket_website_url: The website URL of the bucket (if static web hosting is enabled). Default: Inferred from bucket name
        :param encryption_key: 
        :param is_website: If this bucket has been configured for static website hosting. Default: false
        :param notifications_handler_role: The role to be used by the notifications handler. Default: - a new role will be created.
        :param region: The region this existing bucket is in. Default: - it's assumed the bucket is in the same region as the scope it's being imported into

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            # my_lambda: lambda.Function
            
            bucket = s3.Bucket.from_bucket_attributes(self, "ImportedBucket",
                bucket_arn="arn:aws:s3:::my-bucket"
            )
            
            # now you can just call methods on the bucket
            bucket.add_event_notification(s3.EventType.OBJECT_CREATED, s3n.LambdaDestination(my_lambda), prefix="home/myusername/*")
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if account is not None:
            self._values["account"] = account
        if bucket_arn is not None:
            self._values["bucket_arn"] = bucket_arn
        if bucket_domain_name is not None:
            self._values["bucket_domain_name"] = bucket_domain_name
        if bucket_dual_stack_domain_name is not None:
            self._values["bucket_dual_stack_domain_name"] = bucket_dual_stack_domain_name
        if bucket_name is not None:
            self._values["bucket_name"] = bucket_name
        if bucket_regional_domain_name is not None:
            self._values["bucket_regional_domain_name"] = bucket_regional_domain_name
        if bucket_website_new_url_format is not None:
            self._values["bucket_website_new_url_format"] = bucket_website_new_url_format
        if bucket_website_url is not None:
            self._values["bucket_website_url"] = bucket_website_url
        if encryption_key is not None:
            self._values["encryption_key"] = encryption_key
        if is_website is not None:
            self._values["is_website"] = is_website
        if notifications_handler_role is not None:
            self._values["notifications_handler_role"] = notifications_handler_role
        if region is not None:
            self._values["region"] = region

    @builtins.property
    def account(self) -> typing.Optional[builtins.str]:
        '''The account this existing bucket belongs to.

        :default: - it's assumed the bucket belongs to the same account as the scope it's being imported into
        '''
        result = self._values.get("account")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def bucket_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the bucket.

        At least one of bucketArn or bucketName must be
        defined in order to initialize a bucket ref.
        '''
        result = self._values.get("bucket_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def bucket_domain_name(self) -> typing.Optional[builtins.str]:
        '''The domain name of the bucket.

        :default: Inferred from bucket name
        '''
        result = self._values.get("bucket_domain_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def bucket_dual_stack_domain_name(self) -> typing.Optional[builtins.str]:
        '''The IPv6 DNS name of the specified bucket.'''
        result = self._values.get("bucket_dual_stack_domain_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def bucket_name(self) -> typing.Optional[builtins.str]:
        '''The name of the bucket.

        If the underlying value of ARN is a string, the
        name will be parsed from the ARN. Otherwise, the name is optional, but
        some features that require the bucket name such as auto-creating a bucket
        policy, won't work.
        '''
        result = self._values.get("bucket_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def bucket_regional_domain_name(self) -> typing.Optional[builtins.str]:
        '''The regional domain name of the specified bucket.'''
        result = self._values.get("bucket_regional_domain_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def bucket_website_new_url_format(self) -> typing.Optional[builtins.bool]:
        '''The format of the website URL of the bucket.

        This should be true for
        regions launched since 2014.

        :default: false
        '''
        result = self._values.get("bucket_website_new_url_format")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def bucket_website_url(self) -> typing.Optional[builtins.str]:
        '''The website URL of the bucket (if static web hosting is enabled).

        :default: Inferred from bucket name
        '''
        result = self._values.get("bucket_website_url")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        result = self._values.get("encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def is_website(self) -> typing.Optional[builtins.bool]:
        '''If this bucket has been configured for static website hosting.

        :default: false
        '''
        result = self._values.get("is_website")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def notifications_handler_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The role to be used by the notifications handler.

        :default: - a new role will be created.
        '''
        result = self._values.get("notifications_handler_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def region(self) -> typing.Optional[builtins.str]:
        '''The region this existing bucket is in.

        :default: - it's assumed the bucket is in the same region as the scope it's being imported into
        '''
        result = self._values.get("region")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BucketAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_s3.BucketEncryption")
class BucketEncryption(enum.Enum):
    '''What kind of server-side encryption to apply to this bucket.

    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        bucket = s3.Bucket(self, "MyEncryptedBucket",
            encryption=s3.BucketEncryption.KMS
        )
        
        # you can access the encryption key:
        assert(bucket.encryption_key instanceof kms.Key)
    '''

    UNENCRYPTED = "UNENCRYPTED"
    '''Objects in the bucket are not encrypted.'''
    KMS_MANAGED = "KMS_MANAGED"
    '''Server-side KMS encryption with a master key managed by KMS.'''
    S3_MANAGED = "S3_MANAGED"
    '''Server-side encryption with a master key managed by S3.'''
    KMS = "KMS"
    '''Server-side encryption with a KMS key managed by the user.

    If ``encryptionKey`` is specified, this key will be used, otherwise, one will be defined.
    '''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.BucketMetrics",
    jsii_struct_bases=[],
    name_mapping={"id": "id", "prefix": "prefix", "tag_filters": "tagFilters"},
)
class BucketMetrics:
    def __init__(
        self,
        *,
        id: builtins.str,
        prefix: typing.Optional[builtins.str] = None,
        tag_filters: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
    ) -> None:
        '''Specifies a metrics configuration for the CloudWatch request metrics from an Amazon S3 bucket.

        :param id: The ID used to identify the metrics configuration.
        :param prefix: The prefix that an object must have to be included in the metrics results.
        :param tag_filters: Specifies a list of tag filters to use as a metrics configuration filter. The metrics configuration includes only objects that meet the filter's criteria.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            
            # tag_filters: Any
            
            bucket_metrics = s3.BucketMetrics(
                id="id",
            
                # the properties below are optional
                prefix="prefix",
                tag_filters={
                    "tag_filters_key": tag_filters
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "id": id,
        }
        if prefix is not None:
            self._values["prefix"] = prefix
        if tag_filters is not None:
            self._values["tag_filters"] = tag_filters

    @builtins.property
    def id(self) -> builtins.str:
        '''The ID used to identify the metrics configuration.'''
        result = self._values.get("id")
        assert result is not None, "Required property 'id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def prefix(self) -> typing.Optional[builtins.str]:
        '''The prefix that an object must have to be included in the metrics results.'''
        result = self._values.get("prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tag_filters(self) -> typing.Optional[typing.Mapping[builtins.str, typing.Any]]:
        '''Specifies a list of tag filters to use as a metrics configuration filter.

        The metrics configuration includes only objects that meet the filter's criteria.
        '''
        result = self._values.get("tag_filters")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, typing.Any]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BucketMetrics(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.BucketNotificationDestinationConfig",
    jsii_struct_bases=[],
    name_mapping={"arn": "arn", "type": "type", "dependencies": "dependencies"},
)
class BucketNotificationDestinationConfig:
    def __init__(
        self,
        *,
        arn: builtins.str,
        type: "BucketNotificationDestinationType",
        dependencies: typing.Optional[typing.Sequence[constructs.IDependable]] = None,
    ) -> None:
        '''Represents the properties of a notification destination.

        :param arn: The ARN of the destination (i.e. Lambda, SNS, SQS).
        :param type: The notification type.
        :param dependencies: Any additional dependencies that should be resolved before the bucket notification can be configured (for example, the SNS Topic Policy resource).

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            import constructs as constructs
            
            # dependable: constructs.IDependable
            
            bucket_notification_destination_config = s3.BucketNotificationDestinationConfig(
                arn="arn",
                type=s3.BucketNotificationDestinationType.LAMBDA,
            
                # the properties below are optional
                dependencies=[dependable]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "arn": arn,
            "type": type,
        }
        if dependencies is not None:
            self._values["dependencies"] = dependencies

    @builtins.property
    def arn(self) -> builtins.str:
        '''The ARN of the destination (i.e. Lambda, SNS, SQS).'''
        result = self._values.get("arn")
        assert result is not None, "Required property 'arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def type(self) -> "BucketNotificationDestinationType":
        '''The notification type.'''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast("BucketNotificationDestinationType", result)

    @builtins.property
    def dependencies(self) -> typing.Optional[typing.List[constructs.IDependable]]:
        '''Any additional dependencies that should be resolved before the bucket notification can be configured (for example, the SNS Topic Policy resource).'''
        result = self._values.get("dependencies")
        return typing.cast(typing.Optional[typing.List[constructs.IDependable]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BucketNotificationDestinationConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_s3.BucketNotificationDestinationType")
class BucketNotificationDestinationType(enum.Enum):
    '''Supported types of notification destinations.'''

    LAMBDA = "LAMBDA"
    QUEUE = "QUEUE"
    TOPIC = "TOPIC"


class BucketPolicy(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_s3.BucketPolicy",
):
    '''The bucket policy for an Amazon S3 bucket.

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
        import aws_cdk as cdk
        from aws_cdk import aws_s3 as s3
        
        # bucket: s3.Bucket
        
        bucket_policy = s3.BucketPolicy(self, "MyBucketPolicy",
            bucket=bucket,
        
            # the properties below are optional
            removal_policy=cdk.RemovalPolicy.DESTROY
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        bucket: "IBucket",
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param bucket: The Amazon S3 bucket that the policy applies to.
        :param removal_policy: Policy to apply when the policy is removed from this stack. Default: - RemovalPolicy.DESTROY.
        '''
        props = BucketPolicyProps(bucket=bucket, removal_policy=removal_policy)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="applyRemovalPolicy")
    def apply_removal_policy(self, removal_policy: _RemovalPolicy_9f93c814) -> None:
        '''Sets the removal policy for the BucketPolicy.

        :param removal_policy: the RemovalPolicy to set.
        '''
        return typing.cast(None, jsii.invoke(self, "applyRemovalPolicy", [removal_policy]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="document")
    def document(self) -> _PolicyDocument_3ac34393:
        '''A policy document containing permissions to add to the specified bucket.

        For more information, see Access Policy Language Overview in the Amazon
        Simple Storage Service Developer Guide.
        '''
        return typing.cast(_PolicyDocument_3ac34393, jsii.get(self, "document"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.BucketPolicyProps",
    jsii_struct_bases=[],
    name_mapping={"bucket": "bucket", "removal_policy": "removalPolicy"},
)
class BucketPolicyProps:
    def __init__(
        self,
        *,
        bucket: "IBucket",
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
    ) -> None:
        '''
        :param bucket: The Amazon S3 bucket that the policy applies to.
        :param removal_policy: Policy to apply when the policy is removed from this stack. Default: - RemovalPolicy.DESTROY.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_s3 as s3
            
            # bucket: s3.Bucket
            
            bucket_policy_props = s3.BucketPolicyProps(
                bucket=bucket,
            
                # the properties below are optional
                removal_policy=cdk.RemovalPolicy.DESTROY
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "bucket": bucket,
        }
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy

    @builtins.property
    def bucket(self) -> "IBucket":
        '''The Amazon S3 bucket that the policy applies to.'''
        result = self._values.get("bucket")
        assert result is not None, "Required property 'bucket' is missing"
        return typing.cast("IBucket", result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''Policy to apply when the policy is removed from this stack.

        :default: - RemovalPolicy.DESTROY.
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BucketPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.BucketProps",
    jsii_struct_bases=[],
    name_mapping={
        "access_control": "accessControl",
        "auto_delete_objects": "autoDeleteObjects",
        "block_public_access": "blockPublicAccess",
        "bucket_key_enabled": "bucketKeyEnabled",
        "bucket_name": "bucketName",
        "cors": "cors",
        "encryption": "encryption",
        "encryption_key": "encryptionKey",
        "enforce_ssl": "enforceSSL",
        "intelligent_tiering_configurations": "intelligentTieringConfigurations",
        "inventories": "inventories",
        "lifecycle_rules": "lifecycleRules",
        "metrics": "metrics",
        "notifications_handler_role": "notificationsHandlerRole",
        "object_ownership": "objectOwnership",
        "public_read_access": "publicReadAccess",
        "removal_policy": "removalPolicy",
        "server_access_logs_bucket": "serverAccessLogsBucket",
        "server_access_logs_prefix": "serverAccessLogsPrefix",
        "transfer_acceleration": "transferAcceleration",
        "versioned": "versioned",
        "website_error_document": "websiteErrorDocument",
        "website_index_document": "websiteIndexDocument",
        "website_redirect": "websiteRedirect",
        "website_routing_rules": "websiteRoutingRules",
    },
)
class BucketProps:
    def __init__(
        self,
        *,
        access_control: typing.Optional[BucketAccessControl] = None,
        auto_delete_objects: typing.Optional[builtins.bool] = None,
        block_public_access: typing.Optional[BlockPublicAccess] = None,
        bucket_key_enabled: typing.Optional[builtins.bool] = None,
        bucket_name: typing.Optional[builtins.str] = None,
        cors: typing.Optional[typing.Sequence["CorsRule"]] = None,
        encryption: typing.Optional[BucketEncryption] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        enforce_ssl: typing.Optional[builtins.bool] = None,
        intelligent_tiering_configurations: typing.Optional[typing.Sequence["IntelligentTieringConfiguration"]] = None,
        inventories: typing.Optional[typing.Sequence["Inventory"]] = None,
        lifecycle_rules: typing.Optional[typing.Sequence["LifecycleRule"]] = None,
        metrics: typing.Optional[typing.Sequence[BucketMetrics]] = None,
        notifications_handler_role: typing.Optional[_IRole_235f5d8e] = None,
        object_ownership: typing.Optional["ObjectOwnership"] = None,
        public_read_access: typing.Optional[builtins.bool] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        server_access_logs_bucket: typing.Optional["IBucket"] = None,
        server_access_logs_prefix: typing.Optional[builtins.str] = None,
        transfer_acceleration: typing.Optional[builtins.bool] = None,
        versioned: typing.Optional[builtins.bool] = None,
        website_error_document: typing.Optional[builtins.str] = None,
        website_index_document: typing.Optional[builtins.str] = None,
        website_redirect: typing.Optional["RedirectTarget"] = None,
        website_routing_rules: typing.Optional[typing.Sequence["RoutingRule"]] = None,
    ) -> None:
        '''
        :param access_control: Specifies a canned ACL that grants predefined permissions to the bucket. Default: BucketAccessControl.PRIVATE
        :param auto_delete_objects: Whether all objects should be automatically deleted when the bucket is removed from the stack or when the stack is deleted. Requires the ``removalPolicy`` to be set to ``RemovalPolicy.DESTROY``. **Warning** if you have deployed a bucket with ``autoDeleteObjects: true``, switching this to ``false`` in a CDK version *before* ``1.126.0`` will lead to all objects in the bucket being deleted. Be sure to update your bucket resources by deploying with CDK version ``1.126.0`` or later **before** switching this value to ``false``. Default: false
        :param block_public_access: The block public access configuration of this bucket. Default: - CloudFormation defaults will apply. New buckets and objects don't allow public access, but users can modify bucket policies or object permissions to allow public access
        :param bucket_key_enabled: Specifies whether Amazon S3 should use an S3 Bucket Key with server-side encryption using KMS (SSE-KMS) for new objects in the bucket. Only relevant, when Encryption is set to {@link BucketEncryption.KMS} Default: - false
        :param bucket_name: Physical name of this bucket. Default: - Assigned by CloudFormation (recommended).
        :param cors: The CORS configuration of this bucket. Default: - No CORS configuration.
        :param encryption: The kind of server-side encryption to apply to this bucket. If you choose KMS, you can specify a KMS key via ``encryptionKey``. If encryption key is not specified, a key will automatically be created. Default: - ``Kms`` if ``encryptionKey`` is specified, or ``Unencrypted`` otherwise.
        :param encryption_key: External KMS key to use for bucket encryption. The 'encryption' property must be either not specified or set to "Kms". An error will be emitted if encryption is set to "Unencrypted" or "Managed". Default: - If encryption is set to "Kms" and this property is undefined, a new KMS key will be created and associated with this bucket.
        :param enforce_ssl: Enforces SSL for requests. S3.5 of the AWS Foundational Security Best Practices Regarding S3. Default: false
        :param intelligent_tiering_configurations: Inteligent Tiering Configurations. Default: No Intelligent Tiiering Configurations.
        :param inventories: The inventory configuration of the bucket. Default: - No inventory configuration
        :param lifecycle_rules: Rules that define how Amazon S3 manages objects during their lifetime. Default: - No lifecycle rules.
        :param metrics: The metrics configuration of this bucket. Default: - No metrics configuration.
        :param notifications_handler_role: The role to be used by the notifications handler. Default: - a new role will be created.
        :param object_ownership: The objectOwnership of the bucket. Default: - No ObjectOwnership configuration, uploading account will own the object.
        :param public_read_access: Grants public read access to all objects in the bucket. Similar to calling ``bucket.grantPublicAccess()`` Default: false
        :param removal_policy: Policy to apply when the bucket is removed from this stack. Default: - The bucket will be orphaned.
        :param server_access_logs_bucket: Destination bucket for the server access logs. Default: - If "serverAccessLogsPrefix" undefined - access logs disabled, otherwise - log to current bucket.
        :param server_access_logs_prefix: Optional log file prefix to use for the bucket's access logs. If defined without "serverAccessLogsBucket", enables access logs to current bucket with this prefix. Default: - No log file prefix
        :param transfer_acceleration: Whether this bucket should have transfer acceleration turned on or not. Default: false
        :param versioned: Whether this bucket should have versioning turned on or not. Default: false
        :param website_error_document: The name of the error document (e.g. "404.html") for the website. ``websiteIndexDocument`` must also be set if this is set. Default: - No error document.
        :param website_index_document: The name of the index document (e.g. "index.html") for the website. Enables static website hosting for this bucket. Default: - No index document.
        :param website_redirect: Specifies the redirect behavior of all requests to a website endpoint of a bucket. If you specify this property, you can't specify "websiteIndexDocument", "websiteErrorDocument" nor , "websiteRoutingRules". Default: - No redirection.
        :param website_routing_rules: Rules that define when a redirect is applied and the redirect behavior. Default: - No redirection rules.

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            source_bucket = s3.Bucket(self, "MyBucket",
                versioned=True
            )
            
            pipeline = codepipeline.Pipeline(self, "MyPipeline")
            source_output = codepipeline.Artifact()
            source_action = codepipeline_actions.S3SourceAction(
                action_name="S3Source",
                bucket=source_bucket,
                bucket_key="path/to/file.zip",
                output=source_output
            )
            pipeline.add_stage(
                stage_name="Source",
                actions=[source_action]
            )
        '''
        if isinstance(website_redirect, dict):
            website_redirect = RedirectTarget(**website_redirect)
        self._values: typing.Dict[str, typing.Any] = {}
        if access_control is not None:
            self._values["access_control"] = access_control
        if auto_delete_objects is not None:
            self._values["auto_delete_objects"] = auto_delete_objects
        if block_public_access is not None:
            self._values["block_public_access"] = block_public_access
        if bucket_key_enabled is not None:
            self._values["bucket_key_enabled"] = bucket_key_enabled
        if bucket_name is not None:
            self._values["bucket_name"] = bucket_name
        if cors is not None:
            self._values["cors"] = cors
        if encryption is not None:
            self._values["encryption"] = encryption
        if encryption_key is not None:
            self._values["encryption_key"] = encryption_key
        if enforce_ssl is not None:
            self._values["enforce_ssl"] = enforce_ssl
        if intelligent_tiering_configurations is not None:
            self._values["intelligent_tiering_configurations"] = intelligent_tiering_configurations
        if inventories is not None:
            self._values["inventories"] = inventories
        if lifecycle_rules is not None:
            self._values["lifecycle_rules"] = lifecycle_rules
        if metrics is not None:
            self._values["metrics"] = metrics
        if notifications_handler_role is not None:
            self._values["notifications_handler_role"] = notifications_handler_role
        if object_ownership is not None:
            self._values["object_ownership"] = object_ownership
        if public_read_access is not None:
            self._values["public_read_access"] = public_read_access
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy
        if server_access_logs_bucket is not None:
            self._values["server_access_logs_bucket"] = server_access_logs_bucket
        if server_access_logs_prefix is not None:
            self._values["server_access_logs_prefix"] = server_access_logs_prefix
        if transfer_acceleration is not None:
            self._values["transfer_acceleration"] = transfer_acceleration
        if versioned is not None:
            self._values["versioned"] = versioned
        if website_error_document is not None:
            self._values["website_error_document"] = website_error_document
        if website_index_document is not None:
            self._values["website_index_document"] = website_index_document
        if website_redirect is not None:
            self._values["website_redirect"] = website_redirect
        if website_routing_rules is not None:
            self._values["website_routing_rules"] = website_routing_rules

    @builtins.property
    def access_control(self) -> typing.Optional[BucketAccessControl]:
        '''Specifies a canned ACL that grants predefined permissions to the bucket.

        :default: BucketAccessControl.PRIVATE
        '''
        result = self._values.get("access_control")
        return typing.cast(typing.Optional[BucketAccessControl], result)

    @builtins.property
    def auto_delete_objects(self) -> typing.Optional[builtins.bool]:
        '''Whether all objects should be automatically deleted when the bucket is removed from the stack or when the stack is deleted.

        Requires the ``removalPolicy`` to be set to ``RemovalPolicy.DESTROY``.

        **Warning** if you have deployed a bucket with ``autoDeleteObjects: true``,
        switching this to ``false`` in a CDK version *before* ``1.126.0`` will lead to
        all objects in the bucket being deleted. Be sure to update your bucket resources
        by deploying with CDK version ``1.126.0`` or later **before** switching this value to ``false``.

        :default: false
        '''
        result = self._values.get("auto_delete_objects")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def block_public_access(self) -> typing.Optional[BlockPublicAccess]:
        '''The block public access configuration of this bucket.

        :default: - CloudFormation defaults will apply. New buckets and objects don't allow public access, but users can modify bucket policies or object permissions to allow public access

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html
        '''
        result = self._values.get("block_public_access")
        return typing.cast(typing.Optional[BlockPublicAccess], result)

    @builtins.property
    def bucket_key_enabled(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether Amazon S3 should use an S3 Bucket Key with server-side encryption using KMS (SSE-KMS) for new objects in the bucket.

        Only relevant, when Encryption is set to {@link BucketEncryption.KMS}

        :default: - false
        '''
        result = self._values.get("bucket_key_enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def bucket_name(self) -> typing.Optional[builtins.str]:
        '''Physical name of this bucket.

        :default: - Assigned by CloudFormation (recommended).
        '''
        result = self._values.get("bucket_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cors(self) -> typing.Optional[typing.List["CorsRule"]]:
        '''The CORS configuration of this bucket.

        :default: - No CORS configuration.

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors.html
        '''
        result = self._values.get("cors")
        return typing.cast(typing.Optional[typing.List["CorsRule"]], result)

    @builtins.property
    def encryption(self) -> typing.Optional[BucketEncryption]:
        '''The kind of server-side encryption to apply to this bucket.

        If you choose KMS, you can specify a KMS key via ``encryptionKey``. If
        encryption key is not specified, a key will automatically be created.

        :default: - ``Kms`` if ``encryptionKey`` is specified, or ``Unencrypted`` otherwise.
        '''
        result = self._values.get("encryption")
        return typing.cast(typing.Optional[BucketEncryption], result)

    @builtins.property
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''External KMS key to use for bucket encryption.

        The 'encryption' property must be either not specified or set to "Kms".
        An error will be emitted if encryption is set to "Unencrypted" or
        "Managed".

        :default:

        - If encryption is set to "Kms" and this property is undefined,
        a new KMS key will be created and associated with this bucket.
        '''
        result = self._values.get("encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def enforce_ssl(self) -> typing.Optional[builtins.bool]:
        '''Enforces SSL for requests.

        S3.5 of the AWS Foundational Security Best Practices Regarding S3.

        :default: false

        :see: https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-ssl-requests-only.html
        '''
        result = self._values.get("enforce_ssl")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def intelligent_tiering_configurations(
        self,
    ) -> typing.Optional[typing.List["IntelligentTieringConfiguration"]]:
        '''Inteligent Tiering Configurations.

        :default: No Intelligent Tiiering Configurations.

        :see: https://docs.aws.amazon.com/AmazonS3/latest/userguide/intelligent-tiering.html
        '''
        result = self._values.get("intelligent_tiering_configurations")
        return typing.cast(typing.Optional[typing.List["IntelligentTieringConfiguration"]], result)

    @builtins.property
    def inventories(self) -> typing.Optional[typing.List["Inventory"]]:
        '''The inventory configuration of the bucket.

        :default: - No inventory configuration

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-inventory.html
        '''
        result = self._values.get("inventories")
        return typing.cast(typing.Optional[typing.List["Inventory"]], result)

    @builtins.property
    def lifecycle_rules(self) -> typing.Optional[typing.List["LifecycleRule"]]:
        '''Rules that define how Amazon S3 manages objects during their lifetime.

        :default: - No lifecycle rules.
        '''
        result = self._values.get("lifecycle_rules")
        return typing.cast(typing.Optional[typing.List["LifecycleRule"]], result)

    @builtins.property
    def metrics(self) -> typing.Optional[typing.List[BucketMetrics]]:
        '''The metrics configuration of this bucket.

        :default: - No metrics configuration.

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-metricsconfiguration.html
        '''
        result = self._values.get("metrics")
        return typing.cast(typing.Optional[typing.List[BucketMetrics]], result)

    @builtins.property
    def notifications_handler_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The role to be used by the notifications handler.

        :default: - a new role will be created.
        '''
        result = self._values.get("notifications_handler_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def object_ownership(self) -> typing.Optional["ObjectOwnership"]:
        '''The objectOwnership of the bucket.

        :default: - No ObjectOwnership configuration, uploading account will own the object.

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/about-object-ownership.html
        '''
        result = self._values.get("object_ownership")
        return typing.cast(typing.Optional["ObjectOwnership"], result)

    @builtins.property
    def public_read_access(self) -> typing.Optional[builtins.bool]:
        '''Grants public read access to all objects in the bucket.

        Similar to calling ``bucket.grantPublicAccess()``

        :default: false
        '''
        result = self._values.get("public_read_access")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''Policy to apply when the bucket is removed from this stack.

        :default: - The bucket will be orphaned.
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    @builtins.property
    def server_access_logs_bucket(self) -> typing.Optional["IBucket"]:
        '''Destination bucket for the server access logs.

        :default: - If "serverAccessLogsPrefix" undefined - access logs disabled, otherwise - log to current bucket.
        '''
        result = self._values.get("server_access_logs_bucket")
        return typing.cast(typing.Optional["IBucket"], result)

    @builtins.property
    def server_access_logs_prefix(self) -> typing.Optional[builtins.str]:
        '''Optional log file prefix to use for the bucket's access logs.

        If defined without "serverAccessLogsBucket", enables access logs to current bucket with this prefix.

        :default: - No log file prefix
        '''
        result = self._values.get("server_access_logs_prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def transfer_acceleration(self) -> typing.Optional[builtins.bool]:
        '''Whether this bucket should have transfer acceleration turned on or not.

        :default: false
        '''
        result = self._values.get("transfer_acceleration")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def versioned(self) -> typing.Optional[builtins.bool]:
        '''Whether this bucket should have versioning turned on or not.

        :default: false
        '''
        result = self._values.get("versioned")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def website_error_document(self) -> typing.Optional[builtins.str]:
        '''The name of the error document (e.g. "404.html") for the website. ``websiteIndexDocument`` must also be set if this is set.

        :default: - No error document.
        '''
        result = self._values.get("website_error_document")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def website_index_document(self) -> typing.Optional[builtins.str]:
        '''The name of the index document (e.g. "index.html") for the website. Enables static website hosting for this bucket.

        :default: - No index document.
        '''
        result = self._values.get("website_index_document")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def website_redirect(self) -> typing.Optional["RedirectTarget"]:
        '''Specifies the redirect behavior of all requests to a website endpoint of a bucket.

        If you specify this property, you can't specify "websiteIndexDocument", "websiteErrorDocument" nor , "websiteRoutingRules".

        :default: - No redirection.
        '''
        result = self._values.get("website_redirect")
        return typing.cast(typing.Optional["RedirectTarget"], result)

    @builtins.property
    def website_routing_rules(self) -> typing.Optional[typing.List["RoutingRule"]]:
        '''Rules that define when a redirect is applied and the redirect behavior.

        :default: - No redirection rules.
        '''
        result = self._values.get("website_routing_rules")
        return typing.cast(typing.Optional[typing.List["RoutingRule"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BucketProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnAccessPoint(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_s3.CfnAccessPoint",
):
    '''A CloudFormation ``AWS::S3::AccessPoint``.

    The AWS::S3::AccessPoint resource is an Amazon S3 resource type that you can use to access buckets.

    :cloudformationResource: AWS::S3::AccessPoint
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_s3 as s3
        
        # policy: Any
        # policy_status: Any
        
        cfn_access_point = s3.CfnAccessPoint(self, "MyCfnAccessPoint",
            bucket="bucket",
        
            # the properties below are optional
            name="name",
            policy=policy,
            policy_status=policy_status,
            public_access_block_configuration=s3.CfnAccessPoint.PublicAccessBlockConfigurationProperty(
                block_public_acls=False,
                block_public_policy=False,
                ignore_public_acls=False,
                restrict_public_buckets=False
            ),
            vpc_configuration=s3.CfnAccessPoint.VpcConfigurationProperty(
                vpc_id="vpcId"
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        bucket: builtins.str,
        name: typing.Optional[builtins.str] = None,
        policy: typing.Any = None,
        policy_status: typing.Any = None,
        public_access_block_configuration: typing.Optional[typing.Union["CfnAccessPoint.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]] = None,
        vpc_configuration: typing.Optional[typing.Union["CfnAccessPoint.VpcConfigurationProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::S3::AccessPoint``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param bucket: The name of the bucket associated with this access point.
        :param name: The name of this access point. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the access point name.
        :param policy: The access point policy associated with this access point.
        :param policy_status: The container element for a bucket's policy status.
        :param public_access_block_configuration: The PublicAccessBlock configuration that you want to apply to this Amazon S3 bucket. You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see `The Meaning of "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`_ in the *Amazon S3 User Guide* .
        :param vpc_configuration: The Virtual Private Cloud (VPC) configuration for this access point, if one exists.
        '''
        props = CfnAccessPointProps(
            bucket=bucket,
            name=name,
            policy=policy,
            policy_status=policy_status,
            public_access_block_configuration=public_access_block_configuration,
            vpc_configuration=vpc_configuration,
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
    @jsii.member(jsii_name="attrAlias")
    def attr_alias(self) -> builtins.str:
        '''The alias for this access point.

        :cloudformationAttribute: Alias
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAlias"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''This property contains the details of the ARN for the access point.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of this access point.

        :cloudformationAttribute: Name
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrNetworkOrigin")
    def attr_network_origin(self) -> builtins.str:
        '''Indicates whether this access point allows access from the internet.

        If ``VpcConfiguration`` is specified for this access point, then ``NetworkOrigin`` is ``VPC`` , and the access point doesn't allow access from the internet. Otherwise, ``NetworkOrigin`` is ``Internet`` , and the access point allows access from the internet, subject to the access point and bucket access policies.

        *Allowed values* : ``VPC`` | ``Internet``

        :cloudformationAttribute: NetworkOrigin
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrNetworkOrigin"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucket")
    def bucket(self) -> builtins.str:
        '''The name of the bucket associated with this access point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-bucket
        '''
        return typing.cast(builtins.str, jsii.get(self, "bucket"))

    @bucket.setter
    def bucket(self, value: builtins.str) -> None:
        jsii.set(self, "bucket", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policy")
    def policy(self) -> typing.Any:
        '''The access point policy associated with this access point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-policy
        '''
        return typing.cast(typing.Any, jsii.get(self, "policy"))

    @policy.setter
    def policy(self, value: typing.Any) -> None:
        jsii.set(self, "policy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyStatus")
    def policy_status(self) -> typing.Any:
        '''The container element for a bucket's policy status.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-policystatus
        '''
        return typing.cast(typing.Any, jsii.get(self, "policyStatus"))

    @policy_status.setter
    def policy_status(self, value: typing.Any) -> None:
        jsii.set(self, "policyStatus", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of this access point.

        If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the access point name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="publicAccessBlockConfiguration")
    def public_access_block_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnAccessPoint.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]]:
        '''The PublicAccessBlock configuration that you want to apply to this Amazon S3 bucket.

        You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see `The Meaning of "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-publicaccessblockconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnAccessPoint.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "publicAccessBlockConfiguration"))

    @public_access_block_configuration.setter
    def public_access_block_configuration(
        self,
        value: typing.Optional[typing.Union["CfnAccessPoint.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "publicAccessBlockConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcConfiguration")
    def vpc_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnAccessPoint.VpcConfigurationProperty", _IResolvable_da3f097b]]:
        '''The Virtual Private Cloud (VPC) configuration for this access point, if one exists.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-vpcconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnAccessPoint.VpcConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "vpcConfiguration"))

    @vpc_configuration.setter
    def vpc_configuration(
        self,
        value: typing.Optional[typing.Union["CfnAccessPoint.VpcConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "vpcConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnAccessPoint.PublicAccessBlockConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "block_public_acls": "blockPublicAcls",
            "block_public_policy": "blockPublicPolicy",
            "ignore_public_acls": "ignorePublicAcls",
            "restrict_public_buckets": "restrictPublicBuckets",
        },
    )
    class PublicAccessBlockConfigurationProperty:
        def __init__(
            self,
            *,
            block_public_acls: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            block_public_policy: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            ignore_public_acls: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            restrict_public_buckets: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The PublicAccessBlock configuration that you want to apply to this Amazon S3 bucket.

            You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see `The Meaning of "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`_ in the *Amazon S3 User Guide* .

            :param block_public_acls: Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket. Setting this element to ``TRUE`` causes the following behavior: - PUT Bucket ACL and PUT Object ACL calls fail if the specified ACL is public. - PUT Object calls fail if the request includes a public ACL. - PUT Bucket calls fail if the request includes a public ACL. Enabling this setting doesn't affect existing policies or ACLs.
            :param block_public_policy: Specifies whether Amazon S3 should block public bucket policies for this bucket. Setting this element to ``TRUE`` causes Amazon S3 to reject calls to PUT Bucket policy if the specified bucket policy allows public access. Enabling this setting doesn't affect existing bucket policies.
            :param ignore_public_acls: Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket. Setting this element to ``TRUE`` causes Amazon S3 to ignore all public ACLs on this bucket and objects in this bucket. Enabling this setting doesn't affect the persistence of any existing ACLs and doesn't prevent new public ACLs from being set.
            :param restrict_public_buckets: Specifies whether Amazon S3 should restrict public bucket policies for this bucket. Setting this element to ``TRUE`` restricts access to this bucket to only AWS service principals and authorized users within this account if the bucket has a public policy. Enabling this setting doesn't affect previously stored bucket policies, except that public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-accesspoint-publicaccessblockconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                public_access_block_configuration_property = s3.CfnAccessPoint.PublicAccessBlockConfigurationProperty(
                    block_public_acls=False,
                    block_public_policy=False,
                    ignore_public_acls=False,
                    restrict_public_buckets=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if block_public_acls is not None:
                self._values["block_public_acls"] = block_public_acls
            if block_public_policy is not None:
                self._values["block_public_policy"] = block_public_policy
            if ignore_public_acls is not None:
                self._values["ignore_public_acls"] = ignore_public_acls
            if restrict_public_buckets is not None:
                self._values["restrict_public_buckets"] = restrict_public_buckets

        @builtins.property
        def block_public_acls(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket.

            Setting this element to ``TRUE`` causes the following behavior:

            - PUT Bucket ACL and PUT Object ACL calls fail if the specified ACL is public.
            - PUT Object calls fail if the request includes a public ACL.
            - PUT Bucket calls fail if the request includes a public ACL.

            Enabling this setting doesn't affect existing policies or ACLs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-accesspoint-publicaccessblockconfiguration.html#cfn-s3-accesspoint-publicaccessblockconfiguration-blockpublicacls
            '''
            result = self._values.get("block_public_acls")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def block_public_policy(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should block public bucket policies for this bucket.

            Setting this element to ``TRUE`` causes Amazon S3 to reject calls to PUT Bucket policy if the specified bucket policy allows public access.

            Enabling this setting doesn't affect existing bucket policies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-accesspoint-publicaccessblockconfiguration.html#cfn-s3-accesspoint-publicaccessblockconfiguration-blockpublicpolicy
            '''
            result = self._values.get("block_public_policy")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def ignore_public_acls(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket.

            Setting this element to ``TRUE`` causes Amazon S3 to ignore all public ACLs on this bucket and objects in this bucket.

            Enabling this setting doesn't affect the persistence of any existing ACLs and doesn't prevent new public ACLs from being set.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-accesspoint-publicaccessblockconfiguration.html#cfn-s3-accesspoint-publicaccessblockconfiguration-ignorepublicacls
            '''
            result = self._values.get("ignore_public_acls")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def restrict_public_buckets(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should restrict public bucket policies for this bucket.

            Setting this element to ``TRUE`` restricts access to this bucket to only AWS service principals and authorized users within this account if the bucket has a public policy.

            Enabling this setting doesn't affect previously stored bucket policies, except that public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-accesspoint-publicaccessblockconfiguration.html#cfn-s3-accesspoint-publicaccessblockconfiguration-restrictpublicbuckets
            '''
            result = self._values.get("restrict_public_buckets")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PublicAccessBlockConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnAccessPoint.VpcConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"vpc_id": "vpcId"},
    )
    class VpcConfigurationProperty:
        def __init__(self, *, vpc_id: typing.Optional[builtins.str] = None) -> None:
            '''The Virtual Private Cloud (VPC) configuration for this access point.

            :param vpc_id: If this field is specified, the access point will only allow connections from the specified VPC ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-accesspoint-vpcconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                vpc_configuration_property = s3.CfnAccessPoint.VpcConfigurationProperty(
                    vpc_id="vpcId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if vpc_id is not None:
                self._values["vpc_id"] = vpc_id

        @builtins.property
        def vpc_id(self) -> typing.Optional[builtins.str]:
            '''If this field is specified, the access point will only allow connections from the specified VPC ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-accesspoint-vpcconfiguration.html#cfn-s3-accesspoint-vpcconfiguration-vpcid
            '''
            result = self._values.get("vpc_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VpcConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.CfnAccessPointProps",
    jsii_struct_bases=[],
    name_mapping={
        "bucket": "bucket",
        "name": "name",
        "policy": "policy",
        "policy_status": "policyStatus",
        "public_access_block_configuration": "publicAccessBlockConfiguration",
        "vpc_configuration": "vpcConfiguration",
    },
)
class CfnAccessPointProps:
    def __init__(
        self,
        *,
        bucket: builtins.str,
        name: typing.Optional[builtins.str] = None,
        policy: typing.Any = None,
        policy_status: typing.Any = None,
        public_access_block_configuration: typing.Optional[typing.Union[CfnAccessPoint.PublicAccessBlockConfigurationProperty, _IResolvable_da3f097b]] = None,
        vpc_configuration: typing.Optional[typing.Union[CfnAccessPoint.VpcConfigurationProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnAccessPoint``.

        :param bucket: The name of the bucket associated with this access point.
        :param name: The name of this access point. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the access point name.
        :param policy: The access point policy associated with this access point.
        :param policy_status: The container element for a bucket's policy status.
        :param public_access_block_configuration: The PublicAccessBlock configuration that you want to apply to this Amazon S3 bucket. You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see `The Meaning of "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`_ in the *Amazon S3 User Guide* .
        :param vpc_configuration: The Virtual Private Cloud (VPC) configuration for this access point, if one exists.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            
            # policy: Any
            # policy_status: Any
            
            cfn_access_point_props = s3.CfnAccessPointProps(
                bucket="bucket",
            
                # the properties below are optional
                name="name",
                policy=policy,
                policy_status=policy_status,
                public_access_block_configuration=s3.CfnAccessPoint.PublicAccessBlockConfigurationProperty(
                    block_public_acls=False,
                    block_public_policy=False,
                    ignore_public_acls=False,
                    restrict_public_buckets=False
                ),
                vpc_configuration=s3.CfnAccessPoint.VpcConfigurationProperty(
                    vpc_id="vpcId"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "bucket": bucket,
        }
        if name is not None:
            self._values["name"] = name
        if policy is not None:
            self._values["policy"] = policy
        if policy_status is not None:
            self._values["policy_status"] = policy_status
        if public_access_block_configuration is not None:
            self._values["public_access_block_configuration"] = public_access_block_configuration
        if vpc_configuration is not None:
            self._values["vpc_configuration"] = vpc_configuration

    @builtins.property
    def bucket(self) -> builtins.str:
        '''The name of the bucket associated with this access point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-bucket
        '''
        result = self._values.get("bucket")
        assert result is not None, "Required property 'bucket' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of this access point.

        If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the access point name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def policy(self) -> typing.Any:
        '''The access point policy associated with this access point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-policy
        '''
        result = self._values.get("policy")
        return typing.cast(typing.Any, result)

    @builtins.property
    def policy_status(self) -> typing.Any:
        '''The container element for a bucket's policy status.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-policystatus
        '''
        result = self._values.get("policy_status")
        return typing.cast(typing.Any, result)

    @builtins.property
    def public_access_block_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnAccessPoint.PublicAccessBlockConfigurationProperty, _IResolvable_da3f097b]]:
        '''The PublicAccessBlock configuration that you want to apply to this Amazon S3 bucket.

        You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see `The Meaning of "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-publicaccessblockconfiguration
        '''
        result = self._values.get("public_access_block_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnAccessPoint.PublicAccessBlockConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def vpc_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnAccessPoint.VpcConfigurationProperty, _IResolvable_da3f097b]]:
        '''The Virtual Private Cloud (VPC) configuration for this access point, if one exists.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-accesspoint.html#cfn-s3-accesspoint-vpcconfiguration
        '''
        result = self._values.get("vpc_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnAccessPoint.VpcConfigurationProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAccessPointProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnBucket(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_s3.CfnBucket",
):
    '''A CloudFormation ``AWS::S3::Bucket``.

    The ``AWS::S3::Bucket`` resource creates an Amazon S3 bucket in the same AWS Region where you create the AWS CloudFormation stack.

    To control how AWS CloudFormation handles the bucket when the stack is deleted, you can set a deletion policy for your bucket. You can choose to *retain* the bucket or to *delete* the bucket. For more information, see `DeletionPolicy Attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-deletionpolicy.html>`_ .
    .. epigraph::

       You can only delete empty buckets. Deletion fails for buckets that have contents.

    :cloudformationResource: AWS::S3::Bucket
    :exampleMetadata: infused
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html

    Example::

        # cfn_template: cfn_inc.CfnInclude
        
        cfn_bucket = cfn_template.get_resource("Bucket")
        
        role = iam.Role(self, "Role",
            assumed_by=iam.AnyPrincipal()
        )
        role.add_to_policy(iam.PolicyStatement(
            actions=["s3:*"],
            resources=[cfn_bucket.attr_arn]
        ))
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        accelerate_configuration: typing.Optional[typing.Union["CfnBucket.AccelerateConfigurationProperty", _IResolvable_da3f097b]] = None,
        access_control: typing.Optional[builtins.str] = None,
        analytics_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.AnalyticsConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        bucket_encryption: typing.Optional[typing.Union["CfnBucket.BucketEncryptionProperty", _IResolvable_da3f097b]] = None,
        bucket_name: typing.Optional[builtins.str] = None,
        cors_configuration: typing.Optional[typing.Union["CfnBucket.CorsConfigurationProperty", _IResolvable_da3f097b]] = None,
        intelligent_tiering_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.IntelligentTieringConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        inventory_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.InventoryConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        lifecycle_configuration: typing.Optional[typing.Union["CfnBucket.LifecycleConfigurationProperty", _IResolvable_da3f097b]] = None,
        logging_configuration: typing.Optional[typing.Union["CfnBucket.LoggingConfigurationProperty", _IResolvable_da3f097b]] = None,
        metrics_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.MetricsConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        notification_configuration: typing.Optional[typing.Union["CfnBucket.NotificationConfigurationProperty", _IResolvable_da3f097b]] = None,
        object_lock_configuration: typing.Optional[typing.Union["CfnBucket.ObjectLockConfigurationProperty", _IResolvable_da3f097b]] = None,
        object_lock_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ownership_controls: typing.Optional[typing.Union["CfnBucket.OwnershipControlsProperty", _IResolvable_da3f097b]] = None,
        public_access_block_configuration: typing.Optional[typing.Union["CfnBucket.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]] = None,
        replication_configuration: typing.Optional[typing.Union["CfnBucket.ReplicationConfigurationProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        versioning_configuration: typing.Optional[typing.Union["CfnBucket.VersioningConfigurationProperty", _IResolvable_da3f097b]] = None,
        website_configuration: typing.Optional[typing.Union["CfnBucket.WebsiteConfigurationProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::S3::Bucket``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param accelerate_configuration: Configures the transfer acceleration state for an Amazon S3 bucket. For more information, see `Amazon S3 Transfer Acceleration <https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html>`_ in the *Amazon S3 User Guide* .
        :param access_control: A canned access control list (ACL) that grants predefined permissions to the bucket. For more information about canned ACLs, see `Canned ACL <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl>`_ in the *Amazon S3 User Guide* . Be aware that the syntax for this property differs from the information provided in the *Amazon S3 User Guide* . The AccessControl property is case-sensitive and must be one of the following values: Private, PublicRead, PublicReadWrite, AuthenticatedRead, LogDeliveryWrite, BucketOwnerRead, BucketOwnerFullControl, or AwsExecRead.
        :param analytics_configurations: Specifies the configuration and any analyses for the analytics filter of an Amazon S3 bucket.
        :param bucket_encryption: Specifies default encryption for a bucket using server-side encryption with Amazon S3-managed keys (SSE-S3) or AWS KMS-managed keys (SSE-KMS) bucket. For information about the Amazon S3 default encryption feature, see `Amazon S3 Default Encryption for S3 Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html>`_ in the *Amazon S3 User Guide* .
        :param bucket_name: A name for the bucket. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the bucket name. The bucket name must contain only lowercase letters, numbers, periods (.), and dashes (-) and must follow `Amazon S3 bucket restrictions and limitations <https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html>`_ . For more information, see `Rules for naming Amazon S3 buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html#bucketnamingrules>`_ in the *Amazon S3 User Guide* . .. epigraph:: If you specify a name, you can't perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you need to replace the resource, specify a new name.
        :param cors_configuration: Describes the cross-origin access configuration for objects in an Amazon S3 bucket. For more information, see `Enabling Cross-Origin Resource Sharing <https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html>`_ in the *Amazon S3 User Guide* .
        :param intelligent_tiering_configurations: Defines how Amazon S3 handles Intelligent-Tiering storage.
        :param inventory_configurations: Specifies the inventory configuration for an Amazon S3 bucket. For more information, see `GET Bucket inventory <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETInventoryConfig.html>`_ in the *Amazon S3 API Reference* .
        :param lifecycle_configuration: Specifies the lifecycle configuration for objects in an Amazon S3 bucket. For more information, see `Object Lifecycle Management <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html>`_ in the *Amazon S3 User Guide* .
        :param logging_configuration: Settings that define where logs are stored.
        :param metrics_configurations: Specifies a metrics configuration for the CloudWatch request metrics (specified by the metrics configuration ID) from an Amazon S3 bucket. If you're updating an existing metrics configuration, note that this is a full replacement of the existing metrics configuration. If you don't include the elements you want to keep, they are erased. For more information, see `PutBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTMetricConfiguration.html>`_ .
        :param notification_configuration: Configuration that defines how Amazon S3 handles bucket notifications.
        :param object_lock_configuration: Places an Object Lock configuration on the specified bucket. The rule specified in the Object Lock configuration will be applied by default to every new object placed in the specified bucket. For more information, see `Locking Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html>`_ . .. epigraph:: - The ``DefaultRetention`` settings require both a mode and a period. - The ``DefaultRetention`` period can be either ``Days`` or ``Years`` but you must select one. You cannot specify ``Days`` and ``Years`` at the same time. - You can only enable Object Lock for new buckets. If you want to turn on Object Lock for an existing bucket, contact AWS Support.
        :param object_lock_enabled: Indicates whether this bucket has an Object Lock configuration enabled. Enable ``ObjectLockEnabled`` when you apply ``ObjectLockConfiguration`` to a bucket.
        :param ownership_controls: Configuration that defines how Amazon S3 handles Object Ownership rules.
        :param public_access_block_configuration: Configuration that defines how Amazon S3 handles public access.
        :param replication_configuration: Configuration for replicating objects in an S3 bucket. To enable replication, you must also enable versioning by using the ``VersioningConfiguration`` property. Amazon S3 can store replicated objects in a single destination bucket or multiple destination buckets. The destination bucket or buckets must already exist.
        :param tags: An arbitrary set of tags (key-value pairs) for this S3 bucket.
        :param versioning_configuration: Enables multiple versions of all objects in this bucket. You might enable versioning to prevent objects from being deleted or overwritten by mistake or to archive objects so that you can retrieve previous versions of them.
        :param website_configuration: Information used to configure the bucket as a static website. For more information, see `Hosting Websites on Amazon S3 <https://docs.aws.amazon.com/AmazonS3/latest/dev/WebsiteHosting.html>`_ .
        '''
        props = CfnBucketProps(
            accelerate_configuration=accelerate_configuration,
            access_control=access_control,
            analytics_configurations=analytics_configurations,
            bucket_encryption=bucket_encryption,
            bucket_name=bucket_name,
            cors_configuration=cors_configuration,
            intelligent_tiering_configurations=intelligent_tiering_configurations,
            inventory_configurations=inventory_configurations,
            lifecycle_configuration=lifecycle_configuration,
            logging_configuration=logging_configuration,
            metrics_configurations=metrics_configurations,
            notification_configuration=notification_configuration,
            object_lock_configuration=object_lock_configuration,
            object_lock_enabled=object_lock_enabled,
            ownership_controls=ownership_controls,
            public_access_block_configuration=public_access_block_configuration,
            replication_configuration=replication_configuration,
            tags=tags,
            versioning_configuration=versioning_configuration,
            website_configuration=website_configuration,
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
        '''Returns the Amazon Resource Name (ARN) of the specified bucket.

        Example: ``arn:aws:s3:::DOC-EXAMPLE-BUCKET``

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDomainName")
    def attr_domain_name(self) -> builtins.str:
        '''Returns the IPv4 DNS name of the specified bucket.

        Example: ``DOC-EXAMPLE-BUCKET.s3.amazonaws.com``

        :cloudformationAttribute: DomainName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDualStackDomainName")
    def attr_dual_stack_domain_name(self) -> builtins.str:
        '''Returns the IPv6 DNS name of the specified bucket.

        Example: ``DOC-EXAMPLE-BUCKET.s3.dualstack.us-east-2.amazonaws.com``

        For more information about dual-stack endpoints, see `Using Amazon S3 Dual-Stack Endpoints <https://docs.aws.amazon.com/AmazonS3/latest/dev/dual-stack-endpoints.html>`_ .

        :cloudformationAttribute: DualStackDomainName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDualStackDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRegionalDomainName")
    def attr_regional_domain_name(self) -> builtins.str:
        '''Returns the regional domain name of the specified bucket.

        Example: ``DOC-EXAMPLE-BUCKET.s3.us-east-2.amazonaws.com``

        :cloudformationAttribute: RegionalDomainName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRegionalDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrWebsiteUrl")
    def attr_website_url(self) -> builtins.str:
        '''Returns the Amazon S3 website endpoint for the specified bucket.

        Example (IPv4): ``http://DOC-EXAMPLE-BUCKET.s3-website.us-east-2.amazonaws.com``

        Example (IPv6): ``http://DOC-EXAMPLE-BUCKET.s3.dualstack.us-east-2.amazonaws.com``

        :cloudformationAttribute: WebsiteURL
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrWebsiteUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An arbitrary set of tags (key-value pairs) for this S3 bucket.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accelerateConfiguration")
    def accelerate_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.AccelerateConfigurationProperty", _IResolvable_da3f097b]]:
        '''Configures the transfer acceleration state for an Amazon S3 bucket.

        For more information, see `Amazon S3 Transfer Acceleration <https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-accelerateconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.AccelerateConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "accelerateConfiguration"))

    @accelerate_configuration.setter
    def accelerate_configuration(
        self,
        value: typing.Optional[typing.Union["CfnBucket.AccelerateConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "accelerateConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accessControl")
    def access_control(self) -> typing.Optional[builtins.str]:
        '''A canned access control list (ACL) that grants predefined permissions to the bucket.

        For more information about canned ACLs, see `Canned ACL <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl>`_ in the *Amazon S3 User Guide* .

        Be aware that the syntax for this property differs from the information provided in the *Amazon S3 User Guide* . The AccessControl property is case-sensitive and must be one of the following values: Private, PublicRead, PublicReadWrite, AuthenticatedRead, LogDeliveryWrite, BucketOwnerRead, BucketOwnerFullControl, or AwsExecRead.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-accesscontrol
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "accessControl"))

    @access_control.setter
    def access_control(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "accessControl", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="analyticsConfigurations")
    def analytics_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.AnalyticsConfigurationProperty", _IResolvable_da3f097b]]]]:
        '''Specifies the configuration and any analyses for the analytics filter of an Amazon S3 bucket.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-analyticsconfigurations
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.AnalyticsConfigurationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "analyticsConfigurations"))

    @analytics_configurations.setter
    def analytics_configurations(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.AnalyticsConfigurationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "analyticsConfigurations", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketEncryption")
    def bucket_encryption(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.BucketEncryptionProperty", _IResolvable_da3f097b]]:
        '''Specifies default encryption for a bucket using server-side encryption with Amazon S3-managed keys (SSE-S3) or AWS KMS-managed keys (SSE-KMS) bucket.

        For information about the Amazon S3 default encryption feature, see `Amazon S3 Default Encryption for S3 Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-bucketencryption
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.BucketEncryptionProperty", _IResolvable_da3f097b]], jsii.get(self, "bucketEncryption"))

    @bucket_encryption.setter
    def bucket_encryption(
        self,
        value: typing.Optional[typing.Union["CfnBucket.BucketEncryptionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "bucketEncryption", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketName")
    def bucket_name(self) -> typing.Optional[builtins.str]:
        '''A name for the bucket.

        If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the bucket name. The bucket name must contain only lowercase letters, numbers, periods (.), and dashes (-) and must follow `Amazon S3 bucket restrictions and limitations <https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html>`_ . For more information, see `Rules for naming Amazon S3 buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html#bucketnamingrules>`_ in the *Amazon S3 User Guide* .
        .. epigraph::

           If you specify a name, you can't perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you need to replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "bucketName"))

    @bucket_name.setter
    def bucket_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "bucketName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="corsConfiguration")
    def cors_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.CorsConfigurationProperty", _IResolvable_da3f097b]]:
        '''Describes the cross-origin access configuration for objects in an Amazon S3 bucket.

        For more information, see `Enabling Cross-Origin Resource Sharing <https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-crossoriginconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.CorsConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "corsConfiguration"))

    @cors_configuration.setter
    def cors_configuration(
        self,
        value: typing.Optional[typing.Union["CfnBucket.CorsConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "corsConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="intelligentTieringConfigurations")
    def intelligent_tiering_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.IntelligentTieringConfigurationProperty", _IResolvable_da3f097b]]]]:
        '''Defines how Amazon S3 handles Intelligent-Tiering storage.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-intelligenttieringconfigurations
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.IntelligentTieringConfigurationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "intelligentTieringConfigurations"))

    @intelligent_tiering_configurations.setter
    def intelligent_tiering_configurations(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.IntelligentTieringConfigurationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "intelligentTieringConfigurations", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="inventoryConfigurations")
    def inventory_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.InventoryConfigurationProperty", _IResolvable_da3f097b]]]]:
        '''Specifies the inventory configuration for an Amazon S3 bucket.

        For more information, see `GET Bucket inventory <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETInventoryConfig.html>`_ in the *Amazon S3 API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-inventoryconfigurations
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.InventoryConfigurationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "inventoryConfigurations"))

    @inventory_configurations.setter
    def inventory_configurations(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.InventoryConfigurationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "inventoryConfigurations", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lifecycleConfiguration")
    def lifecycle_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.LifecycleConfigurationProperty", _IResolvable_da3f097b]]:
        '''Specifies the lifecycle configuration for objects in an Amazon S3 bucket.

        For more information, see `Object Lifecycle Management <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-lifecycleconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.LifecycleConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "lifecycleConfiguration"))

    @lifecycle_configuration.setter
    def lifecycle_configuration(
        self,
        value: typing.Optional[typing.Union["CfnBucket.LifecycleConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "lifecycleConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loggingConfiguration")
    def logging_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.LoggingConfigurationProperty", _IResolvable_da3f097b]]:
        '''Settings that define where logs are stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-loggingconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.LoggingConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "loggingConfiguration"))

    @logging_configuration.setter
    def logging_configuration(
        self,
        value: typing.Optional[typing.Union["CfnBucket.LoggingConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "loggingConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="metricsConfigurations")
    def metrics_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.MetricsConfigurationProperty", _IResolvable_da3f097b]]]]:
        '''Specifies a metrics configuration for the CloudWatch request metrics (specified by the metrics configuration ID) from an Amazon S3 bucket.

        If you're updating an existing metrics configuration, note that this is a full replacement of the existing metrics configuration. If you don't include the elements you want to keep, they are erased. For more information, see `PutBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTMetricConfiguration.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-metricsconfigurations
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.MetricsConfigurationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "metricsConfigurations"))

    @metrics_configurations.setter
    def metrics_configurations(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.MetricsConfigurationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "metricsConfigurations", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationConfiguration")
    def notification_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.NotificationConfigurationProperty", _IResolvable_da3f097b]]:
        '''Configuration that defines how Amazon S3 handles bucket notifications.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-notification
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.NotificationConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "notificationConfiguration"))

    @notification_configuration.setter
    def notification_configuration(
        self,
        value: typing.Optional[typing.Union["CfnBucket.NotificationConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "notificationConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="objectLockConfiguration")
    def object_lock_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.ObjectLockConfigurationProperty", _IResolvable_da3f097b]]:
        '''Places an Object Lock configuration on the specified bucket.

        The rule specified in the Object Lock configuration will be applied by default to every new object placed in the specified bucket. For more information, see `Locking Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html>`_ .
        .. epigraph::

           - The ``DefaultRetention`` settings require both a mode and a period.
           - The ``DefaultRetention`` period can be either ``Days`` or ``Years`` but you must select one. You cannot specify ``Days`` and ``Years`` at the same time.
           - You can only enable Object Lock for new buckets. If you want to turn on Object Lock for an existing bucket, contact AWS Support.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-objectlockconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.ObjectLockConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "objectLockConfiguration"))

    @object_lock_configuration.setter
    def object_lock_configuration(
        self,
        value: typing.Optional[typing.Union["CfnBucket.ObjectLockConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "objectLockConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="objectLockEnabled")
    def object_lock_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether this bucket has an Object Lock configuration enabled.

        Enable ``ObjectLockEnabled`` when you apply ``ObjectLockConfiguration`` to a bucket.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-objectlockenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "objectLockEnabled"))

    @object_lock_enabled.setter
    def object_lock_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "objectLockEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ownershipControls")
    def ownership_controls(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.OwnershipControlsProperty", _IResolvable_da3f097b]]:
        '''Configuration that defines how Amazon S3 handles Object Ownership rules.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-ownershipcontrols
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.OwnershipControlsProperty", _IResolvable_da3f097b]], jsii.get(self, "ownershipControls"))

    @ownership_controls.setter
    def ownership_controls(
        self,
        value: typing.Optional[typing.Union["CfnBucket.OwnershipControlsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "ownershipControls", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="publicAccessBlockConfiguration")
    def public_access_block_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]]:
        '''Configuration that defines how Amazon S3 handles public access.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-publicaccessblockconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "publicAccessBlockConfiguration"))

    @public_access_block_configuration.setter
    def public_access_block_configuration(
        self,
        value: typing.Optional[typing.Union["CfnBucket.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "publicAccessBlockConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="replicationConfiguration")
    def replication_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.ReplicationConfigurationProperty", _IResolvable_da3f097b]]:
        '''Configuration for replicating objects in an S3 bucket.

        To enable replication, you must also enable versioning by using the ``VersioningConfiguration`` property.

        Amazon S3 can store replicated objects in a single destination bucket or multiple destination buckets. The destination bucket or buckets must already exist.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-replicationconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.ReplicationConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "replicationConfiguration"))

    @replication_configuration.setter
    def replication_configuration(
        self,
        value: typing.Optional[typing.Union["CfnBucket.ReplicationConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "replicationConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="versioningConfiguration")
    def versioning_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.VersioningConfigurationProperty", _IResolvable_da3f097b]]:
        '''Enables multiple versions of all objects in this bucket.

        You might enable versioning to prevent objects from being deleted or overwritten by mistake or to archive objects so that you can retrieve previous versions of them.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-versioning
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.VersioningConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "versioningConfiguration"))

    @versioning_configuration.setter
    def versioning_configuration(
        self,
        value: typing.Optional[typing.Union["CfnBucket.VersioningConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "versioningConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="websiteConfiguration")
    def website_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnBucket.WebsiteConfigurationProperty", _IResolvable_da3f097b]]:
        '''Information used to configure the bucket as a static website.

        For more information, see `Hosting Websites on Amazon S3 <https://docs.aws.amazon.com/AmazonS3/latest/dev/WebsiteHosting.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-websiteconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnBucket.WebsiteConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "websiteConfiguration"))

    @website_configuration.setter
    def website_configuration(
        self,
        value: typing.Optional[typing.Union["CfnBucket.WebsiteConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "websiteConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.AbortIncompleteMultipartUploadProperty",
        jsii_struct_bases=[],
        name_mapping={"days_after_initiation": "daysAfterInitiation"},
    )
    class AbortIncompleteMultipartUploadProperty:
        def __init__(self, *, days_after_initiation: jsii.Number) -> None:
            '''Specifies the days since the initiation of an incomplete multipart upload that Amazon S3 will wait before permanently removing all parts of the upload.

            For more information, see `Stopping Incomplete Multipart Uploads Using a Bucket Lifecycle Policy <https://docs.aws.amazon.com/AmazonS3/latest/dev/mpuoverview.html#mpu-abort-incomplete-mpu-lifecycle-config>`_ in the *Amazon S3 User Guide* .

            :param days_after_initiation: Specifies the number of days after which Amazon S3 stops an incomplete multipart upload.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-abortincompletemultipartupload.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                abort_incomplete_multipart_upload_property = s3.CfnBucket.AbortIncompleteMultipartUploadProperty(
                    days_after_initiation=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "days_after_initiation": days_after_initiation,
            }

        @builtins.property
        def days_after_initiation(self) -> jsii.Number:
            '''Specifies the number of days after which Amazon S3 stops an incomplete multipart upload.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-abortincompletemultipartupload.html#cfn-s3-bucket-abortincompletemultipartupload-daysafterinitiation
            '''
            result = self._values.get("days_after_initiation")
            assert result is not None, "Required property 'days_after_initiation' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AbortIncompleteMultipartUploadProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.AccelerateConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"acceleration_status": "accelerationStatus"},
    )
    class AccelerateConfigurationProperty:
        def __init__(self, *, acceleration_status: builtins.str) -> None:
            '''Configures the transfer acceleration state for an Amazon S3 bucket.

            For more information, see `Amazon S3 Transfer Acceleration <https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html>`_ in the *Amazon S3 User Guide* .

            :param acceleration_status: Specifies the transfer acceleration status of the bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-accelerateconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                accelerate_configuration_property = s3.CfnBucket.AccelerateConfigurationProperty(
                    acceleration_status="accelerationStatus"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "acceleration_status": acceleration_status,
            }

        @builtins.property
        def acceleration_status(self) -> builtins.str:
            '''Specifies the transfer acceleration status of the bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-accelerateconfiguration.html#cfn-s3-bucket-accelerateconfiguration-accelerationstatus
            '''
            result = self._values.get("acceleration_status")
            assert result is not None, "Required property 'acceleration_status' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AccelerateConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.AccessControlTranslationProperty",
        jsii_struct_bases=[],
        name_mapping={"owner": "owner"},
    )
    class AccessControlTranslationProperty:
        def __init__(self, *, owner: builtins.str) -> None:
            '''Specify this only in a cross-account scenario (where source and destination bucket owners are not the same), and you want to change replica ownership to the AWS account that owns the destination bucket.

            If this is not specified in the replication configuration, the replicas are owned by same AWS account that owns the source object.

            :param owner: Specifies the replica ownership. For default and valid values, see `PUT bucket replication <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTreplication.html>`_ in the *Amazon S3 API Reference* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-accesscontroltranslation.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                access_control_translation_property = s3.CfnBucket.AccessControlTranslationProperty(
                    owner="owner"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "owner": owner,
            }

        @builtins.property
        def owner(self) -> builtins.str:
            '''Specifies the replica ownership.

            For default and valid values, see `PUT bucket replication <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTreplication.html>`_ in the *Amazon S3 API Reference* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-accesscontroltranslation.html#cfn-s3-bucket-accesscontroltranslation-owner
            '''
            result = self._values.get("owner")
            assert result is not None, "Required property 'owner' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AccessControlTranslationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.AnalyticsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "id": "id",
            "storage_class_analysis": "storageClassAnalysis",
            "prefix": "prefix",
            "tag_filters": "tagFilters",
        },
    )
    class AnalyticsConfigurationProperty:
        def __init__(
            self,
            *,
            id: builtins.str,
            storage_class_analysis: typing.Union["CfnBucket.StorageClassAnalysisProperty", _IResolvable_da3f097b],
            prefix: typing.Optional[builtins.str] = None,
            tag_filters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Specifies the configuration and any analyses for the analytics filter of an Amazon S3 bucket.

            :param id: The ID that identifies the analytics configuration.
            :param storage_class_analysis: Contains data related to access patterns to be collected and made available to analyze the tradeoffs between different storage classes.
            :param prefix: The prefix that an object must have to be included in the analytics results.
            :param tag_filters: The tags to use when evaluating an analytics filter. The analytics only includes objects that meet the filter's criteria. If no filter is specified, all of the contents of the bucket are included in the analysis.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-analyticsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                analytics_configuration_property = s3.CfnBucket.AnalyticsConfigurationProperty(
                    id="id",
                    storage_class_analysis=s3.CfnBucket.StorageClassAnalysisProperty(
                        data_export=s3.CfnBucket.DataExportProperty(
                            destination=s3.CfnBucket.DestinationProperty(
                                bucket_arn="bucketArn",
                                format="format",
                
                                # the properties below are optional
                                bucket_account_id="bucketAccountId",
                                prefix="prefix"
                            ),
                            output_schema_version="outputSchemaVersion"
                        )
                    ),
                
                    # the properties below are optional
                    prefix="prefix",
                    tag_filters=[s3.CfnBucket.TagFilterProperty(
                        key="key",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "id": id,
                "storage_class_analysis": storage_class_analysis,
            }
            if prefix is not None:
                self._values["prefix"] = prefix
            if tag_filters is not None:
                self._values["tag_filters"] = tag_filters

        @builtins.property
        def id(self) -> builtins.str:
            '''The ID that identifies the analytics configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-analyticsconfiguration.html#cfn-s3-bucket-analyticsconfiguration-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def storage_class_analysis(
            self,
        ) -> typing.Union["CfnBucket.StorageClassAnalysisProperty", _IResolvable_da3f097b]:
            '''Contains data related to access patterns to be collected and made available to analyze the tradeoffs between different storage classes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-analyticsconfiguration.html#cfn-s3-bucket-analyticsconfiguration-storageclassanalysis
            '''
            result = self._values.get("storage_class_analysis")
            assert result is not None, "Required property 'storage_class_analysis' is missing"
            return typing.cast(typing.Union["CfnBucket.StorageClassAnalysisProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def prefix(self) -> typing.Optional[builtins.str]:
            '''The prefix that an object must have to be included in the analytics results.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-analyticsconfiguration.html#cfn-s3-bucket-analyticsconfiguration-prefix
            '''
            result = self._values.get("prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def tag_filters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]]:
            '''The tags to use when evaluating an analytics filter.

            The analytics only includes objects that meet the filter's criteria. If no filter is specified, all of the contents of the bucket are included in the analysis.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-analyticsconfiguration.html#cfn-s3-bucket-analyticsconfiguration-tagfilters
            '''
            result = self._values.get("tag_filters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AnalyticsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.BucketEncryptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "server_side_encryption_configuration": "serverSideEncryptionConfiguration",
        },
    )
    class BucketEncryptionProperty:
        def __init__(
            self,
            *,
            server_side_encryption_configuration: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.ServerSideEncryptionRuleProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''Specifies default encryption for a bucket using server-side encryption with Amazon S3-managed keys (SSE-S3) or AWS KMS-managed keys (SSE-KMS) bucket.

            For information about the Amazon S3 default encryption feature, see `Amazon S3 Default Encryption for S3 Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html>`_ in the *Amazon S3 User Guide* .

            :param server_side_encryption_configuration: Specifies the default server-side-encryption configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-bucketencryption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                bucket_encryption_property = s3.CfnBucket.BucketEncryptionProperty(
                    server_side_encryption_configuration=[s3.CfnBucket.ServerSideEncryptionRuleProperty(
                        bucket_key_enabled=False,
                        server_side_encryption_by_default=s3.CfnBucket.ServerSideEncryptionByDefaultProperty(
                            sse_algorithm="sseAlgorithm",
                
                            # the properties below are optional
                            kms_master_key_id="kmsMasterKeyId"
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "server_side_encryption_configuration": server_side_encryption_configuration,
            }

        @builtins.property
        def server_side_encryption_configuration(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.ServerSideEncryptionRuleProperty", _IResolvable_da3f097b]]]:
            '''Specifies the default server-side-encryption configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-bucketencryption.html#cfn-s3-bucket-bucketencryption-serversideencryptionconfiguration
            '''
            result = self._values.get("server_side_encryption_configuration")
            assert result is not None, "Required property 'server_side_encryption_configuration' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.ServerSideEncryptionRuleProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BucketEncryptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.CorsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"cors_rules": "corsRules"},
    )
    class CorsConfigurationProperty:
        def __init__(
            self,
            *,
            cors_rules: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.CorsRuleProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''Describes the cross-origin access configuration for objects in an Amazon S3 bucket.

            For more information, see `Enabling Cross-Origin Resource Sharing <https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html>`_ in the *Amazon S3 User Guide* .

            :param cors_rules: A set of origins and methods (cross-origin access that you want to allow). You can add up to 100 rules to the configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                cors_configuration_property = s3.CfnBucket.CorsConfigurationProperty(
                    cors_rules=[s3.CfnBucket.CorsRuleProperty(
                        allowed_methods=["allowedMethods"],
                        allowed_origins=["allowedOrigins"],
                
                        # the properties below are optional
                        allowed_headers=["allowedHeaders"],
                        exposed_headers=["exposedHeaders"],
                        id="id",
                        max_age=123
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "cors_rules": cors_rules,
            }

        @builtins.property
        def cors_rules(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.CorsRuleProperty", _IResolvable_da3f097b]]]:
            '''A set of origins and methods (cross-origin access that you want to allow).

            You can add up to 100 rules to the configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors.html#cfn-s3-bucket-cors-corsrule
            '''
            result = self._values.get("cors_rules")
            assert result is not None, "Required property 'cors_rules' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.CorsRuleProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CorsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.CorsRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "allowed_methods": "allowedMethods",
            "allowed_origins": "allowedOrigins",
            "allowed_headers": "allowedHeaders",
            "exposed_headers": "exposedHeaders",
            "id": "id",
            "max_age": "maxAge",
        },
    )
    class CorsRuleProperty:
        def __init__(
            self,
            *,
            allowed_methods: typing.Sequence[builtins.str],
            allowed_origins: typing.Sequence[builtins.str],
            allowed_headers: typing.Optional[typing.Sequence[builtins.str]] = None,
            exposed_headers: typing.Optional[typing.Sequence[builtins.str]] = None,
            id: typing.Optional[builtins.str] = None,
            max_age: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies a cross-origin access rule for an Amazon S3 bucket.

            :param allowed_methods: An HTTP method that you allow the origin to run. *Allowed values* : ``GET`` | ``PUT`` | ``HEAD`` | ``POST`` | ``DELETE``
            :param allowed_origins: One or more origins you want customers to be able to access the bucket from.
            :param allowed_headers: Headers that are specified in the ``Access-Control-Request-Headers`` header. These headers are allowed in a preflight OPTIONS request. In response to any preflight OPTIONS request, Amazon S3 returns any requested headers that are allowed.
            :param exposed_headers: One or more headers in the response that you want customers to be able to access from their applications (for example, from a JavaScript ``XMLHttpRequest`` object).
            :param id: A unique identifier for this rule. The value must be no more than 255 characters.
            :param max_age: The time in seconds that your browser is to cache the preflight response for the specified resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors-corsrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                cors_rule_property = s3.CfnBucket.CorsRuleProperty(
                    allowed_methods=["allowedMethods"],
                    allowed_origins=["allowedOrigins"],
                
                    # the properties below are optional
                    allowed_headers=["allowedHeaders"],
                    exposed_headers=["exposedHeaders"],
                    id="id",
                    max_age=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "allowed_methods": allowed_methods,
                "allowed_origins": allowed_origins,
            }
            if allowed_headers is not None:
                self._values["allowed_headers"] = allowed_headers
            if exposed_headers is not None:
                self._values["exposed_headers"] = exposed_headers
            if id is not None:
                self._values["id"] = id
            if max_age is not None:
                self._values["max_age"] = max_age

        @builtins.property
        def allowed_methods(self) -> typing.List[builtins.str]:
            '''An HTTP method that you allow the origin to run.

            *Allowed values* : ``GET`` | ``PUT`` | ``HEAD`` | ``POST`` | ``DELETE``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors-corsrule.html#cfn-s3-bucket-cors-corsrule-allowedmethods
            '''
            result = self._values.get("allowed_methods")
            assert result is not None, "Required property 'allowed_methods' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def allowed_origins(self) -> typing.List[builtins.str]:
            '''One or more origins you want customers to be able to access the bucket from.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors-corsrule.html#cfn-s3-bucket-cors-corsrule-allowedorigins
            '''
            result = self._values.get("allowed_origins")
            assert result is not None, "Required property 'allowed_origins' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def allowed_headers(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Headers that are specified in the ``Access-Control-Request-Headers`` header.

            These headers are allowed in a preflight OPTIONS request. In response to any preflight OPTIONS request, Amazon S3 returns any requested headers that are allowed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors-corsrule.html#cfn-s3-bucket-cors-corsrule-allowedheaders
            '''
            result = self._values.get("allowed_headers")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def exposed_headers(self) -> typing.Optional[typing.List[builtins.str]]:
            '''One or more headers in the response that you want customers to be able to access from their applications (for example, from a JavaScript ``XMLHttpRequest`` object).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors-corsrule.html#cfn-s3-bucket-cors-corsrule-exposedheaders
            '''
            result = self._values.get("exposed_headers")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def id(self) -> typing.Optional[builtins.str]:
            '''A unique identifier for this rule.

            The value must be no more than 255 characters.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors-corsrule.html#cfn-s3-bucket-cors-corsrule-id
            '''
            result = self._values.get("id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def max_age(self) -> typing.Optional[jsii.Number]:
            '''The time in seconds that your browser is to cache the preflight response for the specified resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-cors-corsrule.html#cfn-s3-bucket-cors-corsrule-maxage
            '''
            result = self._values.get("max_age")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CorsRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.DataExportProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination": "destination",
            "output_schema_version": "outputSchemaVersion",
        },
    )
    class DataExportProperty:
        def __init__(
            self,
            *,
            destination: typing.Union["CfnBucket.DestinationProperty", _IResolvable_da3f097b],
            output_schema_version: builtins.str,
        ) -> None:
            '''Specifies how data related to the storage class analysis for an Amazon S3 bucket should be exported.

            :param destination: The place to store the data for an analysis.
            :param output_schema_version: The version of the output schema to use when exporting data. Must be ``V_1`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-dataexport.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                data_export_property = s3.CfnBucket.DataExportProperty(
                    destination=s3.CfnBucket.DestinationProperty(
                        bucket_arn="bucketArn",
                        format="format",
                
                        # the properties below are optional
                        bucket_account_id="bucketAccountId",
                        prefix="prefix"
                    ),
                    output_schema_version="outputSchemaVersion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination": destination,
                "output_schema_version": output_schema_version,
            }

        @builtins.property
        def destination(
            self,
        ) -> typing.Union["CfnBucket.DestinationProperty", _IResolvable_da3f097b]:
            '''The place to store the data for an analysis.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-dataexport.html#cfn-s3-bucket-dataexport-destination
            '''
            result = self._values.get("destination")
            assert result is not None, "Required property 'destination' is missing"
            return typing.cast(typing.Union["CfnBucket.DestinationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def output_schema_version(self) -> builtins.str:
            '''The version of the output schema to use when exporting data.

            Must be ``V_1`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-dataexport.html#cfn-s3-bucket-dataexport-outputschemaversion
            '''
            result = self._values.get("output_schema_version")
            assert result is not None, "Required property 'output_schema_version' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataExportProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.DefaultRetentionProperty",
        jsii_struct_bases=[],
        name_mapping={"days": "days", "mode": "mode", "years": "years"},
    )
    class DefaultRetentionProperty:
        def __init__(
            self,
            *,
            days: typing.Optional[jsii.Number] = None,
            mode: typing.Optional[builtins.str] = None,
            years: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The container element for specifying the default Object Lock retention settings for new objects placed in the specified bucket.

            .. epigraph::

               - The ``DefaultRetention`` settings require both a mode and a period.
               - The ``DefaultRetention`` period can be either ``Days`` or ``Years`` but you must select one. You cannot specify ``Days`` and ``Years`` at the same time.

            :param days: The number of days that you want to specify for the default retention period. If Object Lock is turned on, you must specify ``Mode`` and specify either ``Days`` or ``Years`` .
            :param mode: The default Object Lock retention mode you want to apply to new objects placed in the specified bucket. If Object Lock is turned on, you must specify ``Mode`` and specify either ``Days`` or ``Years`` .
            :param years: The number of years that you want to specify for the default retention period. If Object Lock is turned on, you must specify ``Mode`` and specify either ``Days`` or ``Years`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-defaultretention.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                default_retention_property = s3.CfnBucket.DefaultRetentionProperty(
                    days=123,
                    mode="mode",
                    years=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if days is not None:
                self._values["days"] = days
            if mode is not None:
                self._values["mode"] = mode
            if years is not None:
                self._values["years"] = years

        @builtins.property
        def days(self) -> typing.Optional[jsii.Number]:
            '''The number of days that you want to specify for the default retention period.

            If Object Lock is turned on, you must specify ``Mode`` and specify either ``Days`` or ``Years`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-defaultretention.html#cfn-s3-bucket-defaultretention-days
            '''
            result = self._values.get("days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def mode(self) -> typing.Optional[builtins.str]:
            '''The default Object Lock retention mode you want to apply to new objects placed in the specified bucket.

            If Object Lock is turned on, you must specify ``Mode`` and specify either ``Days`` or ``Years`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-defaultretention.html#cfn-s3-bucket-defaultretention-mode
            '''
            result = self._values.get("mode")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def years(self) -> typing.Optional[jsii.Number]:
            '''The number of years that you want to specify for the default retention period.

            If Object Lock is turned on, you must specify ``Mode`` and specify either ``Days`` or ``Years`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-defaultretention.html#cfn-s3-bucket-defaultretention-years
            '''
            result = self._values.get("years")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DefaultRetentionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.DeleteMarkerReplicationProperty",
        jsii_struct_bases=[],
        name_mapping={"status": "status"},
    )
    class DeleteMarkerReplicationProperty:
        def __init__(self, *, status: typing.Optional[builtins.str] = None) -> None:
            '''Specifies whether Amazon S3 replicates delete markers.

            If you specify a ``Filter`` in your replication configuration, you must also include a ``DeleteMarkerReplication`` element. If your ``Filter`` includes a ``Tag`` element, the ``DeleteMarkerReplication`` ``Status`` must be set to Disabled, because Amazon S3 does not support replicating delete markers for tag-based rules. For an example configuration, see `Basic Rule Configuration <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-add-config.html#replication-config-min-rule-config>`_ .

            For more information about delete marker replication, see `Basic Rule Configuration <https://docs.aws.amazon.com/AmazonS3/latest/dev/delete-marker-replication.html>`_ .
            .. epigraph::

               If you are using an earlier version of the replication configuration, Amazon S3 handles replication of delete markers differently. For more information, see `Backward Compatibility <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-add-config.html#replication-backward-compat-considerations>`_ .

            :param status: Indicates whether to replicate delete markers. Disabled by default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-deletemarkerreplication.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                delete_marker_replication_property = s3.CfnBucket.DeleteMarkerReplicationProperty(
                    status="status"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if status is not None:
                self._values["status"] = status

        @builtins.property
        def status(self) -> typing.Optional[builtins.str]:
            '''Indicates whether to replicate delete markers.

            Disabled by default.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-deletemarkerreplication.html#cfn-s3-bucket-deletemarkerreplication-status
            '''
            result = self._values.get("status")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeleteMarkerReplicationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.DestinationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_arn": "bucketArn",
            "format": "format",
            "bucket_account_id": "bucketAccountId",
            "prefix": "prefix",
        },
    )
    class DestinationProperty:
        def __init__(
            self,
            *,
            bucket_arn: builtins.str,
            format: builtins.str,
            bucket_account_id: typing.Optional[builtins.str] = None,
            prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies information about where to publish analysis or configuration results for an Amazon S3 bucket.

            :param bucket_arn: The Amazon Resource Name (ARN) of the bucket to which data is exported.
            :param format: Specifies the file format used when exporting data to Amazon S3. *Allowed values* : ``CSV`` | ``ORC`` | ``Parquet``
            :param bucket_account_id: The account ID that owns the destination S3 bucket. If no account ID is provided, the owner is not validated before exporting data. .. epigraph:: Although this value is optional, we strongly recommend that you set it to help prevent problems if the destination bucket ownership changes.
            :param prefix: The prefix to use when exporting data. The prefix is prepended to all results.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-destination.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                destination_property = s3.CfnBucket.DestinationProperty(
                    bucket_arn="bucketArn",
                    format="format",
                
                    # the properties below are optional
                    bucket_account_id="bucketAccountId",
                    prefix="prefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket_arn": bucket_arn,
                "format": format,
            }
            if bucket_account_id is not None:
                self._values["bucket_account_id"] = bucket_account_id
            if prefix is not None:
                self._values["prefix"] = prefix

        @builtins.property
        def bucket_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the bucket to which data is exported.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-destination.html#cfn-s3-bucket-destination-bucketarn
            '''
            result = self._values.get("bucket_arn")
            assert result is not None, "Required property 'bucket_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def format(self) -> builtins.str:
            '''Specifies the file format used when exporting data to Amazon S3.

            *Allowed values* : ``CSV`` | ``ORC`` | ``Parquet``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-destination.html#cfn-s3-bucket-destination-format
            '''
            result = self._values.get("format")
            assert result is not None, "Required property 'format' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def bucket_account_id(self) -> typing.Optional[builtins.str]:
            '''The account ID that owns the destination S3 bucket.

            If no account ID is provided, the owner is not validated before exporting data.
            .. epigraph::

               Although this value is optional, we strongly recommend that you set it to help prevent problems if the destination bucket ownership changes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-destination.html#cfn-s3-bucket-destination-bucketaccountid
            '''
            result = self._values.get("bucket_account_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def prefix(self) -> typing.Optional[builtins.str]:
            '''The prefix to use when exporting data.

            The prefix is prepended to all results.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-destination.html#cfn-s3-bucket-destination-prefix
            '''
            result = self._values.get("prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DestinationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.EncryptionConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"replica_kms_key_id": "replicaKmsKeyId"},
    )
    class EncryptionConfigurationProperty:
        def __init__(self, *, replica_kms_key_id: builtins.str) -> None:
            '''Specifies encryption-related information for an Amazon S3 bucket that is a destination for replicated objects.

            :param replica_kms_key_id: Specifies the ID (Key ARN or Alias ARN) of the customer managed AWS KMS key stored in AWS Key Management Service (KMS) for the destination bucket. Amazon S3 uses this key to encrypt replica objects. Amazon S3 only supports symmetric, customer managed KMS keys. For more information, see `Using symmetric and asymmetric keys <https://docs.aws.amazon.com//kms/latest/developerguide/symmetric-asymmetric.html>`_ in the *AWS Key Management Service Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-encryptionconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                encryption_configuration_property = s3.CfnBucket.EncryptionConfigurationProperty(
                    replica_kms_key_id="replicaKmsKeyId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "replica_kms_key_id": replica_kms_key_id,
            }

        @builtins.property
        def replica_kms_key_id(self) -> builtins.str:
            '''Specifies the ID (Key ARN or Alias ARN) of the customer managed AWS KMS key stored in AWS Key Management Service (KMS) for the destination bucket.

            Amazon S3 uses this key to encrypt replica objects. Amazon S3 only supports symmetric, customer managed KMS keys. For more information, see `Using symmetric and asymmetric keys <https://docs.aws.amazon.com//kms/latest/developerguide/symmetric-asymmetric.html>`_ in the *AWS Key Management Service Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-encryptionconfiguration.html#cfn-s3-bucket-encryptionconfiguration-replicakmskeyid
            '''
            result = self._values.get("replica_kms_key_id")
            assert result is not None, "Required property 'replica_kms_key_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.EventBridgeConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"event_bridge_enabled": "eventBridgeEnabled"},
    )
    class EventBridgeConfigurationProperty:
        def __init__(
            self,
            *,
            event_bridge_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Amazon S3 can send events to Amazon EventBridge whenever certain events happen in your bucket, see `Using EventBridge <https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html>`_ in the *Amazon S3 User Guide* .

            Unlike other destinations, delivery of events to EventBridge can be either enabled or disabled for a bucket. If enabled, all events will be sent to EventBridge and you can use EventBridge rules to route events to additional targets. For more information, see `What Is Amazon EventBridge <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-what-is.html>`_ in the *Amazon EventBridge User Guide*

            :param event_bridge_enabled: Enables delivery of events to Amazon EventBridge.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-eventbridgeconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                event_bridge_configuration_property = s3.CfnBucket.EventBridgeConfigurationProperty(
                    event_bridge_enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if event_bridge_enabled is not None:
                self._values["event_bridge_enabled"] = event_bridge_enabled

        @builtins.property
        def event_bridge_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables delivery of events to Amazon EventBridge.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-eventbridgeconfig.html#cfn-s3-bucket-eventbridgeconfiguration-eventbridgeenabled
            '''
            result = self._values.get("event_bridge_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EventBridgeConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.FilterRuleProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class FilterRuleProperty:
        def __init__(self, *, name: builtins.str, value: builtins.str) -> None:
            '''Specifies the Amazon S3 object key name to filter on and whether to filter on the suffix or prefix of the key name.

            :param name: The object key name prefix or suffix identifying one or more objects to which the filtering rule applies. The maximum length is 1,024 characters. Overlapping prefixes and suffixes are not supported. For more information, see `Configuring Event Notifications <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_ in the *Amazon S3 User Guide* .
            :param value: The value that the filter searches for in object key names.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfiguration-config-filter-s3key-rules.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                filter_rule_property = s3.CfnBucket.FilterRuleProperty(
                    name="name",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "value": value,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The object key name prefix or suffix identifying one or more objects to which the filtering rule applies.

            The maximum length is 1,024 characters. Overlapping prefixes and suffixes are not supported. For more information, see `Configuring Event Notifications <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfiguration-config-filter-s3key-rules.html#cfn-s3-bucket-notificationconfiguraiton-config-filter-s3key-rules-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The value that the filter searches for in object key names.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfiguration-config-filter-s3key-rules.html#cfn-s3-bucket-notificationconfiguraiton-config-filter-s3key-rules-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FilterRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.IntelligentTieringConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "id": "id",
            "status": "status",
            "tierings": "tierings",
            "prefix": "prefix",
            "tag_filters": "tagFilters",
        },
    )
    class IntelligentTieringConfigurationProperty:
        def __init__(
            self,
            *,
            id: builtins.str,
            status: builtins.str,
            tierings: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.TieringProperty", _IResolvable_da3f097b]]],
            prefix: typing.Optional[builtins.str] = None,
            tag_filters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Specifies the S3 Intelligent-Tiering configuration for an Amazon S3 bucket.

            For information about the S3 Intelligent-Tiering storage class, see `Storage class for automatically optimizing frequently and infrequently accessed objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html#sc-dynamic-data-access>`_ .

            :param id: The ID used to identify the S3 Intelligent-Tiering configuration.
            :param status: Specifies the status of the configuration.
            :param tierings: Specifies a list of S3 Intelligent-Tiering storage class tiers in the configuration. At least one tier must be defined in the list. At most, you can specify two tiers in the list, one for each available AccessTier: ``ARCHIVE_ACCESS`` and ``DEEP_ARCHIVE_ACCESS`` . .. epigraph:: You only need Intelligent Tiering Configuration enabled on a bucket if you want to automatically move objects stored in the Intelligent-Tiering storage class to Archive Access or Deep Archive Access tiers.
            :param prefix: An object key name prefix that identifies the subset of objects to which the rule applies.
            :param tag_filters: A container for a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-intelligenttieringconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                intelligent_tiering_configuration_property = s3.CfnBucket.IntelligentTieringConfigurationProperty(
                    id="id",
                    status="status",
                    tierings=[s3.CfnBucket.TieringProperty(
                        access_tier="accessTier",
                        days=123
                    )],
                
                    # the properties below are optional
                    prefix="prefix",
                    tag_filters=[s3.CfnBucket.TagFilterProperty(
                        key="key",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "id": id,
                "status": status,
                "tierings": tierings,
            }
            if prefix is not None:
                self._values["prefix"] = prefix
            if tag_filters is not None:
                self._values["tag_filters"] = tag_filters

        @builtins.property
        def id(self) -> builtins.str:
            '''The ID used to identify the S3 Intelligent-Tiering configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-intelligenttieringconfiguration.html#cfn-s3-bucket-intelligenttieringconfiguration-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def status(self) -> builtins.str:
            '''Specifies the status of the configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-intelligenttieringconfiguration.html#cfn-s3-bucket-intelligenttieringconfiguration-status
            '''
            result = self._values.get("status")
            assert result is not None, "Required property 'status' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def tierings(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TieringProperty", _IResolvable_da3f097b]]]:
            '''Specifies a list of S3 Intelligent-Tiering storage class tiers in the configuration.

            At least one tier must be defined in the list. At most, you can specify two tiers in the list, one for each available AccessTier: ``ARCHIVE_ACCESS`` and ``DEEP_ARCHIVE_ACCESS`` .
            .. epigraph::

               You only need Intelligent Tiering Configuration enabled on a bucket if you want to automatically move objects stored in the Intelligent-Tiering storage class to Archive Access or Deep Archive Access tiers.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-intelligenttieringconfiguration.html#cfn-s3-bucket-intelligenttieringconfiguration-tierings
            '''
            result = self._values.get("tierings")
            assert result is not None, "Required property 'tierings' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TieringProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def prefix(self) -> typing.Optional[builtins.str]:
            '''An object key name prefix that identifies the subset of objects to which the rule applies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-intelligenttieringconfiguration.html#cfn-s3-bucket-intelligenttieringconfiguration-prefix
            '''
            result = self._values.get("prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def tag_filters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]]:
            '''A container for a key-value pair.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-intelligenttieringconfiguration.html#cfn-s3-bucket-intelligenttieringconfiguration-tagfilters
            '''
            result = self._values.get("tag_filters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IntelligentTieringConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.InventoryConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination": "destination",
            "enabled": "enabled",
            "id": "id",
            "included_object_versions": "includedObjectVersions",
            "schedule_frequency": "scheduleFrequency",
            "optional_fields": "optionalFields",
            "prefix": "prefix",
        },
    )
    class InventoryConfigurationProperty:
        def __init__(
            self,
            *,
            destination: typing.Union["CfnBucket.DestinationProperty", _IResolvable_da3f097b],
            enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
            id: builtins.str,
            included_object_versions: builtins.str,
            schedule_frequency: builtins.str,
            optional_fields: typing.Optional[typing.Sequence[builtins.str]] = None,
            prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the inventory configuration for an Amazon S3 bucket.

            For more information, see `GET Bucket inventory <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETInventoryConfig.html>`_ in the *Amazon S3 API Reference* .

            :param destination: Contains information about where to publish the inventory results.
            :param enabled: Specifies whether the inventory is enabled or disabled. If set to ``True`` , an inventory list is generated. If set to ``False`` , no inventory list is generated.
            :param id: The ID used to identify the inventory configuration.
            :param included_object_versions: Object versions to include in the inventory list. If set to ``All`` , the list includes all the object versions, which adds the version-related fields ``VersionId`` , ``IsLatest`` , and ``DeleteMarker`` to the list. If set to ``Current`` , the list does not contain these version-related fields.
            :param schedule_frequency: Specifies the schedule for generating inventory results. *Allowed values* : ``Daily`` | ``Weekly``
            :param optional_fields: Contains the optional fields that are included in the inventory results. *Valid values* : ``Size | LastModifiedDate | StorageClass | ETag | IsMultipartUploaded | ReplicationStatus | EncryptionStatus | ObjectLockRetainUntilDate | ObjectLockMode | ObjectLockLegalHoldStatus | IntelligentTieringAccessTier | BucketKeyStatus``
            :param prefix: Specifies the inventory filter prefix.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-inventoryconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                inventory_configuration_property = s3.CfnBucket.InventoryConfigurationProperty(
                    destination=s3.CfnBucket.DestinationProperty(
                        bucket_arn="bucketArn",
                        format="format",
                
                        # the properties below are optional
                        bucket_account_id="bucketAccountId",
                        prefix="prefix"
                    ),
                    enabled=False,
                    id="id",
                    included_object_versions="includedObjectVersions",
                    schedule_frequency="scheduleFrequency",
                
                    # the properties below are optional
                    optional_fields=["optionalFields"],
                    prefix="prefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination": destination,
                "enabled": enabled,
                "id": id,
                "included_object_versions": included_object_versions,
                "schedule_frequency": schedule_frequency,
            }
            if optional_fields is not None:
                self._values["optional_fields"] = optional_fields
            if prefix is not None:
                self._values["prefix"] = prefix

        @builtins.property
        def destination(
            self,
        ) -> typing.Union["CfnBucket.DestinationProperty", _IResolvable_da3f097b]:
            '''Contains information about where to publish the inventory results.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-inventoryconfiguration.html#cfn-s3-bucket-inventoryconfiguration-destination
            '''
            result = self._values.get("destination")
            assert result is not None, "Required property 'destination' is missing"
            return typing.cast(typing.Union["CfnBucket.DestinationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Specifies whether the inventory is enabled or disabled.

            If set to ``True`` , an inventory list is generated. If set to ``False`` , no inventory list is generated.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-inventoryconfiguration.html#cfn-s3-bucket-inventoryconfiguration-enabled
            '''
            result = self._values.get("enabled")
            assert result is not None, "Required property 'enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def id(self) -> builtins.str:
            '''The ID used to identify the inventory configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-inventoryconfiguration.html#cfn-s3-bucket-inventoryconfiguration-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def included_object_versions(self) -> builtins.str:
            '''Object versions to include in the inventory list.

            If set to ``All`` , the list includes all the object versions, which adds the version-related fields ``VersionId`` , ``IsLatest`` , and ``DeleteMarker`` to the list. If set to ``Current`` , the list does not contain these version-related fields.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-inventoryconfiguration.html#cfn-s3-bucket-inventoryconfiguration-includedobjectversions
            '''
            result = self._values.get("included_object_versions")
            assert result is not None, "Required property 'included_object_versions' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def schedule_frequency(self) -> builtins.str:
            '''Specifies the schedule for generating inventory results.

            *Allowed values* : ``Daily`` | ``Weekly``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-inventoryconfiguration.html#cfn-s3-bucket-inventoryconfiguration-schedulefrequency
            '''
            result = self._values.get("schedule_frequency")
            assert result is not None, "Required property 'schedule_frequency' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def optional_fields(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Contains the optional fields that are included in the inventory results.

            *Valid values* : ``Size | LastModifiedDate | StorageClass | ETag | IsMultipartUploaded | ReplicationStatus | EncryptionStatus | ObjectLockRetainUntilDate | ObjectLockMode | ObjectLockLegalHoldStatus | IntelligentTieringAccessTier | BucketKeyStatus``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-inventoryconfiguration.html#cfn-s3-bucket-inventoryconfiguration-optionalfields
            '''
            result = self._values.get("optional_fields")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def prefix(self) -> typing.Optional[builtins.str]:
            '''Specifies the inventory filter prefix.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-inventoryconfiguration.html#cfn-s3-bucket-inventoryconfiguration-prefix
            '''
            result = self._values.get("prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InventoryConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.LambdaConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"event": "event", "function": "function", "filter": "filter"},
    )
    class LambdaConfigurationProperty:
        def __init__(
            self,
            *,
            event: builtins.str,
            function: builtins.str,
            filter: typing.Optional[typing.Union["CfnBucket.NotificationFilterProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Describes the AWS Lambda functions to invoke and the events for which to invoke them.

            :param event: The Amazon S3 bucket event for which to invoke the AWS Lambda function. For more information, see `Supported Event Types <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_ in the *Amazon S3 User Guide* .
            :param function: The Amazon Resource Name (ARN) of the AWS Lambda function that Amazon S3 invokes when the specified event type occurs.
            :param filter: The filtering rules that determine which objects invoke the AWS Lambda function. For example, you can create a filter so that only image files with a ``.jpg`` extension invoke the function when they are added to the Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-lambdaconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                lambda_configuration_property = s3.CfnBucket.LambdaConfigurationProperty(
                    event="event",
                    function="function",
                
                    # the properties below are optional
                    filter=s3.CfnBucket.NotificationFilterProperty(
                        s3_key=s3.CfnBucket.S3KeyFilterProperty(
                            rules=[s3.CfnBucket.FilterRuleProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "event": event,
                "function": function,
            }
            if filter is not None:
                self._values["filter"] = filter

        @builtins.property
        def event(self) -> builtins.str:
            '''The Amazon S3 bucket event for which to invoke the AWS Lambda function.

            For more information, see `Supported Event Types <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-lambdaconfig.html#cfn-s3-bucket-notificationconfig-lambdaconfig-event
            '''
            result = self._values.get("event")
            assert result is not None, "Required property 'event' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def function(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the AWS Lambda function that Amazon S3 invokes when the specified event type occurs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-lambdaconfig.html#cfn-s3-bucket-notificationconfig-lambdaconfig-function
            '''
            result = self._values.get("function")
            assert result is not None, "Required property 'function' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def filter(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.NotificationFilterProperty", _IResolvable_da3f097b]]:
            '''The filtering rules that determine which objects invoke the AWS Lambda function.

            For example, you can create a filter so that only image files with a ``.jpg`` extension invoke the function when they are added to the Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-lambdaconfig.html#cfn-s3-bucket-notificationconfig-lambdaconfig-filter
            '''
            result = self._values.get("filter")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.NotificationFilterProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LambdaConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.LifecycleConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"rules": "rules"},
    )
    class LifecycleConfigurationProperty:
        def __init__(
            self,
            *,
            rules: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.RuleProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''Specifies the lifecycle configuration for objects in an Amazon S3 bucket.

            For more information, see `Object Lifecycle Management <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html>`_ in the *Amazon S3 User Guide* .

            :param rules: A lifecycle rule for individual objects in an Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                lifecycle_configuration_property = s3.CfnBucket.LifecycleConfigurationProperty(
                    rules=[s3.CfnBucket.RuleProperty(
                        status="status",
                
                        # the properties below are optional
                        abort_incomplete_multipart_upload=s3.CfnBucket.AbortIncompleteMultipartUploadProperty(
                            days_after_initiation=123
                        ),
                        expiration_date=Date(),
                        expiration_in_days=123,
                        expired_object_delete_marker=False,
                        id="id",
                        noncurrent_version_expiration=s3.CfnBucket.NoncurrentVersionExpirationProperty(
                            noncurrent_days=123,
                
                            # the properties below are optional
                            newer_noncurrent_versions=123
                        ),
                        noncurrent_version_expiration_in_days=123,
                        noncurrent_version_transition=s3.CfnBucket.NoncurrentVersionTransitionProperty(
                            storage_class="storageClass",
                            transition_in_days=123,
                
                            # the properties below are optional
                            newer_noncurrent_versions=123
                        ),
                        noncurrent_version_transitions=[s3.CfnBucket.NoncurrentVersionTransitionProperty(
                            storage_class="storageClass",
                            transition_in_days=123,
                
                            # the properties below are optional
                            newer_noncurrent_versions=123
                        )],
                        object_size_greater_than=123,
                        object_size_less_than=123,
                        prefix="prefix",
                        tag_filters=[s3.CfnBucket.TagFilterProperty(
                            key="key",
                            value="value"
                        )],
                        transition=s3.CfnBucket.TransitionProperty(
                            storage_class="storageClass",
                
                            # the properties below are optional
                            transition_date=Date(),
                            transition_in_days=123
                        ),
                        transitions=[s3.CfnBucket.TransitionProperty(
                            storage_class="storageClass",
                
                            # the properties below are optional
                            transition_date=Date(),
                            transition_in_days=123
                        )]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "rules": rules,
            }

        @builtins.property
        def rules(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.RuleProperty", _IResolvable_da3f097b]]]:
            '''A lifecycle rule for individual objects in an Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig.html#cfn-s3-bucket-lifecycleconfig-rules
            '''
            result = self._values.get("rules")
            assert result is not None, "Required property 'rules' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.RuleProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LifecycleConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.LoggingConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination_bucket_name": "destinationBucketName",
            "log_file_prefix": "logFilePrefix",
        },
    )
    class LoggingConfigurationProperty:
        def __init__(
            self,
            *,
            destination_bucket_name: typing.Optional[builtins.str] = None,
            log_file_prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Describes where logs are stored and the prefix that Amazon S3 assigns to all log object keys for a bucket.

            For examples and more information, see `PUT Bucket logging <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlogging.html>`_ in the *Amazon S3 API Reference* .
            .. epigraph::

               To successfully complete the ``AWS::S3::Bucket LoggingConfiguration`` request, you must have ``s3:PutObject`` and ``s3:PutObjectAcl`` in your IAM permissions.

            :param destination_bucket_name: The name of the bucket where Amazon S3 should store server access log files. You can store log files in any bucket that you own. By default, logs are stored in the bucket where the ``LoggingConfiguration`` property is defined.
            :param log_file_prefix: A prefix for all log object keys. If you store log files from multiple Amazon S3 buckets in a single bucket, you can use a prefix to distinguish which log files came from which bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-loggingconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                logging_configuration_property = s3.CfnBucket.LoggingConfigurationProperty(
                    destination_bucket_name="destinationBucketName",
                    log_file_prefix="logFilePrefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if destination_bucket_name is not None:
                self._values["destination_bucket_name"] = destination_bucket_name
            if log_file_prefix is not None:
                self._values["log_file_prefix"] = log_file_prefix

        @builtins.property
        def destination_bucket_name(self) -> typing.Optional[builtins.str]:
            '''The name of the bucket where Amazon S3 should store server access log files.

            You can store log files in any bucket that you own. By default, logs are stored in the bucket where the ``LoggingConfiguration`` property is defined.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-loggingconfig.html#cfn-s3-bucket-loggingconfig-destinationbucketname
            '''
            result = self._values.get("destination_bucket_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def log_file_prefix(self) -> typing.Optional[builtins.str]:
            '''A prefix for all log object keys.

            If you store log files from multiple Amazon S3 buckets in a single bucket, you can use a prefix to distinguish which log files came from which bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-loggingconfig.html#cfn-s3-bucket-loggingconfig-logfileprefix
            '''
            result = self._values.get("log_file_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoggingConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.MetricsConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "id": "id",
            "access_point_arn": "accessPointArn",
            "prefix": "prefix",
            "tag_filters": "tagFilters",
        },
    )
    class MetricsConfigurationProperty:
        def __init__(
            self,
            *,
            id: builtins.str,
            access_point_arn: typing.Optional[builtins.str] = None,
            prefix: typing.Optional[builtins.str] = None,
            tag_filters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Specifies a metrics configuration for the CloudWatch request metrics (specified by the metrics configuration ID) from an Amazon S3 bucket.

            If you're updating an existing metrics configuration, note that this is a full replacement of the existing metrics configuration. If you don't include the elements you want to keep, they are erased. For examples, see `AWS::S3::Bucket <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#aws-properties-s3-bucket--examples>`_ . For more information, see `PUT Bucket metrics <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTMetricConfiguration.html>`_ in the *Amazon S3 API Reference* .

            :param id: The ID used to identify the metrics configuration. This can be any value you choose that helps you identify your metrics configuration.
            :param access_point_arn: The access point that was used while performing operations on the object. The metrics configuration only includes objects that meet the filter's criteria.
            :param prefix: The prefix that an object must have to be included in the metrics results.
            :param tag_filters: Specifies a list of tag filters to use as a metrics configuration filter. The metrics configuration includes only objects that meet the filter's criteria.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-metricsconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                metrics_configuration_property = s3.CfnBucket.MetricsConfigurationProperty(
                    id="id",
                
                    # the properties below are optional
                    access_point_arn="accessPointArn",
                    prefix="prefix",
                    tag_filters=[s3.CfnBucket.TagFilterProperty(
                        key="key",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "id": id,
            }
            if access_point_arn is not None:
                self._values["access_point_arn"] = access_point_arn
            if prefix is not None:
                self._values["prefix"] = prefix
            if tag_filters is not None:
                self._values["tag_filters"] = tag_filters

        @builtins.property
        def id(self) -> builtins.str:
            '''The ID used to identify the metrics configuration.

            This can be any value you choose that helps you identify your metrics configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-metricsconfiguration.html#cfn-s3-bucket-metricsconfiguration-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def access_point_arn(self) -> typing.Optional[builtins.str]:
            '''The access point that was used while performing operations on the object.

            The metrics configuration only includes objects that meet the filter's criteria.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-metricsconfiguration.html#cfn-s3-bucket-metricsconfiguration-accesspointarn
            '''
            result = self._values.get("access_point_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def prefix(self) -> typing.Optional[builtins.str]:
            '''The prefix that an object must have to be included in the metrics results.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-metricsconfiguration.html#cfn-s3-bucket-metricsconfiguration-prefix
            '''
            result = self._values.get("prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def tag_filters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]]:
            '''Specifies a list of tag filters to use as a metrics configuration filter.

            The metrics configuration includes only objects that meet the filter's criteria.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-metricsconfiguration.html#cfn-s3-bucket-metricsconfiguration-tagfilters
            '''
            result = self._values.get("tag_filters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MetricsConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.MetricsProperty",
        jsii_struct_bases=[],
        name_mapping={"status": "status", "event_threshold": "eventThreshold"},
    )
    class MetricsProperty:
        def __init__(
            self,
            *,
            status: builtins.str,
            event_threshold: typing.Optional[typing.Union["CfnBucket.ReplicationTimeValueProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A container specifying replication metrics-related settings enabling replication metrics and events.

            :param status: Specifies whether the replication metrics are enabled.
            :param event_threshold: A container specifying the time threshold for emitting the ``s3:Replication:OperationMissedThreshold`` event.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-metrics.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                metrics_property = s3.CfnBucket.MetricsProperty(
                    status="status",
                
                    # the properties below are optional
                    event_threshold=s3.CfnBucket.ReplicationTimeValueProperty(
                        minutes=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "status": status,
            }
            if event_threshold is not None:
                self._values["event_threshold"] = event_threshold

        @builtins.property
        def status(self) -> builtins.str:
            '''Specifies whether the replication metrics are enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-metrics.html#cfn-s3-bucket-metrics-status
            '''
            result = self._values.get("status")
            assert result is not None, "Required property 'status' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def event_threshold(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.ReplicationTimeValueProperty", _IResolvable_da3f097b]]:
            '''A container specifying the time threshold for emitting the ``s3:Replication:OperationMissedThreshold`` event.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-metrics.html#cfn-s3-bucket-metrics-eventthreshold
            '''
            result = self._values.get("event_threshold")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.ReplicationTimeValueProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MetricsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.NoncurrentVersionExpirationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "noncurrent_days": "noncurrentDays",
            "newer_noncurrent_versions": "newerNoncurrentVersions",
        },
    )
    class NoncurrentVersionExpirationProperty:
        def __init__(
            self,
            *,
            noncurrent_days: jsii.Number,
            newer_noncurrent_versions: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies when noncurrent object versions expire.

            Upon expiration, Amazon S3 permanently deletes the noncurrent object versions. You set this lifecycle configuration action on a bucket that has versioning enabled (or suspended) to request that Amazon S3 delete noncurrent object versions at a specific period in the object's lifetime.

            :param noncurrent_days: Specifies the number of days an object is noncurrent before Amazon S3 can perform the associated action. For information about the noncurrent days calculations, see `How Amazon S3 Calculates When an Object Became Noncurrent <https://docs.aws.amazon.com/AmazonS3/latest/dev/intro-lifecycle-rules.html#non-current-days-calculations>`_ in the *Amazon S3 User Guide* .
            :param newer_noncurrent_versions: Specifies how many noncurrent versions Amazon S3 will retain. If there are this many more recent noncurrent versions, Amazon S3 will take the associated action. For more information about noncurrent versions, see `Lifecycle configuration elements <https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule-noncurrentversionexpiration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                noncurrent_version_expiration_property = s3.CfnBucket.NoncurrentVersionExpirationProperty(
                    noncurrent_days=123,
                
                    # the properties below are optional
                    newer_noncurrent_versions=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "noncurrent_days": noncurrent_days,
            }
            if newer_noncurrent_versions is not None:
                self._values["newer_noncurrent_versions"] = newer_noncurrent_versions

        @builtins.property
        def noncurrent_days(self) -> jsii.Number:
            '''Specifies the number of days an object is noncurrent before Amazon S3 can perform the associated action.

            For information about the noncurrent days calculations, see `How Amazon S3 Calculates When an Object Became Noncurrent <https://docs.aws.amazon.com/AmazonS3/latest/dev/intro-lifecycle-rules.html#non-current-days-calculations>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule-noncurrentversionexpiration.html#cfn-s3-bucket-lifecycleconfig-rule-noncurrentversionexpiration-noncurrentdays
            '''
            result = self._values.get("noncurrent_days")
            assert result is not None, "Required property 'noncurrent_days' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def newer_noncurrent_versions(self) -> typing.Optional[jsii.Number]:
            '''Specifies how many noncurrent versions Amazon S3 will retain.

            If there are this many more recent noncurrent versions, Amazon S3 will take the associated action. For more information about noncurrent versions, see `Lifecycle configuration elements <https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule-noncurrentversionexpiration.html#cfn-s3-bucket-lifecycleconfig-rule-noncurrentversionexpiration-newernoncurrentversions
            '''
            result = self._values.get("newer_noncurrent_versions")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NoncurrentVersionExpirationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.NoncurrentVersionTransitionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "storage_class": "storageClass",
            "transition_in_days": "transitionInDays",
            "newer_noncurrent_versions": "newerNoncurrentVersions",
        },
    )
    class NoncurrentVersionTransitionProperty:
        def __init__(
            self,
            *,
            storage_class: builtins.str,
            transition_in_days: jsii.Number,
            newer_noncurrent_versions: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Container for the transition rule that describes when noncurrent objects transition to the ``STANDARD_IA`` , ``ONEZONE_IA`` , ``INTELLIGENT_TIERING`` , ``GLACIER_IR`` , ``GLACIER`` , or ``DEEP_ARCHIVE`` storage class.

            If your bucket is versioning-enabled (or versioning is suspended), you can set this action to request that Amazon S3 transition noncurrent object versions to the ``STANDARD_IA`` , ``ONEZONE_IA`` , ``INTELLIGENT_TIERING`` , ``GLACIER_IR`` , ``GLACIER`` , or ``DEEP_ARCHIVE`` storage class at a specific period in the object's lifetime.

            :param storage_class: The class of storage used to store the object.
            :param transition_in_days: Specifies the number of days an object is noncurrent before Amazon S3 can perform the associated action. For information about the noncurrent days calculations, see `How Amazon S3 Calculates How Long an Object Has Been Noncurrent <https://docs.aws.amazon.com/AmazonS3/latest/dev/intro-lifecycle-rules.html#non-current-days-calculations>`_ in the *Amazon S3 User Guide* .
            :param newer_noncurrent_versions: Specifies how many noncurrent versions Amazon S3 will retain. If there are this many more recent noncurrent versions, Amazon S3 will take the associated action. For more information about noncurrent versions, see `Lifecycle configuration elements <https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule-noncurrentversiontransition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                noncurrent_version_transition_property = s3.CfnBucket.NoncurrentVersionTransitionProperty(
                    storage_class="storageClass",
                    transition_in_days=123,
                
                    # the properties below are optional
                    newer_noncurrent_versions=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "storage_class": storage_class,
                "transition_in_days": transition_in_days,
            }
            if newer_noncurrent_versions is not None:
                self._values["newer_noncurrent_versions"] = newer_noncurrent_versions

        @builtins.property
        def storage_class(self) -> builtins.str:
            '''The class of storage used to store the object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule-noncurrentversiontransition.html#cfn-s3-bucket-lifecycleconfig-rule-noncurrentversiontransition-storageclass
            '''
            result = self._values.get("storage_class")
            assert result is not None, "Required property 'storage_class' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def transition_in_days(self) -> jsii.Number:
            '''Specifies the number of days an object is noncurrent before Amazon S3 can perform the associated action.

            For information about the noncurrent days calculations, see `How Amazon S3 Calculates How Long an Object Has Been Noncurrent <https://docs.aws.amazon.com/AmazonS3/latest/dev/intro-lifecycle-rules.html#non-current-days-calculations>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule-noncurrentversiontransition.html#cfn-s3-bucket-lifecycleconfig-rule-noncurrentversiontransition-transitionindays
            '''
            result = self._values.get("transition_in_days")
            assert result is not None, "Required property 'transition_in_days' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def newer_noncurrent_versions(self) -> typing.Optional[jsii.Number]:
            '''Specifies how many noncurrent versions Amazon S3 will retain.

            If there are this many more recent noncurrent versions, Amazon S3 will take the associated action. For more information about noncurrent versions, see `Lifecycle configuration elements <https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule-noncurrentversiontransition.html#cfn-s3-bucket-lifecycleconfig-rule-noncurrentversiontransition-newernoncurrentversions
            '''
            result = self._values.get("newer_noncurrent_versions")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NoncurrentVersionTransitionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.NotificationConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "event_bridge_configuration": "eventBridgeConfiguration",
            "lambda_configurations": "lambdaConfigurations",
            "queue_configurations": "queueConfigurations",
            "topic_configurations": "topicConfigurations",
        },
    )
    class NotificationConfigurationProperty:
        def __init__(
            self,
            *,
            event_bridge_configuration: typing.Optional[typing.Union["CfnBucket.EventBridgeConfigurationProperty", _IResolvable_da3f097b]] = None,
            lambda_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.LambdaConfigurationProperty", _IResolvable_da3f097b]]]] = None,
            queue_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.QueueConfigurationProperty", _IResolvable_da3f097b]]]] = None,
            topic_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.TopicConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Describes the notification configuration for an Amazon S3 bucket.

            .. epigraph::

               If you create the target resource and related permissions in the same template, you might have a circular dependency.

               For example, you might use the ``AWS::Lambda::Permission`` resource to grant the bucket permission to invoke an AWS Lambda function. However, AWS CloudFormation can't create the bucket until the bucket has permission to invoke the function ( AWS CloudFormation checks whether the bucket can invoke the function). If you're using Refs to pass the bucket name, this leads to a circular dependency.

               To avoid this dependency, you can create all resources without specifying the notification configuration. Then, update the stack with a notification configuration.

               For more information on permissions, see `AWS::Lambda::Permission <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html>`_ and `Granting Permissions to Publish Event Notification Messages to a Destination <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html#grant-destinations-permissions-to-s3>`_ .

            :param event_bridge_configuration: Enables delivery of events to Amazon EventBridge.
            :param lambda_configurations: Describes the AWS Lambda functions to invoke and the events for which to invoke them.
            :param queue_configurations: The Amazon Simple Queue Service queues to publish messages to and the events for which to publish messages.
            :param topic_configurations: The topic to which notifications are sent and the events for which notifications are generated.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                notification_configuration_property = s3.CfnBucket.NotificationConfigurationProperty(
                    event_bridge_configuration=s3.CfnBucket.EventBridgeConfigurationProperty(
                        event_bridge_enabled=False
                    ),
                    lambda_configurations=[s3.CfnBucket.LambdaConfigurationProperty(
                        event="event",
                        function="function",
                
                        # the properties below are optional
                        filter=s3.CfnBucket.NotificationFilterProperty(
                            s3_key=s3.CfnBucket.S3KeyFilterProperty(
                                rules=[s3.CfnBucket.FilterRuleProperty(
                                    name="name",
                                    value="value"
                                )]
                            )
                        )
                    )],
                    queue_configurations=[s3.CfnBucket.QueueConfigurationProperty(
                        event="event",
                        queue="queue",
                
                        # the properties below are optional
                        filter=s3.CfnBucket.NotificationFilterProperty(
                            s3_key=s3.CfnBucket.S3KeyFilterProperty(
                                rules=[s3.CfnBucket.FilterRuleProperty(
                                    name="name",
                                    value="value"
                                )]
                            )
                        )
                    )],
                    topic_configurations=[s3.CfnBucket.TopicConfigurationProperty(
                        event="event",
                        topic="topic",
                
                        # the properties below are optional
                        filter=s3.CfnBucket.NotificationFilterProperty(
                            s3_key=s3.CfnBucket.S3KeyFilterProperty(
                                rules=[s3.CfnBucket.FilterRuleProperty(
                                    name="name",
                                    value="value"
                                )]
                            )
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if event_bridge_configuration is not None:
                self._values["event_bridge_configuration"] = event_bridge_configuration
            if lambda_configurations is not None:
                self._values["lambda_configurations"] = lambda_configurations
            if queue_configurations is not None:
                self._values["queue_configurations"] = queue_configurations
            if topic_configurations is not None:
                self._values["topic_configurations"] = topic_configurations

        @builtins.property
        def event_bridge_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.EventBridgeConfigurationProperty", _IResolvable_da3f097b]]:
            '''Enables delivery of events to Amazon EventBridge.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig.html#cfn-s3-bucket-notificationconfig-eventbridgeconfig
            '''
            result = self._values.get("event_bridge_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.EventBridgeConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def lambda_configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.LambdaConfigurationProperty", _IResolvable_da3f097b]]]]:
            '''Describes the AWS Lambda functions to invoke and the events for which to invoke them.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig.html#cfn-s3-bucket-notificationconfig-lambdaconfig
            '''
            result = self._values.get("lambda_configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.LambdaConfigurationProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def queue_configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.QueueConfigurationProperty", _IResolvable_da3f097b]]]]:
            '''The Amazon Simple Queue Service queues to publish messages to and the events for which to publish messages.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig.html#cfn-s3-bucket-notificationconfig-queueconfig
            '''
            result = self._values.get("queue_configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.QueueConfigurationProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def topic_configurations(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TopicConfigurationProperty", _IResolvable_da3f097b]]]]:
            '''The topic to which notifications are sent and the events for which notifications are generated.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig.html#cfn-s3-bucket-notificationconfig-topicconfig
            '''
            result = self._values.get("topic_configurations")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TopicConfigurationProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NotificationConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.NotificationFilterProperty",
        jsii_struct_bases=[],
        name_mapping={"s3_key": "s3Key"},
    )
    class NotificationFilterProperty:
        def __init__(
            self,
            *,
            s3_key: typing.Union["CfnBucket.S3KeyFilterProperty", _IResolvable_da3f097b],
        ) -> None:
            '''Specifies object key name filtering rules.

            For information about key name filtering, see `Configuring Event Notifications <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_ in the *Amazon S3 User Guide* .

            :param s3_key: A container for object key name prefix and suffix filtering rules.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfiguration-config-filter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                notification_filter_property = s3.CfnBucket.NotificationFilterProperty(
                    s3_key=s3.CfnBucket.S3KeyFilterProperty(
                        rules=[s3.CfnBucket.FilterRuleProperty(
                            name="name",
                            value="value"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "s3_key": s3_key,
            }

        @builtins.property
        def s3_key(
            self,
        ) -> typing.Union["CfnBucket.S3KeyFilterProperty", _IResolvable_da3f097b]:
            '''A container for object key name prefix and suffix filtering rules.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfiguration-config-filter.html#cfn-s3-bucket-notificationconfiguraiton-config-filter-s3key
            '''
            result = self._values.get("s3_key")
            assert result is not None, "Required property 's3_key' is missing"
            return typing.cast(typing.Union["CfnBucket.S3KeyFilterProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NotificationFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ObjectLockConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"object_lock_enabled": "objectLockEnabled", "rule": "rule"},
    )
    class ObjectLockConfigurationProperty:
        def __init__(
            self,
            *,
            object_lock_enabled: typing.Optional[builtins.str] = None,
            rule: typing.Optional[typing.Union["CfnBucket.ObjectLockRuleProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Places an Object Lock configuration on the specified bucket.

            The rule specified in the Object Lock configuration will be applied by default to every new object placed in the specified bucket. For more information, see `Locking Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html>`_ .

            :param object_lock_enabled: Indicates whether this bucket has an Object Lock configuration enabled. Enable ``ObjectLockEnabled`` when you apply ``ObjectLockConfiguration`` to a bucket.
            :param rule: Specifies the Object Lock rule for the specified object. Enable the this rule when you apply ``ObjectLockConfiguration`` to a bucket. If Object Lock is turned on, bucket settings require both ``Mode`` and a period of either ``Days`` or ``Years`` . You cannot specify ``Days`` and ``Years`` at the same time. For more information, see `ObjectLockRule <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-objectlockrule.html>`_ and `DefaultRetention <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-defaultretention.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-objectlockconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                object_lock_configuration_property = s3.CfnBucket.ObjectLockConfigurationProperty(
                    object_lock_enabled="objectLockEnabled",
                    rule=s3.CfnBucket.ObjectLockRuleProperty(
                        default_retention=s3.CfnBucket.DefaultRetentionProperty(
                            days=123,
                            mode="mode",
                            years=123
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if object_lock_enabled is not None:
                self._values["object_lock_enabled"] = object_lock_enabled
            if rule is not None:
                self._values["rule"] = rule

        @builtins.property
        def object_lock_enabled(self) -> typing.Optional[builtins.str]:
            '''Indicates whether this bucket has an Object Lock configuration enabled.

            Enable ``ObjectLockEnabled`` when you apply ``ObjectLockConfiguration`` to a bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-objectlockconfiguration.html#cfn-s3-bucket-objectlockconfiguration-objectlockenabled
            '''
            result = self._values.get("object_lock_enabled")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def rule(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.ObjectLockRuleProperty", _IResolvable_da3f097b]]:
            '''Specifies the Object Lock rule for the specified object.

            Enable the this rule when you apply ``ObjectLockConfiguration`` to a bucket. If Object Lock is turned on, bucket settings require both ``Mode`` and a period of either ``Days`` or ``Years`` . You cannot specify ``Days`` and ``Years`` at the same time. For more information, see `ObjectLockRule <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-objectlockrule.html>`_ and `DefaultRetention <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-defaultretention.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-objectlockconfiguration.html#cfn-s3-bucket-objectlockconfiguration-rule
            '''
            result = self._values.get("rule")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.ObjectLockRuleProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ObjectLockConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ObjectLockRuleProperty",
        jsii_struct_bases=[],
        name_mapping={"default_retention": "defaultRetention"},
    )
    class ObjectLockRuleProperty:
        def __init__(
            self,
            *,
            default_retention: typing.Optional[typing.Union["CfnBucket.DefaultRetentionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies the Object Lock rule for the specified object.

            Enable the this rule when you apply ``ObjectLockConfiguration`` to a bucket.

            :param default_retention: The default Object Lock retention mode and period that you want to apply to new objects placed in the specified bucket. If Object Lock is turned on, bucket settings require both ``Mode`` and a period of either ``Days`` or ``Years`` . You cannot specify ``Days`` and ``Years`` at the same time. For more information about allowable values for mode and period, see `DefaultRetention <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-defaultretention.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-objectlockrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                object_lock_rule_property = s3.CfnBucket.ObjectLockRuleProperty(
                    default_retention=s3.CfnBucket.DefaultRetentionProperty(
                        days=123,
                        mode="mode",
                        years=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if default_retention is not None:
                self._values["default_retention"] = default_retention

        @builtins.property
        def default_retention(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.DefaultRetentionProperty", _IResolvable_da3f097b]]:
            '''The default Object Lock retention mode and period that you want to apply to new objects placed in the specified bucket.

            If Object Lock is turned on, bucket settings require both ``Mode`` and a period of either ``Days`` or ``Years`` . You cannot specify ``Days`` and ``Years`` at the same time. For more information about allowable values for mode and period, see `DefaultRetention <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-defaultretention.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-objectlockrule.html#cfn-s3-bucket-objectlockrule-defaultretention
            '''
            result = self._values.get("default_retention")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.DefaultRetentionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ObjectLockRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.OwnershipControlsProperty",
        jsii_struct_bases=[],
        name_mapping={"rules": "rules"},
    )
    class OwnershipControlsProperty:
        def __init__(
            self,
            *,
            rules: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.OwnershipControlsRuleProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''Specifies the container element for Object Ownership rules.

            S3 Object Ownership is an Amazon S3 bucket-level setting that you can use to disable access control lists (ACLs) and take ownership of every object in your bucket, simplifying access management for data stored in Amazon S3. For more information, see `Controlling ownership of objects and disabling ACLs <https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html>`_ in the *Amazon S3 User Guide* .

            :param rules: Specifies the container element for Object Ownership rules.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-ownershipcontrols.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                ownership_controls_property = s3.CfnBucket.OwnershipControlsProperty(
                    rules=[s3.CfnBucket.OwnershipControlsRuleProperty(
                        object_ownership="objectOwnership"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "rules": rules,
            }

        @builtins.property
        def rules(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.OwnershipControlsRuleProperty", _IResolvable_da3f097b]]]:
            '''Specifies the container element for Object Ownership rules.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-ownershipcontrols.html#cfn-s3-bucket-ownershipcontrols-rules
            '''
            result = self._values.get("rules")
            assert result is not None, "Required property 'rules' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.OwnershipControlsRuleProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OwnershipControlsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.OwnershipControlsRuleProperty",
        jsii_struct_bases=[],
        name_mapping={"object_ownership": "objectOwnership"},
    )
    class OwnershipControlsRuleProperty:
        def __init__(
            self,
            *,
            object_ownership: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies an Object Ownership rule.

            S3 Object Ownership is an Amazon S3 bucket-level setting that you can use to disable access control lists (ACLs) and take ownership of every object in your bucket, simplifying access management for data stored in Amazon S3. For more information, see `Controlling ownership of objects and disabling ACLs <https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html>`_ in the *Amazon S3 User Guide* .

            :param object_ownership: Specifies an Object Ownership rule. *Allowed values* : ``BucketOwnerEnforced`` | ``ObjectWriter`` | ``BucketOwnerPreferred``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-ownershipcontrolsrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                ownership_controls_rule_property = s3.CfnBucket.OwnershipControlsRuleProperty(
                    object_ownership="objectOwnership"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if object_ownership is not None:
                self._values["object_ownership"] = object_ownership

        @builtins.property
        def object_ownership(self) -> typing.Optional[builtins.str]:
            '''Specifies an Object Ownership rule.

            *Allowed values* : ``BucketOwnerEnforced`` | ``ObjectWriter`` | ``BucketOwnerPreferred``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-ownershipcontrolsrule.html#cfn-s3-bucket-ownershipcontrolsrule-objectownership
            '''
            result = self._values.get("object_ownership")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OwnershipControlsRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.PublicAccessBlockConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "block_public_acls": "blockPublicAcls",
            "block_public_policy": "blockPublicPolicy",
            "ignore_public_acls": "ignorePublicAcls",
            "restrict_public_buckets": "restrictPublicBuckets",
        },
    )
    class PublicAccessBlockConfigurationProperty:
        def __init__(
            self,
            *,
            block_public_acls: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            block_public_policy: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            ignore_public_acls: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            restrict_public_buckets: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The PublicAccessBlock configuration that you want to apply to this Amazon S3 bucket.

            You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see `The Meaning of "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`_ in the *Amazon S3 User Guide* .

            :param block_public_acls: Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket. Setting this element to ``TRUE`` causes the following behavior: - PUT Bucket ACL and PUT Object ACL calls fail if the specified ACL is public. - PUT Object calls fail if the request includes a public ACL. - PUT Bucket calls fail if the request includes a public ACL. Enabling this setting doesn't affect existing policies or ACLs.
            :param block_public_policy: Specifies whether Amazon S3 should block public bucket policies for this bucket. Setting this element to ``TRUE`` causes Amazon S3 to reject calls to PUT Bucket policy if the specified bucket policy allows public access. Enabling this setting doesn't affect existing bucket policies.
            :param ignore_public_acls: Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket. Setting this element to ``TRUE`` causes Amazon S3 to ignore all public ACLs on this bucket and objects in this bucket. Enabling this setting doesn't affect the persistence of any existing ACLs and doesn't prevent new public ACLs from being set.
            :param restrict_public_buckets: Specifies whether Amazon S3 should restrict public bucket policies for this bucket. Setting this element to ``TRUE`` restricts access to this bucket to only AWS service principals and authorized users within this account if the bucket has a public policy. Enabling this setting doesn't affect previously stored bucket policies, except that public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                public_access_block_configuration_property = s3.CfnBucket.PublicAccessBlockConfigurationProperty(
                    block_public_acls=False,
                    block_public_policy=False,
                    ignore_public_acls=False,
                    restrict_public_buckets=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if block_public_acls is not None:
                self._values["block_public_acls"] = block_public_acls
            if block_public_policy is not None:
                self._values["block_public_policy"] = block_public_policy
            if ignore_public_acls is not None:
                self._values["ignore_public_acls"] = ignore_public_acls
            if restrict_public_buckets is not None:
                self._values["restrict_public_buckets"] = restrict_public_buckets

        @builtins.property
        def block_public_acls(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket.

            Setting this element to ``TRUE`` causes the following behavior:

            - PUT Bucket ACL and PUT Object ACL calls fail if the specified ACL is public.
            - PUT Object calls fail if the request includes a public ACL.
            - PUT Bucket calls fail if the request includes a public ACL.

            Enabling this setting doesn't affect existing policies or ACLs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-blockpublicacls
            '''
            result = self._values.get("block_public_acls")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def block_public_policy(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should block public bucket policies for this bucket.

            Setting this element to ``TRUE`` causes Amazon S3 to reject calls to PUT Bucket policy if the specified bucket policy allows public access.

            Enabling this setting doesn't affect existing bucket policies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-blockpublicpolicy
            '''
            result = self._values.get("block_public_policy")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def ignore_public_acls(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket.

            Setting this element to ``TRUE`` causes Amazon S3 to ignore all public ACLs on this bucket and objects in this bucket.

            Enabling this setting doesn't affect the persistence of any existing ACLs and doesn't prevent new public ACLs from being set.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-ignorepublicacls
            '''
            result = self._values.get("ignore_public_acls")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def restrict_public_buckets(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should restrict public bucket policies for this bucket.

            Setting this element to ``TRUE`` restricts access to this bucket to only AWS service principals and authorized users within this account if the bucket has a public policy.

            Enabling this setting doesn't affect previously stored bucket policies, except that public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-publicaccessblockconfiguration.html#cfn-s3-bucket-publicaccessblockconfiguration-restrictpublicbuckets
            '''
            result = self._values.get("restrict_public_buckets")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PublicAccessBlockConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.QueueConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"event": "event", "queue": "queue", "filter": "filter"},
    )
    class QueueConfigurationProperty:
        def __init__(
            self,
            *,
            event: builtins.str,
            queue: builtins.str,
            filter: typing.Optional[typing.Union["CfnBucket.NotificationFilterProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies the configuration for publishing messages to an Amazon Simple Queue Service (Amazon SQS) queue when Amazon S3 detects specified events.

            :param event: The Amazon S3 bucket event about which you want to publish messages to Amazon SQS. For more information, see `Supported Event Types <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_ in the *Amazon S3 User Guide* .
            :param queue: The Amazon Resource Name (ARN) of the Amazon SQS queue to which Amazon S3 publishes a message when it detects events of the specified type. FIFO queues are not allowed when enabling an SQS queue as the event notification destination.
            :param filter: The filtering rules that determine which objects trigger notifications. For example, you can create a filter so that Amazon S3 sends notifications only when image files with a ``.jpg`` extension are added to the bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-queueconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                queue_configuration_property = s3.CfnBucket.QueueConfigurationProperty(
                    event="event",
                    queue="queue",
                
                    # the properties below are optional
                    filter=s3.CfnBucket.NotificationFilterProperty(
                        s3_key=s3.CfnBucket.S3KeyFilterProperty(
                            rules=[s3.CfnBucket.FilterRuleProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "event": event,
                "queue": queue,
            }
            if filter is not None:
                self._values["filter"] = filter

        @builtins.property
        def event(self) -> builtins.str:
            '''The Amazon S3 bucket event about which you want to publish messages to Amazon SQS.

            For more information, see `Supported Event Types <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-queueconfig.html#cfn-s3-bucket-notificationconfig-queueconfig-event
            '''
            result = self._values.get("event")
            assert result is not None, "Required property 'event' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def queue(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the Amazon SQS queue to which Amazon S3 publishes a message when it detects events of the specified type.

            FIFO queues are not allowed when enabling an SQS queue as the event notification destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-queueconfig.html#cfn-s3-bucket-notificationconfig-queueconfig-queue
            '''
            result = self._values.get("queue")
            assert result is not None, "Required property 'queue' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def filter(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.NotificationFilterProperty", _IResolvable_da3f097b]]:
            '''The filtering rules that determine which objects trigger notifications.

            For example, you can create a filter so that Amazon S3 sends notifications only when image files with a ``.jpg`` extension are added to the bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-queueconfig.html#cfn-s3-bucket-notificationconfig-queueconfig-filter
            '''
            result = self._values.get("filter")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.NotificationFilterProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "QueueConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.RedirectAllRequestsToProperty",
        jsii_struct_bases=[],
        name_mapping={"host_name": "hostName", "protocol": "protocol"},
    )
    class RedirectAllRequestsToProperty:
        def __init__(
            self,
            *,
            host_name: builtins.str,
            protocol: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the redirect behavior of all requests to a website endpoint of an Amazon S3 bucket.

            :param host_name: Name of the host where requests are redirected.
            :param protocol: Protocol to use when redirecting requests. The default is the protocol that is used in the original request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-redirectallrequeststo.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                redirect_all_requests_to_property = s3.CfnBucket.RedirectAllRequestsToProperty(
                    host_name="hostName",
                
                    # the properties below are optional
                    protocol="protocol"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "host_name": host_name,
            }
            if protocol is not None:
                self._values["protocol"] = protocol

        @builtins.property
        def host_name(self) -> builtins.str:
            '''Name of the host where requests are redirected.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-redirectallrequeststo.html#cfn-s3-websiteconfiguration-redirectallrequeststo-hostname
            '''
            result = self._values.get("host_name")
            assert result is not None, "Required property 'host_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def protocol(self) -> typing.Optional[builtins.str]:
            '''Protocol to use when redirecting requests.

            The default is the protocol that is used in the original request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-redirectallrequeststo.html#cfn-s3-websiteconfiguration-redirectallrequeststo-protocol
            '''
            result = self._values.get("protocol")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RedirectAllRequestsToProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.RedirectRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "host_name": "hostName",
            "http_redirect_code": "httpRedirectCode",
            "protocol": "protocol",
            "replace_key_prefix_with": "replaceKeyPrefixWith",
            "replace_key_with": "replaceKeyWith",
        },
    )
    class RedirectRuleProperty:
        def __init__(
            self,
            *,
            host_name: typing.Optional[builtins.str] = None,
            http_redirect_code: typing.Optional[builtins.str] = None,
            protocol: typing.Optional[builtins.str] = None,
            replace_key_prefix_with: typing.Optional[builtins.str] = None,
            replace_key_with: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies how requests are redirected.

            In the event of an error, you can specify a different error code to return.

            :param host_name: The host name to use in the redirect request.
            :param http_redirect_code: The HTTP redirect code to use on the response. Not required if one of the siblings is present.
            :param protocol: Protocol to use when redirecting requests. The default is the protocol that is used in the original request.
            :param replace_key_prefix_with: The object key prefix to use in the redirect request. For example, to redirect requests for all pages with prefix ``docs/`` (objects in the ``docs/`` folder) to ``documents/`` , you can set a condition block with ``KeyPrefixEquals`` set to ``docs/`` and in the Redirect set ``ReplaceKeyPrefixWith`` to ``/documents`` . Not required if one of the siblings is present. Can be present only if ``ReplaceKeyWith`` is not provided. .. epigraph:: Replacement must be made for object keys containing special characters (such as carriage returns) when using XML requests. For more information, see `XML related object key constraints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html#object-key-xml-related-constraints>`_ .
            :param replace_key_with: The specific object key to use in the redirect request. For example, redirect request to ``error.html`` . Not required if one of the siblings is present. Can be present only if ``ReplaceKeyPrefixWith`` is not provided. .. epigraph:: Replacement must be made for object keys containing special characters (such as carriage returns) when using XML requests. For more information, see `XML related object key constraints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html#object-key-xml-related-constraints>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules-redirectrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                redirect_rule_property = s3.CfnBucket.RedirectRuleProperty(
                    host_name="hostName",
                    http_redirect_code="httpRedirectCode",
                    protocol="protocol",
                    replace_key_prefix_with="replaceKeyPrefixWith",
                    replace_key_with="replaceKeyWith"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if host_name is not None:
                self._values["host_name"] = host_name
            if http_redirect_code is not None:
                self._values["http_redirect_code"] = http_redirect_code
            if protocol is not None:
                self._values["protocol"] = protocol
            if replace_key_prefix_with is not None:
                self._values["replace_key_prefix_with"] = replace_key_prefix_with
            if replace_key_with is not None:
                self._values["replace_key_with"] = replace_key_with

        @builtins.property
        def host_name(self) -> typing.Optional[builtins.str]:
            '''The host name to use in the redirect request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules-redirectrule.html#cfn-s3-websiteconfiguration-redirectrule-hostname
            '''
            result = self._values.get("host_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def http_redirect_code(self) -> typing.Optional[builtins.str]:
            '''The HTTP redirect code to use on the response.

            Not required if one of the siblings is present.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules-redirectrule.html#cfn-s3-websiteconfiguration-redirectrule-httpredirectcode
            '''
            result = self._values.get("http_redirect_code")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def protocol(self) -> typing.Optional[builtins.str]:
            '''Protocol to use when redirecting requests.

            The default is the protocol that is used in the original request.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules-redirectrule.html#cfn-s3-websiteconfiguration-redirectrule-protocol
            '''
            result = self._values.get("protocol")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def replace_key_prefix_with(self) -> typing.Optional[builtins.str]:
            '''The object key prefix to use in the redirect request.

            For example, to redirect requests for all pages with prefix ``docs/`` (objects in the ``docs/`` folder) to ``documents/`` , you can set a condition block with ``KeyPrefixEquals`` set to ``docs/`` and in the Redirect set ``ReplaceKeyPrefixWith`` to ``/documents`` . Not required if one of the siblings is present. Can be present only if ``ReplaceKeyWith`` is not provided.
            .. epigraph::

               Replacement must be made for object keys containing special characters (such as carriage returns) when using XML requests. For more information, see `XML related object key constraints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html#object-key-xml-related-constraints>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules-redirectrule.html#cfn-s3-websiteconfiguration-redirectrule-replacekeyprefixwith
            '''
            result = self._values.get("replace_key_prefix_with")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def replace_key_with(self) -> typing.Optional[builtins.str]:
            '''The specific object key to use in the redirect request.

            For example, redirect request to ``error.html`` . Not required if one of the siblings is present. Can be present only if ``ReplaceKeyPrefixWith`` is not provided.
            .. epigraph::

               Replacement must be made for object keys containing special characters (such as carriage returns) when using XML requests. For more information, see `XML related object key constraints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html#object-key-xml-related-constraints>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules-redirectrule.html#cfn-s3-websiteconfiguration-redirectrule-replacekeywith
            '''
            result = self._values.get("replace_key_with")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RedirectRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ReplicaModificationsProperty",
        jsii_struct_bases=[],
        name_mapping={"status": "status"},
    )
    class ReplicaModificationsProperty:
        def __init__(self, *, status: builtins.str) -> None:
            '''A filter that you can specify for selection for modifications on replicas.

            :param status: Specifies whether Amazon S3 replicates modifications on replicas. *Allowed values* : ``Enabled`` | ``Disabled``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicamodifications.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                replica_modifications_property = s3.CfnBucket.ReplicaModificationsProperty(
                    status="status"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "status": status,
            }

        @builtins.property
        def status(self) -> builtins.str:
            '''Specifies whether Amazon S3 replicates modifications on replicas.

            *Allowed values* : ``Enabled`` | ``Disabled``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicamodifications.html#cfn-s3-bucket-replicamodifications-status
            '''
            result = self._values.get("status")
            assert result is not None, "Required property 'status' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicaModificationsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ReplicationConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"role": "role", "rules": "rules"},
    )
    class ReplicationConfigurationProperty:
        def __init__(
            self,
            *,
            role: builtins.str,
            rules: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.ReplicationRuleProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A container for replication rules.

            You can add up to 1,000 rules. The maximum size of a replication configuration is 2 MB.

            :param role: The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that Amazon S3 assumes when replicating objects. For more information, see `How to Set Up Replication <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-how-setup.html>`_ in the *Amazon S3 User Guide* .
            :param rules: A container for one or more replication rules. A replication configuration must have at least one rule and can contain a maximum of 1,000 rules.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                replication_configuration_property = s3.CfnBucket.ReplicationConfigurationProperty(
                    role="role",
                    rules=[s3.CfnBucket.ReplicationRuleProperty(
                        destination=s3.CfnBucket.ReplicationDestinationProperty(
                            bucket="bucket",
                
                            # the properties below are optional
                            access_control_translation=s3.CfnBucket.AccessControlTranslationProperty(
                                owner="owner"
                            ),
                            account="account",
                            encryption_configuration=s3.CfnBucket.EncryptionConfigurationProperty(
                                replica_kms_key_id="replicaKmsKeyId"
                            ),
                            metrics=s3.CfnBucket.MetricsProperty(
                                status="status",
                
                                # the properties below are optional
                                event_threshold=s3.CfnBucket.ReplicationTimeValueProperty(
                                    minutes=123
                                )
                            ),
                            replication_time=s3.CfnBucket.ReplicationTimeProperty(
                                status="status",
                                time=s3.CfnBucket.ReplicationTimeValueProperty(
                                    minutes=123
                                )
                            ),
                            storage_class="storageClass"
                        ),
                        status="status",
                
                        # the properties below are optional
                        delete_marker_replication=s3.CfnBucket.DeleteMarkerReplicationProperty(
                            status="status"
                        ),
                        filter=s3.CfnBucket.ReplicationRuleFilterProperty(
                            and=s3.CfnBucket.ReplicationRuleAndOperatorProperty(
                                prefix="prefix",
                                tag_filters=[s3.CfnBucket.TagFilterProperty(
                                    key="key",
                                    value="value"
                                )]
                            ),
                            prefix="prefix",
                            tag_filter=s3.CfnBucket.TagFilterProperty(
                                key="key",
                                value="value"
                            )
                        ),
                        id="id",
                        prefix="prefix",
                        priority=123,
                        source_selection_criteria=s3.CfnBucket.SourceSelectionCriteriaProperty(
                            replica_modifications=s3.CfnBucket.ReplicaModificationsProperty(
                                status="status"
                            ),
                            sse_kms_encrypted_objects=s3.CfnBucket.SseKmsEncryptedObjectsProperty(
                                status="status"
                            )
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "role": role,
                "rules": rules,
            }

        @builtins.property
        def role(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the AWS Identity and Access Management (IAM) role that Amazon S3 assumes when replicating objects.

            For more information, see `How to Set Up Replication <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-how-setup.html>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration.html#cfn-s3-bucket-replicationconfiguration-role
            '''
            result = self._values.get("role")
            assert result is not None, "Required property 'role' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def rules(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.ReplicationRuleProperty", _IResolvable_da3f097b]]]:
            '''A container for one or more replication rules.

            A replication configuration must have at least one rule and can contain a maximum of 1,000 rules.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration.html#cfn-s3-bucket-replicationconfiguration-rules
            '''
            result = self._values.get("rules")
            assert result is not None, "Required property 'rules' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.ReplicationRuleProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicationConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ReplicationDestinationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket": "bucket",
            "access_control_translation": "accessControlTranslation",
            "account": "account",
            "encryption_configuration": "encryptionConfiguration",
            "metrics": "metrics",
            "replication_time": "replicationTime",
            "storage_class": "storageClass",
        },
    )
    class ReplicationDestinationProperty:
        def __init__(
            self,
            *,
            bucket: builtins.str,
            access_control_translation: typing.Optional[typing.Union["CfnBucket.AccessControlTranslationProperty", _IResolvable_da3f097b]] = None,
            account: typing.Optional[builtins.str] = None,
            encryption_configuration: typing.Optional[typing.Union["CfnBucket.EncryptionConfigurationProperty", _IResolvable_da3f097b]] = None,
            metrics: typing.Optional[typing.Union["CfnBucket.MetricsProperty", _IResolvable_da3f097b]] = None,
            replication_time: typing.Optional[typing.Union["CfnBucket.ReplicationTimeProperty", _IResolvable_da3f097b]] = None,
            storage_class: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A container for information about the replication destination and its configurations including enabling the S3 Replication Time Control (S3 RTC).

            :param bucket: The Amazon Resource Name (ARN) of the bucket where you want Amazon S3 to store the results.
            :param access_control_translation: Specify this only in a cross-account scenario (where source and destination bucket owners are not the same), and you want to change replica ownership to the AWS account that owns the destination bucket. If this is not specified in the replication configuration, the replicas are owned by same AWS account that owns the source object.
            :param account: Destination bucket owner account ID. In a cross-account scenario, if you direct Amazon S3 to change replica ownership to the AWS account that owns the destination bucket by specifying the ``AccessControlTranslation`` property, this is the account ID of the destination bucket owner. For more information, see `Cross-Region Replication Additional Configuration: Change Replica Owner <https://docs.aws.amazon.com/AmazonS3/latest/dev/crr-change-owner.html>`_ in the *Amazon S3 User Guide* . If you specify the ``AccessControlTranslation`` property, the ``Account`` property is required.
            :param encryption_configuration: Specifies encryption-related information.
            :param metrics: A container specifying replication metrics-related settings enabling replication metrics and events.
            :param replication_time: A container specifying S3 Replication Time Control (S3 RTC), including whether S3 RTC is enabled and the time when all objects and operations on objects must be replicated. Must be specified together with a ``Metrics`` block.
            :param storage_class: The storage class to use when replicating objects, such as S3 Standard or reduced redundancy. By default, Amazon S3 uses the storage class of the source object to create the object replica. For valid values, see the ``StorageClass`` element of the `PUT Bucket replication <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTreplication.html>`_ action in the *Amazon S3 API Reference* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules-destination.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                replication_destination_property = s3.CfnBucket.ReplicationDestinationProperty(
                    bucket="bucket",
                
                    # the properties below are optional
                    access_control_translation=s3.CfnBucket.AccessControlTranslationProperty(
                        owner="owner"
                    ),
                    account="account",
                    encryption_configuration=s3.CfnBucket.EncryptionConfigurationProperty(
                        replica_kms_key_id="replicaKmsKeyId"
                    ),
                    metrics=s3.CfnBucket.MetricsProperty(
                        status="status",
                
                        # the properties below are optional
                        event_threshold=s3.CfnBucket.ReplicationTimeValueProperty(
                            minutes=123
                        )
                    ),
                    replication_time=s3.CfnBucket.ReplicationTimeProperty(
                        status="status",
                        time=s3.CfnBucket.ReplicationTimeValueProperty(
                            minutes=123
                        )
                    ),
                    storage_class="storageClass"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket": bucket,
            }
            if access_control_translation is not None:
                self._values["access_control_translation"] = access_control_translation
            if account is not None:
                self._values["account"] = account
            if encryption_configuration is not None:
                self._values["encryption_configuration"] = encryption_configuration
            if metrics is not None:
                self._values["metrics"] = metrics
            if replication_time is not None:
                self._values["replication_time"] = replication_time
            if storage_class is not None:
                self._values["storage_class"] = storage_class

        @builtins.property
        def bucket(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the bucket where you want Amazon S3 to store the results.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules-destination.html#cfn-s3-bucket-replicationconfiguration-rules-destination-bucket
            '''
            result = self._values.get("bucket")
            assert result is not None, "Required property 'bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def access_control_translation(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.AccessControlTranslationProperty", _IResolvable_da3f097b]]:
            '''Specify this only in a cross-account scenario (where source and destination bucket owners are not the same), and you want to change replica ownership to the AWS account that owns the destination bucket.

            If this is not specified in the replication configuration, the replicas are owned by same AWS account that owns the source object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules-destination.html#cfn-s3-bucket-replicationdestination-accesscontroltranslation
            '''
            result = self._values.get("access_control_translation")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.AccessControlTranslationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def account(self) -> typing.Optional[builtins.str]:
            '''Destination bucket owner account ID.

            In a cross-account scenario, if you direct Amazon S3 to change replica ownership to the AWS account that owns the destination bucket by specifying the ``AccessControlTranslation`` property, this is the account ID of the destination bucket owner. For more information, see `Cross-Region Replication Additional Configuration: Change Replica Owner <https://docs.aws.amazon.com/AmazonS3/latest/dev/crr-change-owner.html>`_ in the *Amazon S3 User Guide* .

            If you specify the ``AccessControlTranslation`` property, the ``Account`` property is required.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules-destination.html#cfn-s3-bucket-replicationdestination-account
            '''
            result = self._values.get("account")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def encryption_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.EncryptionConfigurationProperty", _IResolvable_da3f097b]]:
            '''Specifies encryption-related information.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules-destination.html#cfn-s3-bucket-replicationdestination-encryptionconfiguration
            '''
            result = self._values.get("encryption_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.EncryptionConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def metrics(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.MetricsProperty", _IResolvable_da3f097b]]:
            '''A container specifying replication metrics-related settings enabling replication metrics and events.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules-destination.html#cfn-s3-bucket-replicationdestination-metrics
            '''
            result = self._values.get("metrics")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.MetricsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def replication_time(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.ReplicationTimeProperty", _IResolvable_da3f097b]]:
            '''A container specifying S3 Replication Time Control (S3 RTC), including whether S3 RTC is enabled and the time when all objects and operations on objects must be replicated.

            Must be specified together with a ``Metrics`` block.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules-destination.html#cfn-s3-bucket-replicationdestination-replicationtime
            '''
            result = self._values.get("replication_time")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.ReplicationTimeProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def storage_class(self) -> typing.Optional[builtins.str]:
            '''The storage class to use when replicating objects, such as S3 Standard or reduced redundancy.

            By default, Amazon S3 uses the storage class of the source object to create the object replica.

            For valid values, see the ``StorageClass`` element of the `PUT Bucket replication <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTreplication.html>`_ action in the *Amazon S3 API Reference* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules-destination.html#cfn-s3-bucket-replicationconfiguration-rules-destination-storageclass
            '''
            result = self._values.get("storage_class")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicationDestinationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ReplicationRuleAndOperatorProperty",
        jsii_struct_bases=[],
        name_mapping={"prefix": "prefix", "tag_filters": "tagFilters"},
    )
    class ReplicationRuleAndOperatorProperty:
        def __init__(
            self,
            *,
            prefix: typing.Optional[builtins.str] = None,
            tag_filters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A container for specifying rule filters.

            The filters determine the subset of objects to which the rule applies. This element is required only if you specify more than one filter.

            For example:

            - If you specify both a ``Prefix`` and a ``TagFilter`` , wrap these filters in an ``And`` tag.
            - If you specify a filter based on multiple tags, wrap the ``TagFilter`` elements in an ``And`` tag

            :param prefix: An object key name prefix that identifies the subset of objects to which the rule applies.
            :param tag_filters: An array of tags containing key and value pairs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationruleandoperator.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                replication_rule_and_operator_property = s3.CfnBucket.ReplicationRuleAndOperatorProperty(
                    prefix="prefix",
                    tag_filters=[s3.CfnBucket.TagFilterProperty(
                        key="key",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if prefix is not None:
                self._values["prefix"] = prefix
            if tag_filters is not None:
                self._values["tag_filters"] = tag_filters

        @builtins.property
        def prefix(self) -> typing.Optional[builtins.str]:
            '''An object key name prefix that identifies the subset of objects to which the rule applies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationruleandoperator.html#cfn-s3-bucket-replicationruleandoperator-prefix
            '''
            result = self._values.get("prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def tag_filters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]]:
            '''An array of tags containing key and value pairs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationruleandoperator.html#cfn-s3-bucket-replicationruleandoperator-tagfilters
            '''
            result = self._values.get("tag_filters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicationRuleAndOperatorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ReplicationRuleFilterProperty",
        jsii_struct_bases=[],
        name_mapping={"and_": "and", "prefix": "prefix", "tag_filter": "tagFilter"},
    )
    class ReplicationRuleFilterProperty:
        def __init__(
            self,
            *,
            and_: typing.Optional[typing.Union["CfnBucket.ReplicationRuleAndOperatorProperty", _IResolvable_da3f097b]] = None,
            prefix: typing.Optional[builtins.str] = None,
            tag_filter: typing.Optional[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A filter that identifies the subset of objects to which the replication rule applies.

            A ``Filter`` must specify exactly one ``Prefix`` , ``TagFilter`` , or an ``And`` child element.

            :param and_: A container for specifying rule filters. The filters determine the subset of objects to which the rule applies. This element is required only if you specify more than one filter. For example: - If you specify both a ``Prefix`` and a ``TagFilter`` , wrap these filters in an ``And`` tag. - If you specify a filter based on multiple tags, wrap the ``TagFilter`` elements in an ``And`` tag.
            :param prefix: An object key name prefix that identifies the subset of objects to which the rule applies. .. epigraph:: Replacement must be made for object keys containing special characters (such as carriage returns) when using XML requests. For more information, see `XML related object key constraints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html#object-key-xml-related-constraints>`_ .
            :param tag_filter: A container for specifying a tag key and value. The rule applies only to objects that have the tag in their tag set.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationrulefilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                replication_rule_filter_property = s3.CfnBucket.ReplicationRuleFilterProperty(
                    and=s3.CfnBucket.ReplicationRuleAndOperatorProperty(
                        prefix="prefix",
                        tag_filters=[s3.CfnBucket.TagFilterProperty(
                            key="key",
                            value="value"
                        )]
                    ),
                    prefix="prefix",
                    tag_filter=s3.CfnBucket.TagFilterProperty(
                        key="key",
                        value="value"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if and_ is not None:
                self._values["and_"] = and_
            if prefix is not None:
                self._values["prefix"] = prefix
            if tag_filter is not None:
                self._values["tag_filter"] = tag_filter

        @builtins.property
        def and_(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.ReplicationRuleAndOperatorProperty", _IResolvable_da3f097b]]:
            '''A container for specifying rule filters.

            The filters determine the subset of objects to which the rule applies. This element is required only if you specify more than one filter. For example:

            - If you specify both a ``Prefix`` and a ``TagFilter`` , wrap these filters in an ``And`` tag.
            - If you specify a filter based on multiple tags, wrap the ``TagFilter`` elements in an ``And`` tag.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationrulefilter.html#cfn-s3-bucket-replicationrulefilter-and
            '''
            result = self._values.get("and_")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.ReplicationRuleAndOperatorProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def prefix(self) -> typing.Optional[builtins.str]:
            '''An object key name prefix that identifies the subset of objects to which the rule applies.

            .. epigraph::

               Replacement must be made for object keys containing special characters (such as carriage returns) when using XML requests. For more information, see `XML related object key constraints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html#object-key-xml-related-constraints>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationrulefilter.html#cfn-s3-bucket-replicationrulefilter-prefix
            '''
            result = self._values.get("prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def tag_filter(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]:
            '''A container for specifying a tag key and value.

            The rule applies only to objects that have the tag in their tag set.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationrulefilter.html#cfn-s3-bucket-replicationrulefilter-tagfilter
            '''
            result = self._values.get("tag_filter")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicationRuleFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ReplicationRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "destination": "destination",
            "status": "status",
            "delete_marker_replication": "deleteMarkerReplication",
            "filter": "filter",
            "id": "id",
            "prefix": "prefix",
            "priority": "priority",
            "source_selection_criteria": "sourceSelectionCriteria",
        },
    )
    class ReplicationRuleProperty:
        def __init__(
            self,
            *,
            destination: typing.Union["CfnBucket.ReplicationDestinationProperty", _IResolvable_da3f097b],
            status: builtins.str,
            delete_marker_replication: typing.Optional[typing.Union["CfnBucket.DeleteMarkerReplicationProperty", _IResolvable_da3f097b]] = None,
            filter: typing.Optional[typing.Union["CfnBucket.ReplicationRuleFilterProperty", _IResolvable_da3f097b]] = None,
            id: typing.Optional[builtins.str] = None,
            prefix: typing.Optional[builtins.str] = None,
            priority: typing.Optional[jsii.Number] = None,
            source_selection_criteria: typing.Optional[typing.Union["CfnBucket.SourceSelectionCriteriaProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies which Amazon S3 objects to replicate and where to store the replicas.

            :param destination: A container for information about the replication destination and its configurations including enabling the S3 Replication Time Control (S3 RTC).
            :param status: Specifies whether the rule is enabled.
            :param delete_marker_replication: Specifies whether Amazon S3 replicates delete markers. If you specify a ``Filter`` in your replication configuration, you must also include a ``DeleteMarkerReplication`` element. If your ``Filter`` includes a ``Tag`` element, the ``DeleteMarkerReplication`` ``Status`` must be set to Disabled, because Amazon S3 does not support replicating delete markers for tag-based rules. For an example configuration, see `Basic Rule Configuration <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-add-config.html#replication-config-min-rule-config>`_ . For more information about delete marker replication, see `Basic Rule Configuration <https://docs.aws.amazon.com/AmazonS3/latest/dev/delete-marker-replication.html>`_ . .. epigraph:: If you are using an earlier version of the replication configuration, Amazon S3 handles replication of delete markers differently. For more information, see `Backward Compatibility <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-add-config.html#replication-backward-compat-considerations>`_ .
            :param filter: A filter that identifies the subset of objects to which the replication rule applies. A ``Filter`` must specify exactly one ``Prefix`` , ``TagFilter`` , or an ``And`` child element. The use of the filter field indicates this is a V2 replication configuration. V1 does not have this field.
            :param id: A unique identifier for the rule. The maximum value is 255 characters. If you don't specify a value, AWS CloudFormation generates a random ID. When using a V2 replication configuration this property is capitalized as "ID".
            :param prefix: An object key name prefix that identifies the object or objects to which the rule applies. The maximum prefix length is 1,024 characters. To include all objects in a bucket, specify an empty string. .. epigraph:: Replacement must be made for object keys containing special characters (such as carriage returns) when using XML requests. For more information, see `XML related object key constraints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html#object-key-xml-related-constraints>`_ .
            :param priority: The priority indicates which rule has precedence whenever two or more replication rules conflict. Amazon S3 will attempt to replicate objects according to all replication rules. However, if there are two or more rules with the same destination bucket, then objects will be replicated according to the rule with the highest priority. The higher the number, the higher the priority. For more information, see `Replication <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication.html>`_ in the *Amazon S3 User Guide* .
            :param source_selection_criteria: A container that describes additional filters for identifying the source objects that you want to replicate. You can choose to enable or disable the replication of these objects.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                replication_rule_property = s3.CfnBucket.ReplicationRuleProperty(
                    destination=s3.CfnBucket.ReplicationDestinationProperty(
                        bucket="bucket",
                
                        # the properties below are optional
                        access_control_translation=s3.CfnBucket.AccessControlTranslationProperty(
                            owner="owner"
                        ),
                        account="account",
                        encryption_configuration=s3.CfnBucket.EncryptionConfigurationProperty(
                            replica_kms_key_id="replicaKmsKeyId"
                        ),
                        metrics=s3.CfnBucket.MetricsProperty(
                            status="status",
                
                            # the properties below are optional
                            event_threshold=s3.CfnBucket.ReplicationTimeValueProperty(
                                minutes=123
                            )
                        ),
                        replication_time=s3.CfnBucket.ReplicationTimeProperty(
                            status="status",
                            time=s3.CfnBucket.ReplicationTimeValueProperty(
                                minutes=123
                            )
                        ),
                        storage_class="storageClass"
                    ),
                    status="status",
                
                    # the properties below are optional
                    delete_marker_replication=s3.CfnBucket.DeleteMarkerReplicationProperty(
                        status="status"
                    ),
                    filter=s3.CfnBucket.ReplicationRuleFilterProperty(
                        and=s3.CfnBucket.ReplicationRuleAndOperatorProperty(
                            prefix="prefix",
                            tag_filters=[s3.CfnBucket.TagFilterProperty(
                                key="key",
                                value="value"
                            )]
                        ),
                        prefix="prefix",
                        tag_filter=s3.CfnBucket.TagFilterProperty(
                            key="key",
                            value="value"
                        )
                    ),
                    id="id",
                    prefix="prefix",
                    priority=123,
                    source_selection_criteria=s3.CfnBucket.SourceSelectionCriteriaProperty(
                        replica_modifications=s3.CfnBucket.ReplicaModificationsProperty(
                            status="status"
                        ),
                        sse_kms_encrypted_objects=s3.CfnBucket.SseKmsEncryptedObjectsProperty(
                            status="status"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "destination": destination,
                "status": status,
            }
            if delete_marker_replication is not None:
                self._values["delete_marker_replication"] = delete_marker_replication
            if filter is not None:
                self._values["filter"] = filter
            if id is not None:
                self._values["id"] = id
            if prefix is not None:
                self._values["prefix"] = prefix
            if priority is not None:
                self._values["priority"] = priority
            if source_selection_criteria is not None:
                self._values["source_selection_criteria"] = source_selection_criteria

        @builtins.property
        def destination(
            self,
        ) -> typing.Union["CfnBucket.ReplicationDestinationProperty", _IResolvable_da3f097b]:
            '''A container for information about the replication destination and its configurations including enabling the S3 Replication Time Control (S3 RTC).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationconfiguration-rules-destination
            '''
            result = self._values.get("destination")
            assert result is not None, "Required property 'destination' is missing"
            return typing.cast(typing.Union["CfnBucket.ReplicationDestinationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def status(self) -> builtins.str:
            '''Specifies whether the rule is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationconfiguration-rules-status
            '''
            result = self._values.get("status")
            assert result is not None, "Required property 'status' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def delete_marker_replication(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.DeleteMarkerReplicationProperty", _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 replicates delete markers.

            If you specify a ``Filter`` in your replication configuration, you must also include a ``DeleteMarkerReplication`` element. If your ``Filter`` includes a ``Tag`` element, the ``DeleteMarkerReplication`` ``Status`` must be set to Disabled, because Amazon S3 does not support replicating delete markers for tag-based rules. For an example configuration, see `Basic Rule Configuration <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-add-config.html#replication-config-min-rule-config>`_ .

            For more information about delete marker replication, see `Basic Rule Configuration <https://docs.aws.amazon.com/AmazonS3/latest/dev/delete-marker-replication.html>`_ .
            .. epigraph::

               If you are using an earlier version of the replication configuration, Amazon S3 handles replication of delete markers differently. For more information, see `Backward Compatibility <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication-add-config.html#replication-backward-compat-considerations>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationrule-deletemarkerreplication
            '''
            result = self._values.get("delete_marker_replication")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.DeleteMarkerReplicationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def filter(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.ReplicationRuleFilterProperty", _IResolvable_da3f097b]]:
            '''A filter that identifies the subset of objects to which the replication rule applies.

            A ``Filter`` must specify exactly one ``Prefix`` , ``TagFilter`` , or an ``And`` child element. The use of the filter field indicates this is a V2 replication configuration. V1 does not have this field.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationrule-filter
            '''
            result = self._values.get("filter")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.ReplicationRuleFilterProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def id(self) -> typing.Optional[builtins.str]:
            '''A unique identifier for the rule.

            The maximum value is 255 characters. If you don't specify a value, AWS CloudFormation generates a random ID. When using a V2 replication configuration this property is capitalized as "ID".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationconfiguration-rules-id
            '''
            result = self._values.get("id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def prefix(self) -> typing.Optional[builtins.str]:
            '''An object key name prefix that identifies the object or objects to which the rule applies.

            The maximum prefix length is 1,024 characters. To include all objects in a bucket, specify an empty string.
            .. epigraph::

               Replacement must be made for object keys containing special characters (such as carriage returns) when using XML requests. For more information, see `XML related object key constraints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html#object-key-xml-related-constraints>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationconfiguration-rules-prefix
            '''
            result = self._values.get("prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def priority(self) -> typing.Optional[jsii.Number]:
            '''The priority indicates which rule has precedence whenever two or more replication rules conflict.

            Amazon S3 will attempt to replicate objects according to all replication rules. However, if there are two or more rules with the same destination bucket, then objects will be replicated according to the rule with the highest priority. The higher the number, the higher the priority.

            For more information, see `Replication <https://docs.aws.amazon.com/AmazonS3/latest/dev/replication.html>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationrule-priority
            '''
            result = self._values.get("priority")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def source_selection_criteria(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.SourceSelectionCriteriaProperty", _IResolvable_da3f097b]]:
            '''A container that describes additional filters for identifying the source objects that you want to replicate.

            You can choose to enable or disable the replication of these objects.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationconfiguration-rules.html#cfn-s3-bucket-replicationrule-sourceselectioncriteria
            '''
            result = self._values.get("source_selection_criteria")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.SourceSelectionCriteriaProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicationRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ReplicationTimeProperty",
        jsii_struct_bases=[],
        name_mapping={"status": "status", "time": "time"},
    )
    class ReplicationTimeProperty:
        def __init__(
            self,
            *,
            status: builtins.str,
            time: typing.Union["CfnBucket.ReplicationTimeValueProperty", _IResolvable_da3f097b],
        ) -> None:
            '''A container specifying S3 Replication Time Control (S3 RTC) related information, including whether S3 RTC is enabled and the time when all objects and operations on objects must be replicated.

            Must be specified together with a ``Metrics`` block.

            :param status: Specifies whether the replication time is enabled.
            :param time: A container specifying the time by which replication should be complete for all objects and operations on objects.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationtime.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                replication_time_property = s3.CfnBucket.ReplicationTimeProperty(
                    status="status",
                    time=s3.CfnBucket.ReplicationTimeValueProperty(
                        minutes=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "status": status,
                "time": time,
            }

        @builtins.property
        def status(self) -> builtins.str:
            '''Specifies whether the replication time is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationtime.html#cfn-s3-bucket-replicationtime-status
            '''
            result = self._values.get("status")
            assert result is not None, "Required property 'status' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def time(
            self,
        ) -> typing.Union["CfnBucket.ReplicationTimeValueProperty", _IResolvable_da3f097b]:
            '''A container specifying the time by which replication should be complete for all objects and operations on objects.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationtime.html#cfn-s3-bucket-replicationtime-time
            '''
            result = self._values.get("time")
            assert result is not None, "Required property 'time' is missing"
            return typing.cast(typing.Union["CfnBucket.ReplicationTimeValueProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicationTimeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ReplicationTimeValueProperty",
        jsii_struct_bases=[],
        name_mapping={"minutes": "minutes"},
    )
    class ReplicationTimeValueProperty:
        def __init__(self, *, minutes: jsii.Number) -> None:
            '''A container specifying the time value for S3 Replication Time Control (S3 RTC) and replication metrics ``EventThreshold`` .

            :param minutes: Contains an integer specifying time in minutes. Valid value: 15

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationtimevalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                replication_time_value_property = s3.CfnBucket.ReplicationTimeValueProperty(
                    minutes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "minutes": minutes,
            }

        @builtins.property
        def minutes(self) -> jsii.Number:
            '''Contains an integer specifying time in minutes.

            Valid value: 15

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-replicationtimevalue.html#cfn-s3-bucket-replicationtimevalue-minutes
            '''
            result = self._values.get("minutes")
            assert result is not None, "Required property 'minutes' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ReplicationTimeValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.RoutingRuleConditionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "http_error_code_returned_equals": "httpErrorCodeReturnedEquals",
            "key_prefix_equals": "keyPrefixEquals",
        },
    )
    class RoutingRuleConditionProperty:
        def __init__(
            self,
            *,
            http_error_code_returned_equals: typing.Optional[builtins.str] = None,
            key_prefix_equals: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A container for describing a condition that must be met for the specified redirect to apply.

            For example, 1. If request is for pages in the ``/docs`` folder, redirect to the ``/documents`` folder. 2. If request results in HTTP error 4xx, redirect request to another host where you might process the error.

            :param http_error_code_returned_equals: The HTTP error code when the redirect is applied. In the event of an error, if the error code equals this value, then the specified redirect is applied. Required when parent element ``Condition`` is specified and sibling ``KeyPrefixEquals`` is not specified. If both are specified, then both must be true for the redirect to be applied.
            :param key_prefix_equals: The object key name prefix when the redirect is applied. For example, to redirect requests for ``ExamplePage.html`` , the key prefix will be ``ExamplePage.html`` . To redirect request for all pages with the prefix ``docs/`` , the key prefix will be ``/docs`` , which identifies all objects in the docs/ folder. Required when the parent element ``Condition`` is specified and sibling ``HttpErrorCodeReturnedEquals`` is not specified. If both conditions are specified, both must be true for the redirect to be applied.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules-routingrulecondition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                routing_rule_condition_property = s3.CfnBucket.RoutingRuleConditionProperty(
                    http_error_code_returned_equals="httpErrorCodeReturnedEquals",
                    key_prefix_equals="keyPrefixEquals"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if http_error_code_returned_equals is not None:
                self._values["http_error_code_returned_equals"] = http_error_code_returned_equals
            if key_prefix_equals is not None:
                self._values["key_prefix_equals"] = key_prefix_equals

        @builtins.property
        def http_error_code_returned_equals(self) -> typing.Optional[builtins.str]:
            '''The HTTP error code when the redirect is applied.

            In the event of an error, if the error code equals this value, then the specified redirect is applied.

            Required when parent element ``Condition`` is specified and sibling ``KeyPrefixEquals`` is not specified. If both are specified, then both must be true for the redirect to be applied.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules-routingrulecondition.html#cfn-s3-websiteconfiguration-routingrules-routingrulecondition-httperrorcodereturnedequals
            '''
            result = self._values.get("http_error_code_returned_equals")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def key_prefix_equals(self) -> typing.Optional[builtins.str]:
            '''The object key name prefix when the redirect is applied.

            For example, to redirect requests for ``ExamplePage.html`` , the key prefix will be ``ExamplePage.html`` . To redirect request for all pages with the prefix ``docs/`` , the key prefix will be ``/docs`` , which identifies all objects in the docs/ folder.

            Required when the parent element ``Condition`` is specified and sibling ``HttpErrorCodeReturnedEquals`` is not specified. If both conditions are specified, both must be true for the redirect to be applied.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules-routingrulecondition.html#cfn-s3-websiteconfiguration-routingrules-routingrulecondition-keyprefixequals
            '''
            result = self._values.get("key_prefix_equals")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RoutingRuleConditionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.RoutingRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "redirect_rule": "redirectRule",
            "routing_rule_condition": "routingRuleCondition",
        },
    )
    class RoutingRuleProperty:
        def __init__(
            self,
            *,
            redirect_rule: typing.Union["CfnBucket.RedirectRuleProperty", _IResolvable_da3f097b],
            routing_rule_condition: typing.Optional[typing.Union["CfnBucket.RoutingRuleConditionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies the redirect behavior and when a redirect is applied.

            For more information about routing rules, see `Configuring advanced conditional redirects <https://docs.aws.amazon.com/AmazonS3/latest/dev/how-to-page-redirect.html#advanced-conditional-redirects>`_ in the *Amazon S3 User Guide* .

            :param redirect_rule: Container for redirect information. You can redirect requests to another host, to another page, or with another protocol. In the event of an error, you can specify a different error code to return.
            :param routing_rule_condition: A container for describing a condition that must be met for the specified redirect to apply. For example, 1. If request is for pages in the ``/docs`` folder, redirect to the ``/documents`` folder. 2. If request results in HTTP error 4xx, redirect request to another host where you might process the error.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                routing_rule_property = s3.CfnBucket.RoutingRuleProperty(
                    redirect_rule=s3.CfnBucket.RedirectRuleProperty(
                        host_name="hostName",
                        http_redirect_code="httpRedirectCode",
                        protocol="protocol",
                        replace_key_prefix_with="replaceKeyPrefixWith",
                        replace_key_with="replaceKeyWith"
                    ),
                
                    # the properties below are optional
                    routing_rule_condition=s3.CfnBucket.RoutingRuleConditionProperty(
                        http_error_code_returned_equals="httpErrorCodeReturnedEquals",
                        key_prefix_equals="keyPrefixEquals"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "redirect_rule": redirect_rule,
            }
            if routing_rule_condition is not None:
                self._values["routing_rule_condition"] = routing_rule_condition

        @builtins.property
        def redirect_rule(
            self,
        ) -> typing.Union["CfnBucket.RedirectRuleProperty", _IResolvable_da3f097b]:
            '''Container for redirect information.

            You can redirect requests to another host, to another page, or with another protocol. In the event of an error, you can specify a different error code to return.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules.html#cfn-s3-websiteconfiguration-routingrules-redirectrule
            '''
            result = self._values.get("redirect_rule")
            assert result is not None, "Required property 'redirect_rule' is missing"
            return typing.cast(typing.Union["CfnBucket.RedirectRuleProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def routing_rule_condition(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.RoutingRuleConditionProperty", _IResolvable_da3f097b]]:
            '''A container for describing a condition that must be met for the specified redirect to apply.

            For example, 1. If request is for pages in the ``/docs`` folder, redirect to the ``/documents`` folder. 2. If request results in HTTP error 4xx, redirect request to another host where you might process the error.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration-routingrules.html#cfn-s3-websiteconfiguration-routingrules-routingrulecondition
            '''
            result = self._values.get("routing_rule_condition")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.RoutingRuleConditionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RoutingRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.RuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "status": "status",
            "abort_incomplete_multipart_upload": "abortIncompleteMultipartUpload",
            "expiration_date": "expirationDate",
            "expiration_in_days": "expirationInDays",
            "expired_object_delete_marker": "expiredObjectDeleteMarker",
            "id": "id",
            "noncurrent_version_expiration": "noncurrentVersionExpiration",
            "noncurrent_version_expiration_in_days": "noncurrentVersionExpirationInDays",
            "noncurrent_version_transition": "noncurrentVersionTransition",
            "noncurrent_version_transitions": "noncurrentVersionTransitions",
            "object_size_greater_than": "objectSizeGreaterThan",
            "object_size_less_than": "objectSizeLessThan",
            "prefix": "prefix",
            "tag_filters": "tagFilters",
            "transition": "transition",
            "transitions": "transitions",
        },
    )
    class RuleProperty:
        def __init__(
            self,
            *,
            status: builtins.str,
            abort_incomplete_multipart_upload: typing.Optional[typing.Union["CfnBucket.AbortIncompleteMultipartUploadProperty", _IResolvable_da3f097b]] = None,
            expiration_date: typing.Optional[typing.Union[_IResolvable_da3f097b, datetime.datetime]] = None,
            expiration_in_days: typing.Optional[jsii.Number] = None,
            expired_object_delete_marker: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            id: typing.Optional[builtins.str] = None,
            noncurrent_version_expiration: typing.Optional[typing.Union["CfnBucket.NoncurrentVersionExpirationProperty", _IResolvable_da3f097b]] = None,
            noncurrent_version_expiration_in_days: typing.Optional[jsii.Number] = None,
            noncurrent_version_transition: typing.Optional[typing.Union["CfnBucket.NoncurrentVersionTransitionProperty", _IResolvable_da3f097b]] = None,
            noncurrent_version_transitions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.NoncurrentVersionTransitionProperty", _IResolvable_da3f097b]]]] = None,
            object_size_greater_than: typing.Optional[jsii.Number] = None,
            object_size_less_than: typing.Optional[jsii.Number] = None,
            prefix: typing.Optional[builtins.str] = None,
            tag_filters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]] = None,
            transition: typing.Optional[typing.Union["CfnBucket.TransitionProperty", _IResolvable_da3f097b]] = None,
            transitions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.TransitionProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Specifies lifecycle rules for an Amazon S3 bucket.

            For more information, see `Put Bucket Lifecycle Configuration <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTlifecycle.html>`_ in the *Amazon S3 API Reference* .

            You must specify at least one of the following properties: ``AbortIncompleteMultipartUpload`` , ``ExpirationDate`` , ``ExpirationInDays`` , ``NoncurrentVersionExpirationInDays`` , ``NoncurrentVersionTransition`` , ``NoncurrentVersionTransitions`` , ``Transition`` , or ``Transitions`` .

            :param status: If ``Enabled`` , the rule is currently being applied. If ``Disabled`` , the rule is not currently being applied.
            :param abort_incomplete_multipart_upload: Specifies a lifecycle rule that stops incomplete multipart uploads to an Amazon S3 bucket.
            :param expiration_date: Indicates when objects are deleted from Amazon S3 and Amazon S3 Glacier. The date value must be in ISO 8601 format. The time is always midnight UTC. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time.
            :param expiration_in_days: Indicates the number of days after creation when objects are deleted from Amazon S3 and Amazon S3 Glacier. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time.
            :param expired_object_delete_marker: Indicates whether Amazon S3 will remove a delete marker without any noncurrent versions. If set to true, the delete marker will be removed if there are no noncurrent versions. This cannot be specified with ``ExpirationInDays`` , ``ExpirationDate`` , or ``TagFilters`` .
            :param id: Unique identifier for the rule. The value can't be longer than 255 characters.
            :param noncurrent_version_expiration: Specifies when noncurrent object versions expire. Upon expiration, Amazon S3 permanently deletes the noncurrent object versions. You set this lifecycle configuration action on a bucket that has versioning enabled (or suspended) to request that Amazon S3 delete noncurrent object versions at a specific period in the object's lifetime.
            :param noncurrent_version_expiration_in_days: (Deprecated.) For buckets with versioning enabled (or suspended), specifies the time, in days, between when a new version of the object is uploaded to the bucket and when old versions of the object expire. When object versions expire, Amazon S3 permanently deletes them. If you specify a transition and expiration time, the expiration time must be later than the transition time.
            :param noncurrent_version_transition: (Deprecated.) For buckets with versioning enabled (or suspended), specifies when non-current objects transition to a specified storage class. If you specify a transition and expiration time, the expiration time must be later than the transition time. If you specify this property, don't specify the ``NoncurrentVersionTransitions`` property.
            :param noncurrent_version_transitions: For buckets with versioning enabled (or suspended), one or more transition rules that specify when non-current objects transition to a specified storage class. If you specify a transition and expiration time, the expiration time must be later than the transition time. If you specify this property, don't specify the ``NoncurrentVersionTransition`` property.
            :param object_size_greater_than: Specifies the minimum object size in bytes for this rule to apply to. For more information about size based rules, see `Lifecycle configuration using size-based rules <https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html#lc-size-rules>`_ in the *Amazon S3 User Guide* .
            :param object_size_less_than: Specifies the maximum object size in bytes for this rule to apply to. For more information about sized based rules, see `Lifecycle configuration using size-based rules <https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html#lc-size-rules>`_ in the *Amazon S3 User Guide* .
            :param prefix: Object key prefix that identifies one or more objects to which this rule applies. .. epigraph:: Replacement must be made for object keys containing special characters (such as carriage returns) when using XML requests. For more information, see `XML related object key constraints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html#object-key-xml-related-constraints>`_ .
            :param tag_filters: Tags to use to identify a subset of objects to which the lifecycle rule applies.
            :param transition: (Deprecated.) Specifies when an object transitions to a specified storage class. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time. If you specify this property, don't specify the ``Transitions`` property.
            :param transitions: One or more transition rules that specify when an object transitions to a specified storage class. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time. If you specify this property, don't specify the ``Transition`` property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                rule_property = s3.CfnBucket.RuleProperty(
                    status="status",
                
                    # the properties below are optional
                    abort_incomplete_multipart_upload=s3.CfnBucket.AbortIncompleteMultipartUploadProperty(
                        days_after_initiation=123
                    ),
                    expiration_date=Date(),
                    expiration_in_days=123,
                    expired_object_delete_marker=False,
                    id="id",
                    noncurrent_version_expiration=s3.CfnBucket.NoncurrentVersionExpirationProperty(
                        noncurrent_days=123,
                
                        # the properties below are optional
                        newer_noncurrent_versions=123
                    ),
                    noncurrent_version_expiration_in_days=123,
                    noncurrent_version_transition=s3.CfnBucket.NoncurrentVersionTransitionProperty(
                        storage_class="storageClass",
                        transition_in_days=123,
                
                        # the properties below are optional
                        newer_noncurrent_versions=123
                    ),
                    noncurrent_version_transitions=[s3.CfnBucket.NoncurrentVersionTransitionProperty(
                        storage_class="storageClass",
                        transition_in_days=123,
                
                        # the properties below are optional
                        newer_noncurrent_versions=123
                    )],
                    object_size_greater_than=123,
                    object_size_less_than=123,
                    prefix="prefix",
                    tag_filters=[s3.CfnBucket.TagFilterProperty(
                        key="key",
                        value="value"
                    )],
                    transition=s3.CfnBucket.TransitionProperty(
                        storage_class="storageClass",
                
                        # the properties below are optional
                        transition_date=Date(),
                        transition_in_days=123
                    ),
                    transitions=[s3.CfnBucket.TransitionProperty(
                        storage_class="storageClass",
                
                        # the properties below are optional
                        transition_date=Date(),
                        transition_in_days=123
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "status": status,
            }
            if abort_incomplete_multipart_upload is not None:
                self._values["abort_incomplete_multipart_upload"] = abort_incomplete_multipart_upload
            if expiration_date is not None:
                self._values["expiration_date"] = expiration_date
            if expiration_in_days is not None:
                self._values["expiration_in_days"] = expiration_in_days
            if expired_object_delete_marker is not None:
                self._values["expired_object_delete_marker"] = expired_object_delete_marker
            if id is not None:
                self._values["id"] = id
            if noncurrent_version_expiration is not None:
                self._values["noncurrent_version_expiration"] = noncurrent_version_expiration
            if noncurrent_version_expiration_in_days is not None:
                self._values["noncurrent_version_expiration_in_days"] = noncurrent_version_expiration_in_days
            if noncurrent_version_transition is not None:
                self._values["noncurrent_version_transition"] = noncurrent_version_transition
            if noncurrent_version_transitions is not None:
                self._values["noncurrent_version_transitions"] = noncurrent_version_transitions
            if object_size_greater_than is not None:
                self._values["object_size_greater_than"] = object_size_greater_than
            if object_size_less_than is not None:
                self._values["object_size_less_than"] = object_size_less_than
            if prefix is not None:
                self._values["prefix"] = prefix
            if tag_filters is not None:
                self._values["tag_filters"] = tag_filters
            if transition is not None:
                self._values["transition"] = transition
            if transitions is not None:
                self._values["transitions"] = transitions

        @builtins.property
        def status(self) -> builtins.str:
            '''If ``Enabled`` , the rule is currently being applied.

            If ``Disabled`` , the rule is not currently being applied.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-status
            '''
            result = self._values.get("status")
            assert result is not None, "Required property 'status' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def abort_incomplete_multipart_upload(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.AbortIncompleteMultipartUploadProperty", _IResolvable_da3f097b]]:
            '''Specifies a lifecycle rule that stops incomplete multipart uploads to an Amazon S3 bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-rule-abortincompletemultipartupload
            '''
            result = self._values.get("abort_incomplete_multipart_upload")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.AbortIncompleteMultipartUploadProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def expiration_date(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, datetime.datetime]]:
            '''Indicates when objects are deleted from Amazon S3 and Amazon S3 Glacier.

            The date value must be in ISO 8601 format. The time is always midnight UTC. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-expirationdate
            '''
            result = self._values.get("expiration_date")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, datetime.datetime]], result)

        @builtins.property
        def expiration_in_days(self) -> typing.Optional[jsii.Number]:
            '''Indicates the number of days after creation when objects are deleted from Amazon S3 and Amazon S3 Glacier.

            If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-expirationindays
            '''
            result = self._values.get("expiration_in_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def expired_object_delete_marker(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether Amazon S3 will remove a delete marker without any noncurrent versions.

            If set to true, the delete marker will be removed if there are no noncurrent versions. This cannot be specified with ``ExpirationInDays`` , ``ExpirationDate`` , or ``TagFilters`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-rule-expiredobjectdeletemarker
            '''
            result = self._values.get("expired_object_delete_marker")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def id(self) -> typing.Optional[builtins.str]:
            '''Unique identifier for the rule.

            The value can't be longer than 255 characters.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-id
            '''
            result = self._values.get("id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def noncurrent_version_expiration(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.NoncurrentVersionExpirationProperty", _IResolvable_da3f097b]]:
            '''Specifies when noncurrent object versions expire.

            Upon expiration, Amazon S3 permanently deletes the noncurrent object versions. You set this lifecycle configuration action on a bucket that has versioning enabled (or suspended) to request that Amazon S3 delete noncurrent object versions at a specific period in the object's lifetime.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-noncurrentversionexpiration
            '''
            result = self._values.get("noncurrent_version_expiration")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.NoncurrentVersionExpirationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def noncurrent_version_expiration_in_days(self) -> typing.Optional[jsii.Number]:
            '''(Deprecated.) For buckets with versioning enabled (or suspended), specifies the time, in days, between when a new version of the object is uploaded to the bucket and when old versions of the object expire. When object versions expire, Amazon S3 permanently deletes them. If you specify a transition and expiration time, the expiration time must be later than the transition time.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-noncurrentversionexpirationindays
            '''
            result = self._values.get("noncurrent_version_expiration_in_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def noncurrent_version_transition(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.NoncurrentVersionTransitionProperty", _IResolvable_da3f097b]]:
            '''(Deprecated.) For buckets with versioning enabled (or suspended), specifies when non-current objects transition to a specified storage class. If you specify a transition and expiration time, the expiration time must be later than the transition time. If you specify this property, don't specify the ``NoncurrentVersionTransitions`` property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-noncurrentversiontransition
            '''
            result = self._values.get("noncurrent_version_transition")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.NoncurrentVersionTransitionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def noncurrent_version_transitions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.NoncurrentVersionTransitionProperty", _IResolvable_da3f097b]]]]:
            '''For buckets with versioning enabled (or suspended), one or more transition rules that specify when non-current objects transition to a specified storage class.

            If you specify a transition and expiration time, the expiration time must be later than the transition time. If you specify this property, don't specify the ``NoncurrentVersionTransition`` property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-noncurrentversiontransitions
            '''
            result = self._values.get("noncurrent_version_transitions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.NoncurrentVersionTransitionProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def object_size_greater_than(self) -> typing.Optional[jsii.Number]:
            '''Specifies the minimum object size in bytes for this rule to apply to.

            For more information about size based rules, see `Lifecycle configuration using size-based rules <https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html#lc-size-rules>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-objectsizegreaterthan
            '''
            result = self._values.get("object_size_greater_than")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def object_size_less_than(self) -> typing.Optional[jsii.Number]:
            '''Specifies the maximum object size in bytes for this rule to apply to.

            For more information about sized based rules, see `Lifecycle configuration using size-based rules <https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html#lc-size-rules>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-objectsizelessthan
            '''
            result = self._values.get("object_size_less_than")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def prefix(self) -> typing.Optional[builtins.str]:
            '''Object key prefix that identifies one or more objects to which this rule applies.

            .. epigraph::

               Replacement must be made for object keys containing special characters (such as carriage returns) when using XML requests. For more information, see `XML related object key constraints <https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html#object-key-xml-related-constraints>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-prefix
            '''
            result = self._values.get("prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def tag_filters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]]:
            '''Tags to use to identify a subset of objects to which the lifecycle rule applies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-rule-tagfilters
            '''
            result = self._values.get("tag_filters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TagFilterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def transition(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.TransitionProperty", _IResolvable_da3f097b]]:
            '''(Deprecated.) Specifies when an object transitions to a specified storage class. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time. If you specify this property, don't specify the ``Transitions`` property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-transition
            '''
            result = self._values.get("transition")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.TransitionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def transitions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TransitionProperty", _IResolvable_da3f097b]]]]:
            '''One or more transition rules that specify when an object transitions to a specified storage class.

            If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time. If you specify this property, don't specify the ``Transition`` property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule.html#cfn-s3-bucket-lifecycleconfig-rule-transitions
            '''
            result = self._values.get("transitions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.TransitionProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.S3KeyFilterProperty",
        jsii_struct_bases=[],
        name_mapping={"rules": "rules"},
    )
    class S3KeyFilterProperty:
        def __init__(
            self,
            *,
            rules: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.FilterRuleProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''A container for object key name prefix and suffix filtering rules.

            .. epigraph::

               The same type of filter rule cannot be used more than once. For example, you cannot specify two prefix rules.

            :param rules: A list of containers for the key-value pair that defines the criteria for the filter rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfiguration-config-filter-s3key.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                s3_key_filter_property = s3.CfnBucket.S3KeyFilterProperty(
                    rules=[s3.CfnBucket.FilterRuleProperty(
                        name="name",
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
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.FilterRuleProperty", _IResolvable_da3f097b]]]:
            '''A list of containers for the key-value pair that defines the criteria for the filter rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfiguration-config-filter-s3key.html#cfn-s3-bucket-notificationconfiguraiton-config-filter-s3key-rules
            '''
            result = self._values.get("rules")
            assert result is not None, "Required property 'rules' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.FilterRuleProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3KeyFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ServerSideEncryptionByDefaultProperty",
        jsii_struct_bases=[],
        name_mapping={
            "sse_algorithm": "sseAlgorithm",
            "kms_master_key_id": "kmsMasterKeyId",
        },
    )
    class ServerSideEncryptionByDefaultProperty:
        def __init__(
            self,
            *,
            sse_algorithm: builtins.str,
            kms_master_key_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Describes the default server-side encryption to apply to new objects in the bucket.

            If a PUT Object request doesn't specify any server-side encryption, this default encryption will be applied. If you don't specify a customer managed key at configuration, Amazon S3 automatically creates an AWS KMS key in your AWS account the first time that you add an object encrypted with SSE-KMS to a bucket. By default, Amazon S3 uses this KMS key for SSE-KMS. For more information, see `PUT Bucket encryption <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTencryption.html>`_ in the *Amazon S3 API Reference* .

            :param sse_algorithm: Server-side encryption algorithm to use for the default encryption.
            :param kms_master_key_id: KMS key ID to use for the default encryption. This parameter is allowed if SSEAlgorithm is aws:kms. You can specify the key ID or the Amazon Resource Name (ARN) of the CMK. However, if you are using encryption with cross-account operations, you must use a fully qualified CMK ARN. For more information, see `Using encryption for cross-account operations <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html#bucket-encryption-update-bucket-policy>`_ . For example: - Key ID: ``1234abcd-12ab-34cd-56ef-1234567890ab`` - Key ARN: ``arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`` .. epigraph:: Amazon S3 only supports symmetric KMS keys and not asymmetric KMS keys. For more information, see `Using Symmetric and Asymmetric Keys <https://docs.aws.amazon.com//kms/latest/developerguide/symmetric-asymmetric.html>`_ in the *AWS Key Management Service Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-serversideencryptionbydefault.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                server_side_encryption_by_default_property = s3.CfnBucket.ServerSideEncryptionByDefaultProperty(
                    sse_algorithm="sseAlgorithm",
                
                    # the properties below are optional
                    kms_master_key_id="kmsMasterKeyId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "sse_algorithm": sse_algorithm,
            }
            if kms_master_key_id is not None:
                self._values["kms_master_key_id"] = kms_master_key_id

        @builtins.property
        def sse_algorithm(self) -> builtins.str:
            '''Server-side encryption algorithm to use for the default encryption.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-serversideencryptionbydefault.html#cfn-s3-bucket-serversideencryptionbydefault-ssealgorithm
            '''
            result = self._values.get("sse_algorithm")
            assert result is not None, "Required property 'sse_algorithm' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def kms_master_key_id(self) -> typing.Optional[builtins.str]:
            '''KMS key ID to use for the default encryption. This parameter is allowed if SSEAlgorithm is aws:kms.

            You can specify the key ID or the Amazon Resource Name (ARN) of the CMK. However, if you are using encryption with cross-account operations, you must use a fully qualified CMK ARN. For more information, see `Using encryption for cross-account operations <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html#bucket-encryption-update-bucket-policy>`_ .

            For example:

            - Key ID: ``1234abcd-12ab-34cd-56ef-1234567890ab``
            - Key ARN: ``arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab``

            .. epigraph::

               Amazon S3 only supports symmetric KMS keys and not asymmetric KMS keys. For more information, see `Using Symmetric and Asymmetric Keys <https://docs.aws.amazon.com//kms/latest/developerguide/symmetric-asymmetric.html>`_ in the *AWS Key Management Service Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-serversideencryptionbydefault.html#cfn-s3-bucket-serversideencryptionbydefault-kmsmasterkeyid
            '''
            result = self._values.get("kms_master_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ServerSideEncryptionByDefaultProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.ServerSideEncryptionRuleProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_key_enabled": "bucketKeyEnabled",
            "server_side_encryption_by_default": "serverSideEncryptionByDefault",
        },
    )
    class ServerSideEncryptionRuleProperty:
        def __init__(
            self,
            *,
            bucket_key_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            server_side_encryption_by_default: typing.Optional[typing.Union["CfnBucket.ServerSideEncryptionByDefaultProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies the default server-side encryption configuration.

            :param bucket_key_enabled: Specifies whether Amazon S3 should use an S3 Bucket Key with server-side encryption using KMS (SSE-KMS) for new objects in the bucket. Existing objects are not affected. Setting the ``BucketKeyEnabled`` element to ``true`` causes Amazon S3 to use an S3 Bucket Key. By default, S3 Bucket Key is not enabled. For more information, see `Amazon S3 Bucket Keys <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-key.html>`_ in the *Amazon S3 User Guide* .
            :param server_side_encryption_by_default: Specifies the default server-side encryption to apply to new objects in the bucket. If a PUT Object request doesn't specify any server-side encryption, this default encryption will be applied.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-serversideencryptionrule.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                server_side_encryption_rule_property = s3.CfnBucket.ServerSideEncryptionRuleProperty(
                    bucket_key_enabled=False,
                    server_side_encryption_by_default=s3.CfnBucket.ServerSideEncryptionByDefaultProperty(
                        sse_algorithm="sseAlgorithm",
                
                        # the properties below are optional
                        kms_master_key_id="kmsMasterKeyId"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if bucket_key_enabled is not None:
                self._values["bucket_key_enabled"] = bucket_key_enabled
            if server_side_encryption_by_default is not None:
                self._values["server_side_encryption_by_default"] = server_side_encryption_by_default

        @builtins.property
        def bucket_key_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should use an S3 Bucket Key with server-side encryption using KMS (SSE-KMS) for new objects in the bucket.

            Existing objects are not affected. Setting the ``BucketKeyEnabled`` element to ``true`` causes Amazon S3 to use an S3 Bucket Key. By default, S3 Bucket Key is not enabled.

            For more information, see `Amazon S3 Bucket Keys <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-key.html>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-serversideencryptionrule.html#cfn-s3-bucket-serversideencryptionrule-bucketkeyenabled
            '''
            result = self._values.get("bucket_key_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def server_side_encryption_by_default(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.ServerSideEncryptionByDefaultProperty", _IResolvable_da3f097b]]:
            '''Specifies the default server-side encryption to apply to new objects in the bucket.

            If a PUT Object request doesn't specify any server-side encryption, this default encryption will be applied.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-serversideencryptionrule.html#cfn-s3-bucket-serversideencryptionrule-serversideencryptionbydefault
            '''
            result = self._values.get("server_side_encryption_by_default")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.ServerSideEncryptionByDefaultProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ServerSideEncryptionRuleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.SourceSelectionCriteriaProperty",
        jsii_struct_bases=[],
        name_mapping={
            "replica_modifications": "replicaModifications",
            "sse_kms_encrypted_objects": "sseKmsEncryptedObjects",
        },
    )
    class SourceSelectionCriteriaProperty:
        def __init__(
            self,
            *,
            replica_modifications: typing.Optional[typing.Union["CfnBucket.ReplicaModificationsProperty", _IResolvable_da3f097b]] = None,
            sse_kms_encrypted_objects: typing.Optional[typing.Union["CfnBucket.SseKmsEncryptedObjectsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A container that describes additional filters for identifying the source objects that you want to replicate.

            You can choose to enable or disable the replication of these objects.

            :param replica_modifications: A filter that you can specify for selection for modifications on replicas.
            :param sse_kms_encrypted_objects: A container for filter information for the selection of Amazon S3 objects encrypted with AWS KMS.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-sourceselectioncriteria.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                source_selection_criteria_property = s3.CfnBucket.SourceSelectionCriteriaProperty(
                    replica_modifications=s3.CfnBucket.ReplicaModificationsProperty(
                        status="status"
                    ),
                    sse_kms_encrypted_objects=s3.CfnBucket.SseKmsEncryptedObjectsProperty(
                        status="status"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if replica_modifications is not None:
                self._values["replica_modifications"] = replica_modifications
            if sse_kms_encrypted_objects is not None:
                self._values["sse_kms_encrypted_objects"] = sse_kms_encrypted_objects

        @builtins.property
        def replica_modifications(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.ReplicaModificationsProperty", _IResolvable_da3f097b]]:
            '''A filter that you can specify for selection for modifications on replicas.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-sourceselectioncriteria.html#cfn-s3-bucket-sourceselectioncriteria-replicamodifications
            '''
            result = self._values.get("replica_modifications")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.ReplicaModificationsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sse_kms_encrypted_objects(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.SseKmsEncryptedObjectsProperty", _IResolvable_da3f097b]]:
            '''A container for filter information for the selection of Amazon S3 objects encrypted with AWS KMS.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-sourceselectioncriteria.html#cfn-s3-bucket-sourceselectioncriteria-ssekmsencryptedobjects
            '''
            result = self._values.get("sse_kms_encrypted_objects")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.SseKmsEncryptedObjectsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SourceSelectionCriteriaProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.SseKmsEncryptedObjectsProperty",
        jsii_struct_bases=[],
        name_mapping={"status": "status"},
    )
    class SseKmsEncryptedObjectsProperty:
        def __init__(self, *, status: builtins.str) -> None:
            '''A container for filter information for the selection of S3 objects encrypted with AWS KMS.

            :param status: Specifies whether Amazon S3 replicates objects created with server-side encryption using an AWS KMS key stored in AWS Key Management Service.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-ssekmsencryptedobjects.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                sse_kms_encrypted_objects_property = s3.CfnBucket.SseKmsEncryptedObjectsProperty(
                    status="status"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "status": status,
            }

        @builtins.property
        def status(self) -> builtins.str:
            '''Specifies whether Amazon S3 replicates objects created with server-side encryption using an AWS KMS key stored in AWS Key Management Service.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-ssekmsencryptedobjects.html#cfn-s3-bucket-ssekmsencryptedobjects-status
            '''
            result = self._values.get("status")
            assert result is not None, "Required property 'status' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SseKmsEncryptedObjectsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.StorageClassAnalysisProperty",
        jsii_struct_bases=[],
        name_mapping={"data_export": "dataExport"},
    )
    class StorageClassAnalysisProperty:
        def __init__(
            self,
            *,
            data_export: typing.Optional[typing.Union["CfnBucket.DataExportProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies data related to access patterns to be collected and made available to analyze the tradeoffs between different storage classes for an Amazon S3 bucket.

            :param data_export: Specifies how data related to the storage class analysis for an Amazon S3 bucket should be exported.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-storageclassanalysis.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                storage_class_analysis_property = s3.CfnBucket.StorageClassAnalysisProperty(
                    data_export=s3.CfnBucket.DataExportProperty(
                        destination=s3.CfnBucket.DestinationProperty(
                            bucket_arn="bucketArn",
                            format="format",
                
                            # the properties below are optional
                            bucket_account_id="bucketAccountId",
                            prefix="prefix"
                        ),
                        output_schema_version="outputSchemaVersion"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if data_export is not None:
                self._values["data_export"] = data_export

        @builtins.property
        def data_export(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.DataExportProperty", _IResolvable_da3f097b]]:
            '''Specifies how data related to the storage class analysis for an Amazon S3 bucket should be exported.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-storageclassanalysis.html#cfn-s3-bucket-storageclassanalysis-dataexport
            '''
            result = self._values.get("data_export")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.DataExportProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StorageClassAnalysisProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.TagFilterProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class TagFilterProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''Specifies tags to use to identify a subset of objects for an Amazon S3 bucket.

            :param key: The tag key.
            :param value: The tag value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-tagfilter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                tag_filter_property = s3.CfnBucket.TagFilterProperty(
                    key="key",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "key": key,
                "value": value,
            }

        @builtins.property
        def key(self) -> builtins.str:
            '''The tag key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-tagfilter.html#cfn-s3-bucket-tagfilter-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The tag value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-tagfilter.html#cfn-s3-bucket-tagfilter-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TagFilterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.TieringProperty",
        jsii_struct_bases=[],
        name_mapping={"access_tier": "accessTier", "days": "days"},
    )
    class TieringProperty:
        def __init__(self, *, access_tier: builtins.str, days: jsii.Number) -> None:
            '''The S3 Intelligent-Tiering storage class is designed to optimize storage costs by automatically moving data to the most cost-effective storage access tier, without additional operational overhead.

            :param access_tier: S3 Intelligent-Tiering access tier. See `Storage class for automatically optimizing frequently and infrequently accessed objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html#sc-dynamic-data-access>`_ for a list of access tiers in the S3 Intelligent-Tiering storage class.
            :param days: The number of consecutive days of no access after which an object will be eligible to be transitioned to the corresponding tier. The minimum number of days specified for Archive Access tier must be at least 90 days and Deep Archive Access tier must be at least 180 days. The maximum can be up to 2 years (730 days).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-tiering.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                tiering_property = s3.CfnBucket.TieringProperty(
                    access_tier="accessTier",
                    days=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "access_tier": access_tier,
                "days": days,
            }

        @builtins.property
        def access_tier(self) -> builtins.str:
            '''S3 Intelligent-Tiering access tier.

            See `Storage class for automatically optimizing frequently and infrequently accessed objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-class-intro.html#sc-dynamic-data-access>`_ for a list of access tiers in the S3 Intelligent-Tiering storage class.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-tiering.html#cfn-s3-bucket-tiering-accesstier
            '''
            result = self._values.get("access_tier")
            assert result is not None, "Required property 'access_tier' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def days(self) -> jsii.Number:
            '''The number of consecutive days of no access after which an object will be eligible to be transitioned to the corresponding tier.

            The minimum number of days specified for Archive Access tier must be at least 90 days and Deep Archive Access tier must be at least 180 days. The maximum can be up to 2 years (730 days).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-tiering.html#cfn-s3-bucket-tiering-days
            '''
            result = self._values.get("days")
            assert result is not None, "Required property 'days' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TieringProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.TopicConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"event": "event", "topic": "topic", "filter": "filter"},
    )
    class TopicConfigurationProperty:
        def __init__(
            self,
            *,
            event: builtins.str,
            topic: builtins.str,
            filter: typing.Optional[typing.Union["CfnBucket.NotificationFilterProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A container for specifying the configuration for publication of messages to an Amazon Simple Notification Service (Amazon SNS) topic when Amazon S3 detects specified events.

            :param event: The Amazon S3 bucket event about which to send notifications. For more information, see `Supported Event Types <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_ in the *Amazon S3 User Guide* .
            :param topic: The Amazon Resource Name (ARN) of the Amazon SNS topic to which Amazon S3 publishes a message when it detects events of the specified type.
            :param filter: The filtering rules that determine for which objects to send notifications. For example, you can create a filter so that Amazon S3 sends notifications only when image files with a ``.jpg`` extension are added to the bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-topicconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                topic_configuration_property = s3.CfnBucket.TopicConfigurationProperty(
                    event="event",
                    topic="topic",
                
                    # the properties below are optional
                    filter=s3.CfnBucket.NotificationFilterProperty(
                        s3_key=s3.CfnBucket.S3KeyFilterProperty(
                            rules=[s3.CfnBucket.FilterRuleProperty(
                                name="name",
                                value="value"
                            )]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "event": event,
                "topic": topic,
            }
            if filter is not None:
                self._values["filter"] = filter

        @builtins.property
        def event(self) -> builtins.str:
            '''The Amazon S3 bucket event about which to send notifications.

            For more information, see `Supported Event Types <https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_ in the *Amazon S3 User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-topicconfig.html#cfn-s3-bucket-notificationconfig-topicconfig-event
            '''
            result = self._values.get("event")
            assert result is not None, "Required property 'event' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def topic(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the Amazon SNS topic to which Amazon S3 publishes a message when it detects events of the specified type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-topicconfig.html#cfn-s3-bucket-notificationconfig-topicconfig-topic
            '''
            result = self._values.get("topic")
            assert result is not None, "Required property 'topic' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def filter(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.NotificationFilterProperty", _IResolvable_da3f097b]]:
            '''The filtering rules that determine for which objects to send notifications.

            For example, you can create a filter so that Amazon S3 sends notifications only when image files with a ``.jpg`` extension are added to the bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-notificationconfig-topicconfig.html#cfn-s3-bucket-notificationconfig-topicconfig-filter
            '''
            result = self._values.get("filter")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.NotificationFilterProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TopicConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.TransitionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "storage_class": "storageClass",
            "transition_date": "transitionDate",
            "transition_in_days": "transitionInDays",
        },
    )
    class TransitionProperty:
        def __init__(
            self,
            *,
            storage_class: builtins.str,
            transition_date: typing.Optional[typing.Union[_IResolvable_da3f097b, datetime.datetime]] = None,
            transition_in_days: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies when an object transitions to a specified storage class.

            For more information about Amazon S3 lifecycle configuration rules, see `Transitioning Objects Using Amazon S3 Lifecycle <https://docs.aws.amazon.com/AmazonS3/latest/dev/lifecycle-transition-general-considerations.html>`_ in the *Amazon S3 User Guide* .

            :param storage_class: The storage class to which you want the object to transition.
            :param transition_date: Indicates when objects are transitioned to the specified storage class. The date value must be in ISO 8601 format. The time is always midnight UTC.
            :param transition_in_days: Indicates the number of days after creation when objects are transitioned to the specified storage class. The value must be a positive integer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule-transition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                transition_property = s3.CfnBucket.TransitionProperty(
                    storage_class="storageClass",
                
                    # the properties below are optional
                    transition_date=Date(),
                    transition_in_days=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "storage_class": storage_class,
            }
            if transition_date is not None:
                self._values["transition_date"] = transition_date
            if transition_in_days is not None:
                self._values["transition_in_days"] = transition_in_days

        @builtins.property
        def storage_class(self) -> builtins.str:
            '''The storage class to which you want the object to transition.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule-transition.html#cfn-s3-bucket-lifecycleconfig-rule-transition-storageclass
            '''
            result = self._values.get("storage_class")
            assert result is not None, "Required property 'storage_class' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def transition_date(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, datetime.datetime]]:
            '''Indicates when objects are transitioned to the specified storage class.

            The date value must be in ISO 8601 format. The time is always midnight UTC.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule-transition.html#cfn-s3-bucket-lifecycleconfig-rule-transition-transitiondate
            '''
            result = self._values.get("transition_date")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, datetime.datetime]], result)

        @builtins.property
        def transition_in_days(self) -> typing.Optional[jsii.Number]:
            '''Indicates the number of days after creation when objects are transitioned to the specified storage class.

            The value must be a positive integer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-lifecycleconfig-rule-transition.html#cfn-s3-bucket-lifecycleconfig-rule-transition-transitionindays
            '''
            result = self._values.get("transition_in_days")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TransitionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.VersioningConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"status": "status"},
    )
    class VersioningConfigurationProperty:
        def __init__(self, *, status: builtins.str) -> None:
            '''Describes the versioning state of an Amazon S3 bucket.

            For more information, see `PUT Bucket versioning <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTVersioningStatus.html>`_ in the *Amazon S3 API Reference* .

            :param status: The versioning state of the bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-versioningconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                versioning_configuration_property = s3.CfnBucket.VersioningConfigurationProperty(
                    status="status"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "status": status,
            }

        @builtins.property
        def status(self) -> builtins.str:
            '''The versioning state of the bucket.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket-versioningconfig.html#cfn-s3-bucket-versioningconfig-status
            '''
            result = self._values.get("status")
            assert result is not None, "Required property 'status' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VersioningConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnBucket.WebsiteConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "error_document": "errorDocument",
            "index_document": "indexDocument",
            "redirect_all_requests_to": "redirectAllRequestsTo",
            "routing_rules": "routingRules",
        },
    )
    class WebsiteConfigurationProperty:
        def __init__(
            self,
            *,
            error_document: typing.Optional[builtins.str] = None,
            index_document: typing.Optional[builtins.str] = None,
            redirect_all_requests_to: typing.Optional[typing.Union["CfnBucket.RedirectAllRequestsToProperty", _IResolvable_da3f097b]] = None,
            routing_rules: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnBucket.RoutingRuleProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Specifies website configuration parameters for an Amazon S3 bucket.

            :param error_document: The name of the error document for the website.
            :param index_document: The name of the index document for the website.
            :param redirect_all_requests_to: The redirect behavior for every request to this bucket's website endpoint. .. epigraph:: If you specify this property, you can't specify any other property.
            :param routing_rules: Rules that define when a redirect is applied and the redirect behavior.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                website_configuration_property = s3.CfnBucket.WebsiteConfigurationProperty(
                    error_document="errorDocument",
                    index_document="indexDocument",
                    redirect_all_requests_to=s3.CfnBucket.RedirectAllRequestsToProperty(
                        host_name="hostName",
                
                        # the properties below are optional
                        protocol="protocol"
                    ),
                    routing_rules=[s3.CfnBucket.RoutingRuleProperty(
                        redirect_rule=s3.CfnBucket.RedirectRuleProperty(
                            host_name="hostName",
                            http_redirect_code="httpRedirectCode",
                            protocol="protocol",
                            replace_key_prefix_with="replaceKeyPrefixWith",
                            replace_key_with="replaceKeyWith"
                        ),
                
                        # the properties below are optional
                        routing_rule_condition=s3.CfnBucket.RoutingRuleConditionProperty(
                            http_error_code_returned_equals="httpErrorCodeReturnedEquals",
                            key_prefix_equals="keyPrefixEquals"
                        )
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if error_document is not None:
                self._values["error_document"] = error_document
            if index_document is not None:
                self._values["index_document"] = index_document
            if redirect_all_requests_to is not None:
                self._values["redirect_all_requests_to"] = redirect_all_requests_to
            if routing_rules is not None:
                self._values["routing_rules"] = routing_rules

        @builtins.property
        def error_document(self) -> typing.Optional[builtins.str]:
            '''The name of the error document for the website.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration.html#cfn-s3-websiteconfiguration-errordocument
            '''
            result = self._values.get("error_document")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def index_document(self) -> typing.Optional[builtins.str]:
            '''The name of the index document for the website.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration.html#cfn-s3-websiteconfiguration-indexdocument
            '''
            result = self._values.get("index_document")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def redirect_all_requests_to(
            self,
        ) -> typing.Optional[typing.Union["CfnBucket.RedirectAllRequestsToProperty", _IResolvable_da3f097b]]:
            '''The redirect behavior for every request to this bucket's website endpoint.

            .. epigraph::

               If you specify this property, you can't specify any other property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration.html#cfn-s3-websiteconfiguration-redirectallrequeststo
            '''
            result = self._values.get("redirect_all_requests_to")
            return typing.cast(typing.Optional[typing.Union["CfnBucket.RedirectAllRequestsToProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def routing_rules(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.RoutingRuleProperty", _IResolvable_da3f097b]]]]:
            '''Rules that define when a redirect is applied and the redirect behavior.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-websiteconfiguration.html#cfn-s3-websiteconfiguration-routingrules
            '''
            result = self._values.get("routing_rules")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnBucket.RoutingRuleProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "WebsiteConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnBucketPolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_s3.CfnBucketPolicy",
):
    '''A CloudFormation ``AWS::S3::BucketPolicy``.

    Applies an Amazon S3 bucket policy to an Amazon S3 bucket. If you are using an identity other than the root user of the AWS account that owns the bucket, the calling identity must have the ``PutBucketPolicy`` permissions on the specified bucket and belong to the bucket owner's account in order to use this operation.

    If you don't have ``PutBucketPolicy`` permissions, Amazon S3 returns a ``403 Access Denied`` error. If you have the correct permissions, but you're not using an identity that belongs to the bucket owner's account, Amazon S3 returns a ``405 Method Not Allowed`` error.
    .. epigraph::

       As a security precaution, the root user of the AWS account that owns a bucket can always use this operation, even if the policy explicitly denies the root user the ability to perform this action.

    For more information, see `Bucket policy examples <https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html>`_ .

    The following operations are related to ``PutBucketPolicy`` :

    - `CreateBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html>`_
    - `DeleteBucket <https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html>`_

    :cloudformationResource: AWS::S3::BucketPolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_s3 as s3
        
        # policy_document: Any
        
        cfn_bucket_policy = s3.CfnBucketPolicy(self, "MyCfnBucketPolicy",
            bucket="bucket",
            policy_document=policy_document
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        bucket: builtins.str,
        policy_document: typing.Any,
    ) -> None:
        '''Create a new ``AWS::S3::BucketPolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param bucket: The name of the Amazon S3 bucket to which the policy applies.
        :param policy_document: A policy document containing permissions to add to the specified bucket. In IAM, you must provide policy documents in JSON format. However, in CloudFormation you can provide the policy in JSON or YAML format because CloudFormation converts YAML to JSON before submitting it to IAM. For more information, see the AWS::IAM::Policy `PolicyDocument <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-policydocument>`_ resource description in this guide and `Access Policy Language Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-policy-language-overview.html>`_ in the *Amazon S3 User Guide* .
        '''
        props = CfnBucketPolicyProps(bucket=bucket, policy_document=policy_document)

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
    @jsii.member(jsii_name="bucket")
    def bucket(self) -> builtins.str:
        '''The name of the Amazon S3 bucket to which the policy applies.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html#aws-properties-s3-policy-bucket
        '''
        return typing.cast(builtins.str, jsii.get(self, "bucket"))

    @bucket.setter
    def bucket(self, value: builtins.str) -> None:
        jsii.set(self, "bucket", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyDocument")
    def policy_document(self) -> typing.Any:
        '''A policy document containing permissions to add to the specified bucket.

        In IAM, you must provide policy documents in JSON format. However, in CloudFormation you can provide the policy in JSON or YAML format because CloudFormation converts YAML to JSON before submitting it to IAM. For more information, see the AWS::IAM::Policy `PolicyDocument <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-policydocument>`_ resource description in this guide and `Access Policy Language Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-policy-language-overview.html>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html#aws-properties-s3-policy-policydocument
        '''
        return typing.cast(typing.Any, jsii.get(self, "policyDocument"))

    @policy_document.setter
    def policy_document(self, value: typing.Any) -> None:
        jsii.set(self, "policyDocument", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.CfnBucketPolicyProps",
    jsii_struct_bases=[],
    name_mapping={"bucket": "bucket", "policy_document": "policyDocument"},
)
class CfnBucketPolicyProps:
    def __init__(self, *, bucket: builtins.str, policy_document: typing.Any) -> None:
        '''Properties for defining a ``CfnBucketPolicy``.

        :param bucket: The name of the Amazon S3 bucket to which the policy applies.
        :param policy_document: A policy document containing permissions to add to the specified bucket. In IAM, you must provide policy documents in JSON format. However, in CloudFormation you can provide the policy in JSON or YAML format because CloudFormation converts YAML to JSON before submitting it to IAM. For more information, see the AWS::IAM::Policy `PolicyDocument <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-policydocument>`_ resource description in this guide and `Access Policy Language Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-policy-language-overview.html>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            
            # policy_document: Any
            
            cfn_bucket_policy_props = s3.CfnBucketPolicyProps(
                bucket="bucket",
                policy_document=policy_document
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "bucket": bucket,
            "policy_document": policy_document,
        }

    @builtins.property
    def bucket(self) -> builtins.str:
        '''The name of the Amazon S3 bucket to which the policy applies.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html#aws-properties-s3-policy-bucket
        '''
        result = self._values.get("bucket")
        assert result is not None, "Required property 'bucket' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def policy_document(self) -> typing.Any:
        '''A policy document containing permissions to add to the specified bucket.

        In IAM, you must provide policy documents in JSON format. However, in CloudFormation you can provide the policy in JSON or YAML format because CloudFormation converts YAML to JSON before submitting it to IAM. For more information, see the AWS::IAM::Policy `PolicyDocument <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html#cfn-iam-policy-policydocument>`_ resource description in this guide and `Access Policy Language Overview <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-policy-language-overview.html>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html#aws-properties-s3-policy-policydocument
        '''
        result = self._values.get("policy_document")
        assert result is not None, "Required property 'policy_document' is missing"
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnBucketPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.CfnBucketProps",
    jsii_struct_bases=[],
    name_mapping={
        "accelerate_configuration": "accelerateConfiguration",
        "access_control": "accessControl",
        "analytics_configurations": "analyticsConfigurations",
        "bucket_encryption": "bucketEncryption",
        "bucket_name": "bucketName",
        "cors_configuration": "corsConfiguration",
        "intelligent_tiering_configurations": "intelligentTieringConfigurations",
        "inventory_configurations": "inventoryConfigurations",
        "lifecycle_configuration": "lifecycleConfiguration",
        "logging_configuration": "loggingConfiguration",
        "metrics_configurations": "metricsConfigurations",
        "notification_configuration": "notificationConfiguration",
        "object_lock_configuration": "objectLockConfiguration",
        "object_lock_enabled": "objectLockEnabled",
        "ownership_controls": "ownershipControls",
        "public_access_block_configuration": "publicAccessBlockConfiguration",
        "replication_configuration": "replicationConfiguration",
        "tags": "tags",
        "versioning_configuration": "versioningConfiguration",
        "website_configuration": "websiteConfiguration",
    },
)
class CfnBucketProps:
    def __init__(
        self,
        *,
        accelerate_configuration: typing.Optional[typing.Union[CfnBucket.AccelerateConfigurationProperty, _IResolvable_da3f097b]] = None,
        access_control: typing.Optional[builtins.str] = None,
        analytics_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnBucket.AnalyticsConfigurationProperty, _IResolvable_da3f097b]]]] = None,
        bucket_encryption: typing.Optional[typing.Union[CfnBucket.BucketEncryptionProperty, _IResolvable_da3f097b]] = None,
        bucket_name: typing.Optional[builtins.str] = None,
        cors_configuration: typing.Optional[typing.Union[CfnBucket.CorsConfigurationProperty, _IResolvable_da3f097b]] = None,
        intelligent_tiering_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnBucket.IntelligentTieringConfigurationProperty, _IResolvable_da3f097b]]]] = None,
        inventory_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnBucket.InventoryConfigurationProperty, _IResolvable_da3f097b]]]] = None,
        lifecycle_configuration: typing.Optional[typing.Union[CfnBucket.LifecycleConfigurationProperty, _IResolvable_da3f097b]] = None,
        logging_configuration: typing.Optional[typing.Union[CfnBucket.LoggingConfigurationProperty, _IResolvable_da3f097b]] = None,
        metrics_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnBucket.MetricsConfigurationProperty, _IResolvable_da3f097b]]]] = None,
        notification_configuration: typing.Optional[typing.Union[CfnBucket.NotificationConfigurationProperty, _IResolvable_da3f097b]] = None,
        object_lock_configuration: typing.Optional[typing.Union[CfnBucket.ObjectLockConfigurationProperty, _IResolvable_da3f097b]] = None,
        object_lock_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ownership_controls: typing.Optional[typing.Union[CfnBucket.OwnershipControlsProperty, _IResolvable_da3f097b]] = None,
        public_access_block_configuration: typing.Optional[typing.Union[CfnBucket.PublicAccessBlockConfigurationProperty, _IResolvable_da3f097b]] = None,
        replication_configuration: typing.Optional[typing.Union[CfnBucket.ReplicationConfigurationProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        versioning_configuration: typing.Optional[typing.Union[CfnBucket.VersioningConfigurationProperty, _IResolvable_da3f097b]] = None,
        website_configuration: typing.Optional[typing.Union[CfnBucket.WebsiteConfigurationProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnBucket``.

        :param accelerate_configuration: Configures the transfer acceleration state for an Amazon S3 bucket. For more information, see `Amazon S3 Transfer Acceleration <https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html>`_ in the *Amazon S3 User Guide* .
        :param access_control: A canned access control list (ACL) that grants predefined permissions to the bucket. For more information about canned ACLs, see `Canned ACL <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl>`_ in the *Amazon S3 User Guide* . Be aware that the syntax for this property differs from the information provided in the *Amazon S3 User Guide* . The AccessControl property is case-sensitive and must be one of the following values: Private, PublicRead, PublicReadWrite, AuthenticatedRead, LogDeliveryWrite, BucketOwnerRead, BucketOwnerFullControl, or AwsExecRead.
        :param analytics_configurations: Specifies the configuration and any analyses for the analytics filter of an Amazon S3 bucket.
        :param bucket_encryption: Specifies default encryption for a bucket using server-side encryption with Amazon S3-managed keys (SSE-S3) or AWS KMS-managed keys (SSE-KMS) bucket. For information about the Amazon S3 default encryption feature, see `Amazon S3 Default Encryption for S3 Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html>`_ in the *Amazon S3 User Guide* .
        :param bucket_name: A name for the bucket. If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the bucket name. The bucket name must contain only lowercase letters, numbers, periods (.), and dashes (-) and must follow `Amazon S3 bucket restrictions and limitations <https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html>`_ . For more information, see `Rules for naming Amazon S3 buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html#bucketnamingrules>`_ in the *Amazon S3 User Guide* . .. epigraph:: If you specify a name, you can't perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you need to replace the resource, specify a new name.
        :param cors_configuration: Describes the cross-origin access configuration for objects in an Amazon S3 bucket. For more information, see `Enabling Cross-Origin Resource Sharing <https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html>`_ in the *Amazon S3 User Guide* .
        :param intelligent_tiering_configurations: Defines how Amazon S3 handles Intelligent-Tiering storage.
        :param inventory_configurations: Specifies the inventory configuration for an Amazon S3 bucket. For more information, see `GET Bucket inventory <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETInventoryConfig.html>`_ in the *Amazon S3 API Reference* .
        :param lifecycle_configuration: Specifies the lifecycle configuration for objects in an Amazon S3 bucket. For more information, see `Object Lifecycle Management <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html>`_ in the *Amazon S3 User Guide* .
        :param logging_configuration: Settings that define where logs are stored.
        :param metrics_configurations: Specifies a metrics configuration for the CloudWatch request metrics (specified by the metrics configuration ID) from an Amazon S3 bucket. If you're updating an existing metrics configuration, note that this is a full replacement of the existing metrics configuration. If you don't include the elements you want to keep, they are erased. For more information, see `PutBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTMetricConfiguration.html>`_ .
        :param notification_configuration: Configuration that defines how Amazon S3 handles bucket notifications.
        :param object_lock_configuration: Places an Object Lock configuration on the specified bucket. The rule specified in the Object Lock configuration will be applied by default to every new object placed in the specified bucket. For more information, see `Locking Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html>`_ . .. epigraph:: - The ``DefaultRetention`` settings require both a mode and a period. - The ``DefaultRetention`` period can be either ``Days`` or ``Years`` but you must select one. You cannot specify ``Days`` and ``Years`` at the same time. - You can only enable Object Lock for new buckets. If you want to turn on Object Lock for an existing bucket, contact AWS Support.
        :param object_lock_enabled: Indicates whether this bucket has an Object Lock configuration enabled. Enable ``ObjectLockEnabled`` when you apply ``ObjectLockConfiguration`` to a bucket.
        :param ownership_controls: Configuration that defines how Amazon S3 handles Object Ownership rules.
        :param public_access_block_configuration: Configuration that defines how Amazon S3 handles public access.
        :param replication_configuration: Configuration for replicating objects in an S3 bucket. To enable replication, you must also enable versioning by using the ``VersioningConfiguration`` property. Amazon S3 can store replicated objects in a single destination bucket or multiple destination buckets. The destination bucket or buckets must already exist.
        :param tags: An arbitrary set of tags (key-value pairs) for this S3 bucket.
        :param versioning_configuration: Enables multiple versions of all objects in this bucket. You might enable versioning to prevent objects from being deleted or overwritten by mistake or to archive objects so that you can retrieve previous versions of them.
        :param website_configuration: Information used to configure the bucket as a static website. For more information, see `Hosting Websites on Amazon S3 <https://docs.aws.amazon.com/AmazonS3/latest/dev/WebsiteHosting.html>`_ .

        :exampleMetadata: infused
        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            raw_bucket = s3.CfnBucket(self, "Bucket")
            # -or-
            raw_bucket_alt = my_bucket.node.default_child
            
            # then
            raw_bucket.cfn_options.condition = CfnCondition(self, "EnableBucket")
            raw_bucket.cfn_options.metadata = {
                "metadata_key": "MetadataValue"
            }
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if accelerate_configuration is not None:
            self._values["accelerate_configuration"] = accelerate_configuration
        if access_control is not None:
            self._values["access_control"] = access_control
        if analytics_configurations is not None:
            self._values["analytics_configurations"] = analytics_configurations
        if bucket_encryption is not None:
            self._values["bucket_encryption"] = bucket_encryption
        if bucket_name is not None:
            self._values["bucket_name"] = bucket_name
        if cors_configuration is not None:
            self._values["cors_configuration"] = cors_configuration
        if intelligent_tiering_configurations is not None:
            self._values["intelligent_tiering_configurations"] = intelligent_tiering_configurations
        if inventory_configurations is not None:
            self._values["inventory_configurations"] = inventory_configurations
        if lifecycle_configuration is not None:
            self._values["lifecycle_configuration"] = lifecycle_configuration
        if logging_configuration is not None:
            self._values["logging_configuration"] = logging_configuration
        if metrics_configurations is not None:
            self._values["metrics_configurations"] = metrics_configurations
        if notification_configuration is not None:
            self._values["notification_configuration"] = notification_configuration
        if object_lock_configuration is not None:
            self._values["object_lock_configuration"] = object_lock_configuration
        if object_lock_enabled is not None:
            self._values["object_lock_enabled"] = object_lock_enabled
        if ownership_controls is not None:
            self._values["ownership_controls"] = ownership_controls
        if public_access_block_configuration is not None:
            self._values["public_access_block_configuration"] = public_access_block_configuration
        if replication_configuration is not None:
            self._values["replication_configuration"] = replication_configuration
        if tags is not None:
            self._values["tags"] = tags
        if versioning_configuration is not None:
            self._values["versioning_configuration"] = versioning_configuration
        if website_configuration is not None:
            self._values["website_configuration"] = website_configuration

    @builtins.property
    def accelerate_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.AccelerateConfigurationProperty, _IResolvable_da3f097b]]:
        '''Configures the transfer acceleration state for an Amazon S3 bucket.

        For more information, see `Amazon S3 Transfer Acceleration <https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-accelerateconfiguration
        '''
        result = self._values.get("accelerate_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.AccelerateConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def access_control(self) -> typing.Optional[builtins.str]:
        '''A canned access control list (ACL) that grants predefined permissions to the bucket.

        For more information about canned ACLs, see `Canned ACL <https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl>`_ in the *Amazon S3 User Guide* .

        Be aware that the syntax for this property differs from the information provided in the *Amazon S3 User Guide* . The AccessControl property is case-sensitive and must be one of the following values: Private, PublicRead, PublicReadWrite, AuthenticatedRead, LogDeliveryWrite, BucketOwnerRead, BucketOwnerFullControl, or AwsExecRead.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-accesscontrol
        '''
        result = self._values.get("access_control")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def analytics_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBucket.AnalyticsConfigurationProperty, _IResolvable_da3f097b]]]]:
        '''Specifies the configuration and any analyses for the analytics filter of an Amazon S3 bucket.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-analyticsconfigurations
        '''
        result = self._values.get("analytics_configurations")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBucket.AnalyticsConfigurationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def bucket_encryption(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.BucketEncryptionProperty, _IResolvable_da3f097b]]:
        '''Specifies default encryption for a bucket using server-side encryption with Amazon S3-managed keys (SSE-S3) or AWS KMS-managed keys (SSE-KMS) bucket.

        For information about the Amazon S3 default encryption feature, see `Amazon S3 Default Encryption for S3 Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-bucketencryption
        '''
        result = self._values.get("bucket_encryption")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.BucketEncryptionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def bucket_name(self) -> typing.Optional[builtins.str]:
        '''A name for the bucket.

        If you don't specify a name, AWS CloudFormation generates a unique ID and uses that ID for the bucket name. The bucket name must contain only lowercase letters, numbers, periods (.), and dashes (-) and must follow `Amazon S3 bucket restrictions and limitations <https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html>`_ . For more information, see `Rules for naming Amazon S3 buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html#bucketnamingrules>`_ in the *Amazon S3 User Guide* .
        .. epigraph::

           If you specify a name, you can't perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you need to replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-name
        '''
        result = self._values.get("bucket_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cors_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.CorsConfigurationProperty, _IResolvable_da3f097b]]:
        '''Describes the cross-origin access configuration for objects in an Amazon S3 bucket.

        For more information, see `Enabling Cross-Origin Resource Sharing <https://docs.aws.amazon.com/AmazonS3/latest/dev/cors.html>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-crossoriginconfig
        '''
        result = self._values.get("cors_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.CorsConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def intelligent_tiering_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBucket.IntelligentTieringConfigurationProperty, _IResolvable_da3f097b]]]]:
        '''Defines how Amazon S3 handles Intelligent-Tiering storage.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-intelligenttieringconfigurations
        '''
        result = self._values.get("intelligent_tiering_configurations")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBucket.IntelligentTieringConfigurationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def inventory_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBucket.InventoryConfigurationProperty, _IResolvable_da3f097b]]]]:
        '''Specifies the inventory configuration for an Amazon S3 bucket.

        For more information, see `GET Bucket inventory <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketGETInventoryConfig.html>`_ in the *Amazon S3 API Reference* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-inventoryconfigurations
        '''
        result = self._values.get("inventory_configurations")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBucket.InventoryConfigurationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def lifecycle_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.LifecycleConfigurationProperty, _IResolvable_da3f097b]]:
        '''Specifies the lifecycle configuration for objects in an Amazon S3 bucket.

        For more information, see `Object Lifecycle Management <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-lifecycleconfig
        '''
        result = self._values.get("lifecycle_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.LifecycleConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def logging_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.LoggingConfigurationProperty, _IResolvable_da3f097b]]:
        '''Settings that define where logs are stored.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-loggingconfig
        '''
        result = self._values.get("logging_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.LoggingConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def metrics_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBucket.MetricsConfigurationProperty, _IResolvable_da3f097b]]]]:
        '''Specifies a metrics configuration for the CloudWatch request metrics (specified by the metrics configuration ID) from an Amazon S3 bucket.

        If you're updating an existing metrics configuration, note that this is a full replacement of the existing metrics configuration. If you don't include the elements you want to keep, they are erased. For more information, see `PutBucketMetricsConfiguration <https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTMetricConfiguration.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-metricsconfigurations
        '''
        result = self._values.get("metrics_configurations")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnBucket.MetricsConfigurationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def notification_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.NotificationConfigurationProperty, _IResolvable_da3f097b]]:
        '''Configuration that defines how Amazon S3 handles bucket notifications.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-notification
        '''
        result = self._values.get("notification_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.NotificationConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def object_lock_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.ObjectLockConfigurationProperty, _IResolvable_da3f097b]]:
        '''Places an Object Lock configuration on the specified bucket.

        The rule specified in the Object Lock configuration will be applied by default to every new object placed in the specified bucket. For more information, see `Locking Objects <https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock.html>`_ .
        .. epigraph::

           - The ``DefaultRetention`` settings require both a mode and a period.
           - The ``DefaultRetention`` period can be either ``Days`` or ``Years`` but you must select one. You cannot specify ``Days`` and ``Years`` at the same time.
           - You can only enable Object Lock for new buckets. If you want to turn on Object Lock for an existing bucket, contact AWS Support.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-objectlockconfiguration
        '''
        result = self._values.get("object_lock_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.ObjectLockConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def object_lock_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether this bucket has an Object Lock configuration enabled.

        Enable ``ObjectLockEnabled`` when you apply ``ObjectLockConfiguration`` to a bucket.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-objectlockenabled
        '''
        result = self._values.get("object_lock_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def ownership_controls(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.OwnershipControlsProperty, _IResolvable_da3f097b]]:
        '''Configuration that defines how Amazon S3 handles Object Ownership rules.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-ownershipcontrols
        '''
        result = self._values.get("ownership_controls")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.OwnershipControlsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def public_access_block_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.PublicAccessBlockConfigurationProperty, _IResolvable_da3f097b]]:
        '''Configuration that defines how Amazon S3 handles public access.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-publicaccessblockconfiguration
        '''
        result = self._values.get("public_access_block_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.PublicAccessBlockConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def replication_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.ReplicationConfigurationProperty, _IResolvable_da3f097b]]:
        '''Configuration for replicating objects in an S3 bucket.

        To enable replication, you must also enable versioning by using the ``VersioningConfiguration`` property.

        Amazon S3 can store replicated objects in a single destination bucket or multiple destination buckets. The destination bucket or buckets must already exist.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-replicationconfiguration
        '''
        result = self._values.get("replication_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.ReplicationConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An arbitrary set of tags (key-value pairs) for this S3 bucket.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def versioning_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.VersioningConfigurationProperty, _IResolvable_da3f097b]]:
        '''Enables multiple versions of all objects in this bucket.

        You might enable versioning to prevent objects from being deleted or overwritten by mistake or to archive objects so that you can retrieve previous versions of them.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-versioning
        '''
        result = self._values.get("versioning_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.VersioningConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def website_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnBucket.WebsiteConfigurationProperty, _IResolvable_da3f097b]]:
        '''Information used to configure the bucket as a static website.

        For more information, see `Hosting Websites on Amazon S3 <https://docs.aws.amazon.com/AmazonS3/latest/dev/WebsiteHosting.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-bucket.html#cfn-s3-bucket-websiteconfiguration
        '''
        result = self._values.get("website_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnBucket.WebsiteConfigurationProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnBucketProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnMultiRegionAccessPoint(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_s3.CfnMultiRegionAccessPoint",
):
    '''A CloudFormation ``AWS::S3::MultiRegionAccessPoint``.

    The ``AWS::S3::MultiRegionAccessPoint`` resource creates an Amazon S3 Multi-Region Access Point. To learn more about Multi-Region Access Points, see `Multi-Region Access Points in Amazon S3 <https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiRegionAccessPoints.html>`_ in the in the *Amazon S3 User Guide* .

    :cloudformationResource: AWS::S3::MultiRegionAccessPoint
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspoint.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_s3 as s3
        
        cfn_multi_region_access_point = s3.CfnMultiRegionAccessPoint(self, "MyCfnMultiRegionAccessPoint",
            regions=[s3.CfnMultiRegionAccessPoint.RegionProperty(
                bucket="bucket"
            )],
        
            # the properties below are optional
            name="name",
            public_access_block_configuration=s3.CfnMultiRegionAccessPoint.PublicAccessBlockConfigurationProperty(
                block_public_acls=False,
                block_public_policy=False,
                ignore_public_acls=False,
                restrict_public_buckets=False
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        regions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnMultiRegionAccessPoint.RegionProperty", _IResolvable_da3f097b]]],
        name: typing.Optional[builtins.str] = None,
        public_access_block_configuration: typing.Optional[typing.Union["CfnMultiRegionAccessPoint.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::S3::MultiRegionAccessPoint``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param regions: A collection of the Regions and buckets associated with the Multi-Region Access Point.
        :param name: The name of the Multi-Region Access Point.
        :param public_access_block_configuration: The PublicAccessBlock configuration that you want to apply to this Multi-Region Access Point. You can enable the configuration options in any combination. For more information about when Amazon S3 considers an object public, see `The Meaning of "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`_ in the *Amazon S3 User Guide* .
        '''
        props = CfnMultiRegionAccessPointProps(
            regions=regions,
            name=name,
            public_access_block_configuration=public_access_block_configuration,
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
    @jsii.member(jsii_name="attrAlias")
    def attr_alias(self) -> builtins.str:
        '''The alias for the Multi-Region Access Point.

        For more information about the distinction between the name and the alias of an Multi-Region Access Point, see `Managing Multi-Region Access Points <https://docs.aws.amazon.com/AmazonS3/latest/userguide/CreatingMultiRegionAccessPoints.html#multi-region-access-point-naming>`_ in the *Amazon S3 User Guide* .

        :cloudformationAttribute: Alias
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrAlias"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCreatedAt")
    def attr_created_at(self) -> builtins.str:
        '''The timestamp of when the Multi-Region Access Point is created.

        :cloudformationAttribute: CreatedAt
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedAt"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="regions")
    def regions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnMultiRegionAccessPoint.RegionProperty", _IResolvable_da3f097b]]]:
        '''A collection of the Regions and buckets associated with the Multi-Region Access Point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspoint.html#cfn-s3-multiregionaccesspoint-regions
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnMultiRegionAccessPoint.RegionProperty", _IResolvable_da3f097b]]], jsii.get(self, "regions"))

    @regions.setter
    def regions(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnMultiRegionAccessPoint.RegionProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "regions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Multi-Region Access Point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspoint.html#cfn-s3-multiregionaccesspoint-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="publicAccessBlockConfiguration")
    def public_access_block_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnMultiRegionAccessPoint.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]]:
        '''The PublicAccessBlock configuration that you want to apply to this Multi-Region Access Point.

        You can enable the configuration options in any combination. For more information about when Amazon S3 considers an object public, see `The Meaning of "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspoint.html#cfn-s3-multiregionaccesspoint-publicaccessblockconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnMultiRegionAccessPoint.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "publicAccessBlockConfiguration"))

    @public_access_block_configuration.setter
    def public_access_block_configuration(
        self,
        value: typing.Optional[typing.Union["CfnMultiRegionAccessPoint.PublicAccessBlockConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "publicAccessBlockConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnMultiRegionAccessPoint.PublicAccessBlockConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "block_public_acls": "blockPublicAcls",
            "block_public_policy": "blockPublicPolicy",
            "ignore_public_acls": "ignorePublicAcls",
            "restrict_public_buckets": "restrictPublicBuckets",
        },
    )
    class PublicAccessBlockConfigurationProperty:
        def __init__(
            self,
            *,
            block_public_acls: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            block_public_policy: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            ignore_public_acls: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            restrict_public_buckets: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The PublicAccessBlock configuration that you want to apply to this Amazon S3 Multi-Region Access Point.

            You can enable the configuration options in any combination. For more information about when Amazon S3 considers an object public, see `The Meaning of "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`_ in the *Amazon S3 User Guide* .

            :param block_public_acls: Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket. Setting this element to ``TRUE`` causes the following behavior: - PUT Bucket ACL and PUT Object ACL calls fail if the specified ACL is public. - PUT Object calls fail if the request includes a public ACL. - PUT Bucket calls fail if the request includes a public ACL. Enabling this setting doesn't affect existing policies or ACLs.
            :param block_public_policy: Specifies whether Amazon S3 should block public bucket policies for this bucket. Setting this element to ``TRUE`` causes Amazon S3 to reject calls to PUT Bucket policy if the specified bucket policy allows public access. Enabling this setting doesn't affect existing bucket policies.
            :param ignore_public_acls: Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket. Setting this element to ``TRUE`` causes Amazon S3 to ignore all public ACLs on this bucket and objects in this bucket. Enabling this setting doesn't affect the persistence of any existing ACLs and doesn't prevent new public ACLs from being set.
            :param restrict_public_buckets: Specifies whether Amazon S3 should restrict public bucket policies for this bucket. Setting this element to ``TRUE`` restricts access to this bucket to only AWS service principals and authorized users within this account if the bucket has a public policy. Enabling this setting doesn't affect previously stored bucket policies, except that public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-multiregionaccesspoint-publicaccessblockconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                public_access_block_configuration_property = s3.CfnMultiRegionAccessPoint.PublicAccessBlockConfigurationProperty(
                    block_public_acls=False,
                    block_public_policy=False,
                    ignore_public_acls=False,
                    restrict_public_buckets=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if block_public_acls is not None:
                self._values["block_public_acls"] = block_public_acls
            if block_public_policy is not None:
                self._values["block_public_policy"] = block_public_policy
            if ignore_public_acls is not None:
                self._values["ignore_public_acls"] = ignore_public_acls
            if restrict_public_buckets is not None:
                self._values["restrict_public_buckets"] = restrict_public_buckets

        @builtins.property
        def block_public_acls(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket.

            Setting this element to ``TRUE`` causes the following behavior:

            - PUT Bucket ACL and PUT Object ACL calls fail if the specified ACL is public.
            - PUT Object calls fail if the request includes a public ACL.
            - PUT Bucket calls fail if the request includes a public ACL.

            Enabling this setting doesn't affect existing policies or ACLs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-multiregionaccesspoint-publicaccessblockconfiguration.html#cfn-s3-multiregionaccesspoint-publicaccessblockconfiguration-blockpublicacls
            '''
            result = self._values.get("block_public_acls")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def block_public_policy(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should block public bucket policies for this bucket.

            Setting this element to ``TRUE`` causes Amazon S3 to reject calls to PUT Bucket policy if the specified bucket policy allows public access.

            Enabling this setting doesn't affect existing bucket policies.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-multiregionaccesspoint-publicaccessblockconfiguration.html#cfn-s3-multiregionaccesspoint-publicaccessblockconfiguration-blockpublicpolicy
            '''
            result = self._values.get("block_public_policy")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def ignore_public_acls(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket.

            Setting this element to ``TRUE`` causes Amazon S3 to ignore all public ACLs on this bucket and objects in this bucket.

            Enabling this setting doesn't affect the persistence of any existing ACLs and doesn't prevent new public ACLs from being set.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-multiregionaccesspoint-publicaccessblockconfiguration.html#cfn-s3-multiregionaccesspoint-publicaccessblockconfiguration-ignorepublicacls
            '''
            result = self._values.get("ignore_public_acls")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def restrict_public_buckets(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon S3 should restrict public bucket policies for this bucket.

            Setting this element to ``TRUE`` restricts access to this bucket to only AWS service principals and authorized users within this account if the bucket has a public policy.

            Enabling this setting doesn't affect previously stored bucket policies, except that public and cross-account access within any public bucket policy, including non-public delegation to specific accounts, is blocked.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-multiregionaccesspoint-publicaccessblockconfiguration.html#cfn-s3-multiregionaccesspoint-publicaccessblockconfiguration-restrictpublicbuckets
            '''
            result = self._values.get("restrict_public_buckets")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PublicAccessBlockConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnMultiRegionAccessPoint.RegionProperty",
        jsii_struct_bases=[],
        name_mapping={"bucket": "bucket"},
    )
    class RegionProperty:
        def __init__(self, *, bucket: builtins.str) -> None:
            '''A bucket associated with a specific Region when creating Multi-Region Access Points.

            :param bucket: The name of the associated bucket for the Region.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-multiregionaccesspoint-region.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                region_property = s3.CfnMultiRegionAccessPoint.RegionProperty(
                    bucket="bucket"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket": bucket,
            }

        @builtins.property
        def bucket(self) -> builtins.str:
            '''The name of the associated bucket for the Region.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-multiregionaccesspoint-region.html#cfn-s3-multiregionaccesspoint-region-bucket
            '''
            result = self._values.get("bucket")
            assert result is not None, "Required property 'bucket' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RegionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnMultiRegionAccessPointPolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_s3.CfnMultiRegionAccessPointPolicy",
):
    '''A CloudFormation ``AWS::S3::MultiRegionAccessPointPolicy``.

    Applies an Amazon S3 access policy to an Amazon S3 Multi-Region Access Point.

    It is not possible to delete an access policy for a Multi-Region Access Point from the CloudFormation template. When you attempt to delete the policy, CloudFormation updates the policy using ``DeletionPolicy:Retain`` and ``UpdateReplacePolicy:Retain`` . CloudFormation updates the policy to only allow access to the account that created the bucket.

    :cloudformationResource: AWS::S3::MultiRegionAccessPointPolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspointpolicy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_s3 as s3
        
        # policy: Any
        
        cfn_multi_region_access_point_policy = s3.CfnMultiRegionAccessPointPolicy(self, "MyCfnMultiRegionAccessPointPolicy",
            mrap_name="mrapName",
            policy=policy
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        mrap_name: builtins.str,
        policy: typing.Any,
    ) -> None:
        '''Create a new ``AWS::S3::MultiRegionAccessPointPolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param mrap_name: The name of the Multi-Region Access Point.
        :param policy: The access policy associated with the Multi-Region Access Point.
        '''
        props = CfnMultiRegionAccessPointPolicyProps(
            mrap_name=mrap_name, policy=policy
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
    @jsii.member(jsii_name="mrapName")
    def mrap_name(self) -> builtins.str:
        '''The name of the Multi-Region Access Point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspointpolicy.html#cfn-s3-multiregionaccesspointpolicy-mrapname
        '''
        return typing.cast(builtins.str, jsii.get(self, "mrapName"))

    @mrap_name.setter
    def mrap_name(self, value: builtins.str) -> None:
        jsii.set(self, "mrapName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policy")
    def policy(self) -> typing.Any:
        '''The access policy associated with the Multi-Region Access Point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspointpolicy.html#cfn-s3-multiregionaccesspointpolicy-policy
        '''
        return typing.cast(typing.Any, jsii.get(self, "policy"))

    @policy.setter
    def policy(self, value: typing.Any) -> None:
        jsii.set(self, "policy", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.CfnMultiRegionAccessPointPolicyProps",
    jsii_struct_bases=[],
    name_mapping={"mrap_name": "mrapName", "policy": "policy"},
)
class CfnMultiRegionAccessPointPolicyProps:
    def __init__(self, *, mrap_name: builtins.str, policy: typing.Any) -> None:
        '''Properties for defining a ``CfnMultiRegionAccessPointPolicy``.

        :param mrap_name: The name of the Multi-Region Access Point.
        :param policy: The access policy associated with the Multi-Region Access Point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspointpolicy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            
            # policy: Any
            
            cfn_multi_region_access_point_policy_props = s3.CfnMultiRegionAccessPointPolicyProps(
                mrap_name="mrapName",
                policy=policy
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "mrap_name": mrap_name,
            "policy": policy,
        }

    @builtins.property
    def mrap_name(self) -> builtins.str:
        '''The name of the Multi-Region Access Point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspointpolicy.html#cfn-s3-multiregionaccesspointpolicy-mrapname
        '''
        result = self._values.get("mrap_name")
        assert result is not None, "Required property 'mrap_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def policy(self) -> typing.Any:
        '''The access policy associated with the Multi-Region Access Point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspointpolicy.html#cfn-s3-multiregionaccesspointpolicy-policy
        '''
        result = self._values.get("policy")
        assert result is not None, "Required property 'policy' is missing"
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnMultiRegionAccessPointPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.CfnMultiRegionAccessPointProps",
    jsii_struct_bases=[],
    name_mapping={
        "regions": "regions",
        "name": "name",
        "public_access_block_configuration": "publicAccessBlockConfiguration",
    },
)
class CfnMultiRegionAccessPointProps:
    def __init__(
        self,
        *,
        regions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnMultiRegionAccessPoint.RegionProperty, _IResolvable_da3f097b]]],
        name: typing.Optional[builtins.str] = None,
        public_access_block_configuration: typing.Optional[typing.Union[CfnMultiRegionAccessPoint.PublicAccessBlockConfigurationProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnMultiRegionAccessPoint``.

        :param regions: A collection of the Regions and buckets associated with the Multi-Region Access Point.
        :param name: The name of the Multi-Region Access Point.
        :param public_access_block_configuration: The PublicAccessBlock configuration that you want to apply to this Multi-Region Access Point. You can enable the configuration options in any combination. For more information about when Amazon S3 considers an object public, see `The Meaning of "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspoint.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            
            cfn_multi_region_access_point_props = s3.CfnMultiRegionAccessPointProps(
                regions=[s3.CfnMultiRegionAccessPoint.RegionProperty(
                    bucket="bucket"
                )],
            
                # the properties below are optional
                name="name",
                public_access_block_configuration=s3.CfnMultiRegionAccessPoint.PublicAccessBlockConfigurationProperty(
                    block_public_acls=False,
                    block_public_policy=False,
                    ignore_public_acls=False,
                    restrict_public_buckets=False
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "regions": regions,
        }
        if name is not None:
            self._values["name"] = name
        if public_access_block_configuration is not None:
            self._values["public_access_block_configuration"] = public_access_block_configuration

    @builtins.property
    def regions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnMultiRegionAccessPoint.RegionProperty, _IResolvable_da3f097b]]]:
        '''A collection of the Regions and buckets associated with the Multi-Region Access Point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspoint.html#cfn-s3-multiregionaccesspoint-regions
        '''
        result = self._values.get("regions")
        assert result is not None, "Required property 'regions' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnMultiRegionAccessPoint.RegionProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the Multi-Region Access Point.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspoint.html#cfn-s3-multiregionaccesspoint-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def public_access_block_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnMultiRegionAccessPoint.PublicAccessBlockConfigurationProperty, _IResolvable_da3f097b]]:
        '''The PublicAccessBlock configuration that you want to apply to this Multi-Region Access Point.

        You can enable the configuration options in any combination. For more information about when Amazon S3 considers an object public, see `The Meaning of "Public" <https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status>`_ in the *Amazon S3 User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-multiregionaccesspoint.html#cfn-s3-multiregionaccesspoint-publicaccessblockconfiguration
        '''
        result = self._values.get("public_access_block_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnMultiRegionAccessPoint.PublicAccessBlockConfigurationProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnMultiRegionAccessPointProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnStorageLens(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens",
):
    '''A CloudFormation ``AWS::S3::StorageLens``.

    The AWS::S3::StorageLens resource creates an instance of an Amazon S3 Storage Lens configuration.

    :cloudformationResource: AWS::S3::StorageLens
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-storagelens.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_s3 as s3
        
        # encryption: Any
        
        cfn_storage_lens = s3.CfnStorageLens(self, "MyCfnStorageLens",
            storage_lens_configuration=s3.CfnStorageLens.StorageLensConfigurationProperty(
                account_level=s3.CfnStorageLens.AccountLevelProperty(
                    bucket_level=s3.CfnStorageLens.BucketLevelProperty(
                        activity_metrics=s3.CfnStorageLens.ActivityMetricsProperty(
                            is_enabled=False
                        ),
                        prefix_level=s3.CfnStorageLens.PrefixLevelProperty(
                            storage_metrics=s3.CfnStorageLens.PrefixLevelStorageMetricsProperty(
                                is_enabled=False,
                                selection_criteria=s3.CfnStorageLens.SelectionCriteriaProperty(
                                    delimiter="delimiter",
                                    max_depth=123,
                                    min_storage_bytes_percentage=123
                                )
                            )
                        )
                    ),
        
                    # the properties below are optional
                    activity_metrics=s3.CfnStorageLens.ActivityMetricsProperty(
                        is_enabled=False
                    )
                ),
                id="id",
                is_enabled=False,
        
                # the properties below are optional
                aws_org=s3.CfnStorageLens.AwsOrgProperty(
                    arn="arn"
                ),
                data_export=s3.CfnStorageLens.DataExportProperty(
                    cloud_watch_metrics=s3.CfnStorageLens.CloudWatchMetricsProperty(
                        is_enabled=False
                    ),
                    s3_bucket_destination=s3.CfnStorageLens.S3BucketDestinationProperty(
                        account_id="accountId",
                        arn="arn",
                        format="format",
                        output_schema_version="outputSchemaVersion",
        
                        # the properties below are optional
                        encryption=encryption,
                        prefix="prefix"
                    )
                ),
                exclude=s3.CfnStorageLens.BucketsAndRegionsProperty(
                    buckets=["buckets"],
                    regions=["regions"]
                ),
                include=s3.CfnStorageLens.BucketsAndRegionsProperty(
                    buckets=["buckets"],
                    regions=["regions"]
                ),
                storage_lens_arn="storageLensArn"
            ),
        
            # the properties below are optional
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
        storage_lens_configuration: typing.Union["CfnStorageLens.StorageLensConfigurationProperty", _IResolvable_da3f097b],
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::S3::StorageLens``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param storage_lens_configuration: This resource contains the details Amazon S3 Storage Lens configuration.
        :param tags: A set of tags (key–value pairs) to associate with the Storage Lens configuration.
        '''
        props = CfnStorageLensProps(
            storage_lens_configuration=storage_lens_configuration, tags=tags
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
    @jsii.member(jsii_name="attrStorageLensConfigurationStorageLensArn")
    def attr_storage_lens_configuration_storage_lens_arn(self) -> builtins.str:
        '''This property contains the details of the ARN of the S3 Storage Lens configuration.

        This property is read-only.

        :cloudformationAttribute: StorageLensConfiguration.StorageLensArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrStorageLensConfigurationStorageLensArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A set of tags (key–value pairs) to associate with the Storage Lens configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-storagelens.html#cfn-s3-storagelens-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="storageLensConfiguration")
    def storage_lens_configuration(
        self,
    ) -> typing.Union["CfnStorageLens.StorageLensConfigurationProperty", _IResolvable_da3f097b]:
        '''This resource contains the details Amazon S3 Storage Lens configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-storagelens.html#cfn-s3-storagelens-storagelensconfiguration
        '''
        return typing.cast(typing.Union["CfnStorageLens.StorageLensConfigurationProperty", _IResolvable_da3f097b], jsii.get(self, "storageLensConfiguration"))

    @storage_lens_configuration.setter
    def storage_lens_configuration(
        self,
        value: typing.Union["CfnStorageLens.StorageLensConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "storageLensConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.AccountLevelProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bucket_level": "bucketLevel",
            "activity_metrics": "activityMetrics",
        },
    )
    class AccountLevelProperty:
        def __init__(
            self,
            *,
            bucket_level: typing.Union["CfnStorageLens.BucketLevelProperty", _IResolvable_da3f097b],
            activity_metrics: typing.Optional[typing.Union["CfnStorageLens.ActivityMetricsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''This resource contains the details of the account-level metrics for Amazon S3 Storage Lens.

            :param bucket_level: This property contains the details of the account-level bucket-level configurations for Amazon S3 Storage Lens.
            :param activity_metrics: This property contains the details of the account-level activity metrics for Amazon S3 Storage Lens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-accountlevel.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                account_level_property = s3.CfnStorageLens.AccountLevelProperty(
                    bucket_level=s3.CfnStorageLens.BucketLevelProperty(
                        activity_metrics=s3.CfnStorageLens.ActivityMetricsProperty(
                            is_enabled=False
                        ),
                        prefix_level=s3.CfnStorageLens.PrefixLevelProperty(
                            storage_metrics=s3.CfnStorageLens.PrefixLevelStorageMetricsProperty(
                                is_enabled=False,
                                selection_criteria=s3.CfnStorageLens.SelectionCriteriaProperty(
                                    delimiter="delimiter",
                                    max_depth=123,
                                    min_storage_bytes_percentage=123
                                )
                            )
                        )
                    ),
                
                    # the properties below are optional
                    activity_metrics=s3.CfnStorageLens.ActivityMetricsProperty(
                        is_enabled=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket_level": bucket_level,
            }
            if activity_metrics is not None:
                self._values["activity_metrics"] = activity_metrics

        @builtins.property
        def bucket_level(
            self,
        ) -> typing.Union["CfnStorageLens.BucketLevelProperty", _IResolvable_da3f097b]:
            '''This property contains the details of the account-level bucket-level configurations for Amazon S3 Storage Lens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-accountlevel.html#cfn-s3-storagelens-accountlevel-bucketlevel
            '''
            result = self._values.get("bucket_level")
            assert result is not None, "Required property 'bucket_level' is missing"
            return typing.cast(typing.Union["CfnStorageLens.BucketLevelProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def activity_metrics(
            self,
        ) -> typing.Optional[typing.Union["CfnStorageLens.ActivityMetricsProperty", _IResolvable_da3f097b]]:
            '''This property contains the details of the account-level activity metrics for Amazon S3 Storage Lens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-accountlevel.html#cfn-s3-storagelens-accountlevel-activitymetrics
            '''
            result = self._values.get("activity_metrics")
            return typing.cast(typing.Optional[typing.Union["CfnStorageLens.ActivityMetricsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AccountLevelProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.ActivityMetricsProperty",
        jsii_struct_bases=[],
        name_mapping={"is_enabled": "isEnabled"},
    )
    class ActivityMetricsProperty:
        def __init__(
            self,
            *,
            is_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''This resource contains the details of the activity metrics for Amazon S3 Storage Lens.

            :param is_enabled: A property that indicates whether the activity metrics is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-activitymetrics.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                activity_metrics_property = s3.CfnStorageLens.ActivityMetricsProperty(
                    is_enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if is_enabled is not None:
                self._values["is_enabled"] = is_enabled

        @builtins.property
        def is_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''A property that indicates whether the activity metrics is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-activitymetrics.html#cfn-s3-storagelens-activitymetrics-isenabled
            '''
            result = self._values.get("is_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ActivityMetricsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.AwsOrgProperty",
        jsii_struct_bases=[],
        name_mapping={"arn": "arn"},
    )
    class AwsOrgProperty:
        def __init__(self, *, arn: builtins.str) -> None:
            '''This resource contains the details of the AWS Organization for Amazon S3 Storage Lens.

            :param arn: This resource contains the ARN of the AWS Organization.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-awsorg.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                aws_org_property = s3.CfnStorageLens.AwsOrgProperty(
                    arn="arn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
            }

        @builtins.property
        def arn(self) -> builtins.str:
            '''This resource contains the ARN of the AWS Organization.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-awsorg.html#cfn-s3-storagelens-awsorg-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AwsOrgProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.BucketLevelProperty",
        jsii_struct_bases=[],
        name_mapping={
            "activity_metrics": "activityMetrics",
            "prefix_level": "prefixLevel",
        },
    )
    class BucketLevelProperty:
        def __init__(
            self,
            *,
            activity_metrics: typing.Optional[typing.Union["CfnStorageLens.ActivityMetricsProperty", _IResolvable_da3f097b]] = None,
            prefix_level: typing.Optional[typing.Union["CfnStorageLens.PrefixLevelProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A property for the bucket-level storage metrics for Amazon S3 Storage Lens.

            :param activity_metrics: A property for the bucket-level activity metrics for Amazon S3 Storage Lens.
            :param prefix_level: A property for the bucket-level prefix-level storage metrics for S3 Storage Lens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-bucketlevel.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                bucket_level_property = s3.CfnStorageLens.BucketLevelProperty(
                    activity_metrics=s3.CfnStorageLens.ActivityMetricsProperty(
                        is_enabled=False
                    ),
                    prefix_level=s3.CfnStorageLens.PrefixLevelProperty(
                        storage_metrics=s3.CfnStorageLens.PrefixLevelStorageMetricsProperty(
                            is_enabled=False,
                            selection_criteria=s3.CfnStorageLens.SelectionCriteriaProperty(
                                delimiter="delimiter",
                                max_depth=123,
                                min_storage_bytes_percentage=123
                            )
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if activity_metrics is not None:
                self._values["activity_metrics"] = activity_metrics
            if prefix_level is not None:
                self._values["prefix_level"] = prefix_level

        @builtins.property
        def activity_metrics(
            self,
        ) -> typing.Optional[typing.Union["CfnStorageLens.ActivityMetricsProperty", _IResolvable_da3f097b]]:
            '''A property for the bucket-level activity metrics for Amazon S3 Storage Lens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-bucketlevel.html#cfn-s3-storagelens-bucketlevel-activitymetrics
            '''
            result = self._values.get("activity_metrics")
            return typing.cast(typing.Optional[typing.Union["CfnStorageLens.ActivityMetricsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def prefix_level(
            self,
        ) -> typing.Optional[typing.Union["CfnStorageLens.PrefixLevelProperty", _IResolvable_da3f097b]]:
            '''A property for the bucket-level prefix-level storage metrics for S3 Storage Lens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-bucketlevel.html#cfn-s3-storagelens-bucketlevel-prefixlevel
            '''
            result = self._values.get("prefix_level")
            return typing.cast(typing.Optional[typing.Union["CfnStorageLens.PrefixLevelProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BucketLevelProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.BucketsAndRegionsProperty",
        jsii_struct_bases=[],
        name_mapping={"buckets": "buckets", "regions": "regions"},
    )
    class BucketsAndRegionsProperty:
        def __init__(
            self,
            *,
            buckets: typing.Optional[typing.Sequence[builtins.str]] = None,
            regions: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''This resource contains the details of the buckets and Regions for the Amazon S3 Storage Lens configuration.

            :param buckets: This property contains the details of the buckets for the Amazon S3 Storage Lens configuration. This should be the bucket Amazon Resource Name(ARN). For valid values, see `Buckets ARN format here <https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_Include.html#API_control_Include_Contents>`_ in the *Amazon S3 API Reference* .
            :param regions: This property contains the details of the Regions for the S3 Storage Lens configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-bucketsandregions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                buckets_and_regions_property = s3.CfnStorageLens.BucketsAndRegionsProperty(
                    buckets=["buckets"],
                    regions=["regions"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if buckets is not None:
                self._values["buckets"] = buckets
            if regions is not None:
                self._values["regions"] = regions

        @builtins.property
        def buckets(self) -> typing.Optional[typing.List[builtins.str]]:
            '''This property contains the details of the buckets for the Amazon S3 Storage Lens configuration.

            This should be the bucket Amazon Resource Name(ARN). For valid values, see `Buckets ARN format here <https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_Include.html#API_control_Include_Contents>`_ in the *Amazon S3 API Reference* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-bucketsandregions.html#cfn-s3-storagelens-bucketsandregions-buckets
            '''
            result = self._values.get("buckets")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def regions(self) -> typing.Optional[typing.List[builtins.str]]:
            '''This property contains the details of the Regions for the S3 Storage Lens configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-bucketsandregions.html#cfn-s3-storagelens-bucketsandregions-regions
            '''
            result = self._values.get("regions")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BucketsAndRegionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.CloudWatchMetricsProperty",
        jsii_struct_bases=[],
        name_mapping={"is_enabled": "isEnabled"},
    )
    class CloudWatchMetricsProperty:
        def __init__(
            self,
            *,
            is_enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
        ) -> None:
            '''This resource enables the Amazon CloudWatch publishing option for S3 Storage Lens metrics.

            For more information, see `Monitor S3 Storage Lens metrics in CloudWatch <https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage_lens_view_metrics_cloudwatch.html>`_ in the *Amazon S3 User Guide* .

            :param is_enabled: This property identifies whether the CloudWatch publishing option for S3 Storage Lens is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-cloudwatchmetrics.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                cloud_watch_metrics_property = s3.CfnStorageLens.CloudWatchMetricsProperty(
                    is_enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "is_enabled": is_enabled,
            }

        @builtins.property
        def is_enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''This property identifies whether the CloudWatch publishing option for S3 Storage Lens is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-cloudwatchmetrics.html#cfn-s3-storagelens-cloudwatchmetrics-isenabled
            '''
            result = self._values.get("is_enabled")
            assert result is not None, "Required property 'is_enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CloudWatchMetricsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.DataExportProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cloud_watch_metrics": "cloudWatchMetrics",
            "s3_bucket_destination": "s3BucketDestination",
        },
    )
    class DataExportProperty:
        def __init__(
            self,
            *,
            cloud_watch_metrics: typing.Optional[typing.Union["CfnStorageLens.CloudWatchMetricsProperty", _IResolvable_da3f097b]] = None,
            s3_bucket_destination: typing.Optional[typing.Union["CfnStorageLens.S3BucketDestinationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''This resource contains the details of the Amazon S3 Storage Lens metrics export.

            :param cloud_watch_metrics: This property enables the Amazon CloudWatch publishing option for S3 Storage Lens metrics.
            :param s3_bucket_destination: This property contains the details of the bucket where the S3 Storage Lens metrics export will be placed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-dataexport.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                # encryption: Any
                
                data_export_property = s3.CfnStorageLens.DataExportProperty(
                    cloud_watch_metrics=s3.CfnStorageLens.CloudWatchMetricsProperty(
                        is_enabled=False
                    ),
                    s3_bucket_destination=s3.CfnStorageLens.S3BucketDestinationProperty(
                        account_id="accountId",
                        arn="arn",
                        format="format",
                        output_schema_version="outputSchemaVersion",
                
                        # the properties below are optional
                        encryption=encryption,
                        prefix="prefix"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cloud_watch_metrics is not None:
                self._values["cloud_watch_metrics"] = cloud_watch_metrics
            if s3_bucket_destination is not None:
                self._values["s3_bucket_destination"] = s3_bucket_destination

        @builtins.property
        def cloud_watch_metrics(
            self,
        ) -> typing.Optional[typing.Union["CfnStorageLens.CloudWatchMetricsProperty", _IResolvable_da3f097b]]:
            '''This property enables the Amazon CloudWatch publishing option for S3 Storage Lens metrics.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-dataexport.html#cfn-s3-storagelens-dataexport-cloudwatchmetrics
            '''
            result = self._values.get("cloud_watch_metrics")
            return typing.cast(typing.Optional[typing.Union["CfnStorageLens.CloudWatchMetricsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def s3_bucket_destination(
            self,
        ) -> typing.Optional[typing.Union["CfnStorageLens.S3BucketDestinationProperty", _IResolvable_da3f097b]]:
            '''This property contains the details of the bucket where the S3 Storage Lens metrics export will be placed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-dataexport.html#cfn-s3-storagelens-dataexport-s3bucketdestination
            '''
            result = self._values.get("s3_bucket_destination")
            return typing.cast(typing.Optional[typing.Union["CfnStorageLens.S3BucketDestinationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataExportProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.PrefixLevelProperty",
        jsii_struct_bases=[],
        name_mapping={"storage_metrics": "storageMetrics"},
    )
    class PrefixLevelProperty:
        def __init__(
            self,
            *,
            storage_metrics: typing.Union["CfnStorageLens.PrefixLevelStorageMetricsProperty", _IResolvable_da3f097b],
        ) -> None:
            '''This resource contains the details of the prefix-level of the Amazon S3 Storage Lens.

            :param storage_metrics: A property for the prefix-level storage metrics for Amazon S3 Storage Lens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-prefixlevel.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                prefix_level_property = s3.CfnStorageLens.PrefixLevelProperty(
                    storage_metrics=s3.CfnStorageLens.PrefixLevelStorageMetricsProperty(
                        is_enabled=False,
                        selection_criteria=s3.CfnStorageLens.SelectionCriteriaProperty(
                            delimiter="delimiter",
                            max_depth=123,
                            min_storage_bytes_percentage=123
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "storage_metrics": storage_metrics,
            }

        @builtins.property
        def storage_metrics(
            self,
        ) -> typing.Union["CfnStorageLens.PrefixLevelStorageMetricsProperty", _IResolvable_da3f097b]:
            '''A property for the prefix-level storage metrics for Amazon S3 Storage Lens.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-prefixlevel.html#cfn-s3-storagelens-prefixlevel-storagemetrics
            '''
            result = self._values.get("storage_metrics")
            assert result is not None, "Required property 'storage_metrics' is missing"
            return typing.cast(typing.Union["CfnStorageLens.PrefixLevelStorageMetricsProperty", _IResolvable_da3f097b], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PrefixLevelProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.PrefixLevelStorageMetricsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "is_enabled": "isEnabled",
            "selection_criteria": "selectionCriteria",
        },
    )
    class PrefixLevelStorageMetricsProperty:
        def __init__(
            self,
            *,
            is_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            selection_criteria: typing.Optional[typing.Union["CfnStorageLens.SelectionCriteriaProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''This resource contains the details of the prefix-level storage metrics for Amazon S3 Storage Lens.

            :param is_enabled: This property identifies whether the details of the prefix-level storage metrics for S3 Storage Lens are enabled.
            :param selection_criteria: This property identifies whether the details of the prefix-level storage metrics for S3 Storage Lens are enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-prefixlevelstoragemetrics.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                prefix_level_storage_metrics_property = s3.CfnStorageLens.PrefixLevelStorageMetricsProperty(
                    is_enabled=False,
                    selection_criteria=s3.CfnStorageLens.SelectionCriteriaProperty(
                        delimiter="delimiter",
                        max_depth=123,
                        min_storage_bytes_percentage=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if is_enabled is not None:
                self._values["is_enabled"] = is_enabled
            if selection_criteria is not None:
                self._values["selection_criteria"] = selection_criteria

        @builtins.property
        def is_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''This property identifies whether the details of the prefix-level storage metrics for S3 Storage Lens are enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-prefixlevelstoragemetrics.html#cfn-s3-storagelens-prefixlevelstoragemetrics-isenabled
            '''
            result = self._values.get("is_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def selection_criteria(
            self,
        ) -> typing.Optional[typing.Union["CfnStorageLens.SelectionCriteriaProperty", _IResolvable_da3f097b]]:
            '''This property identifies whether the details of the prefix-level storage metrics for S3 Storage Lens are enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-prefixlevelstoragemetrics.html#cfn-s3-storagelens-prefixlevelstoragemetrics-selectioncriteria
            '''
            result = self._values.get("selection_criteria")
            return typing.cast(typing.Optional[typing.Union["CfnStorageLens.SelectionCriteriaProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PrefixLevelStorageMetricsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.S3BucketDestinationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "account_id": "accountId",
            "arn": "arn",
            "format": "format",
            "output_schema_version": "outputSchemaVersion",
            "encryption": "encryption",
            "prefix": "prefix",
        },
    )
    class S3BucketDestinationProperty:
        def __init__(
            self,
            *,
            account_id: builtins.str,
            arn: builtins.str,
            format: builtins.str,
            output_schema_version: builtins.str,
            encryption: typing.Any = None,
            prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''This resource contains the details of the bucket where the Amazon S3 Storage Lens metrics export will be placed.

            :param account_id: This property contains the details of the AWS account ID of the S3 Storage Lens export bucket destination.
            :param arn: This property contains the details of the ARN of the bucket destination of the S3 Storage Lens export.
            :param format: This property contains the details of the format of the S3 Storage Lens export bucket destination.
            :param output_schema_version: This property contains the details of the output schema version of the S3 Storage Lens export bucket destination.
            :param encryption: This property contains the details of the encryption of the bucket destination of the Amazon S3 Storage Lens metrics export.
            :param prefix: This property contains the details of the prefix of the bucket destination of the S3 Storage Lens export .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-s3bucketdestination.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                # encryption: Any
                
                s3_bucket_destination_property = s3.CfnStorageLens.S3BucketDestinationProperty(
                    account_id="accountId",
                    arn="arn",
                    format="format",
                    output_schema_version="outputSchemaVersion",
                
                    # the properties below are optional
                    encryption=encryption,
                    prefix="prefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "account_id": account_id,
                "arn": arn,
                "format": format,
                "output_schema_version": output_schema_version,
            }
            if encryption is not None:
                self._values["encryption"] = encryption
            if prefix is not None:
                self._values["prefix"] = prefix

        @builtins.property
        def account_id(self) -> builtins.str:
            '''This property contains the details of the AWS account ID of the S3 Storage Lens export bucket destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-s3bucketdestination.html#cfn-s3-storagelens-s3bucketdestination-accountid
            '''
            result = self._values.get("account_id")
            assert result is not None, "Required property 'account_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def arn(self) -> builtins.str:
            '''This property contains the details of the ARN of the bucket destination of the S3 Storage Lens export.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-s3bucketdestination.html#cfn-s3-storagelens-s3bucketdestination-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def format(self) -> builtins.str:
            '''This property contains the details of the format of the S3 Storage Lens export bucket destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-s3bucketdestination.html#cfn-s3-storagelens-s3bucketdestination-format
            '''
            result = self._values.get("format")
            assert result is not None, "Required property 'format' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def output_schema_version(self) -> builtins.str:
            '''This property contains the details of the output schema version of the S3 Storage Lens export bucket destination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-s3bucketdestination.html#cfn-s3-storagelens-s3bucketdestination-outputschemaversion
            '''
            result = self._values.get("output_schema_version")
            assert result is not None, "Required property 'output_schema_version' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def encryption(self) -> typing.Any:
            '''This property contains the details of the encryption of the bucket destination of the Amazon S3 Storage Lens metrics export.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-s3bucketdestination.html#cfn-s3-storagelens-s3bucketdestination-encryption
            '''
            result = self._values.get("encryption")
            return typing.cast(typing.Any, result)

        @builtins.property
        def prefix(self) -> typing.Optional[builtins.str]:
            '''This property contains the details of the prefix of the bucket destination of the S3 Storage Lens export .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-s3bucketdestination.html#cfn-s3-storagelens-s3bucketdestination-prefix
            '''
            result = self._values.get("prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3BucketDestinationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.SelectionCriteriaProperty",
        jsii_struct_bases=[],
        name_mapping={
            "delimiter": "delimiter",
            "max_depth": "maxDepth",
            "min_storage_bytes_percentage": "minStorageBytesPercentage",
        },
    )
    class SelectionCriteriaProperty:
        def __init__(
            self,
            *,
            delimiter: typing.Optional[builtins.str] = None,
            max_depth: typing.Optional[jsii.Number] = None,
            min_storage_bytes_percentage: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''This resource contains the details of the Amazon S3 Storage Lens selection criteria.

            :param delimiter: This property contains the details of the S3 Storage Lens delimiter being used.
            :param max_depth: This property contains the details of the max depth that S3 Storage Lens will collect metrics up to.
            :param min_storage_bytes_percentage: This property contains the details of the minimum storage bytes percentage threshold that S3 Storage Lens will collect metrics up to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-selectioncriteria.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                selection_criteria_property = s3.CfnStorageLens.SelectionCriteriaProperty(
                    delimiter="delimiter",
                    max_depth=123,
                    min_storage_bytes_percentage=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if delimiter is not None:
                self._values["delimiter"] = delimiter
            if max_depth is not None:
                self._values["max_depth"] = max_depth
            if min_storage_bytes_percentage is not None:
                self._values["min_storage_bytes_percentage"] = min_storage_bytes_percentage

        @builtins.property
        def delimiter(self) -> typing.Optional[builtins.str]:
            '''This property contains the details of the S3 Storage Lens delimiter being used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-selectioncriteria.html#cfn-s3-storagelens-selectioncriteria-delimiter
            '''
            result = self._values.get("delimiter")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def max_depth(self) -> typing.Optional[jsii.Number]:
            '''This property contains the details of the max depth that S3 Storage Lens will collect metrics up to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-selectioncriteria.html#cfn-s3-storagelens-selectioncriteria-maxdepth
            '''
            result = self._values.get("max_depth")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min_storage_bytes_percentage(self) -> typing.Optional[jsii.Number]:
            '''This property contains the details of the minimum storage bytes percentage threshold that S3 Storage Lens will collect metrics up to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-selectioncriteria.html#cfn-s3-storagelens-selectioncriteria-minstoragebytespercentage
            '''
            result = self._values.get("min_storage_bytes_percentage")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SelectionCriteriaProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_s3.CfnStorageLens.StorageLensConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "account_level": "accountLevel",
            "id": "id",
            "is_enabled": "isEnabled",
            "aws_org": "awsOrg",
            "data_export": "dataExport",
            "exclude": "exclude",
            "include": "include",
            "storage_lens_arn": "storageLensArn",
        },
    )
    class StorageLensConfigurationProperty:
        def __init__(
            self,
            *,
            account_level: typing.Union["CfnStorageLens.AccountLevelProperty", _IResolvable_da3f097b],
            id: builtins.str,
            is_enabled: typing.Union[builtins.bool, _IResolvable_da3f097b],
            aws_org: typing.Optional[typing.Union["CfnStorageLens.AwsOrgProperty", _IResolvable_da3f097b]] = None,
            data_export: typing.Optional[typing.Union["CfnStorageLens.DataExportProperty", _IResolvable_da3f097b]] = None,
            exclude: typing.Optional[typing.Union["CfnStorageLens.BucketsAndRegionsProperty", _IResolvable_da3f097b]] = None,
            include: typing.Optional[typing.Union["CfnStorageLens.BucketsAndRegionsProperty", _IResolvable_da3f097b]] = None,
            storage_lens_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''This is the property of the Amazon S3 Storage Lens configuration.

            :param account_level: This property contains the details of the account-level metrics for Amazon S3 Storage Lens configuration.
            :param id: This property contains the details of the ID of the S3 Storage Lens configuration.
            :param is_enabled: This property contains the details of whether the Amazon S3 Storage Lens configuration is enabled.
            :param aws_org: This property contains the details of the AWS Organization for the S3 Storage Lens configuration.
            :param data_export: This property contains the details of this S3 Storage Lens configuration's metrics export.
            :param exclude: This property contains the details of the bucket and or Regions excluded for Amazon S3 Storage Lens configuration.
            :param include: This property contains the details of the bucket and or Regions included for Amazon S3 Storage Lens configuration.
            :param storage_lens_arn: This property contains the details of the ARN of the S3 Storage Lens configuration. This property is read-only.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-storagelensconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_s3 as s3
                
                # encryption: Any
                
                storage_lens_configuration_property = s3.CfnStorageLens.StorageLensConfigurationProperty(
                    account_level=s3.CfnStorageLens.AccountLevelProperty(
                        bucket_level=s3.CfnStorageLens.BucketLevelProperty(
                            activity_metrics=s3.CfnStorageLens.ActivityMetricsProperty(
                                is_enabled=False
                            ),
                            prefix_level=s3.CfnStorageLens.PrefixLevelProperty(
                                storage_metrics=s3.CfnStorageLens.PrefixLevelStorageMetricsProperty(
                                    is_enabled=False,
                                    selection_criteria=s3.CfnStorageLens.SelectionCriteriaProperty(
                                        delimiter="delimiter",
                                        max_depth=123,
                                        min_storage_bytes_percentage=123
                                    )
                                )
                            )
                        ),
                
                        # the properties below are optional
                        activity_metrics=s3.CfnStorageLens.ActivityMetricsProperty(
                            is_enabled=False
                        )
                    ),
                    id="id",
                    is_enabled=False,
                
                    # the properties below are optional
                    aws_org=s3.CfnStorageLens.AwsOrgProperty(
                        arn="arn"
                    ),
                    data_export=s3.CfnStorageLens.DataExportProperty(
                        cloud_watch_metrics=s3.CfnStorageLens.CloudWatchMetricsProperty(
                            is_enabled=False
                        ),
                        s3_bucket_destination=s3.CfnStorageLens.S3BucketDestinationProperty(
                            account_id="accountId",
                            arn="arn",
                            format="format",
                            output_schema_version="outputSchemaVersion",
                
                            # the properties below are optional
                            encryption=encryption,
                            prefix="prefix"
                        )
                    ),
                    exclude=s3.CfnStorageLens.BucketsAndRegionsProperty(
                        buckets=["buckets"],
                        regions=["regions"]
                    ),
                    include=s3.CfnStorageLens.BucketsAndRegionsProperty(
                        buckets=["buckets"],
                        regions=["regions"]
                    ),
                    storage_lens_arn="storageLensArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "account_level": account_level,
                "id": id,
                "is_enabled": is_enabled,
            }
            if aws_org is not None:
                self._values["aws_org"] = aws_org
            if data_export is not None:
                self._values["data_export"] = data_export
            if exclude is not None:
                self._values["exclude"] = exclude
            if include is not None:
                self._values["include"] = include
            if storage_lens_arn is not None:
                self._values["storage_lens_arn"] = storage_lens_arn

        @builtins.property
        def account_level(
            self,
        ) -> typing.Union["CfnStorageLens.AccountLevelProperty", _IResolvable_da3f097b]:
            '''This property contains the details of the account-level metrics for Amazon S3 Storage Lens configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-storagelensconfiguration.html#cfn-s3-storagelens-storagelensconfiguration-accountlevel
            '''
            result = self._values.get("account_level")
            assert result is not None, "Required property 'account_level' is missing"
            return typing.cast(typing.Union["CfnStorageLens.AccountLevelProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def id(self) -> builtins.str:
            '''This property contains the details of the ID of the S3 Storage Lens configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-storagelensconfiguration.html#cfn-s3-storagelens-storagelensconfiguration-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def is_enabled(self) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''This property contains the details of whether the Amazon S3 Storage Lens configuration is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-storagelensconfiguration.html#cfn-s3-storagelens-storagelensconfiguration-isenabled
            '''
            result = self._values.get("is_enabled")
            assert result is not None, "Required property 'is_enabled' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def aws_org(
            self,
        ) -> typing.Optional[typing.Union["CfnStorageLens.AwsOrgProperty", _IResolvable_da3f097b]]:
            '''This property contains the details of the AWS Organization for the S3 Storage Lens configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-storagelensconfiguration.html#cfn-s3-storagelens-storagelensconfiguration-awsorg
            '''
            result = self._values.get("aws_org")
            return typing.cast(typing.Optional[typing.Union["CfnStorageLens.AwsOrgProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def data_export(
            self,
        ) -> typing.Optional[typing.Union["CfnStorageLens.DataExportProperty", _IResolvable_da3f097b]]:
            '''This property contains the details of this S3 Storage Lens configuration's metrics export.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-storagelensconfiguration.html#cfn-s3-storagelens-storagelensconfiguration-dataexport
            '''
            result = self._values.get("data_export")
            return typing.cast(typing.Optional[typing.Union["CfnStorageLens.DataExportProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def exclude(
            self,
        ) -> typing.Optional[typing.Union["CfnStorageLens.BucketsAndRegionsProperty", _IResolvable_da3f097b]]:
            '''This property contains the details of the bucket and or Regions excluded for Amazon S3 Storage Lens configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-storagelensconfiguration.html#cfn-s3-storagelens-storagelensconfiguration-exclude
            '''
            result = self._values.get("exclude")
            return typing.cast(typing.Optional[typing.Union["CfnStorageLens.BucketsAndRegionsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def include(
            self,
        ) -> typing.Optional[typing.Union["CfnStorageLens.BucketsAndRegionsProperty", _IResolvable_da3f097b]]:
            '''This property contains the details of the bucket and or Regions included for Amazon S3 Storage Lens configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-storagelensconfiguration.html#cfn-s3-storagelens-storagelensconfiguration-include
            '''
            result = self._values.get("include")
            return typing.cast(typing.Optional[typing.Union["CfnStorageLens.BucketsAndRegionsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def storage_lens_arn(self) -> typing.Optional[builtins.str]:
            '''This property contains the details of the ARN of the S3 Storage Lens configuration.

            This property is read-only.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-storagelens-storagelensconfiguration.html#cfn-s3-storagelens-storagelensconfiguration-storagelensarn
            '''
            result = self._values.get("storage_lens_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StorageLensConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.CfnStorageLensProps",
    jsii_struct_bases=[],
    name_mapping={
        "storage_lens_configuration": "storageLensConfiguration",
        "tags": "tags",
    },
)
class CfnStorageLensProps:
    def __init__(
        self,
        *,
        storage_lens_configuration: typing.Union[CfnStorageLens.StorageLensConfigurationProperty, _IResolvable_da3f097b],
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnStorageLens``.

        :param storage_lens_configuration: This resource contains the details Amazon S3 Storage Lens configuration.
        :param tags: A set of tags (key–value pairs) to associate with the Storage Lens configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-storagelens.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            
            # encryption: Any
            
            cfn_storage_lens_props = s3.CfnStorageLensProps(
                storage_lens_configuration=s3.CfnStorageLens.StorageLensConfigurationProperty(
                    account_level=s3.CfnStorageLens.AccountLevelProperty(
                        bucket_level=s3.CfnStorageLens.BucketLevelProperty(
                            activity_metrics=s3.CfnStorageLens.ActivityMetricsProperty(
                                is_enabled=False
                            ),
                            prefix_level=s3.CfnStorageLens.PrefixLevelProperty(
                                storage_metrics=s3.CfnStorageLens.PrefixLevelStorageMetricsProperty(
                                    is_enabled=False,
                                    selection_criteria=s3.CfnStorageLens.SelectionCriteriaProperty(
                                        delimiter="delimiter",
                                        max_depth=123,
                                        min_storage_bytes_percentage=123
                                    )
                                )
                            )
                        ),
            
                        # the properties below are optional
                        activity_metrics=s3.CfnStorageLens.ActivityMetricsProperty(
                            is_enabled=False
                        )
                    ),
                    id="id",
                    is_enabled=False,
            
                    # the properties below are optional
                    aws_org=s3.CfnStorageLens.AwsOrgProperty(
                        arn="arn"
                    ),
                    data_export=s3.CfnStorageLens.DataExportProperty(
                        cloud_watch_metrics=s3.CfnStorageLens.CloudWatchMetricsProperty(
                            is_enabled=False
                        ),
                        s3_bucket_destination=s3.CfnStorageLens.S3BucketDestinationProperty(
                            account_id="accountId",
                            arn="arn",
                            format="format",
                            output_schema_version="outputSchemaVersion",
            
                            # the properties below are optional
                            encryption=encryption,
                            prefix="prefix"
                        )
                    ),
                    exclude=s3.CfnStorageLens.BucketsAndRegionsProperty(
                        buckets=["buckets"],
                        regions=["regions"]
                    ),
                    include=s3.CfnStorageLens.BucketsAndRegionsProperty(
                        buckets=["buckets"],
                        regions=["regions"]
                    ),
                    storage_lens_arn="storageLensArn"
                ),
            
                # the properties below are optional
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "storage_lens_configuration": storage_lens_configuration,
        }
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def storage_lens_configuration(
        self,
    ) -> typing.Union[CfnStorageLens.StorageLensConfigurationProperty, _IResolvable_da3f097b]:
        '''This resource contains the details Amazon S3 Storage Lens configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-storagelens.html#cfn-s3-storagelens-storagelensconfiguration
        '''
        result = self._values.get("storage_lens_configuration")
        assert result is not None, "Required property 'storage_lens_configuration' is missing"
        return typing.cast(typing.Union[CfnStorageLens.StorageLensConfigurationProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A set of tags (key–value pairs) to associate with the Storage Lens configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-s3-storagelens.html#cfn-s3-storagelens-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnStorageLensProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.CorsRule",
    jsii_struct_bases=[],
    name_mapping={
        "allowed_methods": "allowedMethods",
        "allowed_origins": "allowedOrigins",
        "allowed_headers": "allowedHeaders",
        "exposed_headers": "exposedHeaders",
        "id": "id",
        "max_age": "maxAge",
    },
)
class CorsRule:
    def __init__(
        self,
        *,
        allowed_methods: typing.Sequence["HttpMethods"],
        allowed_origins: typing.Sequence[builtins.str],
        allowed_headers: typing.Optional[typing.Sequence[builtins.str]] = None,
        exposed_headers: typing.Optional[typing.Sequence[builtins.str]] = None,
        id: typing.Optional[builtins.str] = None,
        max_age: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Specifies a cross-origin access rule for an Amazon S3 bucket.

        :param allowed_methods: An HTTP method that you allow the origin to execute.
        :param allowed_origins: One or more origins you want customers to be able to access the bucket from.
        :param allowed_headers: Headers that are specified in the Access-Control-Request-Headers header. Default: - No headers allowed.
        :param exposed_headers: One or more headers in the response that you want customers to be able to access from their applications. Default: - No headers exposed.
        :param id: A unique identifier for this rule. Default: - No id specified.
        :param max_age: The time in seconds that your browser is to cache the preflight response for the specified resource. Default: - No caching.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            
            cors_rule = s3.CorsRule(
                allowed_methods=[s3.HttpMethods.GET],
                allowed_origins=["allowedOrigins"],
            
                # the properties below are optional
                allowed_headers=["allowedHeaders"],
                exposed_headers=["exposedHeaders"],
                id="id",
                max_age=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "allowed_methods": allowed_methods,
            "allowed_origins": allowed_origins,
        }
        if allowed_headers is not None:
            self._values["allowed_headers"] = allowed_headers
        if exposed_headers is not None:
            self._values["exposed_headers"] = exposed_headers
        if id is not None:
            self._values["id"] = id
        if max_age is not None:
            self._values["max_age"] = max_age

    @builtins.property
    def allowed_methods(self) -> typing.List["HttpMethods"]:
        '''An HTTP method that you allow the origin to execute.'''
        result = self._values.get("allowed_methods")
        assert result is not None, "Required property 'allowed_methods' is missing"
        return typing.cast(typing.List["HttpMethods"], result)

    @builtins.property
    def allowed_origins(self) -> typing.List[builtins.str]:
        '''One or more origins you want customers to be able to access the bucket from.'''
        result = self._values.get("allowed_origins")
        assert result is not None, "Required property 'allowed_origins' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def allowed_headers(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Headers that are specified in the Access-Control-Request-Headers header.

        :default: - No headers allowed.
        '''
        result = self._values.get("allowed_headers")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def exposed_headers(self) -> typing.Optional[typing.List[builtins.str]]:
        '''One or more headers in the response that you want customers to be able to access from their applications.

        :default: - No headers exposed.
        '''
        result = self._values.get("exposed_headers")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def id(self) -> typing.Optional[builtins.str]:
        '''A unique identifier for this rule.

        :default: - No id specified.
        '''
        result = self._values.get("id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def max_age(self) -> typing.Optional[jsii.Number]:
        '''The time in seconds that your browser is to cache the preflight response for the specified resource.

        :default: - No caching.
        '''
        result = self._values.get("max_age")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CorsRule(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_s3.EventType")
class EventType(enum.Enum):
    '''Notification event types.

    :exampleMetadata: infused
    :link: https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html#supported-notification-event-types

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        # my_queue: sqs.Queue
        
        bucket = s3.Bucket(self, "MyBucket")
        bucket.add_event_notification(s3.EventType.OBJECT_REMOVED,
            s3n.SqsDestination(my_queue), prefix="foo/", suffix=".jpg")
    '''

    OBJECT_CREATED = "OBJECT_CREATED"
    '''Amazon S3 APIs such as PUT, POST, and COPY can create an object.

    Using
    these event types, you can enable notification when an object is created
    using a specific API, or you can use the s3:ObjectCreated:* event type to
    request notification regardless of the API that was used to create an
    object.
    '''
    OBJECT_CREATED_PUT = "OBJECT_CREATED_PUT"
    '''Amazon S3 APIs such as PUT, POST, and COPY can create an object.

    Using
    these event types, you can enable notification when an object is created
    using a specific API, or you can use the s3:ObjectCreated:* event type to
    request notification regardless of the API that was used to create an
    object.
    '''
    OBJECT_CREATED_POST = "OBJECT_CREATED_POST"
    '''Amazon S3 APIs such as PUT, POST, and COPY can create an object.

    Using
    these event types, you can enable notification when an object is created
    using a specific API, or you can use the s3:ObjectCreated:* event type to
    request notification regardless of the API that was used to create an
    object.
    '''
    OBJECT_CREATED_COPY = "OBJECT_CREATED_COPY"
    '''Amazon S3 APIs such as PUT, POST, and COPY can create an object.

    Using
    these event types, you can enable notification when an object is created
    using a specific API, or you can use the s3:ObjectCreated:* event type to
    request notification regardless of the API that was used to create an
    object.
    '''
    OBJECT_CREATED_COMPLETE_MULTIPART_UPLOAD = "OBJECT_CREATED_COMPLETE_MULTIPART_UPLOAD"
    '''Amazon S3 APIs such as PUT, POST, and COPY can create an object.

    Using
    these event types, you can enable notification when an object is created
    using a specific API, or you can use the s3:ObjectCreated:* event type to
    request notification regardless of the API that was used to create an
    object.
    '''
    OBJECT_REMOVED = "OBJECT_REMOVED"
    '''By using the ObjectRemoved event types, you can enable notification when an object or a batch of objects is removed from a bucket.

    You can request notification when an object is deleted or a versioned
    object is permanently deleted by using the s3:ObjectRemoved:Delete event
    type. Or you can request notification when a delete marker is created for
    a versioned object by using s3:ObjectRemoved:DeleteMarkerCreated. For
    information about deleting versioned objects, see Deleting Object
    Versions. You can also use a wildcard s3:ObjectRemoved:* to request
    notification anytime an object is deleted.

    You will not receive event notifications from automatic deletes from
    lifecycle policies or from failed operations.
    '''
    OBJECT_REMOVED_DELETE = "OBJECT_REMOVED_DELETE"
    '''By using the ObjectRemoved event types, you can enable notification when an object or a batch of objects is removed from a bucket.

    You can request notification when an object is deleted or a versioned
    object is permanently deleted by using the s3:ObjectRemoved:Delete event
    type. Or you can request notification when a delete marker is created for
    a versioned object by using s3:ObjectRemoved:DeleteMarkerCreated. For
    information about deleting versioned objects, see Deleting Object
    Versions. You can also use a wildcard s3:ObjectRemoved:* to request
    notification anytime an object is deleted.

    You will not receive event notifications from automatic deletes from
    lifecycle policies or from failed operations.
    '''
    OBJECT_REMOVED_DELETE_MARKER_CREATED = "OBJECT_REMOVED_DELETE_MARKER_CREATED"
    '''By using the ObjectRemoved event types, you can enable notification when an object or a batch of objects is removed from a bucket.

    You can request notification when an object is deleted or a versioned
    object is permanently deleted by using the s3:ObjectRemoved:Delete event
    type. Or you can request notification when a delete marker is created for
    a versioned object by using s3:ObjectRemoved:DeleteMarkerCreated. For
    information about deleting versioned objects, see Deleting Object
    Versions. You can also use a wildcard s3:ObjectRemoved:* to request
    notification anytime an object is deleted.

    You will not receive event notifications from automatic deletes from
    lifecycle policies or from failed operations.
    '''
    OBJECT_RESTORE_POST = "OBJECT_RESTORE_POST"
    '''Using restore object event types you can receive notifications for initiation and completion when restoring objects from the S3 Glacier storage class.

    You use s3:ObjectRestore:Post to request notification of object restoration
    initiation.
    '''
    OBJECT_RESTORE_COMPLETED = "OBJECT_RESTORE_COMPLETED"
    '''Using restore object event types you can receive notifications for initiation and completion when restoring objects from the S3 Glacier storage class.

    You use s3:ObjectRestore:Completed to request notification of
    restoration completion.
    '''
    REDUCED_REDUNDANCY_LOST_OBJECT = "REDUCED_REDUNDANCY_LOST_OBJECT"
    '''You can use this event type to request Amazon S3 to send a notification message when Amazon S3 detects that an object of the RRS storage class is lost.'''
    REPLICATION_OPERATION_FAILED_REPLICATION = "REPLICATION_OPERATION_FAILED_REPLICATION"
    '''You receive this notification event when an object that was eligible for replication using Amazon S3 Replication Time Control failed to replicate.'''
    REPLICATION_OPERATION_MISSED_THRESHOLD = "REPLICATION_OPERATION_MISSED_THRESHOLD"
    '''You receive this notification event when an object that was eligible for replication using Amazon S3 Replication Time Control exceeded the 15-minute threshold for replication.'''
    REPLICATION_OPERATION_REPLICATED_AFTER_THRESHOLD = "REPLICATION_OPERATION_REPLICATED_AFTER_THRESHOLD"
    '''You receive this notification event for an object that was eligible for replication using the Amazon S3 Replication Time Control feature replicated after the 15-minute threshold.'''
    REPLICATION_OPERATION_NOT_TRACKED = "REPLICATION_OPERATION_NOT_TRACKED"
    '''You receive this notification event for an object that was eligible for replication using Amazon S3 Replication Time Control but is no longer tracked by replication metrics.'''
    LIFECYCLE_EXPIRATION = "LIFECYCLE_EXPIRATION"
    '''By using the LifecycleExpiration event types, you can receive a notification when Amazon S3 deletes an object based on your S3 Lifecycle configuration.'''
    LIFECYCLE_EXPIRATION_DELETE = "LIFECYCLE_EXPIRATION_DELETE"
    '''The s3:LifecycleExpiration:Delete event type notifies you when an object in an unversioned bucket is deleted.

    It also notifies you when an object version is permanently deleted by an
    S3 Lifecycle configuration.
    '''
    LIFECYCLE_EXPIRATION_DELETE_MARKER_CREATED = "LIFECYCLE_EXPIRATION_DELETE_MARKER_CREATED"
    '''The s3:LifecycleExpiration:DeleteMarkerCreated event type notifies you when S3 Lifecycle creates a delete marker when a current version of an object in versioned bucket is deleted.'''
    LIFECYCLE_TRANSITION = "LIFECYCLE_TRANSITION"
    '''You receive this notification event when an object is transitioned to another Amazon S3 storage class by an S3 Lifecycle configuration.'''
    INTELLIGENT_TIERING = "INTELLIGENT_TIERING"
    '''You receive this notification event when an object within the S3 Intelligent-Tiering storage class moved to the Archive Access tier or Deep Archive Access tier.'''
    OBJECT_TAGGING = "OBJECT_TAGGING"
    '''By using the ObjectTagging event types, you can enable notification when an object tag is added or deleted from an object.'''
    OBJECT_TAGGING_PUT = "OBJECT_TAGGING_PUT"
    '''The s3:ObjectTagging:Put event type notifies you when a tag is PUT on an object or an existing tag is updated.'''
    OBJECT_TAGGING_DELETE = "OBJECT_TAGGING_DELETE"
    '''The s3:ObjectTagging:Delete event type notifies you when a tag is removed from an object.'''
    OBJECT_ACL_PUT = "OBJECT_ACL_PUT"
    '''You receive this notification event when an ACL is PUT on an object or when an existing ACL is changed.

    An event is not generated when a request results in no change to an
    object’s ACL.
    '''


@jsii.enum(jsii_type="aws-cdk-lib.aws_s3.HttpMethods")
class HttpMethods(enum.Enum):
    '''All http request methods.'''

    GET = "GET"
    '''The GET method requests a representation of the specified resource.'''
    PUT = "PUT"
    '''The PUT method replaces all current representations of the target resource with the request payload.'''
    HEAD = "HEAD"
    '''The HEAD method asks for a response identical to that of a GET request, but without the response body.'''
    POST = "POST"
    '''The POST method is used to submit an entity to the specified resource, often causing a change in state or side effects on the server.'''
    DELETE = "DELETE"
    '''The DELETE method deletes the specified resource.'''


@jsii.interface(jsii_type="aws-cdk-lib.aws_s3.IBucket")
class IBucket(_IResource_c80c4260, typing_extensions.Protocol):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketArn")
    def bucket_arn(self) -> builtins.str:
        '''The ARN of the bucket.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketDomainName")
    def bucket_domain_name(self) -> builtins.str:
        '''The IPv4 DNS name of the specified bucket.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketDualStackDomainName")
    def bucket_dual_stack_domain_name(self) -> builtins.str:
        '''The IPv6 DNS name of the specified bucket.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketName")
    def bucket_name(self) -> builtins.str:
        '''The name of the bucket.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketRegionalDomainName")
    def bucket_regional_domain_name(self) -> builtins.str:
        '''The regional domain name of the specified bucket.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketWebsiteDomainName")
    def bucket_website_domain_name(self) -> builtins.str:
        '''The Domain name of the static website.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketWebsiteUrl")
    def bucket_website_url(self) -> builtins.str:
        '''The URL of the static website.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionKey")
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''Optional KMS encryption key associated with this bucket.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isWebsite")
    def is_website(self) -> typing.Optional[builtins.bool]:
        '''If this bucket has been configured for static website hosting.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policy")
    def policy(self) -> typing.Optional[BucketPolicy]:
        '''The resource policy associated with this bucket.

        If ``autoCreatePolicy`` is true, a ``BucketPolicy`` will be created upon the
        first call to addToResourcePolicy(s).
        '''
        ...

    @policy.setter
    def policy(self, value: typing.Optional[BucketPolicy]) -> None:
        ...

    @jsii.member(jsii_name="addEventNotification")
    def add_event_notification(
        self,
        event: EventType,
        dest: "IBucketNotificationDestination",
        *filters: "NotificationKeyFilter",
    ) -> None:
        '''Adds a bucket notification event destination.

        :param event: The event to trigger the notification.
        :param dest: The notification destination (Lambda, SNS Topic or SQS Queue).
        :param filters: S3 object key filter rules to determine which objects trigger this event. Each filter must include a ``prefix`` and/or ``suffix`` that will be matched against the s3 object key. Refer to the S3 Developer Guide for details about allowed filter rules.

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            # my_lambda: lambda.Function
            
            bucket = s3.Bucket(self, "MyBucket")
            bucket.add_event_notification(s3.EventType.OBJECT_CREATED, s3n.LambdaDestination(my_lambda), prefix="home/myusername/*")
        '''
        ...

    @jsii.member(jsii_name="addObjectCreatedNotification")
    def add_object_created_notification(
        self,
        dest: "IBucketNotificationDestination",
        *filters: "NotificationKeyFilter",
    ) -> None:
        '''Subscribes a destination to receive notifications when an object is created in the bucket.

        This is identical to calling
        ``onEvent(s3.EventType.OBJECT_CREATED)``.

        :param dest: The notification destination (see onEvent).
        :param filters: Filters (see onEvent).
        '''
        ...

    @jsii.member(jsii_name="addObjectRemovedNotification")
    def add_object_removed_notification(
        self,
        dest: "IBucketNotificationDestination",
        *filters: "NotificationKeyFilter",
    ) -> None:
        '''Subscribes a destination to receive notifications when an object is removed from the bucket.

        This is identical to calling
        ``onEvent(EventType.OBJECT_REMOVED)``.

        :param dest: The notification destination (see onEvent).
        :param filters: Filters (see onEvent).
        '''
        ...

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        permission: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Adds a statement to the resource policy for a principal (i.e. account/role/service) to perform actions on this bucket and/or its contents. Use ``bucketArn`` and ``arnForObjects(keys)`` to obtain ARNs for this bucket or objects.

        Note that the policy statement may or may not be added to the policy.
        For example, when an ``IBucket`` is created from an existing bucket,
        it's not possible to tell whether the bucket already has a policy
        attached, let alone to re-use that policy to add more statements to it.
        So it's safest to do nothing in these cases.

        :param permission: the policy statement to be added to the bucket's policy.

        :return:

        metadata about the execution of this method. If the policy
        was not added, the value of ``statementAdded`` will be ``false``. You
        should always check this value to make sure that the operation was
        actually carried out. Otherwise, synthesis and deploy will terminate
        silently, which may be confusing.
        '''
        ...

    @jsii.member(jsii_name="arnForObjects")
    def arn_for_objects(self, key_pattern: builtins.str) -> builtins.str:
        '''Returns an ARN that represents all objects within the bucket that match the key pattern specified.

        To represent all keys, specify ``"*"``.

        :param key_pattern: -
        '''
        ...

    @jsii.member(jsii_name="grantDelete")
    def grant_delete(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grants s3:DeleteObject* permission to an IAM principal for objects in this bucket.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        ...

    @jsii.member(jsii_name="grantPublicAccess")
    def grant_public_access(
        self,
        key_prefix: typing.Optional[builtins.str] = None,
        *allowed_actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Allows unrestricted access to objects from this bucket.

        IMPORTANT: This permission allows anyone to perform actions on S3 objects
        in this bucket, which is useful for when you configure your bucket as a
        website and want everyone to be able to read objects in the bucket without
        needing to authenticate.

        Without arguments, this method will grant read ("s3:GetObject") access to
        all objects ("*") in the bucket.

        The method returns the ``iam.Grant`` object, which can then be modified
        as needed. For example, you can add a condition that will restrict access only
        to an IPv4 range like this::

            const grant = bucket.grantPublicAccess();
            grant.resourceStatement!.addCondition(‘IpAddress’, { “aws:SourceIp”: “54.240.143.0/24” });

        :param key_prefix: the prefix of S3 object keys (e.g. ``home/*``). Default is "*".
        :param allowed_actions: the set of S3 actions to allow. Default is "s3:GetObject".

        :return: The ``iam.PolicyStatement`` object, which can be used to apply e.g. conditions.
        '''
        ...

    @jsii.member(jsii_name="grantPut")
    def grant_put(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grants s3:PutObject* and s3:Abort* permissions for this bucket to an IAM principal.

        If encryption is used, permission to use the key to encrypt the contents
        of written files will also be granted to the same principal.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        ...

    @jsii.member(jsii_name="grantPutAcl")
    def grant_put_acl(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Optional[builtins.str] = None,
    ) -> _Grant_a7ae64f8:
        '''Grant the given IAM identity permissions to modify the ACLs of objects in the given Bucket.

        If your application has the '@aws-cdk/aws-s3:grantWriteWithoutAcl' feature flag set,
        calling {@link grantWrite} or {@link grantReadWrite} no longer grants permissions to modify the ACLs of the objects;
        in this case, if you need to modify object ACLs, call this method explicitly.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        ...

    @jsii.member(jsii_name="grantRead")
    def grant_read(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grant read permissions for this bucket and it's contents to an IAM principal (Role/Group/User).

        If encryption is used, permission to use the key to decrypt the contents
        of the bucket will also be granted to the same principal.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        ...

    @jsii.member(jsii_name="grantReadWrite")
    def grant_read_write(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grants read/write permissions for this bucket and it's contents to an IAM principal (Role/Group/User).

        If an encryption key is used, permission to use the key for
        encrypt/decrypt will also be granted.

        Before CDK version 1.85.0, this method granted the ``s3:PutObject*`` permission that included ``s3:PutObjectAcl``,
        which could be used to grant read/write object access to IAM principals in other accounts.
        If you want to get rid of that behavior, update your CDK version to 1.85.0 or later,
        and make sure the ``@aws-cdk/aws-s3:grantWriteWithoutAcl`` feature flag is set to ``true``
        in the ``context`` key of your cdk.json file.
        If you've already updated, but still need the principal to have permissions to modify the ACLs,
        use the {@link grantPutAcl} method.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        ...

    @jsii.member(jsii_name="grantWrite")
    def grant_write(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grant write permissions to this bucket to an IAM principal.

        If encryption is used, permission to use the key to encrypt the contents
        of written files will also be granted to the same principal.

        Before CDK version 1.85.0, this method granted the ``s3:PutObject*`` permission that included ``s3:PutObjectAcl``,
        which could be used to grant read/write object access to IAM principals in other accounts.
        If you want to get rid of that behavior, update your CDK version to 1.85.0 or later,
        and make sure the ``@aws-cdk/aws-s3:grantWriteWithoutAcl`` feature flag is set to ``true``
        in the ``context`` key of your cdk.json file.
        If you've already updated, but still need the principal to have permissions to modify the ACLs,
        use the {@link grantPutAcl} method.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        ...

    @jsii.member(jsii_name="onCloudTrailEvent")
    def on_cloud_trail_event(
        self,
        id: builtins.str,
        *,
        paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event that triggers when something happens to this bucket.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param paths: Only watch changes to these object paths. Default: - Watch changes to all objects
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="onCloudTrailPutObject")
    def on_cloud_trail_put_object(
        self,
        id: builtins.str,
        *,
        paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event that triggers when an object is uploaded to the specified paths (keys) in this bucket using the PutObject API call.

        Note that some tools like ``aws s3 cp`` will automatically use either
        PutObject or the multipart upload API depending on the file size,
        so using ``onCloudTrailWriteObject`` may be preferable.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param paths: Only watch changes to these object paths. Default: - Watch changes to all objects
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="onCloudTrailWriteObject")
    def on_cloud_trail_write_object(
        self,
        id: builtins.str,
        *,
        paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event that triggers when an object at the specified paths (keys) in this bucket are written to.

        This includes
        the events PutObject, CopyObject, and CompleteMultipartUpload.

        Note that some tools like ``aws s3 cp`` will automatically use either
        PutObject or the multipart upload API depending on the file size,
        so using this method may be preferable to ``onCloudTrailPutObject``.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param paths: Only watch changes to these object paths. Default: - Watch changes to all objects
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        ...

    @jsii.member(jsii_name="s3UrlForObject")
    def s3_url_for_object(
        self,
        key: typing.Optional[builtins.str] = None,
    ) -> builtins.str:
        '''The S3 URL of an S3 object.

        For example:

        - ``s3://onlybucket``
        - ``s3://bucket/key``

        :param key: The S3 key of the object. If not specified, the S3 URL of the bucket is returned.

        :return: an ObjectS3Url token
        '''
        ...

    @jsii.member(jsii_name="transferAccelerationUrlForObject")
    def transfer_acceleration_url_for_object(
        self,
        key: typing.Optional[builtins.str] = None,
        *,
        dual_stack: typing.Optional[builtins.bool] = None,
    ) -> builtins.str:
        '''The https Transfer Acceleration URL of an S3 object.

        Specify ``dualStack: true`` at the options
        for dual-stack endpoint (connect to the bucket over IPv6). For example:

        - ``https://bucket.s3-accelerate.amazonaws.com``
        - ``https://bucket.s3-accelerate.amazonaws.com/key``

        :param key: The S3 key of the object. If not specified, the URL of the bucket is returned.
        :param dual_stack: Dual-stack support to connect to the bucket over IPv6. Default: - false

        :return: an TransferAccelerationUrl token
        '''
        ...

    @jsii.member(jsii_name="urlForObject")
    def url_for_object(self, key: typing.Optional[builtins.str] = None) -> builtins.str:
        '''The https URL of an S3 object. For example:.

        - ``https://s3.us-west-1.amazonaws.com/onlybucket``
        - ``https://s3.us-west-1.amazonaws.com/bucket/key``
        - ``https://s3.cn-north-1.amazonaws.com.cn/china-bucket/mykey``

        :param key: The S3 key of the object. If not specified, the URL of the bucket is returned.

        :return: an ObjectS3Url token
        '''
        ...

    @jsii.member(jsii_name="virtualHostedUrlForObject")
    def virtual_hosted_url_for_object(
        self,
        key: typing.Optional[builtins.str] = None,
        *,
        regional: typing.Optional[builtins.bool] = None,
    ) -> builtins.str:
        '''The virtual hosted-style URL of an S3 object. Specify ``regional: false`` at the options for non-regional URL. For example:.

        - ``https://only-bucket.s3.us-west-1.amazonaws.com``
        - ``https://bucket.s3.us-west-1.amazonaws.com/key``
        - ``https://bucket.s3.amazonaws.com/key``
        - ``https://china-bucket.s3.cn-north-1.amazonaws.com.cn/mykey``

        :param key: The S3 key of the object. If not specified, the URL of the bucket is returned.
        :param regional: Specifies the URL includes the region. Default: - true

        :return: an ObjectS3Url token
        '''
        ...


class _IBucketProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_s3.IBucket"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketArn")
    def bucket_arn(self) -> builtins.str:
        '''The ARN of the bucket.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "bucketArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketDomainName")
    def bucket_domain_name(self) -> builtins.str:
        '''The IPv4 DNS name of the specified bucket.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "bucketDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketDualStackDomainName")
    def bucket_dual_stack_domain_name(self) -> builtins.str:
        '''The IPv6 DNS name of the specified bucket.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "bucketDualStackDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketName")
    def bucket_name(self) -> builtins.str:
        '''The name of the bucket.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "bucketName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketRegionalDomainName")
    def bucket_regional_domain_name(self) -> builtins.str:
        '''The regional domain name of the specified bucket.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "bucketRegionalDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketWebsiteDomainName")
    def bucket_website_domain_name(self) -> builtins.str:
        '''The Domain name of the static website.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "bucketWebsiteDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketWebsiteUrl")
    def bucket_website_url(self) -> builtins.str:
        '''The URL of the static website.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "bucketWebsiteUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionKey")
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''Optional KMS encryption key associated with this bucket.'''
        return typing.cast(typing.Optional[_IKey_5f11635f], jsii.get(self, "encryptionKey"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isWebsite")
    def is_website(self) -> typing.Optional[builtins.bool]:
        '''If this bucket has been configured for static website hosting.'''
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "isWebsite"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policy")
    def policy(self) -> typing.Optional[BucketPolicy]:
        '''The resource policy associated with this bucket.

        If ``autoCreatePolicy`` is true, a ``BucketPolicy`` will be created upon the
        first call to addToResourcePolicy(s).
        '''
        return typing.cast(typing.Optional[BucketPolicy], jsii.get(self, "policy"))

    @policy.setter
    def policy(self, value: typing.Optional[BucketPolicy]) -> None:
        jsii.set(self, "policy", value)

    @jsii.member(jsii_name="addEventNotification")
    def add_event_notification(
        self,
        event: EventType,
        dest: "IBucketNotificationDestination",
        *filters: "NotificationKeyFilter",
    ) -> None:
        '''Adds a bucket notification event destination.

        :param event: The event to trigger the notification.
        :param dest: The notification destination (Lambda, SNS Topic or SQS Queue).
        :param filters: S3 object key filter rules to determine which objects trigger this event. Each filter must include a ``prefix`` and/or ``suffix`` that will be matched against the s3 object key. Refer to the S3 Developer Guide for details about allowed filter rules.

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            # my_lambda: lambda.Function
            
            bucket = s3.Bucket(self, "MyBucket")
            bucket.add_event_notification(s3.EventType.OBJECT_CREATED, s3n.LambdaDestination(my_lambda), prefix="home/myusername/*")
        '''
        return typing.cast(None, jsii.invoke(self, "addEventNotification", [event, dest, *filters]))

    @jsii.member(jsii_name="addObjectCreatedNotification")
    def add_object_created_notification(
        self,
        dest: "IBucketNotificationDestination",
        *filters: "NotificationKeyFilter",
    ) -> None:
        '''Subscribes a destination to receive notifications when an object is created in the bucket.

        This is identical to calling
        ``onEvent(s3.EventType.OBJECT_CREATED)``.

        :param dest: The notification destination (see onEvent).
        :param filters: Filters (see onEvent).
        '''
        return typing.cast(None, jsii.invoke(self, "addObjectCreatedNotification", [dest, *filters]))

    @jsii.member(jsii_name="addObjectRemovedNotification")
    def add_object_removed_notification(
        self,
        dest: "IBucketNotificationDestination",
        *filters: "NotificationKeyFilter",
    ) -> None:
        '''Subscribes a destination to receive notifications when an object is removed from the bucket.

        This is identical to calling
        ``onEvent(EventType.OBJECT_REMOVED)``.

        :param dest: The notification destination (see onEvent).
        :param filters: Filters (see onEvent).
        '''
        return typing.cast(None, jsii.invoke(self, "addObjectRemovedNotification", [dest, *filters]))

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        permission: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Adds a statement to the resource policy for a principal (i.e. account/role/service) to perform actions on this bucket and/or its contents. Use ``bucketArn`` and ``arnForObjects(keys)`` to obtain ARNs for this bucket or objects.

        Note that the policy statement may or may not be added to the policy.
        For example, when an ``IBucket`` is created from an existing bucket,
        it's not possible to tell whether the bucket already has a policy
        attached, let alone to re-use that policy to add more statements to it.
        So it's safest to do nothing in these cases.

        :param permission: the policy statement to be added to the bucket's policy.

        :return:

        metadata about the execution of this method. If the policy
        was not added, the value of ``statementAdded`` will be ``false``. You
        should always check this value to make sure that the operation was
        actually carried out. Otherwise, synthesis and deploy will terminate
        silently, which may be confusing.
        '''
        return typing.cast(_AddToResourcePolicyResult_1d0a53ad, jsii.invoke(self, "addToResourcePolicy", [permission]))

    @jsii.member(jsii_name="arnForObjects")
    def arn_for_objects(self, key_pattern: builtins.str) -> builtins.str:
        '''Returns an ARN that represents all objects within the bucket that match the key pattern specified.

        To represent all keys, specify ``"*"``.

        :param key_pattern: -
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "arnForObjects", [key_pattern]))

    @jsii.member(jsii_name="grantDelete")
    def grant_delete(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grants s3:DeleteObject* permission to an IAM principal for objects in this bucket.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantDelete", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="grantPublicAccess")
    def grant_public_access(
        self,
        key_prefix: typing.Optional[builtins.str] = None,
        *allowed_actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Allows unrestricted access to objects from this bucket.

        IMPORTANT: This permission allows anyone to perform actions on S3 objects
        in this bucket, which is useful for when you configure your bucket as a
        website and want everyone to be able to read objects in the bucket without
        needing to authenticate.

        Without arguments, this method will grant read ("s3:GetObject") access to
        all objects ("*") in the bucket.

        The method returns the ``iam.Grant`` object, which can then be modified
        as needed. For example, you can add a condition that will restrict access only
        to an IPv4 range like this::

            const grant = bucket.grantPublicAccess();
            grant.resourceStatement!.addCondition(‘IpAddress’, { “aws:SourceIp”: “54.240.143.0/24” });

        :param key_prefix: the prefix of S3 object keys (e.g. ``home/*``). Default is "*".
        :param allowed_actions: the set of S3 actions to allow. Default is "s3:GetObject".

        :return: The ``iam.PolicyStatement`` object, which can be used to apply e.g. conditions.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPublicAccess", [key_prefix, *allowed_actions]))

    @jsii.member(jsii_name="grantPut")
    def grant_put(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grants s3:PutObject* and s3:Abort* permissions for this bucket to an IAM principal.

        If encryption is used, permission to use the key to encrypt the contents
        of written files will also be granted to the same principal.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPut", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="grantPutAcl")
    def grant_put_acl(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Optional[builtins.str] = None,
    ) -> _Grant_a7ae64f8:
        '''Grant the given IAM identity permissions to modify the ACLs of objects in the given Bucket.

        If your application has the '@aws-cdk/aws-s3:grantWriteWithoutAcl' feature flag set,
        calling {@link grantWrite} or {@link grantReadWrite} no longer grants permissions to modify the ACLs of the objects;
        in this case, if you need to modify object ACLs, call this method explicitly.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPutAcl", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="grantRead")
    def grant_read(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grant read permissions for this bucket and it's contents to an IAM principal (Role/Group/User).

        If encryption is used, permission to use the key to decrypt the contents
        of the bucket will also be granted to the same principal.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantRead", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="grantReadWrite")
    def grant_read_write(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grants read/write permissions for this bucket and it's contents to an IAM principal (Role/Group/User).

        If an encryption key is used, permission to use the key for
        encrypt/decrypt will also be granted.

        Before CDK version 1.85.0, this method granted the ``s3:PutObject*`` permission that included ``s3:PutObjectAcl``,
        which could be used to grant read/write object access to IAM principals in other accounts.
        If you want to get rid of that behavior, update your CDK version to 1.85.0 or later,
        and make sure the ``@aws-cdk/aws-s3:grantWriteWithoutAcl`` feature flag is set to ``true``
        in the ``context`` key of your cdk.json file.
        If you've already updated, but still need the principal to have permissions to modify the ACLs,
        use the {@link grantPutAcl} method.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantReadWrite", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="grantWrite")
    def grant_write(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grant write permissions to this bucket to an IAM principal.

        If encryption is used, permission to use the key to encrypt the contents
        of written files will also be granted to the same principal.

        Before CDK version 1.85.0, this method granted the ``s3:PutObject*`` permission that included ``s3:PutObjectAcl``,
        which could be used to grant read/write object access to IAM principals in other accounts.
        If you want to get rid of that behavior, update your CDK version to 1.85.0 or later,
        and make sure the ``@aws-cdk/aws-s3:grantWriteWithoutAcl`` feature flag is set to ``true``
        in the ``context`` key of your cdk.json file.
        If you've already updated, but still need the principal to have permissions to modify the ACLs,
        use the {@link grantPutAcl} method.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantWrite", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="onCloudTrailEvent")
    def on_cloud_trail_event(
        self,
        id: builtins.str,
        *,
        paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines a CloudWatch event that triggers when something happens to this bucket.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param paths: Only watch changes to these object paths. Default: - Watch changes to all objects
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnCloudTrailBucketEventOptions(
            paths=paths,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCloudTrailEvent", [id, options]))

    @jsii.member(jsii_name="onCloudTrailPutObject")
    def on_cloud_trail_put_object(
        self,
        id: builtins.str,
        *,
        paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event that triggers when an object is uploaded to the specified paths (keys) in this bucket using the PutObject API call.

        Note that some tools like ``aws s3 cp`` will automatically use either
        PutObject or the multipart upload API depending on the file size,
        so using ``onCloudTrailWriteObject`` may be preferable.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param paths: Only watch changes to these object paths. Default: - Watch changes to all objects
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnCloudTrailBucketEventOptions(
            paths=paths,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCloudTrailPutObject", [id, options]))

    @jsii.member(jsii_name="onCloudTrailWriteObject")
    def on_cloud_trail_write_object(
        self,
        id: builtins.str,
        *,
        paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event that triggers when an object at the specified paths (keys) in this bucket are written to.

        This includes
        the events PutObject, CopyObject, and CompleteMultipartUpload.

        Note that some tools like ``aws s3 cp`` will automatically use either
        PutObject or the multipart upload API depending on the file size,
        so using this method may be preferable to ``onCloudTrailPutObject``.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param paths: Only watch changes to these object paths. Default: - Watch changes to all objects
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnCloudTrailBucketEventOptions(
            paths=paths,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCloudTrailWriteObject", [id, options]))

    @jsii.member(jsii_name="s3UrlForObject")
    def s3_url_for_object(
        self,
        key: typing.Optional[builtins.str] = None,
    ) -> builtins.str:
        '''The S3 URL of an S3 object.

        For example:

        - ``s3://onlybucket``
        - ``s3://bucket/key``

        :param key: The S3 key of the object. If not specified, the S3 URL of the bucket is returned.

        :return: an ObjectS3Url token
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "s3UrlForObject", [key]))

    @jsii.member(jsii_name="transferAccelerationUrlForObject")
    def transfer_acceleration_url_for_object(
        self,
        key: typing.Optional[builtins.str] = None,
        *,
        dual_stack: typing.Optional[builtins.bool] = None,
    ) -> builtins.str:
        '''The https Transfer Acceleration URL of an S3 object.

        Specify ``dualStack: true`` at the options
        for dual-stack endpoint (connect to the bucket over IPv6). For example:

        - ``https://bucket.s3-accelerate.amazonaws.com``
        - ``https://bucket.s3-accelerate.amazonaws.com/key``

        :param key: The S3 key of the object. If not specified, the URL of the bucket is returned.
        :param dual_stack: Dual-stack support to connect to the bucket over IPv6. Default: - false

        :return: an TransferAccelerationUrl token
        '''
        options = TransferAccelerationUrlOptions(dual_stack=dual_stack)

        return typing.cast(builtins.str, jsii.invoke(self, "transferAccelerationUrlForObject", [key, options]))

    @jsii.member(jsii_name="urlForObject")
    def url_for_object(self, key: typing.Optional[builtins.str] = None) -> builtins.str:
        '''The https URL of an S3 object. For example:.

        - ``https://s3.us-west-1.amazonaws.com/onlybucket``
        - ``https://s3.us-west-1.amazonaws.com/bucket/key``
        - ``https://s3.cn-north-1.amazonaws.com.cn/china-bucket/mykey``

        :param key: The S3 key of the object. If not specified, the URL of the bucket is returned.

        :return: an ObjectS3Url token
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "urlForObject", [key]))

    @jsii.member(jsii_name="virtualHostedUrlForObject")
    def virtual_hosted_url_for_object(
        self,
        key: typing.Optional[builtins.str] = None,
        *,
        regional: typing.Optional[builtins.bool] = None,
    ) -> builtins.str:
        '''The virtual hosted-style URL of an S3 object. Specify ``regional: false`` at the options for non-regional URL. For example:.

        - ``https://only-bucket.s3.us-west-1.amazonaws.com``
        - ``https://bucket.s3.us-west-1.amazonaws.com/key``
        - ``https://bucket.s3.amazonaws.com/key``
        - ``https://china-bucket.s3.cn-north-1.amazonaws.com.cn/mykey``

        :param key: The S3 key of the object. If not specified, the URL of the bucket is returned.
        :param regional: Specifies the URL includes the region. Default: - true

        :return: an ObjectS3Url token
        '''
        options = VirtualHostedStyleUrlOptions(regional=regional)

        return typing.cast(builtins.str, jsii.invoke(self, "virtualHostedUrlForObject", [key, options]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IBucket).__jsii_proxy_class__ = lambda : _IBucketProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_s3.IBucketNotificationDestination")
class IBucketNotificationDestination(typing_extensions.Protocol):
    '''Implemented by constructs that can be used as bucket notification destinations.'''

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        scope: constructs.Construct,
        bucket: IBucket,
    ) -> BucketNotificationDestinationConfig:
        '''Registers this resource to receive notifications for the specified bucket.

        This method will only be called once for each destination/bucket
        pair and the result will be cached, so there is no need to implement
        idempotency in each destination.

        :param scope: -
        :param bucket: The bucket object to bind to.
        '''
        ...


class _IBucketNotificationDestinationProxy:
    '''Implemented by constructs that can be used as bucket notification destinations.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_s3.IBucketNotificationDestination"

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        scope: constructs.Construct,
        bucket: IBucket,
    ) -> BucketNotificationDestinationConfig:
        '''Registers this resource to receive notifications for the specified bucket.

        This method will only be called once for each destination/bucket
        pair and the result will be cached, so there is no need to implement
        idempotency in each destination.

        :param scope: -
        :param bucket: The bucket object to bind to.
        '''
        return typing.cast(BucketNotificationDestinationConfig, jsii.invoke(self, "bind", [scope, bucket]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IBucketNotificationDestination).__jsii_proxy_class__ = lambda : _IBucketNotificationDestinationProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.IntelligentTieringConfiguration",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "archive_access_tier_time": "archiveAccessTierTime",
        "deep_archive_access_tier_time": "deepArchiveAccessTierTime",
        "prefix": "prefix",
        "tags": "tags",
    },
)
class IntelligentTieringConfiguration:
    def __init__(
        self,
        *,
        name: builtins.str,
        archive_access_tier_time: typing.Optional[_Duration_4839e8c3] = None,
        deep_archive_access_tier_time: typing.Optional[_Duration_4839e8c3] = None,
        prefix: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence["Tag"]] = None,
    ) -> None:
        '''The intelligent tiering configuration.

        :param name: Configuration name.
        :param archive_access_tier_time: When enabled, Intelligent-Tiering will automatically move objects that haven’t been accessed for a minimum of 90 days to the Archive Access tier. Default: Objects will not move to Glacier
        :param deep_archive_access_tier_time: When enabled, Intelligent-Tiering will automatically move objects that haven’t been accessed for a minimum of 180 days to the Deep Archive Access tier. Default: Objects will not move to Glacier Deep Access
        :param prefix: Add a filter to limit the scope of this configuration to a single prefix. Default: this configuration will apply to **all** objects in the bucket.
        :param tags: You can limit the scope of this rule to the key value pairs added below. Default: No filtering will be performed on tags

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_s3 as s3
            
            intelligent_tiering_configuration = s3.IntelligentTieringConfiguration(
                name="name",
            
                # the properties below are optional
                archive_access_tier_time=cdk.Duration.minutes(30),
                deep_archive_access_tier_time=cdk.Duration.minutes(30),
                prefix="prefix",
                tags=[s3.Tag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if archive_access_tier_time is not None:
            self._values["archive_access_tier_time"] = archive_access_tier_time
        if deep_archive_access_tier_time is not None:
            self._values["deep_archive_access_tier_time"] = deep_archive_access_tier_time
        if prefix is not None:
            self._values["prefix"] = prefix
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''Configuration name.'''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def archive_access_tier_time(self) -> typing.Optional[_Duration_4839e8c3]:
        '''When enabled, Intelligent-Tiering will automatically move objects that haven’t been accessed for a minimum of 90 days to the Archive Access tier.

        :default: Objects will not move to Glacier
        '''
        result = self._values.get("archive_access_tier_time")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def deep_archive_access_tier_time(self) -> typing.Optional[_Duration_4839e8c3]:
        '''When enabled, Intelligent-Tiering will automatically move objects that haven’t been accessed for a minimum of 180 days to the Deep Archive Access tier.

        :default: Objects will not move to Glacier Deep Access
        '''
        result = self._values.get("deep_archive_access_tier_time")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def prefix(self) -> typing.Optional[builtins.str]:
        '''Add a filter to limit the scope of this configuration to a single prefix.

        :default: this configuration will apply to **all** objects in the bucket.
        '''
        result = self._values.get("prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List["Tag"]]:
        '''You can limit the scope of this rule to the key value pairs added below.

        :default: No filtering will be performed on tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List["Tag"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "IntelligentTieringConfiguration(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.Inventory",
    jsii_struct_bases=[],
    name_mapping={
        "destination": "destination",
        "enabled": "enabled",
        "format": "format",
        "frequency": "frequency",
        "include_object_versions": "includeObjectVersions",
        "inventory_id": "inventoryId",
        "objects_prefix": "objectsPrefix",
        "optional_fields": "optionalFields",
    },
)
class Inventory:
    def __init__(
        self,
        *,
        destination: "InventoryDestination",
        enabled: typing.Optional[builtins.bool] = None,
        format: typing.Optional["InventoryFormat"] = None,
        frequency: typing.Optional["InventoryFrequency"] = None,
        include_object_versions: typing.Optional["InventoryObjectVersion"] = None,
        inventory_id: typing.Optional[builtins.str] = None,
        objects_prefix: typing.Optional[builtins.str] = None,
        optional_fields: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Specifies the inventory configuration of an S3 Bucket.

        :param destination: The destination of the inventory.
        :param enabled: Whether the inventory is enabled or disabled. Default: true
        :param format: The format of the inventory. Default: InventoryFormat.CSV
        :param frequency: Frequency at which the inventory should be generated. Default: InventoryFrequency.WEEKLY
        :param include_object_versions: If the inventory should contain all the object versions or only the current one. Default: InventoryObjectVersion.ALL
        :param inventory_id: The inventory configuration ID. Default: - generated ID.
        :param objects_prefix: The inventory will only include objects that meet the prefix filter criteria. Default: - No objects prefix
        :param optional_fields: A list of optional fields to be included in the inventory result. Default: - No optional fields.

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-inventory.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            
            # bucket: s3.Bucket
            
            inventory = s3.Inventory(
                destination=s3.InventoryDestination(
                    bucket=bucket,
            
                    # the properties below are optional
                    bucket_owner="bucketOwner",
                    prefix="prefix"
                ),
            
                # the properties below are optional
                enabled=False,
                format=s3.InventoryFormat.CSV,
                frequency=s3.InventoryFrequency.DAILY,
                include_object_versions=s3.InventoryObjectVersion.ALL,
                inventory_id="inventoryId",
                objects_prefix="objectsPrefix",
                optional_fields=["optionalFields"]
            )
        '''
        if isinstance(destination, dict):
            destination = InventoryDestination(**destination)
        self._values: typing.Dict[str, typing.Any] = {
            "destination": destination,
        }
        if enabled is not None:
            self._values["enabled"] = enabled
        if format is not None:
            self._values["format"] = format
        if frequency is not None:
            self._values["frequency"] = frequency
        if include_object_versions is not None:
            self._values["include_object_versions"] = include_object_versions
        if inventory_id is not None:
            self._values["inventory_id"] = inventory_id
        if objects_prefix is not None:
            self._values["objects_prefix"] = objects_prefix
        if optional_fields is not None:
            self._values["optional_fields"] = optional_fields

    @builtins.property
    def destination(self) -> "InventoryDestination":
        '''The destination of the inventory.'''
        result = self._values.get("destination")
        assert result is not None, "Required property 'destination' is missing"
        return typing.cast("InventoryDestination", result)

    @builtins.property
    def enabled(self) -> typing.Optional[builtins.bool]:
        '''Whether the inventory is enabled or disabled.

        :default: true
        '''
        result = self._values.get("enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def format(self) -> typing.Optional["InventoryFormat"]:
        '''The format of the inventory.

        :default: InventoryFormat.CSV
        '''
        result = self._values.get("format")
        return typing.cast(typing.Optional["InventoryFormat"], result)

    @builtins.property
    def frequency(self) -> typing.Optional["InventoryFrequency"]:
        '''Frequency at which the inventory should be generated.

        :default: InventoryFrequency.WEEKLY
        '''
        result = self._values.get("frequency")
        return typing.cast(typing.Optional["InventoryFrequency"], result)

    @builtins.property
    def include_object_versions(self) -> typing.Optional["InventoryObjectVersion"]:
        '''If the inventory should contain all the object versions or only the current one.

        :default: InventoryObjectVersion.ALL
        '''
        result = self._values.get("include_object_versions")
        return typing.cast(typing.Optional["InventoryObjectVersion"], result)

    @builtins.property
    def inventory_id(self) -> typing.Optional[builtins.str]:
        '''The inventory configuration ID.

        :default: - generated ID.
        '''
        result = self._values.get("inventory_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def objects_prefix(self) -> typing.Optional[builtins.str]:
        '''The inventory will only include objects that meet the prefix filter criteria.

        :default: - No objects prefix
        '''
        result = self._values.get("objects_prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def optional_fields(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of optional fields to be included in the inventory result.

        :default: - No optional fields.
        '''
        result = self._values.get("optional_fields")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "Inventory(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.InventoryDestination",
    jsii_struct_bases=[],
    name_mapping={
        "bucket": "bucket",
        "bucket_owner": "bucketOwner",
        "prefix": "prefix",
    },
)
class InventoryDestination:
    def __init__(
        self,
        *,
        bucket: IBucket,
        bucket_owner: typing.Optional[builtins.str] = None,
        prefix: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The destination of the inventory.

        :param bucket: Bucket where all inventories will be saved in.
        :param bucket_owner: The account ID that owns the destination S3 bucket. If no account ID is provided, the owner is not validated before exporting data. It's recommended to set an account ID to prevent problems if the destination bucket ownership changes. Default: - No account ID.
        :param prefix: The prefix to be used when saving the inventory. Default: - No prefix.

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            inventory_bucket = s3.Bucket(self, "InventoryBucket")
            
            data_bucket = s3.Bucket(self, "DataBucket",
                inventories=[s3.Inventory(
                    frequency=s3.InventoryFrequency.DAILY,
                    include_object_versions=s3.InventoryObjectVersion.CURRENT,
                    destination=s3.InventoryDestination(
                        bucket=inventory_bucket
                    )
                ), s3.Inventory(
                    frequency=s3.InventoryFrequency.WEEKLY,
                    include_object_versions=s3.InventoryObjectVersion.ALL,
                    destination=s3.InventoryDestination(
                        bucket=inventory_bucket,
                        prefix="with-all-versions"
                    )
                )
                ]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "bucket": bucket,
        }
        if bucket_owner is not None:
            self._values["bucket_owner"] = bucket_owner
        if prefix is not None:
            self._values["prefix"] = prefix

    @builtins.property
    def bucket(self) -> IBucket:
        '''Bucket where all inventories will be saved in.'''
        result = self._values.get("bucket")
        assert result is not None, "Required property 'bucket' is missing"
        return typing.cast(IBucket, result)

    @builtins.property
    def bucket_owner(self) -> typing.Optional[builtins.str]:
        '''The account ID that owns the destination S3 bucket.

        If no account ID is provided, the owner is not validated before exporting data.
        It's recommended to set an account ID to prevent problems if the destination bucket ownership changes.

        :default: - No account ID.
        '''
        result = self._values.get("bucket_owner")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def prefix(self) -> typing.Optional[builtins.str]:
        '''The prefix to be used when saving the inventory.

        :default: - No prefix.
        '''
        result = self._values.get("prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "InventoryDestination(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_s3.InventoryFormat")
class InventoryFormat(enum.Enum):
    '''All supported inventory list formats.'''

    CSV = "CSV"
    '''Generate the inventory list as CSV.'''
    PARQUET = "PARQUET"
    '''Generate the inventory list as Parquet.'''
    ORC = "ORC"
    '''Generate the inventory list as ORC.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_s3.InventoryFrequency")
class InventoryFrequency(enum.Enum):
    '''All supported inventory frequencies.

    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        inventory_bucket = s3.Bucket(self, "InventoryBucket")
        
        data_bucket = s3.Bucket(self, "DataBucket",
            inventories=[s3.Inventory(
                frequency=s3.InventoryFrequency.DAILY,
                include_object_versions=s3.InventoryObjectVersion.CURRENT,
                destination=s3.InventoryDestination(
                    bucket=inventory_bucket
                )
            ), s3.Inventory(
                frequency=s3.InventoryFrequency.WEEKLY,
                include_object_versions=s3.InventoryObjectVersion.ALL,
                destination=s3.InventoryDestination(
                    bucket=inventory_bucket,
                    prefix="with-all-versions"
                )
            )
            ]
        )
    '''

    DAILY = "DAILY"
    '''A report is generated every day.'''
    WEEKLY = "WEEKLY"
    '''A report is generated every Sunday (UTC timezone) after the initial report.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_s3.InventoryObjectVersion")
class InventoryObjectVersion(enum.Enum):
    '''Inventory version support.

    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        inventory_bucket = s3.Bucket(self, "InventoryBucket")
        
        data_bucket = s3.Bucket(self, "DataBucket",
            inventories=[s3.Inventory(
                frequency=s3.InventoryFrequency.DAILY,
                include_object_versions=s3.InventoryObjectVersion.CURRENT,
                destination=s3.InventoryDestination(
                    bucket=inventory_bucket
                )
            ), s3.Inventory(
                frequency=s3.InventoryFrequency.WEEKLY,
                include_object_versions=s3.InventoryObjectVersion.ALL,
                destination=s3.InventoryDestination(
                    bucket=inventory_bucket,
                    prefix="with-all-versions"
                )
            )
            ]
        )
    '''

    ALL = "ALL"
    '''Includes all versions of each object in the report.'''
    CURRENT = "CURRENT"
    '''Includes only the current version of each object in the report.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.LifecycleRule",
    jsii_struct_bases=[],
    name_mapping={
        "abort_incomplete_multipart_upload_after": "abortIncompleteMultipartUploadAfter",
        "enabled": "enabled",
        "expiration": "expiration",
        "expiration_date": "expirationDate",
        "expired_object_delete_marker": "expiredObjectDeleteMarker",
        "id": "id",
        "noncurrent_version_expiration": "noncurrentVersionExpiration",
        "noncurrent_version_transitions": "noncurrentVersionTransitions",
        "prefix": "prefix",
        "tag_filters": "tagFilters",
        "transitions": "transitions",
    },
)
class LifecycleRule:
    def __init__(
        self,
        *,
        abort_incomplete_multipart_upload_after: typing.Optional[_Duration_4839e8c3] = None,
        enabled: typing.Optional[builtins.bool] = None,
        expiration: typing.Optional[_Duration_4839e8c3] = None,
        expiration_date: typing.Optional[datetime.datetime] = None,
        expired_object_delete_marker: typing.Optional[builtins.bool] = None,
        id: typing.Optional[builtins.str] = None,
        noncurrent_version_expiration: typing.Optional[_Duration_4839e8c3] = None,
        noncurrent_version_transitions: typing.Optional[typing.Sequence["NoncurrentVersionTransition"]] = None,
        prefix: typing.Optional[builtins.str] = None,
        tag_filters: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        transitions: typing.Optional[typing.Sequence["Transition"]] = None,
    ) -> None:
        '''Declaration of a Life cycle rule.

        :param abort_incomplete_multipart_upload_after: Specifies a lifecycle rule that aborts incomplete multipart uploads to an Amazon S3 bucket. The AbortIncompleteMultipartUpload property type creates a lifecycle rule that aborts incomplete multipart uploads to an Amazon S3 bucket. When Amazon S3 aborts a multipart upload, it deletes all parts associated with the multipart upload. Default: Incomplete uploads are never aborted
        :param enabled: Whether this rule is enabled. Default: true
        :param expiration: Indicates the number of days after creation when objects are deleted from Amazon S3 and Amazon Glacier. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time. Default: No expiration timeout
        :param expiration_date: Indicates when objects are deleted from Amazon S3 and Amazon Glacier. The date value must be in ISO 8601 format. The time is always midnight UTC. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time. Default: No expiration date
        :param expired_object_delete_marker: Indicates whether Amazon S3 will remove a delete marker with no noncurrent versions. If set to true, the delete marker will be expired. Default: false
        :param id: A unique identifier for this rule. The value cannot be more than 255 characters.
        :param noncurrent_version_expiration: Time between when a new version of the object is uploaded to the bucket and when old versions of the object expire. For buckets with versioning enabled (or suspended), specifies the time, in days, between when a new version of the object is uploaded to the bucket and when old versions of the object expire. When object versions expire, Amazon S3 permanently deletes them. If you specify a transition and expiration time, the expiration time must be later than the transition time. Default: No noncurrent version expiration
        :param noncurrent_version_transitions: One or more transition rules that specify when non-current objects transition to a specified storage class. Only for for buckets with versioning enabled (or suspended). If you specify a transition and expiration time, the expiration time must be later than the transition time.
        :param prefix: Object key prefix that identifies one or more objects to which this rule applies. Default: Rule applies to all objects
        :param tag_filters: The TagFilter property type specifies tags to use to identify a subset of objects for an Amazon S3 bucket. Default: Rule applies to all objects
        :param transitions: One or more transition rules that specify when an object transitions to a specified storage class. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time. Default: No transition rules

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_s3 as s3
            
            # storage_class: s3.StorageClass
            # tag_filters: Any
            
            lifecycle_rule = s3.LifecycleRule(
                abort_incomplete_multipart_upload_after=cdk.Duration.minutes(30),
                enabled=False,
                expiration=cdk.Duration.minutes(30),
                expiration_date=Date(),
                expired_object_delete_marker=False,
                id="id",
                noncurrent_version_expiration=cdk.Duration.minutes(30),
                noncurrent_version_transitions=[s3.NoncurrentVersionTransition(
                    storage_class=storage_class,
                    transition_after=cdk.Duration.minutes(30),
            
                    # the properties below are optional
                    noncurrent_versions_to_retain=123
                )],
                prefix="prefix",
                tag_filters={
                    "tag_filters_key": tag_filters
                },
                transitions=[s3.Transition(
                    storage_class=storage_class,
            
                    # the properties below are optional
                    transition_after=cdk.Duration.minutes(30),
                    transition_date=Date()
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if abort_incomplete_multipart_upload_after is not None:
            self._values["abort_incomplete_multipart_upload_after"] = abort_incomplete_multipart_upload_after
        if enabled is not None:
            self._values["enabled"] = enabled
        if expiration is not None:
            self._values["expiration"] = expiration
        if expiration_date is not None:
            self._values["expiration_date"] = expiration_date
        if expired_object_delete_marker is not None:
            self._values["expired_object_delete_marker"] = expired_object_delete_marker
        if id is not None:
            self._values["id"] = id
        if noncurrent_version_expiration is not None:
            self._values["noncurrent_version_expiration"] = noncurrent_version_expiration
        if noncurrent_version_transitions is not None:
            self._values["noncurrent_version_transitions"] = noncurrent_version_transitions
        if prefix is not None:
            self._values["prefix"] = prefix
        if tag_filters is not None:
            self._values["tag_filters"] = tag_filters
        if transitions is not None:
            self._values["transitions"] = transitions

    @builtins.property
    def abort_incomplete_multipart_upload_after(
        self,
    ) -> typing.Optional[_Duration_4839e8c3]:
        '''Specifies a lifecycle rule that aborts incomplete multipart uploads to an Amazon S3 bucket.

        The AbortIncompleteMultipartUpload property type creates a lifecycle
        rule that aborts incomplete multipart uploads to an Amazon S3 bucket.
        When Amazon S3 aborts a multipart upload, it deletes all parts
        associated with the multipart upload.

        :default: Incomplete uploads are never aborted
        '''
        result = self._values.get("abort_incomplete_multipart_upload_after")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def enabled(self) -> typing.Optional[builtins.bool]:
        '''Whether this rule is enabled.

        :default: true
        '''
        result = self._values.get("enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def expiration(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Indicates the number of days after creation when objects are deleted from Amazon S3 and Amazon Glacier.

        If you specify an expiration and transition time, you must use the same
        time unit for both properties (either in days or by date). The
        expiration time must also be later than the transition time.

        :default: No expiration timeout
        '''
        result = self._values.get("expiration")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def expiration_date(self) -> typing.Optional[datetime.datetime]:
        '''Indicates when objects are deleted from Amazon S3 and Amazon Glacier.

        The date value must be in ISO 8601 format. The time is always midnight UTC.

        If you specify an expiration and transition time, you must use the same
        time unit for both properties (either in days or by date). The
        expiration time must also be later than the transition time.

        :default: No expiration date
        '''
        result = self._values.get("expiration_date")
        return typing.cast(typing.Optional[datetime.datetime], result)

    @builtins.property
    def expired_object_delete_marker(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether Amazon S3 will remove a delete marker with no noncurrent versions.

        If set to true, the delete marker will be expired.

        :default: false
        '''
        result = self._values.get("expired_object_delete_marker")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def id(self) -> typing.Optional[builtins.str]:
        '''A unique identifier for this rule.

        The value cannot be more than 255 characters.
        '''
        result = self._values.get("id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def noncurrent_version_expiration(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Time between when a new version of the object is uploaded to the bucket and when old versions of the object expire.

        For buckets with versioning enabled (or suspended), specifies the time,
        in days, between when a new version of the object is uploaded to the
        bucket and when old versions of the object expire. When object versions
        expire, Amazon S3 permanently deletes them. If you specify a transition
        and expiration time, the expiration time must be later than the
        transition time.

        :default: No noncurrent version expiration
        '''
        result = self._values.get("noncurrent_version_expiration")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def noncurrent_version_transitions(
        self,
    ) -> typing.Optional[typing.List["NoncurrentVersionTransition"]]:
        '''One or more transition rules that specify when non-current objects transition to a specified storage class.

        Only for for buckets with versioning enabled (or suspended).

        If you specify a transition and expiration time, the expiration time
        must be later than the transition time.
        '''
        result = self._values.get("noncurrent_version_transitions")
        return typing.cast(typing.Optional[typing.List["NoncurrentVersionTransition"]], result)

    @builtins.property
    def prefix(self) -> typing.Optional[builtins.str]:
        '''Object key prefix that identifies one or more objects to which this rule applies.

        :default: Rule applies to all objects
        '''
        result = self._values.get("prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tag_filters(self) -> typing.Optional[typing.Mapping[builtins.str, typing.Any]]:
        '''The TagFilter property type specifies tags to use to identify a subset of objects for an Amazon S3 bucket.

        :default: Rule applies to all objects
        '''
        result = self._values.get("tag_filters")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, typing.Any]], result)

    @builtins.property
    def transitions(self) -> typing.Optional[typing.List["Transition"]]:
        '''One or more transition rules that specify when an object transitions to a specified storage class.

        If you specify an expiration and transition time, you must use the same
        time unit for both properties (either in days or by date). The
        expiration time must also be later than the transition time.

        :default: No transition rules
        '''
        result = self._values.get("transitions")
        return typing.cast(typing.Optional[typing.List["Transition"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LifecycleRule(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.Location",
    jsii_struct_bases=[],
    name_mapping={
        "bucket_name": "bucketName",
        "object_key": "objectKey",
        "object_version": "objectVersion",
    },
)
class Location:
    def __init__(
        self,
        *,
        bucket_name: builtins.str,
        object_key: builtins.str,
        object_version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''An interface that represents the location of a specific object in an S3 Bucket.

        :param bucket_name: The name of the S3 Bucket the object is in.
        :param object_key: The path inside the Bucket where the object is located at.
        :param object_version: The S3 object version.

        :exampleMetadata: infused

        Example::

            start_query_execution_job = tasks.AthenaStartQueryExecution(self, "Athena Start Query",
                query_string=sfn.JsonPath.format("select contacts where year={};", sfn.JsonPath.string_at("$.year")),
                query_execution_context=tasks.QueryExecutionContext(
                    database_name="interactions"
                ),
                result_configuration=tasks.ResultConfiguration(
                    encryption_configuration=tasks.EncryptionConfiguration(
                        encryption_option=tasks.EncryptionOption.S3_MANAGED
                    ),
                    output_location=s3.Location(
                        bucket_name="mybucket",
                        object_key="myprefix"
                    )
                ),
                integration_pattern=sfn.IntegrationPattern.RUN_JOB
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "bucket_name": bucket_name,
            "object_key": object_key,
        }
        if object_version is not None:
            self._values["object_version"] = object_version

    @builtins.property
    def bucket_name(self) -> builtins.str:
        '''The name of the S3 Bucket the object is in.'''
        result = self._values.get("bucket_name")
        assert result is not None, "Required property 'bucket_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def object_key(self) -> builtins.str:
        '''The path inside the Bucket where the object is located at.'''
        result = self._values.get("object_key")
        assert result is not None, "Required property 'object_key' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def object_version(self) -> typing.Optional[builtins.str]:
        '''The S3 object version.'''
        result = self._values.get("object_version")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "Location(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.NoncurrentVersionTransition",
    jsii_struct_bases=[],
    name_mapping={
        "storage_class": "storageClass",
        "transition_after": "transitionAfter",
        "noncurrent_versions_to_retain": "noncurrentVersionsToRetain",
    },
)
class NoncurrentVersionTransition:
    def __init__(
        self,
        *,
        storage_class: "StorageClass",
        transition_after: _Duration_4839e8c3,
        noncurrent_versions_to_retain: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Describes when noncurrent versions transition to a specified storage class.

        :param storage_class: The storage class to which you want the object to transition.
        :param transition_after: Indicates the number of days after creation when objects are transitioned to the specified storage class. Default: No transition count.
        :param noncurrent_versions_to_retain: Indicates the number of noncurrent version objects to be retained. Can be up to 100 noncurrent versions retained. Default: No noncurrent version retained.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_s3 as s3
            
            # storage_class: s3.StorageClass
            
            noncurrent_version_transition = s3.NoncurrentVersionTransition(
                storage_class=storage_class,
                transition_after=cdk.Duration.minutes(30),
            
                # the properties below are optional
                noncurrent_versions_to_retain=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "storage_class": storage_class,
            "transition_after": transition_after,
        }
        if noncurrent_versions_to_retain is not None:
            self._values["noncurrent_versions_to_retain"] = noncurrent_versions_to_retain

    @builtins.property
    def storage_class(self) -> "StorageClass":
        '''The storage class to which you want the object to transition.'''
        result = self._values.get("storage_class")
        assert result is not None, "Required property 'storage_class' is missing"
        return typing.cast("StorageClass", result)

    @builtins.property
    def transition_after(self) -> _Duration_4839e8c3:
        '''Indicates the number of days after creation when objects are transitioned to the specified storage class.

        :default: No transition count.
        '''
        result = self._values.get("transition_after")
        assert result is not None, "Required property 'transition_after' is missing"
        return typing.cast(_Duration_4839e8c3, result)

    @builtins.property
    def noncurrent_versions_to_retain(self) -> typing.Optional[jsii.Number]:
        '''Indicates the number of noncurrent version objects to be retained.

        Can be up to 100 noncurrent versions retained.

        :default: No noncurrent version retained.
        '''
        result = self._values.get("noncurrent_versions_to_retain")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NoncurrentVersionTransition(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.NotificationKeyFilter",
    jsii_struct_bases=[],
    name_mapping={"prefix": "prefix", "suffix": "suffix"},
)
class NotificationKeyFilter:
    def __init__(
        self,
        *,
        prefix: typing.Optional[builtins.str] = None,
        suffix: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param prefix: S3 keys must have the specified prefix.
        :param suffix: S3 keys must have the specified suffix.

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            # my_queue: sqs.Queue
            
            bucket = s3.Bucket(self, "MyBucket")
            bucket.add_event_notification(s3.EventType.OBJECT_REMOVED,
                s3n.SqsDestination(my_queue), prefix="foo/", suffix=".jpg")
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if prefix is not None:
            self._values["prefix"] = prefix
        if suffix is not None:
            self._values["suffix"] = suffix

    @builtins.property
    def prefix(self) -> typing.Optional[builtins.str]:
        '''S3 keys must have the specified prefix.'''
        result = self._values.get("prefix")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def suffix(self) -> typing.Optional[builtins.str]:
        '''S3 keys must have the specified suffix.'''
        result = self._values.get("suffix")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NotificationKeyFilter(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_s3.ObjectOwnership")
class ObjectOwnership(enum.Enum):
    '''The ObjectOwnership of the bucket.

    :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/about-object-ownership.html
    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        s3.Bucket(self, "MyBucket",
            object_ownership=s3.ObjectOwnership.OBJECT_WRITER
        )
    '''

    BUCKET_OWNER_ENFORCED = "BUCKET_OWNER_ENFORCED"
    '''ACLs are disabled, and the bucket owner automatically owns and has full control over every object in the bucket.

    ACLs no longer affect permissions to data in the S3 bucket.
    The bucket uses policies to define access control.
    '''
    BUCKET_OWNER_PREFERRED = "BUCKET_OWNER_PREFERRED"
    '''Objects uploaded to the bucket change ownership to the bucket owner .'''
    OBJECT_WRITER = "OBJECT_WRITER"
    '''The uploading account will own the object.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.OnCloudTrailBucketEventOptions",
    jsii_struct_bases=[_OnEventOptions_8711b8b3],
    name_mapping={
        "description": "description",
        "event_pattern": "eventPattern",
        "rule_name": "ruleName",
        "target": "target",
        "paths": "paths",
    },
)
class OnCloudTrailBucketEventOptions(_OnEventOptions_8711b8b3):
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
        paths: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Options for the onCloudTrailPutObject method.

        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        :param paths: Only watch changes to these object paths. Default: - Watch changes to all objects

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_events as events
            from aws_cdk import aws_s3 as s3
            
            # detail: Any
            # rule_target: events.IRuleTarget
            
            on_cloud_trail_bucket_event_options = s3.OnCloudTrailBucketEventOptions(
                description="description",
                event_pattern=events.EventPattern(
                    account=["account"],
                    detail={
                        "detail_key": detail
                    },
                    detail_type=["detailType"],
                    id=["id"],
                    region=["region"],
                    resources=["resources"],
                    source=["source"],
                    time=["time"],
                    version=["version"]
                ),
                paths=["paths"],
                rule_name="ruleName",
                target=rule_target
            )
        '''
        if isinstance(event_pattern, dict):
            event_pattern = _EventPattern_fe557901(**event_pattern)
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if event_pattern is not None:
            self._values["event_pattern"] = event_pattern
        if rule_name is not None:
            self._values["rule_name"] = rule_name
        if target is not None:
            self._values["target"] = target
        if paths is not None:
            self._values["paths"] = paths

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the rule's purpose.

        :default: - No description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def event_pattern(self) -> typing.Optional[_EventPattern_fe557901]:
        '''Additional restrictions for the event to route to the specified target.

        The method that generates the rule probably imposes some type of event
        filtering. The filtering implied by what you pass here is added
        on top of that filtering.

        :default: - No additional filtering based on an event pattern.

        :see: https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-and-event-patterns.html
        '''
        result = self._values.get("event_pattern")
        return typing.cast(typing.Optional[_EventPattern_fe557901], result)

    @builtins.property
    def rule_name(self) -> typing.Optional[builtins.str]:
        '''A name for the rule.

        :default: AWS CloudFormation generates a unique physical ID.
        '''
        result = self._values.get("rule_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def target(self) -> typing.Optional[_IRuleTarget_7a91f454]:
        '''The target to register for the event.

        :default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        result = self._values.get("target")
        return typing.cast(typing.Optional[_IRuleTarget_7a91f454], result)

    @builtins.property
    def paths(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Only watch changes to these object paths.

        :default: - Watch changes to all objects
        '''
        result = self._values.get("paths")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "OnCloudTrailBucketEventOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_s3.RedirectProtocol")
class RedirectProtocol(enum.Enum):
    '''All http request methods.

    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        bucket = s3.Bucket(self, "MyRedirectedBucket",
            website_routing_rules=[s3.RoutingRule(
                host_name="www.example.com",
                http_redirect_code="302",
                protocol=s3.RedirectProtocol.HTTPS,
                replace_key=s3.ReplaceKey.prefix_with("test/"),
                condition=s3.RoutingRuleCondition(
                    http_error_code_returned_equals="200",
                    key_prefix_equals="prefix"
                )
            )]
        )
    '''

    HTTP = "HTTP"
    HTTPS = "HTTPS"


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.RedirectTarget",
    jsii_struct_bases=[],
    name_mapping={"host_name": "hostName", "protocol": "protocol"},
)
class RedirectTarget:
    def __init__(
        self,
        *,
        host_name: builtins.str,
        protocol: typing.Optional[RedirectProtocol] = None,
    ) -> None:
        '''Specifies a redirect behavior of all requests to a website endpoint of a bucket.

        :param host_name: Name of the host where requests are redirected.
        :param protocol: Protocol to use when redirecting requests. Default: - The protocol used in the original request.

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            bucket = s3.Bucket(self, "MyRedirectedBucket",
                website_redirect=s3.RedirectTarget(host_name="www.example.com")
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "host_name": host_name,
        }
        if protocol is not None:
            self._values["protocol"] = protocol

    @builtins.property
    def host_name(self) -> builtins.str:
        '''Name of the host where requests are redirected.'''
        result = self._values.get("host_name")
        assert result is not None, "Required property 'host_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def protocol(self) -> typing.Optional[RedirectProtocol]:
        '''Protocol to use when redirecting requests.

        :default: - The protocol used in the original request.
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional[RedirectProtocol], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RedirectTarget(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class ReplaceKey(metaclass=jsii.JSIIMeta, jsii_type="aws-cdk-lib.aws_s3.ReplaceKey"):
    '''
    :exampleMetadata: infused

    Example::

        # Example automatically generated from non-compiling source. May contain errors.
        bucket = s3.Bucket(self, "MyRedirectedBucket",
            website_routing_rules=[s3.RoutingRule(
                host_name="www.example.com",
                http_redirect_code="302",
                protocol=s3.RedirectProtocol.HTTPS,
                replace_key=s3.ReplaceKey.prefix_with("test/"),
                condition=s3.RoutingRuleCondition(
                    http_error_code_returned_equals="200",
                    key_prefix_equals="prefix"
                )
            )]
        )
    '''

    @jsii.member(jsii_name="prefixWith") # type: ignore[misc]
    @builtins.classmethod
    def prefix_with(cls, key_replacement: builtins.str) -> "ReplaceKey":
        '''The object key prefix to use in the redirect request.

        :param key_replacement: -
        '''
        return typing.cast("ReplaceKey", jsii.sinvoke(cls, "prefixWith", [key_replacement]))

    @jsii.member(jsii_name="with") # type: ignore[misc]
    @builtins.classmethod
    def with_(cls, key_replacement: builtins.str) -> "ReplaceKey":
        '''The specific object key to use in the redirect request.

        :param key_replacement: -
        '''
        return typing.cast("ReplaceKey", jsii.sinvoke(cls, "with", [key_replacement]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="prefixWithKey")
    def prefix_with_key(self) -> typing.Optional[builtins.str]:
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "prefixWithKey"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="withKey")
    def with_key(self) -> typing.Optional[builtins.str]:
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "withKey"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.RoutingRule",
    jsii_struct_bases=[],
    name_mapping={
        "condition": "condition",
        "host_name": "hostName",
        "http_redirect_code": "httpRedirectCode",
        "protocol": "protocol",
        "replace_key": "replaceKey",
    },
)
class RoutingRule:
    def __init__(
        self,
        *,
        condition: typing.Optional["RoutingRuleCondition"] = None,
        host_name: typing.Optional[builtins.str] = None,
        http_redirect_code: typing.Optional[builtins.str] = None,
        protocol: typing.Optional[RedirectProtocol] = None,
        replace_key: typing.Optional[ReplaceKey] = None,
    ) -> None:
        '''Rule that define when a redirect is applied and the redirect behavior.

        :param condition: Specifies a condition that must be met for the specified redirect to apply. Default: - No condition
        :param host_name: The host name to use in the redirect request. Default: - The host name used in the original request.
        :param http_redirect_code: The HTTP redirect code to use on the response. Default: "301" - Moved Permanently
        :param protocol: Protocol to use when redirecting requests. Default: - The protocol used in the original request.
        :param replace_key: Specifies the object key prefix to use in the redirect request. Default: - The key will not be replaced

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/how-to-page-redirect.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            
            # replace_key: s3.ReplaceKey
            
            routing_rule = s3.RoutingRule(
                condition=s3.RoutingRuleCondition(
                    http_error_code_returned_equals="httpErrorCodeReturnedEquals",
                    key_prefix_equals="keyPrefixEquals"
                ),
                host_name="hostName",
                http_redirect_code="httpRedirectCode",
                protocol=s3.RedirectProtocol.HTTP,
                replace_key=replace_key
            )
        '''
        if isinstance(condition, dict):
            condition = RoutingRuleCondition(**condition)
        self._values: typing.Dict[str, typing.Any] = {}
        if condition is not None:
            self._values["condition"] = condition
        if host_name is not None:
            self._values["host_name"] = host_name
        if http_redirect_code is not None:
            self._values["http_redirect_code"] = http_redirect_code
        if protocol is not None:
            self._values["protocol"] = protocol
        if replace_key is not None:
            self._values["replace_key"] = replace_key

    @builtins.property
    def condition(self) -> typing.Optional["RoutingRuleCondition"]:
        '''Specifies a condition that must be met for the specified redirect to apply.

        :default: - No condition
        '''
        result = self._values.get("condition")
        return typing.cast(typing.Optional["RoutingRuleCondition"], result)

    @builtins.property
    def host_name(self) -> typing.Optional[builtins.str]:
        '''The host name to use in the redirect request.

        :default: - The host name used in the original request.
        '''
        result = self._values.get("host_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def http_redirect_code(self) -> typing.Optional[builtins.str]:
        '''The HTTP redirect code to use on the response.

        :default: "301" - Moved Permanently
        '''
        result = self._values.get("http_redirect_code")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def protocol(self) -> typing.Optional[RedirectProtocol]:
        '''Protocol to use when redirecting requests.

        :default: - The protocol used in the original request.
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional[RedirectProtocol], result)

    @builtins.property
    def replace_key(self) -> typing.Optional[ReplaceKey]:
        '''Specifies the object key prefix to use in the redirect request.

        :default: - The key will not be replaced
        '''
        result = self._values.get("replace_key")
        return typing.cast(typing.Optional[ReplaceKey], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RoutingRule(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.RoutingRuleCondition",
    jsii_struct_bases=[],
    name_mapping={
        "http_error_code_returned_equals": "httpErrorCodeReturnedEquals",
        "key_prefix_equals": "keyPrefixEquals",
    },
)
class RoutingRuleCondition:
    def __init__(
        self,
        *,
        http_error_code_returned_equals: typing.Optional[builtins.str] = None,
        key_prefix_equals: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param http_error_code_returned_equals: The HTTP error code when the redirect is applied. In the event of an error, if the error code equals this value, then the specified redirect is applied. If both condition properties are specified, both must be true for the redirect to be applied. Default: - The HTTP error code will not be verified
        :param key_prefix_equals: The object key name prefix when the redirect is applied. If both condition properties are specified, both must be true for the redirect to be applied. Default: - The object key name will not be verified

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            bucket = s3.Bucket(self, "MyRedirectedBucket",
                website_routing_rules=[s3.RoutingRule(
                    host_name="www.example.com",
                    http_redirect_code="302",
                    protocol=s3.RedirectProtocol.HTTPS,
                    replace_key=s3.ReplaceKey.prefix_with("test/"),
                    condition=s3.RoutingRuleCondition(
                        http_error_code_returned_equals="200",
                        key_prefix_equals="prefix"
                    )
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if http_error_code_returned_equals is not None:
            self._values["http_error_code_returned_equals"] = http_error_code_returned_equals
        if key_prefix_equals is not None:
            self._values["key_prefix_equals"] = key_prefix_equals

    @builtins.property
    def http_error_code_returned_equals(self) -> typing.Optional[builtins.str]:
        '''The HTTP error code when the redirect is applied.

        In the event of an error, if the error code equals this value, then the specified redirect is applied.

        If both condition properties are specified, both must be true for the redirect to be applied.

        :default: - The HTTP error code will not be verified
        '''
        result = self._values.get("http_error_code_returned_equals")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def key_prefix_equals(self) -> typing.Optional[builtins.str]:
        '''The object key name prefix when the redirect is applied.

        If both condition properties are specified, both must be true for the redirect to be applied.

        :default: - The object key name will not be verified
        '''
        result = self._values.get("key_prefix_equals")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RoutingRuleCondition(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class StorageClass(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_s3.StorageClass",
):
    '''Storage class to move an object to.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_s3 as s3
        
        storage_class = s3.StorageClass.DEEP_ARCHIVE
    '''

    def __init__(self, value: builtins.str) -> None:
        '''
        :param value: -
        '''
        jsii.create(self.__class__, self, [value])

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="DEEP_ARCHIVE")
    def DEEP_ARCHIVE(cls) -> "StorageClass":
        '''Use for archiving data that rarely needs to be accessed.

        Data stored in the
        DEEP_ARCHIVE storage class has a minimum storage duration period of 180
        days and a default retrieval time of 12 hours. If you delete an object
        before the 180-day minimum, you are charged for 180 days. For pricing
        information, see Amazon S3 Pricing.
        '''
        return typing.cast("StorageClass", jsii.sget(cls, "DEEP_ARCHIVE"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GLACIER")
    def GLACIER(cls) -> "StorageClass":
        '''Storage class for long-term archival that can take between minutes and hours to access.

        Use for archives where portions of the data might need to be retrieved in
        minutes. Data stored in the GLACIER storage class has a minimum storage
        duration period of 90 days and can be accessed in as little as 1-5 minutes
        using expedited retrieval. If you delete an object before the 90-day
        minimum, you are charged for 90 days.
        '''
        return typing.cast("StorageClass", jsii.sget(cls, "GLACIER"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="GLACIER_INSTANT_RETRIEVAL")
    def GLACIER_INSTANT_RETRIEVAL(cls) -> "StorageClass":
        '''Storage class for long-term archival that can be accessed in a few milliseconds.

        It is ideal for data that is accessed once or twice per quarter, and
        that requires immediate access. Data stored in the GLACIER_IR storage class
        has a minimum storage duration period of 90 days and can be accessed in
        as milliseconds. If you delete an object before the 90-day minimum,
        you are charged for 90 days.
        '''
        return typing.cast("StorageClass", jsii.sget(cls, "GLACIER_INSTANT_RETRIEVAL"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="INFREQUENT_ACCESS")
    def INFREQUENT_ACCESS(cls) -> "StorageClass":
        '''Storage class for data that is accessed less frequently, but requires rapid access when needed.

        Has lower availability than Standard storage.
        '''
        return typing.cast("StorageClass", jsii.sget(cls, "INFREQUENT_ACCESS"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="INTELLIGENT_TIERING")
    def INTELLIGENT_TIERING(cls) -> "StorageClass":
        '''The INTELLIGENT_TIERING storage class is designed to optimize storage costs by automatically moving data to the most cost-effective storage access tier, without performance impact or operational overhead.

        INTELLIGENT_TIERING delivers automatic cost savings by moving data on a
        granular object level between two access tiers, a frequent access tier and
        a lower-cost infrequent access tier, when access patterns change. The
        INTELLIGENT_TIERING storage class is ideal if you want to optimize storage
        costs automatically for long-lived data when access patterns are unknown or
        unpredictable.
        '''
        return typing.cast("StorageClass", jsii.sget(cls, "INTELLIGENT_TIERING"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="ONE_ZONE_INFREQUENT_ACCESS")
    def ONE_ZONE_INFREQUENT_ACCESS(cls) -> "StorageClass":
        '''Infrequent Access that's only stored in one availability zone.

        Has lower availability than standard InfrequentAccess.
        '''
        return typing.cast("StorageClass", jsii.sget(cls, "ONE_ZONE_INFREQUENT_ACCESS"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="value")
    def value(self) -> builtins.str:
        return typing.cast(builtins.str, jsii.get(self, "value"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.Tag",
    jsii_struct_bases=[],
    name_mapping={"key": "key", "value": "value"},
)
class Tag:
    def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
        '''Tag.

        :param key: key to e tagged.
        :param value: additional value.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            
            tag = s3.Tag(
                key="key",
                value="value"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "key": key,
            "value": value,
        }

    @builtins.property
    def key(self) -> builtins.str:
        '''key to e tagged.'''
        result = self._values.get("key")
        assert result is not None, "Required property 'key' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def value(self) -> builtins.str:
        '''additional value.'''
        result = self._values.get("value")
        assert result is not None, "Required property 'value' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "Tag(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.TransferAccelerationUrlOptions",
    jsii_struct_bases=[],
    name_mapping={"dual_stack": "dualStack"},
)
class TransferAccelerationUrlOptions:
    def __init__(self, *, dual_stack: typing.Optional[builtins.bool] = None) -> None:
        '''Options for creating a Transfer Acceleration URL.

        :param dual_stack: Dual-stack support to connect to the bucket over IPv6. Default: - false

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_s3 as s3
            
            transfer_acceleration_url_options = s3.TransferAccelerationUrlOptions(
                dual_stack=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if dual_stack is not None:
            self._values["dual_stack"] = dual_stack

    @builtins.property
    def dual_stack(self) -> typing.Optional[builtins.bool]:
        '''Dual-stack support to connect to the bucket over IPv6.

        :default: - false
        '''
        result = self._values.get("dual_stack")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "TransferAccelerationUrlOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.Transition",
    jsii_struct_bases=[],
    name_mapping={
        "storage_class": "storageClass",
        "transition_after": "transitionAfter",
        "transition_date": "transitionDate",
    },
)
class Transition:
    def __init__(
        self,
        *,
        storage_class: StorageClass,
        transition_after: typing.Optional[_Duration_4839e8c3] = None,
        transition_date: typing.Optional[datetime.datetime] = None,
    ) -> None:
        '''Describes when an object transitions to a specified storage class.

        :param storage_class: The storage class to which you want the object to transition.
        :param transition_after: Indicates the number of days after creation when objects are transitioned to the specified storage class. Default: No transition count.
        :param transition_date: Indicates when objects are transitioned to the specified storage class. The date value must be in ISO 8601 format. The time is always midnight UTC. Default: No transition date.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_s3 as s3
            
            # storage_class: s3.StorageClass
            
            transition = s3.Transition(
                storage_class=storage_class,
            
                # the properties below are optional
                transition_after=cdk.Duration.minutes(30),
                transition_date=Date()
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "storage_class": storage_class,
        }
        if transition_after is not None:
            self._values["transition_after"] = transition_after
        if transition_date is not None:
            self._values["transition_date"] = transition_date

    @builtins.property
    def storage_class(self) -> StorageClass:
        '''The storage class to which you want the object to transition.'''
        result = self._values.get("storage_class")
        assert result is not None, "Required property 'storage_class' is missing"
        return typing.cast(StorageClass, result)

    @builtins.property
    def transition_after(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Indicates the number of days after creation when objects are transitioned to the specified storage class.

        :default: No transition count.
        '''
        result = self._values.get("transition_after")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def transition_date(self) -> typing.Optional[datetime.datetime]:
        '''Indicates when objects are transitioned to the specified storage class.

        The date value must be in ISO 8601 format. The time is always midnight UTC.

        :default: No transition date.
        '''
        result = self._values.get("transition_date")
        return typing.cast(typing.Optional[datetime.datetime], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "Transition(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_s3.VirtualHostedStyleUrlOptions",
    jsii_struct_bases=[],
    name_mapping={"regional": "regional"},
)
class VirtualHostedStyleUrlOptions:
    def __init__(self, *, regional: typing.Optional[builtins.bool] = None) -> None:
        '''Options for creating Virtual-Hosted style URL.

        :param regional: Specifies the URL includes the region. Default: - true

        :exampleMetadata: infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            bucket = s3.Bucket(self, "MyBucket")
            bucket.url_for_object("objectname") # Path-Style URL
            bucket.virtual_hosted_url_for_object("objectname") # Virtual Hosted-Style URL
            bucket.virtual_hosted_url_for_object("objectname", regional=False)
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if regional is not None:
            self._values["regional"] = regional

    @builtins.property
    def regional(self) -> typing.Optional[builtins.bool]:
        '''Specifies the URL includes the region.

        :default: - true
        '''
        result = self._values.get("regional")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "VirtualHostedStyleUrlOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IBucket)
class BucketBase(
    _Resource_45bc6135,
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_s3.BucketBase",
):
    '''Represents an S3 Bucket.

    Buckets can be either defined within this stack:

    new Bucket(this, 'MyBucket', { props });

    Or imported from an existing bucket:

    Bucket.import(this, 'MyImportedBucket', { bucketArn: ... });

    You can also export a bucket and import it into another stack:

    const ref = myBucket.export();
    Bucket.import(this, 'MyImportedBucket', ref);
    '''

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

    @jsii.member(jsii_name="addEventNotification")
    def add_event_notification(
        self,
        event: EventType,
        dest: IBucketNotificationDestination,
        *filters: NotificationKeyFilter,
    ) -> None:
        '''Adds a bucket notification event destination.

        :param event: The event to trigger the notification.
        :param dest: The notification destination (Lambda, SNS Topic or SQS Queue).
        :param filters: S3 object key filter rules to determine which objects trigger this event. Each filter must include a ``prefix`` and/or ``suffix`` that will be matched against the s3 object key. Refer to the S3 Developer Guide for details about allowed filter rules.

        :see: https://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            # my_lambda: lambda.Function
            
            bucket = s3.Bucket(self, "MyBucket")
            bucket.add_event_notification(s3.EventType.OBJECT_CREATED, s3n.LambdaDestination(my_lambda), prefix="home/myusername/*")
        '''
        return typing.cast(None, jsii.invoke(self, "addEventNotification", [event, dest, *filters]))

    @jsii.member(jsii_name="addObjectCreatedNotification")
    def add_object_created_notification(
        self,
        dest: IBucketNotificationDestination,
        *filters: NotificationKeyFilter,
    ) -> None:
        '''Subscribes a destination to receive notifications when an object is created in the bucket.

        This is identical to calling
        ``onEvent(EventType.OBJECT_CREATED)``.

        :param dest: The notification destination (see onEvent).
        :param filters: Filters (see onEvent).
        '''
        return typing.cast(None, jsii.invoke(self, "addObjectCreatedNotification", [dest, *filters]))

    @jsii.member(jsii_name="addObjectRemovedNotification")
    def add_object_removed_notification(
        self,
        dest: IBucketNotificationDestination,
        *filters: NotificationKeyFilter,
    ) -> None:
        '''Subscribes a destination to receive notifications when an object is removed from the bucket.

        This is identical to calling
        ``onEvent(EventType.OBJECT_REMOVED)``.

        :param dest: The notification destination (see onEvent).
        :param filters: Filters (see onEvent).
        '''
        return typing.cast(None, jsii.invoke(self, "addObjectRemovedNotification", [dest, *filters]))

    @jsii.member(jsii_name="addToResourcePolicy")
    def add_to_resource_policy(
        self,
        permission: _PolicyStatement_0fe33853,
    ) -> _AddToResourcePolicyResult_1d0a53ad:
        '''Adds a statement to the resource policy for a principal (i.e. account/role/service) to perform actions on this bucket and/or its contents. Use ``bucketArn`` and ``arnForObjects(keys)`` to obtain ARNs for this bucket or objects.

        Note that the policy statement may or may not be added to the policy.
        For example, when an ``IBucket`` is created from an existing bucket,
        it's not possible to tell whether the bucket already has a policy
        attached, let alone to re-use that policy to add more statements to it.
        So it's safest to do nothing in these cases.

        :param permission: the policy statement to be added to the bucket's policy.

        :return:

        metadata about the execution of this method. If the policy
        was not added, the value of ``statementAdded`` will be ``false``. You
        should always check this value to make sure that the operation was
        actually carried out. Otherwise, synthesis and deploy will terminate
        silently, which may be confusing.
        '''
        return typing.cast(_AddToResourcePolicyResult_1d0a53ad, jsii.invoke(self, "addToResourcePolicy", [permission]))

    @jsii.member(jsii_name="arnForObjects")
    def arn_for_objects(self, key_pattern: builtins.str) -> builtins.str:
        '''Returns an ARN that represents all objects within the bucket that match the key pattern specified.

        To represent all keys, specify ``"*"``.

        If you need to specify a keyPattern with multiple components, concatenate them into a single string, e.g.:

        arnForObjects(``home/${team}/${user}/*``)

        :param key_pattern: -
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "arnForObjects", [key_pattern]))

    @jsii.member(jsii_name="grantDelete")
    def grant_delete(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grants s3:DeleteObject* permission to an IAM principal for objects in this bucket.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantDelete", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="grantPublicAccess")
    def grant_public_access(
        self,
        key_prefix: typing.Optional[builtins.str] = None,
        *allowed_actions: builtins.str,
    ) -> _Grant_a7ae64f8:
        '''Allows unrestricted access to objects from this bucket.

        IMPORTANT: This permission allows anyone to perform actions on S3 objects
        in this bucket, which is useful for when you configure your bucket as a
        website and want everyone to be able to read objects in the bucket without
        needing to authenticate.

        Without arguments, this method will grant read ("s3:GetObject") access to
        all objects ("*") in the bucket.

        The method returns the ``iam.Grant`` object, which can then be modified
        as needed. For example, you can add a condition that will restrict access only
        to an IPv4 range like this::

            const grant = bucket.grantPublicAccess();
            grant.resourceStatement!.addCondition(‘IpAddress’, { “aws:SourceIp”: “54.240.143.0/24” });

        Note that if this ``IBucket`` refers to an existing bucket, possibly not
        managed by CloudFormation, this method will have no effect, since it's
        impossible to modify the policy of an existing bucket.

        :param key_prefix: the prefix of S3 object keys (e.g. ``home/*``). Default is "*".
        :param allowed_actions: the set of S3 actions to allow. Default is "s3:GetObject".
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPublicAccess", [key_prefix, *allowed_actions]))

    @jsii.member(jsii_name="grantPut")
    def grant_put(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grants s3:PutObject* and s3:Abort* permissions for this bucket to an IAM principal.

        If encryption is used, permission to use the key to encrypt the contents
        of written files will also be granted to the same principal.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPut", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="grantPutAcl")
    def grant_put_acl(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Optional[builtins.str] = None,
    ) -> _Grant_a7ae64f8:
        '''Grant the given IAM identity permissions to modify the ACLs of objects in the given Bucket.

        If your application has the '@aws-cdk/aws-s3:grantWriteWithoutAcl' feature flag set,
        calling {@link grantWrite} or {@link grantReadWrite} no longer grants permissions to modify the ACLs of the objects;
        in this case, if you need to modify object ACLs, call this method explicitly.

        :param identity: -
        :param objects_key_pattern: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPutAcl", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="grantRead")
    def grant_read(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grant read permissions for this bucket and it's contents to an IAM principal (Role/Group/User).

        If encryption is used, permission to use the key to decrypt the contents
        of the bucket will also be granted to the same principal.

        :param identity: The principal.
        :param objects_key_pattern: Restrict the permission to a certain key pattern (default '*').
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantRead", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="grantReadWrite")
    def grant_read_write(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grants read/write permissions for this bucket and it's contents to an IAM principal (Role/Group/User).

        If an encryption key is used, permission to use the key for
        encrypt/decrypt will also be granted.

        Before CDK version 1.85.0, this method granted the ``s3:PutObject*`` permission that included ``s3:PutObjectAcl``,
        which could be used to grant read/write object access to IAM principals in other accounts.
        If you want to get rid of that behavior, update your CDK version to 1.85.0 or later,
        and make sure the ``@aws-cdk/aws-s3:grantWriteWithoutAcl`` feature flag is set to ``true``
        in the ``context`` key of your cdk.json file.
        If you've already updated, but still need the principal to have permissions to modify the ACLs,
        use the {@link grantPutAcl} method.

        :param identity: -
        :param objects_key_pattern: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantReadWrite", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="grantWrite")
    def grant_write(
        self,
        identity: _IGrantable_71c4f5de,
        objects_key_pattern: typing.Any = None,
    ) -> _Grant_a7ae64f8:
        '''Grant write permissions to this bucket to an IAM principal.

        If encryption is used, permission to use the key to encrypt the contents
        of written files will also be granted to the same principal.

        Before CDK version 1.85.0, this method granted the ``s3:PutObject*`` permission that included ``s3:PutObjectAcl``,
        which could be used to grant read/write object access to IAM principals in other accounts.
        If you want to get rid of that behavior, update your CDK version to 1.85.0 or later,
        and make sure the ``@aws-cdk/aws-s3:grantWriteWithoutAcl`` feature flag is set to ``true``
        in the ``context`` key of your cdk.json file.
        If you've already updated, but still need the principal to have permissions to modify the ACLs,
        use the {@link grantPutAcl} method.

        :param identity: -
        :param objects_key_pattern: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantWrite", [identity, objects_key_pattern]))

    @jsii.member(jsii_name="onCloudTrailEvent")
    def on_cloud_trail_event(
        self,
        id: builtins.str,
        *,
        paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Define a CloudWatch event that triggers when something happens to this repository.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param paths: Only watch changes to these object paths. Default: - Watch changes to all objects
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnCloudTrailBucketEventOptions(
            paths=paths,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCloudTrailEvent", [id, options]))

    @jsii.member(jsii_name="onCloudTrailPutObject")
    def on_cloud_trail_put_object(
        self,
        id: builtins.str,
        *,
        paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event that triggers when an object is uploaded to the specified paths (keys) in this bucket using the PutObject API call.

        Note that some tools like ``aws s3 cp`` will automatically use either
        PutObject or the multipart upload API depending on the file size,
        so using ``onCloudTrailWriteObject`` may be preferable.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param paths: Only watch changes to these object paths. Default: - Watch changes to all objects
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnCloudTrailBucketEventOptions(
            paths=paths,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCloudTrailPutObject", [id, options]))

    @jsii.member(jsii_name="onCloudTrailWriteObject")
    def on_cloud_trail_write_object(
        self,
        id: builtins.str,
        *,
        paths: typing.Optional[typing.Sequence[builtins.str]] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[_EventPattern_fe557901] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[_IRuleTarget_7a91f454] = None,
    ) -> _Rule_334ed2b5:
        '''Defines an AWS CloudWatch event that triggers when an object at the specified paths (keys) in this bucket are written to.

        This includes
        the events PutObject, CopyObject, and CompleteMultipartUpload.

        Note that some tools like ``aws s3 cp`` will automatically use either
        PutObject or the multipart upload API depending on the file size,
        so using this method may be preferable to ``onCloudTrailPutObject``.

        Requires that there exists at least one CloudTrail Trail in your account
        that captures the event. This method will not create the Trail.

        :param id: The id of the rule.
        :param paths: Only watch changes to these object paths. Default: - Watch changes to all objects
        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        options = OnCloudTrailBucketEventOptions(
            paths=paths,
            description=description,
            event_pattern=event_pattern,
            rule_name=rule_name,
            target=target,
        )

        return typing.cast(_Rule_334ed2b5, jsii.invoke(self, "onCloudTrailWriteObject", [id, options]))

    @jsii.member(jsii_name="s3UrlForObject")
    def s3_url_for_object(
        self,
        key: typing.Optional[builtins.str] = None,
    ) -> builtins.str:
        '''The S3 URL of an S3 object. For example:.

        - ``s3://onlybucket``
        - ``s3://bucket/key``

        :param key: The S3 key of the object. If not specified, the S3 URL of the bucket is returned.

        :return: an ObjectS3Url token
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "s3UrlForObject", [key]))

    @jsii.member(jsii_name="transferAccelerationUrlForObject")
    def transfer_acceleration_url_for_object(
        self,
        key: typing.Optional[builtins.str] = None,
        *,
        dual_stack: typing.Optional[builtins.bool] = None,
    ) -> builtins.str:
        '''The https Transfer Acceleration URL of an S3 object.

        Specify ``dualStack: true`` at the options
        for dual-stack endpoint (connect to the bucket over IPv6). For example:

        - ``https://bucket.s3-accelerate.amazonaws.com``
        - ``https://bucket.s3-accelerate.amazonaws.com/key``

        :param key: The S3 key of the object. If not specified, the URL of the bucket is returned.
        :param dual_stack: Dual-stack support to connect to the bucket over IPv6. Default: - false

        :return: an TransferAccelerationUrl token
        '''
        options = TransferAccelerationUrlOptions(dual_stack=dual_stack)

        return typing.cast(builtins.str, jsii.invoke(self, "transferAccelerationUrlForObject", [key, options]))

    @jsii.member(jsii_name="urlForObject")
    def url_for_object(self, key: typing.Optional[builtins.str] = None) -> builtins.str:
        '''The https URL of an S3 object. Specify ``regional: false`` at the options for non-regional URLs. For example:.

        - ``https://s3.us-west-1.amazonaws.com/onlybucket``
        - ``https://s3.us-west-1.amazonaws.com/bucket/key``
        - ``https://s3.cn-north-1.amazonaws.com.cn/china-bucket/mykey``

        :param key: The S3 key of the object. If not specified, the URL of the bucket is returned.

        :return: an ObjectS3Url token
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "urlForObject", [key]))

    @jsii.member(jsii_name="virtualHostedUrlForObject")
    def virtual_hosted_url_for_object(
        self,
        key: typing.Optional[builtins.str] = None,
        *,
        regional: typing.Optional[builtins.bool] = None,
    ) -> builtins.str:
        '''The virtual hosted-style URL of an S3 object. Specify ``regional: false`` at the options for non-regional URL. For example:.

        - ``https://only-bucket.s3.us-west-1.amazonaws.com``
        - ``https://bucket.s3.us-west-1.amazonaws.com/key``
        - ``https://bucket.s3.amazonaws.com/key``
        - ``https://china-bucket.s3.cn-north-1.amazonaws.com.cn/mykey``

        :param key: The S3 key of the object. If not specified, the URL of the bucket is returned.
        :param regional: Specifies the URL includes the region. Default: - true

        :return: an ObjectS3Url token
        '''
        options = VirtualHostedStyleUrlOptions(regional=regional)

        return typing.cast(builtins.str, jsii.invoke(self, "virtualHostedUrlForObject", [key, options]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketArn")
    @abc.abstractmethod
    def bucket_arn(self) -> builtins.str:
        '''The ARN of the bucket.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketDomainName")
    @abc.abstractmethod
    def bucket_domain_name(self) -> builtins.str:
        '''The IPv4 DNS name of the specified bucket.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketDualStackDomainName")
    @abc.abstractmethod
    def bucket_dual_stack_domain_name(self) -> builtins.str:
        '''The IPv6 DNS name of the specified bucket.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketName")
    @abc.abstractmethod
    def bucket_name(self) -> builtins.str:
        '''The name of the bucket.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketRegionalDomainName")
    @abc.abstractmethod
    def bucket_regional_domain_name(self) -> builtins.str:
        '''The regional domain name of the specified bucket.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketWebsiteDomainName")
    @abc.abstractmethod
    def bucket_website_domain_name(self) -> builtins.str:
        '''The Domain name of the static website.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketWebsiteUrl")
    @abc.abstractmethod
    def bucket_website_url(self) -> builtins.str:
        '''The URL of the static website.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionKey")
    @abc.abstractmethod
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''Optional KMS encryption key associated with this bucket.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isWebsite")
    @abc.abstractmethod
    def is_website(self) -> typing.Optional[builtins.bool]:
        '''If this bucket has been configured for static website hosting.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoCreatePolicy")
    @abc.abstractmethod
    def _auto_create_policy(self) -> builtins.bool:
        '''Indicates if a bucket resource policy should automatically created upon the first call to ``addToResourcePolicy``.'''
        ...

    @_auto_create_policy.setter
    @abc.abstractmethod
    def _auto_create_policy(self, value: builtins.bool) -> None:
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="disallowPublicAccess")
    @abc.abstractmethod
    def _disallow_public_access(self) -> typing.Optional[builtins.bool]:
        '''Whether to disallow public access.'''
        ...

    @_disallow_public_access.setter
    @abc.abstractmethod
    def _disallow_public_access(self, value: typing.Optional[builtins.bool]) -> None:
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationsHandlerRole")
    def _notifications_handler_role(self) -> typing.Optional[_IRole_235f5d8e]:
        return typing.cast(typing.Optional[_IRole_235f5d8e], jsii.get(self, "notificationsHandlerRole"))

    @_notifications_handler_role.setter
    def _notifications_handler_role(
        self,
        value: typing.Optional[_IRole_235f5d8e],
    ) -> None:
        jsii.set(self, "notificationsHandlerRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policy")
    @abc.abstractmethod
    def policy(self) -> typing.Optional[BucketPolicy]:
        '''The resource policy associated with this bucket.

        If ``autoCreatePolicy`` is true, a ``BucketPolicy`` will be created upon the
        first call to addToResourcePolicy(s).
        '''
        ...

    @policy.setter
    @abc.abstractmethod
    def policy(self, value: typing.Optional[BucketPolicy]) -> None:
        ...


class _BucketBaseProxy(
    BucketBase, jsii.proxy_for(_Resource_45bc6135) # type: ignore[misc]
):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketArn")
    def bucket_arn(self) -> builtins.str:
        '''The ARN of the bucket.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketDomainName")
    def bucket_domain_name(self) -> builtins.str:
        '''The IPv4 DNS name of the specified bucket.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketDualStackDomainName")
    def bucket_dual_stack_domain_name(self) -> builtins.str:
        '''The IPv6 DNS name of the specified bucket.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketDualStackDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketName")
    def bucket_name(self) -> builtins.str:
        '''The name of the bucket.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketRegionalDomainName")
    def bucket_regional_domain_name(self) -> builtins.str:
        '''The regional domain name of the specified bucket.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketRegionalDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketWebsiteDomainName")
    def bucket_website_domain_name(self) -> builtins.str:
        '''The Domain name of the static website.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketWebsiteDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketWebsiteUrl")
    def bucket_website_url(self) -> builtins.str:
        '''The URL of the static website.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketWebsiteUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionKey")
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''Optional KMS encryption key associated with this bucket.'''
        return typing.cast(typing.Optional[_IKey_5f11635f], jsii.get(self, "encryptionKey"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isWebsite")
    def is_website(self) -> typing.Optional[builtins.bool]:
        '''If this bucket has been configured for static website hosting.'''
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "isWebsite"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoCreatePolicy")
    def _auto_create_policy(self) -> builtins.bool:
        '''Indicates if a bucket resource policy should automatically created upon the first call to ``addToResourcePolicy``.'''
        return typing.cast(builtins.bool, jsii.get(self, "autoCreatePolicy"))

    @_auto_create_policy.setter
    def _auto_create_policy(self, value: builtins.bool) -> None:
        jsii.set(self, "autoCreatePolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="disallowPublicAccess")
    def _disallow_public_access(self) -> typing.Optional[builtins.bool]:
        '''Whether to disallow public access.'''
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "disallowPublicAccess"))

    @_disallow_public_access.setter
    def _disallow_public_access(self, value: typing.Optional[builtins.bool]) -> None:
        jsii.set(self, "disallowPublicAccess", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policy")
    def policy(self) -> typing.Optional[BucketPolicy]:
        '''The resource policy associated with this bucket.

        If ``autoCreatePolicy`` is true, a ``BucketPolicy`` will be created upon the
        first call to addToResourcePolicy(s).
        '''
        return typing.cast(typing.Optional[BucketPolicy], jsii.get(self, "policy"))

    @policy.setter
    def policy(self, value: typing.Optional[BucketPolicy]) -> None:
        jsii.set(self, "policy", value)

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, BucketBase).__jsii_proxy_class__ = lambda : _BucketBaseProxy


class Bucket(
    BucketBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_s3.Bucket",
):
    '''An S3 bucket with associated policy objects.

    This bucket does not yet have all features that exposed by the underlying
    BucketResource.

    :exampleMetadata: infused

    Example::

        # ecr_repository: ecr.Repository
        
        
        codebuild.Project(self, "Project",
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.WindowsBuildImage.from_ecr_repository(ecr_repository, "v1.0", codebuild.WindowsImageType.SERVER_2019),
                # optional certificate to include in the build image
                certificate=codebuild.BuildEnvironmentCertificate(
                    bucket=s3.Bucket.from_bucket_name(self, "Bucket", "my-bucket"),
                    object_key="path/to/cert.pem"
                )
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        access_control: typing.Optional[BucketAccessControl] = None,
        auto_delete_objects: typing.Optional[builtins.bool] = None,
        block_public_access: typing.Optional[BlockPublicAccess] = None,
        bucket_key_enabled: typing.Optional[builtins.bool] = None,
        bucket_name: typing.Optional[builtins.str] = None,
        cors: typing.Optional[typing.Sequence[CorsRule]] = None,
        encryption: typing.Optional[BucketEncryption] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        enforce_ssl: typing.Optional[builtins.bool] = None,
        intelligent_tiering_configurations: typing.Optional[typing.Sequence[IntelligentTieringConfiguration]] = None,
        inventories: typing.Optional[typing.Sequence[Inventory]] = None,
        lifecycle_rules: typing.Optional[typing.Sequence[LifecycleRule]] = None,
        metrics: typing.Optional[typing.Sequence[BucketMetrics]] = None,
        notifications_handler_role: typing.Optional[_IRole_235f5d8e] = None,
        object_ownership: typing.Optional[ObjectOwnership] = None,
        public_read_access: typing.Optional[builtins.bool] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        server_access_logs_bucket: typing.Optional[IBucket] = None,
        server_access_logs_prefix: typing.Optional[builtins.str] = None,
        transfer_acceleration: typing.Optional[builtins.bool] = None,
        versioned: typing.Optional[builtins.bool] = None,
        website_error_document: typing.Optional[builtins.str] = None,
        website_index_document: typing.Optional[builtins.str] = None,
        website_redirect: typing.Optional[RedirectTarget] = None,
        website_routing_rules: typing.Optional[typing.Sequence[RoutingRule]] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param access_control: Specifies a canned ACL that grants predefined permissions to the bucket. Default: BucketAccessControl.PRIVATE
        :param auto_delete_objects: Whether all objects should be automatically deleted when the bucket is removed from the stack or when the stack is deleted. Requires the ``removalPolicy`` to be set to ``RemovalPolicy.DESTROY``. **Warning** if you have deployed a bucket with ``autoDeleteObjects: true``, switching this to ``false`` in a CDK version *before* ``1.126.0`` will lead to all objects in the bucket being deleted. Be sure to update your bucket resources by deploying with CDK version ``1.126.0`` or later **before** switching this value to ``false``. Default: false
        :param block_public_access: The block public access configuration of this bucket. Default: - CloudFormation defaults will apply. New buckets and objects don't allow public access, but users can modify bucket policies or object permissions to allow public access
        :param bucket_key_enabled: Specifies whether Amazon S3 should use an S3 Bucket Key with server-side encryption using KMS (SSE-KMS) for new objects in the bucket. Only relevant, when Encryption is set to {@link BucketEncryption.KMS} Default: - false
        :param bucket_name: Physical name of this bucket. Default: - Assigned by CloudFormation (recommended).
        :param cors: The CORS configuration of this bucket. Default: - No CORS configuration.
        :param encryption: The kind of server-side encryption to apply to this bucket. If you choose KMS, you can specify a KMS key via ``encryptionKey``. If encryption key is not specified, a key will automatically be created. Default: - ``Kms`` if ``encryptionKey`` is specified, or ``Unencrypted`` otherwise.
        :param encryption_key: External KMS key to use for bucket encryption. The 'encryption' property must be either not specified or set to "Kms". An error will be emitted if encryption is set to "Unencrypted" or "Managed". Default: - If encryption is set to "Kms" and this property is undefined, a new KMS key will be created and associated with this bucket.
        :param enforce_ssl: Enforces SSL for requests. S3.5 of the AWS Foundational Security Best Practices Regarding S3. Default: false
        :param intelligent_tiering_configurations: Inteligent Tiering Configurations. Default: No Intelligent Tiiering Configurations.
        :param inventories: The inventory configuration of the bucket. Default: - No inventory configuration
        :param lifecycle_rules: Rules that define how Amazon S3 manages objects during their lifetime. Default: - No lifecycle rules.
        :param metrics: The metrics configuration of this bucket. Default: - No metrics configuration.
        :param notifications_handler_role: The role to be used by the notifications handler. Default: - a new role will be created.
        :param object_ownership: The objectOwnership of the bucket. Default: - No ObjectOwnership configuration, uploading account will own the object.
        :param public_read_access: Grants public read access to all objects in the bucket. Similar to calling ``bucket.grantPublicAccess()`` Default: false
        :param removal_policy: Policy to apply when the bucket is removed from this stack. Default: - The bucket will be orphaned.
        :param server_access_logs_bucket: Destination bucket for the server access logs. Default: - If "serverAccessLogsPrefix" undefined - access logs disabled, otherwise - log to current bucket.
        :param server_access_logs_prefix: Optional log file prefix to use for the bucket's access logs. If defined without "serverAccessLogsBucket", enables access logs to current bucket with this prefix. Default: - No log file prefix
        :param transfer_acceleration: Whether this bucket should have transfer acceleration turned on or not. Default: false
        :param versioned: Whether this bucket should have versioning turned on or not. Default: false
        :param website_error_document: The name of the error document (e.g. "404.html") for the website. ``websiteIndexDocument`` must also be set if this is set. Default: - No error document.
        :param website_index_document: The name of the index document (e.g. "index.html") for the website. Enables static website hosting for this bucket. Default: - No index document.
        :param website_redirect: Specifies the redirect behavior of all requests to a website endpoint of a bucket. If you specify this property, you can't specify "websiteIndexDocument", "websiteErrorDocument" nor , "websiteRoutingRules". Default: - No redirection.
        :param website_routing_rules: Rules that define when a redirect is applied and the redirect behavior. Default: - No redirection rules.
        '''
        props = BucketProps(
            access_control=access_control,
            auto_delete_objects=auto_delete_objects,
            block_public_access=block_public_access,
            bucket_key_enabled=bucket_key_enabled,
            bucket_name=bucket_name,
            cors=cors,
            encryption=encryption,
            encryption_key=encryption_key,
            enforce_ssl=enforce_ssl,
            intelligent_tiering_configurations=intelligent_tiering_configurations,
            inventories=inventories,
            lifecycle_rules=lifecycle_rules,
            metrics=metrics,
            notifications_handler_role=notifications_handler_role,
            object_ownership=object_ownership,
            public_read_access=public_read_access,
            removal_policy=removal_policy,
            server_access_logs_bucket=server_access_logs_bucket,
            server_access_logs_prefix=server_access_logs_prefix,
            transfer_acceleration=transfer_acceleration,
            versioned=versioned,
            website_error_document=website_error_document,
            website_index_document=website_index_document,
            website_redirect=website_redirect,
            website_routing_rules=website_routing_rules,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromBucketArn") # type: ignore[misc]
    @builtins.classmethod
    def from_bucket_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        bucket_arn: builtins.str,
    ) -> IBucket:
        '''
        :param scope: -
        :param id: -
        :param bucket_arn: -
        '''
        return typing.cast(IBucket, jsii.sinvoke(cls, "fromBucketArn", [scope, id, bucket_arn]))

    @jsii.member(jsii_name="fromBucketAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_bucket_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        bucket_arn: typing.Optional[builtins.str] = None,
        bucket_domain_name: typing.Optional[builtins.str] = None,
        bucket_dual_stack_domain_name: typing.Optional[builtins.str] = None,
        bucket_name: typing.Optional[builtins.str] = None,
        bucket_regional_domain_name: typing.Optional[builtins.str] = None,
        bucket_website_new_url_format: typing.Optional[builtins.bool] = None,
        bucket_website_url: typing.Optional[builtins.str] = None,
        encryption_key: typing.Optional[_IKey_5f11635f] = None,
        is_website: typing.Optional[builtins.bool] = None,
        notifications_handler_role: typing.Optional[_IRole_235f5d8e] = None,
        region: typing.Optional[builtins.str] = None,
    ) -> IBucket:
        '''Creates a Bucket construct that represents an external bucket.

        :param scope: The parent creating construct (usually ``this``).
        :param id: The construct's name.
        :param account: The account this existing bucket belongs to. Default: - it's assumed the bucket belongs to the same account as the scope it's being imported into
        :param bucket_arn: The ARN of the bucket. At least one of bucketArn or bucketName must be defined in order to initialize a bucket ref.
        :param bucket_domain_name: The domain name of the bucket. Default: Inferred from bucket name
        :param bucket_dual_stack_domain_name: The IPv6 DNS name of the specified bucket.
        :param bucket_name: The name of the bucket. If the underlying value of ARN is a string, the name will be parsed from the ARN. Otherwise, the name is optional, but some features that require the bucket name such as auto-creating a bucket policy, won't work.
        :param bucket_regional_domain_name: The regional domain name of the specified bucket.
        :param bucket_website_new_url_format: The format of the website URL of the bucket. This should be true for regions launched since 2014. Default: false
        :param bucket_website_url: The website URL of the bucket (if static web hosting is enabled). Default: Inferred from bucket name
        :param encryption_key: 
        :param is_website: If this bucket has been configured for static website hosting. Default: false
        :param notifications_handler_role: The role to be used by the notifications handler. Default: - a new role will be created.
        :param region: The region this existing bucket is in. Default: - it's assumed the bucket is in the same region as the scope it's being imported into
        '''
        attrs = BucketAttributes(
            account=account,
            bucket_arn=bucket_arn,
            bucket_domain_name=bucket_domain_name,
            bucket_dual_stack_domain_name=bucket_dual_stack_domain_name,
            bucket_name=bucket_name,
            bucket_regional_domain_name=bucket_regional_domain_name,
            bucket_website_new_url_format=bucket_website_new_url_format,
            bucket_website_url=bucket_website_url,
            encryption_key=encryption_key,
            is_website=is_website,
            notifications_handler_role=notifications_handler_role,
            region=region,
        )

        return typing.cast(IBucket, jsii.sinvoke(cls, "fromBucketAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="fromBucketName") # type: ignore[misc]
    @builtins.classmethod
    def from_bucket_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        bucket_name: builtins.str,
    ) -> IBucket:
        '''
        :param scope: -
        :param id: -
        :param bucket_name: -
        '''
        return typing.cast(IBucket, jsii.sinvoke(cls, "fromBucketName", [scope, id, bucket_name]))

    @jsii.member(jsii_name="validateBucketName") # type: ignore[misc]
    @builtins.classmethod
    def validate_bucket_name(cls, physical_name: builtins.str) -> None:
        '''Thrown an exception if the given bucket name is not valid.

        :param physical_name: name of the bucket.
        '''
        return typing.cast(None, jsii.sinvoke(cls, "validateBucketName", [physical_name]))

    @jsii.member(jsii_name="addCorsRule")
    def add_cors_rule(
        self,
        *,
        allowed_methods: typing.Sequence[HttpMethods],
        allowed_origins: typing.Sequence[builtins.str],
        allowed_headers: typing.Optional[typing.Sequence[builtins.str]] = None,
        exposed_headers: typing.Optional[typing.Sequence[builtins.str]] = None,
        id: typing.Optional[builtins.str] = None,
        max_age: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Adds a cross-origin access configuration for objects in an Amazon S3 bucket.

        :param allowed_methods: An HTTP method that you allow the origin to execute.
        :param allowed_origins: One or more origins you want customers to be able to access the bucket from.
        :param allowed_headers: Headers that are specified in the Access-Control-Request-Headers header. Default: - No headers allowed.
        :param exposed_headers: One or more headers in the response that you want customers to be able to access from their applications. Default: - No headers exposed.
        :param id: A unique identifier for this rule. Default: - No id specified.
        :param max_age: The time in seconds that your browser is to cache the preflight response for the specified resource. Default: - No caching.
        '''
        rule = CorsRule(
            allowed_methods=allowed_methods,
            allowed_origins=allowed_origins,
            allowed_headers=allowed_headers,
            exposed_headers=exposed_headers,
            id=id,
            max_age=max_age,
        )

        return typing.cast(None, jsii.invoke(self, "addCorsRule", [rule]))

    @jsii.member(jsii_name="addInventory")
    def add_inventory(
        self,
        *,
        destination: InventoryDestination,
        enabled: typing.Optional[builtins.bool] = None,
        format: typing.Optional[InventoryFormat] = None,
        frequency: typing.Optional[InventoryFrequency] = None,
        include_object_versions: typing.Optional[InventoryObjectVersion] = None,
        inventory_id: typing.Optional[builtins.str] = None,
        objects_prefix: typing.Optional[builtins.str] = None,
        optional_fields: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Add an inventory configuration.

        :param destination: The destination of the inventory.
        :param enabled: Whether the inventory is enabled or disabled. Default: true
        :param format: The format of the inventory. Default: InventoryFormat.CSV
        :param frequency: Frequency at which the inventory should be generated. Default: InventoryFrequency.WEEKLY
        :param include_object_versions: If the inventory should contain all the object versions or only the current one. Default: InventoryObjectVersion.ALL
        :param inventory_id: The inventory configuration ID. Default: - generated ID.
        :param objects_prefix: The inventory will only include objects that meet the prefix filter criteria. Default: - No objects prefix
        :param optional_fields: A list of optional fields to be included in the inventory result. Default: - No optional fields.
        '''
        inventory = Inventory(
            destination=destination,
            enabled=enabled,
            format=format,
            frequency=frequency,
            include_object_versions=include_object_versions,
            inventory_id=inventory_id,
            objects_prefix=objects_prefix,
            optional_fields=optional_fields,
        )

        return typing.cast(None, jsii.invoke(self, "addInventory", [inventory]))

    @jsii.member(jsii_name="addLifecycleRule")
    def add_lifecycle_rule(
        self,
        *,
        abort_incomplete_multipart_upload_after: typing.Optional[_Duration_4839e8c3] = None,
        enabled: typing.Optional[builtins.bool] = None,
        expiration: typing.Optional[_Duration_4839e8c3] = None,
        expiration_date: typing.Optional[datetime.datetime] = None,
        expired_object_delete_marker: typing.Optional[builtins.bool] = None,
        id: typing.Optional[builtins.str] = None,
        noncurrent_version_expiration: typing.Optional[_Duration_4839e8c3] = None,
        noncurrent_version_transitions: typing.Optional[typing.Sequence[NoncurrentVersionTransition]] = None,
        prefix: typing.Optional[builtins.str] = None,
        tag_filters: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        transitions: typing.Optional[typing.Sequence[Transition]] = None,
    ) -> None:
        '''Add a lifecycle rule to the bucket.

        :param abort_incomplete_multipart_upload_after: Specifies a lifecycle rule that aborts incomplete multipart uploads to an Amazon S3 bucket. The AbortIncompleteMultipartUpload property type creates a lifecycle rule that aborts incomplete multipart uploads to an Amazon S3 bucket. When Amazon S3 aborts a multipart upload, it deletes all parts associated with the multipart upload. Default: Incomplete uploads are never aborted
        :param enabled: Whether this rule is enabled. Default: true
        :param expiration: Indicates the number of days after creation when objects are deleted from Amazon S3 and Amazon Glacier. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time. Default: No expiration timeout
        :param expiration_date: Indicates when objects are deleted from Amazon S3 and Amazon Glacier. The date value must be in ISO 8601 format. The time is always midnight UTC. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time. Default: No expiration date
        :param expired_object_delete_marker: Indicates whether Amazon S3 will remove a delete marker with no noncurrent versions. If set to true, the delete marker will be expired. Default: false
        :param id: A unique identifier for this rule. The value cannot be more than 255 characters.
        :param noncurrent_version_expiration: Time between when a new version of the object is uploaded to the bucket and when old versions of the object expire. For buckets with versioning enabled (or suspended), specifies the time, in days, between when a new version of the object is uploaded to the bucket and when old versions of the object expire. When object versions expire, Amazon S3 permanently deletes them. If you specify a transition and expiration time, the expiration time must be later than the transition time. Default: No noncurrent version expiration
        :param noncurrent_version_transitions: One or more transition rules that specify when non-current objects transition to a specified storage class. Only for for buckets with versioning enabled (or suspended). If you specify a transition and expiration time, the expiration time must be later than the transition time.
        :param prefix: Object key prefix that identifies one or more objects to which this rule applies. Default: Rule applies to all objects
        :param tag_filters: The TagFilter property type specifies tags to use to identify a subset of objects for an Amazon S3 bucket. Default: Rule applies to all objects
        :param transitions: One or more transition rules that specify when an object transitions to a specified storage class. If you specify an expiration and transition time, you must use the same time unit for both properties (either in days or by date). The expiration time must also be later than the transition time. Default: No transition rules
        '''
        rule = LifecycleRule(
            abort_incomplete_multipart_upload_after=abort_incomplete_multipart_upload_after,
            enabled=enabled,
            expiration=expiration,
            expiration_date=expiration_date,
            expired_object_delete_marker=expired_object_delete_marker,
            id=id,
            noncurrent_version_expiration=noncurrent_version_expiration,
            noncurrent_version_transitions=noncurrent_version_transitions,
            prefix=prefix,
            tag_filters=tag_filters,
            transitions=transitions,
        )

        return typing.cast(None, jsii.invoke(self, "addLifecycleRule", [rule]))

    @jsii.member(jsii_name="addMetric")
    def add_metric(
        self,
        *,
        id: builtins.str,
        prefix: typing.Optional[builtins.str] = None,
        tag_filters: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
    ) -> None:
        '''Adds a metrics configuration for the CloudWatch request metrics from the bucket.

        :param id: The ID used to identify the metrics configuration.
        :param prefix: The prefix that an object must have to be included in the metrics results.
        :param tag_filters: Specifies a list of tag filters to use as a metrics configuration filter. The metrics configuration includes only objects that meet the filter's criteria.
        '''
        metric = BucketMetrics(id=id, prefix=prefix, tag_filters=tag_filters)

        return typing.cast(None, jsii.invoke(self, "addMetric", [metric]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketArn")
    def bucket_arn(self) -> builtins.str:
        '''The ARN of the bucket.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketDomainName")
    def bucket_domain_name(self) -> builtins.str:
        '''The IPv4 DNS name of the specified bucket.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketDualStackDomainName")
    def bucket_dual_stack_domain_name(self) -> builtins.str:
        '''The IPv6 DNS name of the specified bucket.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketDualStackDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketName")
    def bucket_name(self) -> builtins.str:
        '''The name of the bucket.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketRegionalDomainName")
    def bucket_regional_domain_name(self) -> builtins.str:
        '''The regional domain name of the specified bucket.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketRegionalDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketWebsiteDomainName")
    def bucket_website_domain_name(self) -> builtins.str:
        '''The Domain name of the static website.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketWebsiteDomainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="bucketWebsiteUrl")
    def bucket_website_url(self) -> builtins.str:
        '''The URL of the static website.'''
        return typing.cast(builtins.str, jsii.get(self, "bucketWebsiteUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionKey")
    def encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''Optional KMS encryption key associated with this bucket.'''
        return typing.cast(typing.Optional[_IKey_5f11635f], jsii.get(self, "encryptionKey"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="isWebsite")
    def is_website(self) -> typing.Optional[builtins.bool]:
        '''If this bucket has been configured for static website hosting.'''
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "isWebsite"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoCreatePolicy")
    def _auto_create_policy(self) -> builtins.bool:
        '''Indicates if a bucket resource policy should automatically created upon the first call to ``addToResourcePolicy``.'''
        return typing.cast(builtins.bool, jsii.get(self, "autoCreatePolicy"))

    @_auto_create_policy.setter
    def _auto_create_policy(self, value: builtins.bool) -> None:
        jsii.set(self, "autoCreatePolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="disallowPublicAccess")
    def _disallow_public_access(self) -> typing.Optional[builtins.bool]:
        '''Whether to disallow public access.'''
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "disallowPublicAccess"))

    @_disallow_public_access.setter
    def _disallow_public_access(self, value: typing.Optional[builtins.bool]) -> None:
        jsii.set(self, "disallowPublicAccess", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policy")
    def policy(self) -> typing.Optional[BucketPolicy]:
        '''The resource policy associated with this bucket.

        If ``autoCreatePolicy`` is true, a ``BucketPolicy`` will be created upon the
        first call to addToResourcePolicy(s).
        '''
        return typing.cast(typing.Optional[BucketPolicy], jsii.get(self, "policy"))

    @policy.setter
    def policy(self, value: typing.Optional[BucketPolicy]) -> None:
        jsii.set(self, "policy", value)


__all__ = [
    "BlockPublicAccess",
    "BlockPublicAccessOptions",
    "Bucket",
    "BucketAccessControl",
    "BucketAttributes",
    "BucketBase",
    "BucketEncryption",
    "BucketMetrics",
    "BucketNotificationDestinationConfig",
    "BucketNotificationDestinationType",
    "BucketPolicy",
    "BucketPolicyProps",
    "BucketProps",
    "CfnAccessPoint",
    "CfnAccessPointProps",
    "CfnBucket",
    "CfnBucketPolicy",
    "CfnBucketPolicyProps",
    "CfnBucketProps",
    "CfnMultiRegionAccessPoint",
    "CfnMultiRegionAccessPointPolicy",
    "CfnMultiRegionAccessPointPolicyProps",
    "CfnMultiRegionAccessPointProps",
    "CfnStorageLens",
    "CfnStorageLensProps",
    "CorsRule",
    "EventType",
    "HttpMethods",
    "IBucket",
    "IBucketNotificationDestination",
    "IntelligentTieringConfiguration",
    "Inventory",
    "InventoryDestination",
    "InventoryFormat",
    "InventoryFrequency",
    "InventoryObjectVersion",
    "LifecycleRule",
    "Location",
    "NoncurrentVersionTransition",
    "NotificationKeyFilter",
    "ObjectOwnership",
    "OnCloudTrailBucketEventOptions",
    "RedirectProtocol",
    "RedirectTarget",
    "ReplaceKey",
    "RoutingRule",
    "RoutingRuleCondition",
    "StorageClass",
    "Tag",
    "TransferAccelerationUrlOptions",
    "Transition",
    "VirtualHostedStyleUrlOptions",
]

publication.publish()
