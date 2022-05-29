'''
# Amazon Elasticsearch Service Construct Library

> Amazon Elasticsearch Service has been renamed to Amazon OpenSearch Service; consequently, the [@aws-cdk/aws-opensearchservice](https://docs.aws.amazon.com/cdk/api/latest/docs/aws-opensearchservice-readme.html) module should be used instead. See [Amazon OpenSearch Service FAQs](https://aws.amazon.com/opensearch-service/faqs/#Name_change) for details. See [Migrating to OpenSearch](#migrating-to-opensearch) for migration instructions.

## Quick start

Create a development cluster by simply specifying the version:

```python
dev_domain = es.Domain(self, "Domain",
    version=es.ElasticsearchVersion.V7_1
)
```

To perform version upgrades without replacing the entire domain, specify the `enableVersionUpgrade` property.

```python
dev_domain = es.Domain(self, "Domain",
    version=es.ElasticsearchVersion.V7_10,
    enable_version_upgrade=True
)
```

Create a production grade cluster by also specifying things like capacity and az distribution

```python
prod_domain = es.Domain(self, "Domain",
    version=es.ElasticsearchVersion.V7_1,
    capacity=es.CapacityConfig(
        master_nodes=5,
        data_nodes=20
    ),
    ebs=es.EbsOptions(
        volume_size=20
    ),
    zone_awareness=es.ZoneAwarenessConfig(
        availability_zone_count=3
    ),
    logging=es.LoggingOptions(
        slow_search_log_enabled=True,
        app_log_enabled=True,
        slow_index_log_enabled=True
    )
)
```

This creates an Elasticsearch cluster and automatically sets up log groups for
logging the domain logs and slow search logs.

## A note about SLR

Some cluster configurations (e.g VPC access) require the existence of the [`AWSServiceRoleForAmazonElasticsearchService`](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/slr-es.html) Service-Linked Role.

When performing such operations via the AWS Console, this SLR is created automatically when needed. However, this is not the behavior when using CloudFormation. If an SLR is needed, but doesn't exist, you will encounter a failure message simlar to:

```console
Before you can proceed, you must enable a service-linked role to give Amazon ES...
```

To resolve this, you need to [create](https://docs.aws.amazon.com/IAM/latest/UserGuide/using-service-linked-roles.html#create-service-linked-role) the SLR. We recommend using the AWS CLI:

```console
aws iam create-service-linked-role --aws-service-name es.amazonaws.com
```

You can also create it using the CDK, **but note that only the first application deploying this will succeed**:

```python
slr = iam.CfnServiceLinkedRole(self, "ElasticSLR",
    aws_service_name="es.amazonaws.com"
)
```

## Importing existing domains

To import an existing domain into your CDK application, use the `Domain.fromDomainEndpoint` factory method.
This method accepts a domain endpoint of an already existing domain:

```python
domain_endpoint = "https://my-domain-jcjotrt6f7otem4sqcwbch3c4u.us-east-1.es.amazonaws.com"
domain = es.Domain.from_domain_endpoint(self, "ImportedDomain", domain_endpoint)
```

## Permissions

### IAM

Helper methods also exist for managing access to the domain.

```python
# fn: lambda.Function
# domain: es.Domain


# Grant write access to the app-search index
domain.grant_index_write("app-search", fn)

# Grant read access to the 'app-search/_search' path
domain.grant_path_read("app-search/_search", fn)
```

## Encryption

The domain can also be created with encryption enabled:

```python
domain = es.Domain(self, "Domain",
    version=es.ElasticsearchVersion.V7_4,
    ebs=es.EbsOptions(
        volume_size=100,
        volume_type=ec2.EbsDeviceVolumeType.GENERAL_PURPOSE_SSD
    ),
    node_to_node_encryption=True,
    encryption_at_rest=es.EncryptionAtRestOptions(
        enabled=True
    )
)
```

This sets up the domain with node to node encryption and encryption at
rest. You can also choose to supply your own KMS key to use for encryption at
rest.

## VPC Support

Elasticsearch domains can be placed inside a VPC, providing a secure communication between Amazon ES and other services within the VPC without the need for an internet gateway, NAT device, or VPN connection.

> Visit [VPC Support for Amazon Elasticsearch Service Domains](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html) for more details.

```python
vpc = ec2.Vpc(self, "Vpc")
domain_props = es.DomainProps(
    version=es.ElasticsearchVersion.V7_1,
    removal_policy=RemovalPolicy.DESTROY,
    vpc=vpc,
    # must be enabled since our VPC contains multiple private subnets.
    zone_awareness=es.ZoneAwarenessConfig(
        enabled=True
    ),
    capacity=es.CapacityConfig(
        # must be an even number since the default az count is 2.
        data_nodes=2
    )
)
es.Domain(self, "Domain", domain_props)
```

In addition, you can use the `vpcSubnets` property to control which specific subnets will be used, and the `securityGroups` property to control
which security groups will be attached to the domain. By default, CDK will select all *private* subnets in the VPC, and create one dedicated security group.

## Metrics

Helper methods exist to access common domain metrics for example:

```python
# domain: es.Domain

free_storage_space = domain.metric_free_storage_space()
master_sys_memory_utilization = domain.metric("MasterSysMemoryUtilization")
```

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

## Fine grained access control

The domain can also be created with a master user configured. The password can
be supplied or dynamically created if not supplied.

```python
domain = es.Domain(self, "Domain",
    version=es.ElasticsearchVersion.V7_1,
    enforce_https=True,
    node_to_node_encryption=True,
    encryption_at_rest=es.EncryptionAtRestOptions(
        enabled=True
    ),
    fine_grained_access_control=es.AdvancedSecurityOptions(
        master_user_name="master-user"
    )
)

master_user_password = domain.master_user_password
```

## Using unsigned basic auth

For convenience, the domain can be configured to allow unsigned HTTP requests
that use basic auth. Unless the domain is configured to be part of a VPC this
means anyone can access the domain using the configured master username and
password.

To enable unsigned basic auth access the domain is configured with an access
policy that allows anyonmous requests, HTTPS required, node to node encryption,
encryption at rest and fine grained access control.

If the above settings are not set they will be configured as part of enabling
unsigned basic auth. If they are set with conflicting values, an error will be
thrown.

If no master user is configured a default master user is created with the
username `admin`.

If no password is configured a default master user password is created and
stored in the AWS Secrets Manager as secret. The secret has the prefix
`<domain id>MasterUser`.

```python
domain = es.Domain(self, "Domain",
    version=es.ElasticsearchVersion.V7_1,
    use_unsigned_basic_auth=True
)

master_user_password = domain.master_user_password
```

## Audit logs

Audit logs can be enabled for a domain, but only when fine grained access control is enabled.

```python
domain = es.Domain(self, "Domain",
    version=es.ElasticsearchVersion.V7_1,
    enforce_https=True,
    node_to_node_encryption=True,
    encryption_at_rest=es.EncryptionAtRestOptions(
        enabled=True
    ),
    fine_grained_access_control=es.AdvancedSecurityOptions(
        master_user_name="master-user"
    ),
    logging=es.LoggingOptions(
        audit_log_enabled=True,
        slow_search_log_enabled=True,
        app_log_enabled=True,
        slow_index_log_enabled=True
    )
)
```

## UltraWarm

UltraWarm nodes can be enabled to provide a cost-effective way to store large amounts of read-only data.

```python
domain = es.Domain(self, "Domain",
    version=es.ElasticsearchVersion.V7_10,
    capacity=es.CapacityConfig(
        master_nodes=2,
        warm_nodes=2,
        warm_instance_type="ultrawarm1.medium.elasticsearch"
    )
)
```

## Custom endpoint

Custom endpoints can be configured to reach the ES domain under a custom domain name.

```python
es.Domain(self, "Domain",
    version=es.ElasticsearchVersion.V7_7,
    custom_endpoint=es.CustomEndpointOptions(
        domain_name="search.example.com"
    )
)
```

It is also possible to specify a custom certificate instead of the auto-generated one.

Additionally, an automatic CNAME-Record is created if a hosted zone is provided for the custom endpoint

## Advanced options

[Advanced options](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-advanced-options) can used to configure additional options.

```python
es.Domain(self, "Domain",
    version=es.ElasticsearchVersion.V7_7,
    advanced_options={
        "rest.action.multi.allow_explicit_index": "false",
        "indices.fielddata.cache.size": "25",
        "indices.query.bool.max_clause_count": "2048"
    }
)
```

## Migrating to OpenSearch

To migrate from this module (`@aws-cdk/aws-elasticsearch`) to the new `@aws-cdk/aws-opensearchservice` module, you must modify your CDK application to refer to the new module (including some associated changes) and then perform a CloudFormation resource deletion/import.

### Necessary CDK Modifications

Make the following modifications to your CDK application to migrate to the `@aws-cdk/aws-opensearchservice` module.

* Rewrite module imports to use `'@aws-cdk/aws-opensearchservice` to `'@aws-cdk/aws-elasticsearch`.
  For example:

  ```python
  import aws_cdk.aws_elasticsearch as es
  from aws_cdk.aws_elasticsearch import Domain
  ```

  ...becomes...

  ```python
  import aws_cdk.aws_opensearchservice as opensearch
  from aws_cdk.aws_opensearchservice import Domain
  ```
* Replace instances of `es.ElasticsearchVersion` with `opensearch.EngineVersion`.
  For example:

  ```python
  # Example automatically generated from non-compiling source. May contain errors.
  version = es.ElasticsearchVersion.V7_1
  ```

  ...becomes...

  ```python
  # Example automatically generated from non-compiling source. May contain errors.
  version = opensearch.EngineVersion.ELASTICSEARCH_7_1
  ```
* Replace the `cognitoKibanaAuth` property of `DomainProps` with `cognitoDashboardsAuth`.
  For example:

  ```python
  # Example automatically generated from non-compiling source. May contain errors.
  es.Domain(self, "Domain",
      cognito_kibana_auth=es.CognitoOptions(
          identity_pool_id="test-identity-pool-id",
          user_pool_id="test-user-pool-id",
          role=role
      ),
      version=elasticsearch_version
  )
  ```

  ...becomes...

  ```python
  # Example automatically generated from non-compiling source. May contain errors.
  opensearch.Domain(self, "Domain",
      cognito_dashboards_auth=opensearch.CognitoOptions(
          identity_pool_id="test-identity-pool-id",
          user_pool_id="test-user-pool-id",
          role=role
      ),
      version=open_search_version
  )
  ```
* Rewrite instance type suffixes from `.elasticsearch` to `.search`.
  For example:

  ```python
  # Example automatically generated from non-compiling source. May contain errors.
  es.Domain(self, "Domain",
      capacity=es.CapacityConfig(
          master_node_instance_type="r5.large.elasticsearch"
      ),
      version=elasticsearch_version
  )
  ```

  ...becomes...

  ```python
  # Example automatically generated from non-compiling source. May contain errors.
  opensearch.Domain(self, "Domain",
      capacity=opensearch.CapacityConfig(
          master_node_instance_type="r5.large.search"
      ),
      version=open_search_version
  )
  ```
* Any `CfnInclude`'d domains will need to be re-written in their original template in
  order to be successfully included as a `opensearch.CfnDomain`

### CloudFormation Migration

Follow these steps to migrate your application without data loss:

* Ensure that the [removal policy](https://docs.aws.amazon.com/cdk/api/latest/docs/@aws-cdk_core.RemovalPolicy.html) on your domains are set to `RemovalPolicy.RETAIN`. This is the default for the domain construct, so nothing is required unless you have specifically set the removal policy to some other value.
* Remove the domain resource from your CloudFormation stacks by manually modifying the synthesized templates used to create the CloudFormation stacks. This may also involve modifying or deleting dependent resources, such as the custom resources that CDK creates to manage the domain's access policy or any other resource you have connected to the domain. You will need to search for references to each domain's logical ID to determine which other resources refer to it and replace or delete those references. Do not remove resources that are dependencies of the domain or you will have to recreate or import them before importing the domain. After modification, deploy the stacks through the AWS Management Console or using the AWS CLI.
* Migrate your CDK application to use the new `@aws-cdk/aws-opensearchservice` module by applying the necessary modifications listed above. Synthesize your application and obtain the resulting stack templates.
* Copy just the definition of the domain from the "migrated" templates to the corresponding "stripped" templates that you deployed above. [Import](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-existing-stack.html) the orphaned domains into your CloudFormation stacks using these templates.
* Synthesize and deploy your CDK application to reconfigure/recreate the modified dependent resources. The CloudFormation stacks should now contain the same resources as existed prior to migration.
* Proceed with development as normal!
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
from ..aws_certificatemanager import ICertificate as _ICertificate_c194c70b
from ..aws_cloudwatch import (
    Metric as _Metric_e396a4dc,
    MetricOptions as _MetricOptions_1788b62f,
    Unit as _Unit_61bc6f70,
)
from ..aws_ec2 import (
    Connections as _Connections_0f31fce8,
    EbsDeviceVolumeType as _EbsDeviceVolumeType_6792555b,
    IConnectable as _IConnectable_10015a05,
    ISecurityGroup as _ISecurityGroup_acf8a799,
    IVpc as _IVpc_f30d5663,
    SubnetSelection as _SubnetSelection_e57d76df,
)
from ..aws_iam import (
    Grant as _Grant_a7ae64f8,
    IGrantable as _IGrantable_71c4f5de,
    IRole as _IRole_235f5d8e,
    PolicyStatement as _PolicyStatement_0fe33853,
)
from ..aws_kms import IKey as _IKey_5f11635f
from ..aws_logs import ILogGroup as _ILogGroup_3c4fa718
from ..aws_route53 import IHostedZone as _IHostedZone_9a6907ad


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticsearch.AdvancedSecurityOptions",
    jsii_struct_bases=[],
    name_mapping={
        "master_user_arn": "masterUserArn",
        "master_user_name": "masterUserName",
        "master_user_password": "masterUserPassword",
    },
)
class AdvancedSecurityOptions:
    def __init__(
        self,
        *,
        master_user_arn: typing.Optional[builtins.str] = None,
        master_user_name: typing.Optional[builtins.str] = None,
        master_user_password: typing.Optional[_SecretValue_3dd0ddae] = None,
    ) -> None:
        '''Specifies options for fine-grained access control.

        :param master_user_arn: ARN for the master user. Only specify this or masterUserName, but not both. Default: - fine-grained access control is disabled
        :param master_user_name: Username for the master user. Only specify this or masterUserArn, but not both. Default: - fine-grained access control is disabled
        :param master_user_password: Password for the master user. You can use ``SecretValue.plainText`` to specify a password in plain text or use ``secretsmanager.Secret.fromSecretAttributes`` to reference a secret in Secrets Manager. Default: - A Secrets Manager generated password

        :exampleMetadata: infused

        Example::

            domain = es.Domain(self, "Domain",
                version=es.ElasticsearchVersion.V7_1,
                enforce_https=True,
                node_to_node_encryption=True,
                encryption_at_rest=es.EncryptionAtRestOptions(
                    enabled=True
                ),
                fine_grained_access_control=es.AdvancedSecurityOptions(
                    master_user_name="master-user"
                ),
                logging=es.LoggingOptions(
                    audit_log_enabled=True,
                    slow_search_log_enabled=True,
                    app_log_enabled=True,
                    slow_index_log_enabled=True
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if master_user_arn is not None:
            self._values["master_user_arn"] = master_user_arn
        if master_user_name is not None:
            self._values["master_user_name"] = master_user_name
        if master_user_password is not None:
            self._values["master_user_password"] = master_user_password

    @builtins.property
    def master_user_arn(self) -> typing.Optional[builtins.str]:
        '''ARN for the master user.

        Only specify this or masterUserName, but not both.

        :default: - fine-grained access control is disabled
        '''
        result = self._values.get("master_user_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def master_user_name(self) -> typing.Optional[builtins.str]:
        '''Username for the master user.

        Only specify this or masterUserArn, but not both.

        :default: - fine-grained access control is disabled
        '''
        result = self._values.get("master_user_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def master_user_password(self) -> typing.Optional[_SecretValue_3dd0ddae]:
        '''Password for the master user.

        You can use ``SecretValue.plainText`` to specify a password in plain text or
        use ``secretsmanager.Secret.fromSecretAttributes`` to reference a secret in
        Secrets Manager.

        :default: - A Secrets Manager generated password
        '''
        result = self._values.get("master_user_password")
        return typing.cast(typing.Optional[_SecretValue_3dd0ddae], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AdvancedSecurityOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticsearch.CapacityConfig",
    jsii_struct_bases=[],
    name_mapping={
        "data_node_instance_type": "dataNodeInstanceType",
        "data_nodes": "dataNodes",
        "master_node_instance_type": "masterNodeInstanceType",
        "master_nodes": "masterNodes",
        "warm_instance_type": "warmInstanceType",
        "warm_nodes": "warmNodes",
    },
)
class CapacityConfig:
    def __init__(
        self,
        *,
        data_node_instance_type: typing.Optional[builtins.str] = None,
        data_nodes: typing.Optional[jsii.Number] = None,
        master_node_instance_type: typing.Optional[builtins.str] = None,
        master_nodes: typing.Optional[jsii.Number] = None,
        warm_instance_type: typing.Optional[builtins.str] = None,
        warm_nodes: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Configures the capacity of the cluster such as the instance type and the number of instances.

        :param data_node_instance_type: The instance type for your data nodes, such as ``m3.medium.elasticsearch``. For valid values, see `Supported Instance Types <https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/aes-supported-instance-types.html>`_ in the Amazon Elasticsearch Service Developer Guide. Default: - r5.large.elasticsearch
        :param data_nodes: The number of data nodes (instances) to use in the Amazon ES domain. Default: - 1
        :param master_node_instance_type: The hardware configuration of the computer that hosts the dedicated master node, such as ``m3.medium.elasticsearch``. For valid values, see [Supported Instance Types] (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/aes-supported-instance-types.html) in the Amazon Elasticsearch Service Developer Guide. Default: - r5.large.elasticsearch
        :param master_nodes: The number of instances to use for the master node. Default: - no dedicated master nodes
        :param warm_instance_type: The instance type for your UltraWarm node, such as ``ultrawarm1.medium.elasticsearch``. For valid values, see [UltraWarm Storage Limits] (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/aes-limits.html#limits-ultrawarm) in the Amazon Elasticsearch Service Developer Guide. Default: - ultrawarm1.medium.elasticsearch
        :param warm_nodes: The number of UltraWarm nodes (instances) to use in the Amazon ES domain. Default: - no UltraWarm nodes

        :exampleMetadata: infused

        Example::

            domain = es.Domain(self, "Domain",
                version=es.ElasticsearchVersion.V7_10,
                capacity=es.CapacityConfig(
                    master_nodes=2,
                    warm_nodes=2,
                    warm_instance_type="ultrawarm1.medium.elasticsearch"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if data_node_instance_type is not None:
            self._values["data_node_instance_type"] = data_node_instance_type
        if data_nodes is not None:
            self._values["data_nodes"] = data_nodes
        if master_node_instance_type is not None:
            self._values["master_node_instance_type"] = master_node_instance_type
        if master_nodes is not None:
            self._values["master_nodes"] = master_nodes
        if warm_instance_type is not None:
            self._values["warm_instance_type"] = warm_instance_type
        if warm_nodes is not None:
            self._values["warm_nodes"] = warm_nodes

    @builtins.property
    def data_node_instance_type(self) -> typing.Optional[builtins.str]:
        '''The instance type for your data nodes, such as ``m3.medium.elasticsearch``. For valid values, see `Supported Instance Types <https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/aes-supported-instance-types.html>`_ in the Amazon Elasticsearch Service Developer Guide.

        :default: - r5.large.elasticsearch
        '''
        result = self._values.get("data_node_instance_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def data_nodes(self) -> typing.Optional[jsii.Number]:
        '''The number of data nodes (instances) to use in the Amazon ES domain.

        :default: - 1
        '''
        result = self._values.get("data_nodes")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def master_node_instance_type(self) -> typing.Optional[builtins.str]:
        '''The hardware configuration of the computer that hosts the dedicated master node, such as ``m3.medium.elasticsearch``. For valid values, see [Supported Instance Types] (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/aes-supported-instance-types.html) in the Amazon Elasticsearch Service Developer Guide.

        :default: - r5.large.elasticsearch
        '''
        result = self._values.get("master_node_instance_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def master_nodes(self) -> typing.Optional[jsii.Number]:
        '''The number of instances to use for the master node.

        :default: - no dedicated master nodes
        '''
        result = self._values.get("master_nodes")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def warm_instance_type(self) -> typing.Optional[builtins.str]:
        '''The instance type for your UltraWarm node, such as ``ultrawarm1.medium.elasticsearch``. For valid values, see [UltraWarm Storage Limits] (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/aes-limits.html#limits-ultrawarm) in the Amazon Elasticsearch Service Developer Guide.

        :default: - ultrawarm1.medium.elasticsearch
        '''
        result = self._values.get("warm_instance_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def warm_nodes(self) -> typing.Optional[jsii.Number]:
        '''The number of UltraWarm nodes (instances) to use in the Amazon ES domain.

        :default: - no UltraWarm nodes
        '''
        result = self._values.get("warm_nodes")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CapacityConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnDomain(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain",
):
    '''A CloudFormation ``AWS::Elasticsearch::Domain``.

    The AWS::Elasticsearch::Domain resource creates an Amazon OpenSearch Service (successor to Amazon Elasticsearch Service) domain.
    .. epigraph::

       The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and legacy Elasticsearch. For instructions to upgrade domains defined within CloudFormation from Elasticsearch to OpenSearch, see `Remarks <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html#aws-resource-opensearchservice-domain--remarks>`_ .

    :cloudformationResource: AWS::Elasticsearch::Domain
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticsearch as elasticsearch
        
        # access_policies: Any
        
        cfn_domain = elasticsearch.CfnDomain(self, "MyCfnDomain",
            access_policies=access_policies,
            advanced_options={
                "advanced_options_key": "advancedOptions"
            },
            advanced_security_options=elasticsearch.CfnDomain.AdvancedSecurityOptionsInputProperty(
                enabled=False,
                internal_user_database_enabled=False,
                master_user_options=elasticsearch.CfnDomain.MasterUserOptionsProperty(
                    master_user_arn="masterUserArn",
                    master_user_name="masterUserName",
                    master_user_password="masterUserPassword"
                )
            ),
            cognito_options=elasticsearch.CfnDomain.CognitoOptionsProperty(
                enabled=False,
                identity_pool_id="identityPoolId",
                role_arn="roleArn",
                user_pool_id="userPoolId"
            ),
            domain_endpoint_options=elasticsearch.CfnDomain.DomainEndpointOptionsProperty(
                custom_endpoint="customEndpoint",
                custom_endpoint_certificate_arn="customEndpointCertificateArn",
                custom_endpoint_enabled=False,
                enforce_https=False,
                tls_security_policy="tlsSecurityPolicy"
            ),
            domain_name="domainName",
            ebs_options=elasticsearch.CfnDomain.EBSOptionsProperty(
                ebs_enabled=False,
                iops=123,
                volume_size=123,
                volume_type="volumeType"
            ),
            elasticsearch_cluster_config=elasticsearch.CfnDomain.ElasticsearchClusterConfigProperty(
                cold_storage_options=elasticsearch.CfnDomain.ColdStorageOptionsProperty(
                    enabled=False
                ),
                dedicated_master_count=123,
                dedicated_master_enabled=False,
                dedicated_master_type="dedicatedMasterType",
                instance_count=123,
                instance_type="instanceType",
                warm_count=123,
                warm_enabled=False,
                warm_type="warmType",
                zone_awareness_config=elasticsearch.CfnDomain.ZoneAwarenessConfigProperty(
                    availability_zone_count=123
                ),
                zone_awareness_enabled=False
            ),
            elasticsearch_version="elasticsearchVersion",
            encryption_at_rest_options=elasticsearch.CfnDomain.EncryptionAtRestOptionsProperty(
                enabled=False,
                kms_key_id="kmsKeyId"
            ),
            log_publishing_options={
                "log_publishing_options_key": elasticsearch.CfnDomain.LogPublishingOptionProperty(
                    cloud_watch_logs_log_group_arn="cloudWatchLogsLogGroupArn",
                    enabled=False
                )
            },
            node_to_node_encryption_options=elasticsearch.CfnDomain.NodeToNodeEncryptionOptionsProperty(
                enabled=False
            ),
            snapshot_options=elasticsearch.CfnDomain.SnapshotOptionsProperty(
                automated_snapshot_start_hour=123
            ),
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            vpc_options=elasticsearch.CfnDomain.VPCOptionsProperty(
                security_group_ids=["securityGroupIds"],
                subnet_ids=["subnetIds"]
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        access_policies: typing.Any = None,
        advanced_options: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        advanced_security_options: typing.Optional[typing.Union["CfnDomain.AdvancedSecurityOptionsInputProperty", _IResolvable_da3f097b]] = None,
        cognito_options: typing.Optional[typing.Union["CfnDomain.CognitoOptionsProperty", _IResolvable_da3f097b]] = None,
        domain_endpoint_options: typing.Optional[typing.Union["CfnDomain.DomainEndpointOptionsProperty", _IResolvable_da3f097b]] = None,
        domain_name: typing.Optional[builtins.str] = None,
        ebs_options: typing.Optional[typing.Union["CfnDomain.EBSOptionsProperty", _IResolvable_da3f097b]] = None,
        elasticsearch_cluster_config: typing.Optional[typing.Union["CfnDomain.ElasticsearchClusterConfigProperty", _IResolvable_da3f097b]] = None,
        elasticsearch_version: typing.Optional[builtins.str] = None,
        encryption_at_rest_options: typing.Optional[typing.Union["CfnDomain.EncryptionAtRestOptionsProperty", _IResolvable_da3f097b]] = None,
        log_publishing_options: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDomain.LogPublishingOptionProperty", _IResolvable_da3f097b]]]] = None,
        node_to_node_encryption_options: typing.Optional[typing.Union["CfnDomain.NodeToNodeEncryptionOptionsProperty", _IResolvable_da3f097b]] = None,
        snapshot_options: typing.Optional[typing.Union["CfnDomain.SnapshotOptionsProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        vpc_options: typing.Optional[typing.Union["CfnDomain.VPCOptionsProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Elasticsearch::Domain``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param access_policies: An AWS Identity and Access Management ( IAM ) policy document that specifies who can access the OpenSearch Service domain and their permissions. For more information, see `Configuring access policies <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ac.html#ac-creating>`_ in the *Amazon OpenSearch Service Developer Guid* e.
        :param advanced_options: Additional options to specify for the OpenSearch Service domain. For more information, see `Advanced cluster parameters <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html#createdomain-configure-advanced-options>`_ in the *Amazon OpenSearch Service Developer Guide* .
        :param advanced_security_options: Specifies options for fine-grained access control.
        :param cognito_options: Configures OpenSearch Service to use Amazon Cognito authentication for OpenSearch Dashboards.
        :param domain_endpoint_options: Specifies additional options for the domain endpoint, such as whether to require HTTPS for all traffic or whether to use a custom endpoint rather than the default endpoint.
        :param domain_name: A name for the OpenSearch Service domain. For valid values, see the `DomainName <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/configuration-api.html#configuration-api-datatypes-domainname>`_ data type in the *Amazon OpenSearch Service Developer Guide* . If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the domain name. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.
        :param ebs_options: The configurations of Amazon Elastic Block Store (Amazon EBS) volumes that are attached to data nodes in the OpenSearch Service domain. For more information, see `EBS volume size limits <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/limits.html#ebsresource>`_ in the *Amazon OpenSearch Service Developer Guide* .
        :param elasticsearch_cluster_config: ElasticsearchClusterConfig is a property of the AWS::Elasticsearch::Domain resource that configures the cluster of an Amazon OpenSearch Service domain.
        :param elasticsearch_version: The version of Elasticsearch to use, such as 2.3. If not specified, 1.5 is used as the default. For information about the versions that OpenSearch Service supports, see `Supported versions of OpenSearch and Elasticsearch <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/what-is.html#choosing-version>`_ in the *Amazon OpenSearch Service Developer Guide* . If you set the `EnableVersionUpgrade <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-upgradeopensearchdomain>`_ update policy to ``true`` , you can update ``ElasticsearchVersion`` without interruption. When ``EnableVersionUpgrade`` is set to ``false`` , or is not specified, updating ``ElasticsearchVersion`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .
        :param encryption_at_rest_options: Whether the domain should encrypt data at rest, and if so, the AWS Key Management Service key to use. See `Encryption of data at rest for Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html>`_ .
        :param log_publishing_options: An object with one or more of the following keys: ``SEARCH_SLOW_LOGS`` , ``ES_APPLICATION_LOGS`` , ``INDEX_SLOW_LOGS`` , ``AUDIT_LOGS`` , depending on the types of logs you want to publish. Each key needs a valid ``LogPublishingOption`` value.
        :param node_to_node_encryption_options: Specifies whether node-to-node encryption is enabled. See `Node-to-node encryption for Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ntn.html>`_ .
        :param snapshot_options: *DEPRECATED* . The automated snapshot configuration for the OpenSearch Service domain indices.
        :param tags: An arbitrary set of tags (key–value pairs) to associate with the OpenSearch Service domain.
        :param vpc_options: The virtual private cloud (VPC) configuration for the OpenSearch Service domain. For more information, see `Launching your Amazon OpenSearch Service domains within a VPC <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html>`_ in the *Amazon OpenSearch Service Developer Guide* .
        '''
        props = CfnDomainProps(
            access_policies=access_policies,
            advanced_options=advanced_options,
            advanced_security_options=advanced_security_options,
            cognito_options=cognito_options,
            domain_endpoint_options=domain_endpoint_options,
            domain_name=domain_name,
            ebs_options=ebs_options,
            elasticsearch_cluster_config=elasticsearch_cluster_config,
            elasticsearch_version=elasticsearch_version,
            encryption_at_rest_options=encryption_at_rest_options,
            log_publishing_options=log_publishing_options,
            node_to_node_encryption_options=node_to_node_encryption_options,
            snapshot_options=snapshot_options,
            tags=tags,
            vpc_options=vpc_options,
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
        '''The Amazon Resource Name (ARN) of the domain, such as ``arn:aws:es:us-west-2:123456789012:domain/mystack-elasti-1ab2cdefghij`` .

        This returned value is the same as the one returned by ``AWS::Elasticsearch::Domain.DomainArn`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDomainEndpoint")
    def attr_domain_endpoint(self) -> builtins.str:
        '''The domain-specific endpoint that's used for requests to the OpenSearch APIs, such as ``search-mystack-elasti-1ab2cdefghij-ab1c2deckoyb3hofw7wpqa3cm.us-west-1.es.amazonaws.com`` .

        :cloudformationAttribute: DomainEndpoint
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDomainEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An arbitrary set of tags (key–value pairs) to associate with the OpenSearch Service domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="accessPolicies")
    def access_policies(self) -> typing.Any:
        '''An AWS Identity and Access Management ( IAM ) policy document that specifies who can access the OpenSearch Service domain and their permissions.

        For more information, see `Configuring access policies <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ac.html#ac-creating>`_ in the *Amazon OpenSearch Service Developer Guid* e.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-accesspolicies
        '''
        return typing.cast(typing.Any, jsii.get(self, "accessPolicies"))

    @access_policies.setter
    def access_policies(self, value: typing.Any) -> None:
        jsii.set(self, "accessPolicies", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="advancedOptions")
    def advanced_options(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''Additional options to specify for the OpenSearch Service domain.

        For more information, see `Advanced cluster parameters <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html#createdomain-configure-advanced-options>`_ in the *Amazon OpenSearch Service Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-advancedoptions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], jsii.get(self, "advancedOptions"))

    @advanced_options.setter
    def advanced_options(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]],
    ) -> None:
        jsii.set(self, "advancedOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="advancedSecurityOptions")
    def advanced_security_options(
        self,
    ) -> typing.Optional[typing.Union["CfnDomain.AdvancedSecurityOptionsInputProperty", _IResolvable_da3f097b]]:
        '''Specifies options for fine-grained access control.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-advancedsecurityoptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDomain.AdvancedSecurityOptionsInputProperty", _IResolvable_da3f097b]], jsii.get(self, "advancedSecurityOptions"))

    @advanced_security_options.setter
    def advanced_security_options(
        self,
        value: typing.Optional[typing.Union["CfnDomain.AdvancedSecurityOptionsInputProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "advancedSecurityOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cognitoOptions")
    def cognito_options(
        self,
    ) -> typing.Optional[typing.Union["CfnDomain.CognitoOptionsProperty", _IResolvable_da3f097b]]:
        '''Configures OpenSearch Service to use Amazon Cognito authentication for OpenSearch Dashboards.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-cognitooptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDomain.CognitoOptionsProperty", _IResolvable_da3f097b]], jsii.get(self, "cognitoOptions"))

    @cognito_options.setter
    def cognito_options(
        self,
        value: typing.Optional[typing.Union["CfnDomain.CognitoOptionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "cognitoOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainEndpointOptions")
    def domain_endpoint_options(
        self,
    ) -> typing.Optional[typing.Union["CfnDomain.DomainEndpointOptionsProperty", _IResolvable_da3f097b]]:
        '''Specifies additional options for the domain endpoint, such as whether to require HTTPS for all traffic or whether to use a custom endpoint rather than the default endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-domainendpointoptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDomain.DomainEndpointOptionsProperty", _IResolvable_da3f097b]], jsii.get(self, "domainEndpointOptions"))

    @domain_endpoint_options.setter
    def domain_endpoint_options(
        self,
        value: typing.Optional[typing.Union["CfnDomain.DomainEndpointOptionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "domainEndpointOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> typing.Optional[builtins.str]:
        '''A name for the OpenSearch Service domain.

        For valid values, see the `DomainName <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/configuration-api.html#configuration-api-datatypes-domainname>`_ data type in the *Amazon OpenSearch Service Developer Guide* . If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the domain name. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .
        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-domainname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "domainName"))

    @domain_name.setter
    def domain_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "domainName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ebsOptions")
    def ebs_options(
        self,
    ) -> typing.Optional[typing.Union["CfnDomain.EBSOptionsProperty", _IResolvable_da3f097b]]:
        '''The configurations of Amazon Elastic Block Store (Amazon EBS) volumes that are attached to data nodes in the OpenSearch Service domain.

        For more information, see `EBS volume size limits <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/limits.html#ebsresource>`_ in the *Amazon OpenSearch Service Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-ebsoptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDomain.EBSOptionsProperty", _IResolvable_da3f097b]], jsii.get(self, "ebsOptions"))

    @ebs_options.setter
    def ebs_options(
        self,
        value: typing.Optional[typing.Union["CfnDomain.EBSOptionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "ebsOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="elasticsearchClusterConfig")
    def elasticsearch_cluster_config(
        self,
    ) -> typing.Optional[typing.Union["CfnDomain.ElasticsearchClusterConfigProperty", _IResolvable_da3f097b]]:
        '''ElasticsearchClusterConfig is a property of the AWS::Elasticsearch::Domain resource that configures the cluster of an Amazon OpenSearch Service domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-elasticsearchclusterconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDomain.ElasticsearchClusterConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "elasticsearchClusterConfig"))

    @elasticsearch_cluster_config.setter
    def elasticsearch_cluster_config(
        self,
        value: typing.Optional[typing.Union["CfnDomain.ElasticsearchClusterConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "elasticsearchClusterConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="elasticsearchVersion")
    def elasticsearch_version(self) -> typing.Optional[builtins.str]:
        '''The version of Elasticsearch to use, such as 2.3. If not specified, 1.5 is used as the default. For information about the versions that OpenSearch Service supports, see `Supported versions of OpenSearch and Elasticsearch <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/what-is.html#choosing-version>`_ in the *Amazon OpenSearch Service Developer Guide* .

        If you set the `EnableVersionUpgrade <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-upgradeopensearchdomain>`_ update policy to ``true`` , you can update ``ElasticsearchVersion`` without interruption. When ``EnableVersionUpgrade`` is set to ``false`` , or is not specified, updating ``ElasticsearchVersion`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-elasticsearchversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "elasticsearchVersion"))

    @elasticsearch_version.setter
    def elasticsearch_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "elasticsearchVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionAtRestOptions")
    def encryption_at_rest_options(
        self,
    ) -> typing.Optional[typing.Union["CfnDomain.EncryptionAtRestOptionsProperty", _IResolvable_da3f097b]]:
        '''Whether the domain should encrypt data at rest, and if so, the AWS Key Management Service key to use.

        See `Encryption of data at rest for Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-encryptionatrestoptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDomain.EncryptionAtRestOptionsProperty", _IResolvable_da3f097b]], jsii.get(self, "encryptionAtRestOptions"))

    @encryption_at_rest_options.setter
    def encryption_at_rest_options(
        self,
        value: typing.Optional[typing.Union["CfnDomain.EncryptionAtRestOptionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "encryptionAtRestOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logPublishingOptions")
    def log_publishing_options(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDomain.LogPublishingOptionProperty", _IResolvable_da3f097b]]]]:
        '''An object with one or more of the following keys: ``SEARCH_SLOW_LOGS`` , ``ES_APPLICATION_LOGS`` , ``INDEX_SLOW_LOGS`` , ``AUDIT_LOGS`` , depending on the types of logs you want to publish.

        Each key needs a valid ``LogPublishingOption`` value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-logpublishingoptions
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDomain.LogPublishingOptionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "logPublishingOptions"))

    @log_publishing_options.setter
    def log_publishing_options(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union["CfnDomain.LogPublishingOptionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "logPublishingOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="nodeToNodeEncryptionOptions")
    def node_to_node_encryption_options(
        self,
    ) -> typing.Optional[typing.Union["CfnDomain.NodeToNodeEncryptionOptionsProperty", _IResolvable_da3f097b]]:
        '''Specifies whether node-to-node encryption is enabled.

        See `Node-to-node encryption for Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ntn.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-nodetonodeencryptionoptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDomain.NodeToNodeEncryptionOptionsProperty", _IResolvable_da3f097b]], jsii.get(self, "nodeToNodeEncryptionOptions"))

    @node_to_node_encryption_options.setter
    def node_to_node_encryption_options(
        self,
        value: typing.Optional[typing.Union["CfnDomain.NodeToNodeEncryptionOptionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "nodeToNodeEncryptionOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="snapshotOptions")
    def snapshot_options(
        self,
    ) -> typing.Optional[typing.Union["CfnDomain.SnapshotOptionsProperty", _IResolvable_da3f097b]]:
        '''*DEPRECATED* .

        The automated snapshot configuration for the OpenSearch Service domain indices.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-snapshotoptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDomain.SnapshotOptionsProperty", _IResolvable_da3f097b]], jsii.get(self, "snapshotOptions"))

    @snapshot_options.setter
    def snapshot_options(
        self,
        value: typing.Optional[typing.Union["CfnDomain.SnapshotOptionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "snapshotOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcOptions")
    def vpc_options(
        self,
    ) -> typing.Optional[typing.Union["CfnDomain.VPCOptionsProperty", _IResolvable_da3f097b]]:
        '''The virtual private cloud (VPC) configuration for the OpenSearch Service domain.

        For more information, see `Launching your Amazon OpenSearch Service domains within a VPC <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html>`_ in the *Amazon OpenSearch Service Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-vpcoptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnDomain.VPCOptionsProperty", _IResolvable_da3f097b]], jsii.get(self, "vpcOptions"))

    @vpc_options.setter
    def vpc_options(
        self,
        value: typing.Optional[typing.Union["CfnDomain.VPCOptionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "vpcOptions", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.AdvancedSecurityOptionsInputProperty",
        jsii_struct_bases=[],
        name_mapping={
            "enabled": "enabled",
            "internal_user_database_enabled": "internalUserDatabaseEnabled",
            "master_user_options": "masterUserOptions",
        },
    )
    class AdvancedSecurityOptionsInputProperty:
        def __init__(
            self,
            *,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            internal_user_database_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            master_user_options: typing.Optional[typing.Union["CfnDomain.MasterUserOptionsProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies options for fine-grained access control.

            .. epigraph::

               The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :param enabled: True to enable fine-grained access control. You must also enable encryption of data at rest and node-to-node encryption.
            :param internal_user_database_enabled: True to enable the internal user database.
            :param master_user_options: Specifies information about the master user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-advancedsecurityoptionsinput.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                advanced_security_options_input_property = elasticsearch.CfnDomain.AdvancedSecurityOptionsInputProperty(
                    enabled=False,
                    internal_user_database_enabled=False,
                    master_user_options=elasticsearch.CfnDomain.MasterUserOptionsProperty(
                        master_user_arn="masterUserArn",
                        master_user_name="masterUserName",
                        master_user_password="masterUserPassword"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if enabled is not None:
                self._values["enabled"] = enabled
            if internal_user_database_enabled is not None:
                self._values["internal_user_database_enabled"] = internal_user_database_enabled
            if master_user_options is not None:
                self._values["master_user_options"] = master_user_options

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''True to enable fine-grained access control.

            You must also enable encryption of data at rest and node-to-node encryption.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-advancedsecurityoptionsinput.html#cfn-elasticsearch-domain-advancedsecurityoptionsinput-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def internal_user_database_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''True to enable the internal user database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-advancedsecurityoptionsinput.html#cfn-elasticsearch-domain-advancedsecurityoptionsinput-internaluserdatabaseenabled
            '''
            result = self._values.get("internal_user_database_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def master_user_options(
            self,
        ) -> typing.Optional[typing.Union["CfnDomain.MasterUserOptionsProperty", _IResolvable_da3f097b]]:
            '''Specifies information about the master user.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-advancedsecurityoptionsinput.html#cfn-elasticsearch-domain-advancedsecurityoptionsinput-masteruseroptions
            '''
            result = self._values.get("master_user_options")
            return typing.cast(typing.Optional[typing.Union["CfnDomain.MasterUserOptionsProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AdvancedSecurityOptionsInputProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.CognitoOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "enabled": "enabled",
            "identity_pool_id": "identityPoolId",
            "role_arn": "roleArn",
            "user_pool_id": "userPoolId",
        },
    )
    class CognitoOptionsProperty:
        def __init__(
            self,
            *,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            identity_pool_id: typing.Optional[builtins.str] = None,
            role_arn: typing.Optional[builtins.str] = None,
            user_pool_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Configures OpenSearch Service to use Amazon Cognito authentication for OpenSearch Dashboards.

            .. epigraph::

               The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :param enabled: Whether to enable or disable Amazon Cognito authentication for OpenSearch Dashboards. See `Amazon Cognito authentication for OpenSearch Dashboards <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/cognito-auth.html>`_ .
            :param identity_pool_id: The Amazon Cognito identity pool ID that you want OpenSearch Service to use for OpenSearch Dashboards authentication.
            :param role_arn: The ``AmazonESCognitoAccess`` role that allows OpenSearch Service to configure your user pool and identity pool.
            :param user_pool_id: The Amazon Cognito user pool ID that you want OpenSearch Service to use for OpenSearch Dashboards authentication.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-cognitooptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                cognito_options_property = elasticsearch.CfnDomain.CognitoOptionsProperty(
                    enabled=False,
                    identity_pool_id="identityPoolId",
                    role_arn="roleArn",
                    user_pool_id="userPoolId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if enabled is not None:
                self._values["enabled"] = enabled
            if identity_pool_id is not None:
                self._values["identity_pool_id"] = identity_pool_id
            if role_arn is not None:
                self._values["role_arn"] = role_arn
            if user_pool_id is not None:
                self._values["user_pool_id"] = user_pool_id

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Whether to enable or disable Amazon Cognito authentication for OpenSearch Dashboards.

            See `Amazon Cognito authentication for OpenSearch Dashboards <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/cognito-auth.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-cognitooptions.html#cfn-elasticsearch-domain-cognitooptions-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def identity_pool_id(self) -> typing.Optional[builtins.str]:
            '''The Amazon Cognito identity pool ID that you want OpenSearch Service to use for OpenSearch Dashboards authentication.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-cognitooptions.html#cfn-elasticsearch-domain-cognitooptions-identitypoolid
            '''
            result = self._values.get("identity_pool_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def role_arn(self) -> typing.Optional[builtins.str]:
            '''The ``AmazonESCognitoAccess`` role that allows OpenSearch Service to configure your user pool and identity pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-cognitooptions.html#cfn-elasticsearch-domain-cognitooptions-rolearn
            '''
            result = self._values.get("role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def user_pool_id(self) -> typing.Optional[builtins.str]:
            '''The Amazon Cognito user pool ID that you want OpenSearch Service to use for OpenSearch Dashboards authentication.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-cognitooptions.html#cfn-elasticsearch-domain-cognitooptions-userpoolid
            '''
            result = self._values.get("user_pool_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CognitoOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.ColdStorageOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled"},
    )
    class ColdStorageOptionsProperty:
        def __init__(
            self,
            *,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies options for cold storage. For more information, see `Cold storage for Amazon Elasticsearch Service <https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/cold-storage.html>`_ .

            .. epigraph::

               The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :param enabled: Whether to enable or disable cold storage on the domain. You must enable UltraWarm storage in order to enable cold storage.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-coldstorageoptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                cold_storage_options_property = elasticsearch.CfnDomain.ColdStorageOptionsProperty(
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if enabled is not None:
                self._values["enabled"] = enabled

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Whether to enable or disable cold storage on the domain.

            You must enable UltraWarm storage in order to enable cold storage.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-coldstorageoptions.html#cfn-elasticsearch-domain-coldstorageoptions-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ColdStorageOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.DomainEndpointOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "custom_endpoint": "customEndpoint",
            "custom_endpoint_certificate_arn": "customEndpointCertificateArn",
            "custom_endpoint_enabled": "customEndpointEnabled",
            "enforce_https": "enforceHttps",
            "tls_security_policy": "tlsSecurityPolicy",
        },
    )
    class DomainEndpointOptionsProperty:
        def __init__(
            self,
            *,
            custom_endpoint: typing.Optional[builtins.str] = None,
            custom_endpoint_certificate_arn: typing.Optional[builtins.str] = None,
            custom_endpoint_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            enforce_https: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            tls_security_policy: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies additional options for the domain endpoint, such as whether to require HTTPS for all traffic or whether to use a custom endpoint rather than the default endpoint.

            .. epigraph::

               The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :param custom_endpoint: The fully qualified URL for your custom endpoint.
            :param custom_endpoint_certificate_arn: The AWS Certificate Manager ARN for your domain's SSL/TLS certificate.
            :param custom_endpoint_enabled: True to enable a custom endpoint for the domain. If enabled, you must also provide values for ``CustomEndpoint`` and ``CustomEndpointCertificateArn`` .
            :param enforce_https: True to require that all traffic to the domain arrive over HTTPS.
            :param tls_security_policy: The minimum TLS version required for traffic to the domain. Valid values are TLS 1.0 (default) or 1.2:. - ``Policy-Min-TLS-1-0-2019-07`` - ``Policy-Min-TLS-1-2-2019-07``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domainendpointoptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                domain_endpoint_options_property = elasticsearch.CfnDomain.DomainEndpointOptionsProperty(
                    custom_endpoint="customEndpoint",
                    custom_endpoint_certificate_arn="customEndpointCertificateArn",
                    custom_endpoint_enabled=False,
                    enforce_https=False,
                    tls_security_policy="tlsSecurityPolicy"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if custom_endpoint is not None:
                self._values["custom_endpoint"] = custom_endpoint
            if custom_endpoint_certificate_arn is not None:
                self._values["custom_endpoint_certificate_arn"] = custom_endpoint_certificate_arn
            if custom_endpoint_enabled is not None:
                self._values["custom_endpoint_enabled"] = custom_endpoint_enabled
            if enforce_https is not None:
                self._values["enforce_https"] = enforce_https
            if tls_security_policy is not None:
                self._values["tls_security_policy"] = tls_security_policy

        @builtins.property
        def custom_endpoint(self) -> typing.Optional[builtins.str]:
            '''The fully qualified URL for your custom endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domainendpointoptions.html#cfn-elasticsearch-domain-domainendpointoptions-customendpoint
            '''
            result = self._values.get("custom_endpoint")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def custom_endpoint_certificate_arn(self) -> typing.Optional[builtins.str]:
            '''The AWS Certificate Manager ARN for your domain's SSL/TLS certificate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domainendpointoptions.html#cfn-elasticsearch-domain-domainendpointoptions-customendpointcertificatearn
            '''
            result = self._values.get("custom_endpoint_certificate_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def custom_endpoint_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''True to enable a custom endpoint for the domain.

            If enabled, you must also provide values for ``CustomEndpoint`` and ``CustomEndpointCertificateArn`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domainendpointoptions.html#cfn-elasticsearch-domain-domainendpointoptions-customendpointenabled
            '''
            result = self._values.get("custom_endpoint_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def enforce_https(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''True to require that all traffic to the domain arrive over HTTPS.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domainendpointoptions.html#cfn-elasticsearch-domain-domainendpointoptions-enforcehttps
            '''
            result = self._values.get("enforce_https")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def tls_security_policy(self) -> typing.Optional[builtins.str]:
            '''The minimum TLS version required for traffic to the domain. Valid values are TLS 1.0 (default) or 1.2:.

            - ``Policy-Min-TLS-1-0-2019-07``
            - ``Policy-Min-TLS-1-2-2019-07``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-domainendpointoptions.html#cfn-elasticsearch-domain-domainendpointoptions-tlssecuritypolicy
            '''
            result = self._values.get("tls_security_policy")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DomainEndpointOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.EBSOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ebs_enabled": "ebsEnabled",
            "iops": "iops",
            "volume_size": "volumeSize",
            "volume_type": "volumeType",
        },
    )
    class EBSOptionsProperty:
        def __init__(
            self,
            *,
            ebs_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            iops: typing.Optional[jsii.Number] = None,
            volume_size: typing.Optional[jsii.Number] = None,
            volume_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configurations of Amazon Elastic Block Store (Amazon EBS) volumes that are attached to data nodes in the OpenSearch Service domain.

            For more information, see `EBS volume size limits <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/limits.html#ebsresource>`_ in the *Amazon OpenSearch Service Developer Guide* .
            .. epigraph::

               The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :param ebs_enabled: Specifies whether Amazon EBS volumes are attached to data nodes in the OpenSearch Service domain.
            :param iops: The number of I/O operations per second (IOPS) that the volume supports. This property applies only to the Provisioned IOPS (SSD) EBS volume type.
            :param volume_size: The size (in GiB) of the EBS volume for each data node. The minimum and maximum size of an EBS volume depends on the EBS volume type and the instance type to which it is attached. For more information, see `EBS volume size limits <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/limits.html#ebsresource>`_ in the *Amazon OpenSearch Service Developer Guide* .
            :param volume_type: The EBS volume type to use with the OpenSearch Service domain, such as standard, gp2, or io1. For more information about each type, see `Amazon EBS volume types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-ebsoptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                e_bSOptions_property = elasticsearch.CfnDomain.EBSOptionsProperty(
                    ebs_enabled=False,
                    iops=123,
                    volume_size=123,
                    volume_type="volumeType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ebs_enabled is not None:
                self._values["ebs_enabled"] = ebs_enabled
            if iops is not None:
                self._values["iops"] = iops
            if volume_size is not None:
                self._values["volume_size"] = volume_size
            if volume_type is not None:
                self._values["volume_type"] = volume_type

        @builtins.property
        def ebs_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether Amazon EBS volumes are attached to data nodes in the OpenSearch Service domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-ebsoptions.html#cfn-elasticsearch-domain-ebsoptions-ebsenabled
            '''
            result = self._values.get("ebs_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def iops(self) -> typing.Optional[jsii.Number]:
            '''The number of I/O operations per second (IOPS) that the volume supports.

            This property applies only to the Provisioned IOPS (SSD) EBS volume type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-ebsoptions.html#cfn-elasticsearch-domain-ebsoptions-iops
            '''
            result = self._values.get("iops")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def volume_size(self) -> typing.Optional[jsii.Number]:
            '''The size (in GiB) of the EBS volume for each data node.

            The minimum and maximum size of an EBS volume depends on the EBS volume type and the instance type to which it is attached. For more information, see `EBS volume size limits <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/limits.html#ebsresource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-ebsoptions.html#cfn-elasticsearch-domain-ebsoptions-volumesize
            '''
            result = self._values.get("volume_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def volume_type(self) -> typing.Optional[builtins.str]:
            '''The EBS volume type to use with the OpenSearch Service domain, such as standard, gp2, or io1.

            For more information about each type, see `Amazon EBS volume types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-ebsoptions.html#cfn-elasticsearch-domain-ebsoptions-volumetype
            '''
            result = self._values.get("volume_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EBSOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.ElasticsearchClusterConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cold_storage_options": "coldStorageOptions",
            "dedicated_master_count": "dedicatedMasterCount",
            "dedicated_master_enabled": "dedicatedMasterEnabled",
            "dedicated_master_type": "dedicatedMasterType",
            "instance_count": "instanceCount",
            "instance_type": "instanceType",
            "warm_count": "warmCount",
            "warm_enabled": "warmEnabled",
            "warm_type": "warmType",
            "zone_awareness_config": "zoneAwarenessConfig",
            "zone_awareness_enabled": "zoneAwarenessEnabled",
        },
    )
    class ElasticsearchClusterConfigProperty:
        def __init__(
            self,
            *,
            cold_storage_options: typing.Optional[typing.Union["CfnDomain.ColdStorageOptionsProperty", _IResolvable_da3f097b]] = None,
            dedicated_master_count: typing.Optional[jsii.Number] = None,
            dedicated_master_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            dedicated_master_type: typing.Optional[builtins.str] = None,
            instance_count: typing.Optional[jsii.Number] = None,
            instance_type: typing.Optional[builtins.str] = None,
            warm_count: typing.Optional[jsii.Number] = None,
            warm_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            warm_type: typing.Optional[builtins.str] = None,
            zone_awareness_config: typing.Optional[typing.Union["CfnDomain.ZoneAwarenessConfigProperty", _IResolvable_da3f097b]] = None,
            zone_awareness_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The cluster configuration for the OpenSearch Service domain.

            You can specify options such as the instance type and the number of instances. For more information, see `Creating and managing Amazon OpenSearch Service domains <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html>`_ in the *Amazon OpenSearch Service Developer Guide* .
            .. epigraph::

               The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :param cold_storage_options: Specifies cold storage options for the domain.
            :param dedicated_master_count: The number of instances to use for the master node. If you specify this property, you must specify true for the DedicatedMasterEnabled property.
            :param dedicated_master_enabled: Indicates whether to use a dedicated master node for the OpenSearch Service domain. A dedicated master node is a cluster node that performs cluster management tasks, but doesn't hold data or respond to data upload requests. Dedicated master nodes offload cluster management tasks to increase the stability of your search clusters. See `Dedicated master nodes in Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-dedicatedmasternodes.html>`_ .
            :param dedicated_master_type: The hardware configuration of the computer that hosts the dedicated master node, such as ``m3.medium.elasticsearch`` . If you specify this property, you must specify true for the ``DedicatedMasterEnabled`` property. For valid values, see `Supported instance types in Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html>`_ .
            :param instance_count: The number of data nodes (instances) to use in the OpenSearch Service domain.
            :param instance_type: The instance type for your data nodes, such as ``m3.medium.elasticsearch`` . For valid values, see `Supported instance types in Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html>`_ .
            :param warm_count: The number of warm nodes in the cluster.
            :param warm_enabled: Whether to enable warm storage for the cluster.
            :param warm_type: The instance type for the cluster's warm nodes.
            :param zone_awareness_config: Specifies zone awareness configuration options. Only use if ``ZoneAwarenessEnabled`` is ``true`` .
            :param zone_awareness_enabled: Indicates whether to enable zone awareness for the OpenSearch Service domain. When you enable zone awareness, OpenSearch Service allocates the nodes and replica index shards that belong to a cluster across two Availability Zones (AZs) in the same region to prevent data loss and minimize downtime in the event of node or data center failure. Don't enable zone awareness if your cluster has no replica index shards or is a single-node cluster. For more information, see `Configuring a multi-AZ domain in Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-multiaz.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                elasticsearch_cluster_config_property = elasticsearch.CfnDomain.ElasticsearchClusterConfigProperty(
                    cold_storage_options=elasticsearch.CfnDomain.ColdStorageOptionsProperty(
                        enabled=False
                    ),
                    dedicated_master_count=123,
                    dedicated_master_enabled=False,
                    dedicated_master_type="dedicatedMasterType",
                    instance_count=123,
                    instance_type="instanceType",
                    warm_count=123,
                    warm_enabled=False,
                    warm_type="warmType",
                    zone_awareness_config=elasticsearch.CfnDomain.ZoneAwarenessConfigProperty(
                        availability_zone_count=123
                    ),
                    zone_awareness_enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cold_storage_options is not None:
                self._values["cold_storage_options"] = cold_storage_options
            if dedicated_master_count is not None:
                self._values["dedicated_master_count"] = dedicated_master_count
            if dedicated_master_enabled is not None:
                self._values["dedicated_master_enabled"] = dedicated_master_enabled
            if dedicated_master_type is not None:
                self._values["dedicated_master_type"] = dedicated_master_type
            if instance_count is not None:
                self._values["instance_count"] = instance_count
            if instance_type is not None:
                self._values["instance_type"] = instance_type
            if warm_count is not None:
                self._values["warm_count"] = warm_count
            if warm_enabled is not None:
                self._values["warm_enabled"] = warm_enabled
            if warm_type is not None:
                self._values["warm_type"] = warm_type
            if zone_awareness_config is not None:
                self._values["zone_awareness_config"] = zone_awareness_config
            if zone_awareness_enabled is not None:
                self._values["zone_awareness_enabled"] = zone_awareness_enabled

        @builtins.property
        def cold_storage_options(
            self,
        ) -> typing.Optional[typing.Union["CfnDomain.ColdStorageOptionsProperty", _IResolvable_da3f097b]]:
            '''Specifies cold storage options for the domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html#cfn-elasticsearch-domain-elasticsearchclusterconfig-coldstorageoptions
            '''
            result = self._values.get("cold_storage_options")
            return typing.cast(typing.Optional[typing.Union["CfnDomain.ColdStorageOptionsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def dedicated_master_count(self) -> typing.Optional[jsii.Number]:
            '''The number of instances to use for the master node.

            If you specify this property, you must specify true for the DedicatedMasterEnabled property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html#cfn-elasticsearch-domain-elasticseachclusterconfig-dedicatedmastercount
            '''
            result = self._values.get("dedicated_master_count")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def dedicated_master_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether to use a dedicated master node for the OpenSearch Service domain.

            A dedicated master node is a cluster node that performs cluster management tasks, but doesn't hold data or respond to data upload requests. Dedicated master nodes offload cluster management tasks to increase the stability of your search clusters. See `Dedicated master nodes in Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-dedicatedmasternodes.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html#cfn-elasticsearch-domain-elasticseachclusterconfig-dedicatedmasterenabled
            '''
            result = self._values.get("dedicated_master_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def dedicated_master_type(self) -> typing.Optional[builtins.str]:
            '''The hardware configuration of the computer that hosts the dedicated master node, such as ``m3.medium.elasticsearch`` . If you specify this property, you must specify true for the ``DedicatedMasterEnabled`` property. For valid values, see `Supported instance types in Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html#cfn-elasticsearch-domain-elasticseachclusterconfig-dedicatedmastertype
            '''
            result = self._values.get("dedicated_master_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def instance_count(self) -> typing.Optional[jsii.Number]:
            '''The number of data nodes (instances) to use in the OpenSearch Service domain.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html#cfn-elasticsearch-domain-elasticseachclusterconfig-instancecount
            '''
            result = self._values.get("instance_count")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def instance_type(self) -> typing.Optional[builtins.str]:
            '''The instance type for your data nodes, such as ``m3.medium.elasticsearch`` . For valid values, see `Supported instance types in Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-instance-types.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html#cfn-elasticsearch-domain-elasticseachclusterconfig-instnacetype
            '''
            result = self._values.get("instance_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def warm_count(self) -> typing.Optional[jsii.Number]:
            '''The number of warm nodes in the cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html#cfn-elasticsearch-domain-elasticsearchclusterconfig-warmcount
            '''
            result = self._values.get("warm_count")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def warm_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Whether to enable warm storage for the cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html#cfn-elasticsearch-domain-elasticsearchclusterconfig-warmenabled
            '''
            result = self._values.get("warm_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def warm_type(self) -> typing.Optional[builtins.str]:
            '''The instance type for the cluster's warm nodes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html#cfn-elasticsearch-domain-elasticsearchclusterconfig-warmtype
            '''
            result = self._values.get("warm_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def zone_awareness_config(
            self,
        ) -> typing.Optional[typing.Union["CfnDomain.ZoneAwarenessConfigProperty", _IResolvable_da3f097b]]:
            '''Specifies zone awareness configuration options.

            Only use if ``ZoneAwarenessEnabled`` is ``true`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html#cfn-elasticsearch-domain-elasticsearchclusterconfig-zoneawarenessconfig
            '''
            result = self._values.get("zone_awareness_config")
            return typing.cast(typing.Optional[typing.Union["CfnDomain.ZoneAwarenessConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def zone_awareness_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether to enable zone awareness for the OpenSearch Service domain.

            When you enable zone awareness, OpenSearch Service allocates the nodes and replica index shards that belong to a cluster across two Availability Zones (AZs) in the same region to prevent data loss and minimize downtime in the event of node or data center failure. Don't enable zone awareness if your cluster has no replica index shards or is a single-node cluster. For more information, see `Configuring a multi-AZ domain in Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-multiaz.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-elasticsearchclusterconfig.html#cfn-elasticsearch-domain-elasticseachclusterconfig-zoneawarenessenabled
            '''
            result = self._values.get("zone_awareness_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ElasticsearchClusterConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.EncryptionAtRestOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled", "kms_key_id": "kmsKeyId"},
    )
    class EncryptionAtRestOptionsProperty:
        def __init__(
            self,
            *,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            kms_key_id: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Whether the domain should encrypt data at rest, and if so, the AWS Key Management Service key to use.

            .. epigraph::

               The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :param enabled: Specify ``true`` to enable encryption at rest.
            :param kms_key_id: The KMS key ID. Takes the form ``1a2a3a4-1a2a-3a4a-5a6a-1a2a3a4a5a6a`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-encryptionatrestoptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                encryption_at_rest_options_property = elasticsearch.CfnDomain.EncryptionAtRestOptionsProperty(
                    enabled=False,
                    kms_key_id="kmsKeyId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if enabled is not None:
                self._values["enabled"] = enabled
            if kms_key_id is not None:
                self._values["kms_key_id"] = kms_key_id

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specify ``true`` to enable encryption at rest.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-encryptionatrestoptions.html#cfn-elasticsearch-domain-encryptionatrestoptions-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def kms_key_id(self) -> typing.Optional[builtins.str]:
            '''The KMS key ID.

            Takes the form ``1a2a3a4-1a2a-3a4a-5a6a-1a2a3a4a5a6a`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-encryptionatrestoptions.html#cfn-elasticsearch-domain-encryptionatrestoptions-kmskeyid
            '''
            result = self._values.get("kms_key_id")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionAtRestOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.LogPublishingOptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "cloud_watch_logs_log_group_arn": "cloudWatchLogsLogGroupArn",
            "enabled": "enabled",
        },
    )
    class LogPublishingOptionProperty:
        def __init__(
            self,
            *,
            cloud_watch_logs_log_group_arn: typing.Optional[builtins.str] = None,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''.. epigraph::

   The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            Specifies whether the OpenSearch Service domain publishes the Elasticsearch application, search slow logs, or index slow logs to Amazon CloudWatch. Each option must be an object of name ``SEARCH_SLOW_LOGS`` , ``ES_APPLICATION_LOGS`` , ``INDEX_SLOW_LOGS`` , or ``AUDIT_LOGS`` depending on the type of logs you want to publish.

            If you enable a slow log, you still have to enable the *collection* of slow logs using the Configuration API. To learn more, see `Enabling log publishing ( AWS CLI) <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/createdomain-configure-slow-logs.html#createdomain-configure-slow-logs-cli>`_ .

            :param cloud_watch_logs_log_group_arn: Specifies the CloudWatch log group to publish to.
            :param enabled: If ``true`` , enables the publishing of logs to CloudWatch. Default: ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-logpublishingoption.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                log_publishing_option_property = elasticsearch.CfnDomain.LogPublishingOptionProperty(
                    cloud_watch_logs_log_group_arn="cloudWatchLogsLogGroupArn",
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cloud_watch_logs_log_group_arn is not None:
                self._values["cloud_watch_logs_log_group_arn"] = cloud_watch_logs_log_group_arn
            if enabled is not None:
                self._values["enabled"] = enabled

        @builtins.property
        def cloud_watch_logs_log_group_arn(self) -> typing.Optional[builtins.str]:
            '''Specifies the CloudWatch log group to publish to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-logpublishingoption.html#cfn-elasticsearch-domain-logpublishingoption-cloudwatchlogsloggrouparn
            '''
            result = self._values.get("cloud_watch_logs_log_group_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If ``true`` , enables the publishing of logs to CloudWatch.

            Default: ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-logpublishingoption.html#cfn-elasticsearch-domain-logpublishingoption-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LogPublishingOptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.MasterUserOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "master_user_arn": "masterUserArn",
            "master_user_name": "masterUserName",
            "master_user_password": "masterUserPassword",
        },
    )
    class MasterUserOptionsProperty:
        def __init__(
            self,
            *,
            master_user_arn: typing.Optional[builtins.str] = None,
            master_user_name: typing.Optional[builtins.str] = None,
            master_user_password: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies information about the master user.

            .. epigraph::

               The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :param master_user_arn: ARN for the master user. Only specify if ``InternalUserDatabaseEnabled`` is false in ``AdvancedSecurityOptions`` .
            :param master_user_name: Username for the master user. Only specify if ``InternalUserDatabaseEnabled`` is true in ``AdvancedSecurityOptions`` .
            :param master_user_password: Password for the master user. Only specify if ``InternalUserDatabaseEnabled`` is true in ``AdvancedSecurityOptions`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-masteruseroptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                master_user_options_property = elasticsearch.CfnDomain.MasterUserOptionsProperty(
                    master_user_arn="masterUserArn",
                    master_user_name="masterUserName",
                    master_user_password="masterUserPassword"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if master_user_arn is not None:
                self._values["master_user_arn"] = master_user_arn
            if master_user_name is not None:
                self._values["master_user_name"] = master_user_name
            if master_user_password is not None:
                self._values["master_user_password"] = master_user_password

        @builtins.property
        def master_user_arn(self) -> typing.Optional[builtins.str]:
            '''ARN for the master user.

            Only specify if ``InternalUserDatabaseEnabled`` is false in ``AdvancedSecurityOptions`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-masteruseroptions.html#cfn-elasticsearch-domain-masteruseroptions-masteruserarn
            '''
            result = self._values.get("master_user_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def master_user_name(self) -> typing.Optional[builtins.str]:
            '''Username for the master user.

            Only specify if ``InternalUserDatabaseEnabled`` is true in ``AdvancedSecurityOptions`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-masteruseroptions.html#cfn-elasticsearch-domain-masteruseroptions-masterusername
            '''
            result = self._values.get("master_user_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def master_user_password(self) -> typing.Optional[builtins.str]:
            '''Password for the master user.

            Only specify if ``InternalUserDatabaseEnabled`` is true in ``AdvancedSecurityOptions`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-masteruseroptions.html#cfn-elasticsearch-domain-masteruseroptions-masteruserpassword
            '''
            result = self._values.get("master_user_password")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MasterUserOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.NodeToNodeEncryptionOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled": "enabled"},
    )
    class NodeToNodeEncryptionOptionsProperty:
        def __init__(
            self,
            *,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies whether node-to-node encryption is enabled.

            .. epigraph::

               The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :param enabled: Specifies whether node-to-node encryption is enabled, as a Boolean.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-nodetonodeencryptionoptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                node_to_node_encryption_options_property = elasticsearch.CfnDomain.NodeToNodeEncryptionOptionsProperty(
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if enabled is not None:
                self._values["enabled"] = enabled

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether node-to-node encryption is enabled, as a Boolean.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-nodetonodeencryptionoptions.html#cfn-elasticsearch-domain-nodetonodeencryptionoptions-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NodeToNodeEncryptionOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.SnapshotOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={"automated_snapshot_start_hour": "automatedSnapshotStartHour"},
    )
    class SnapshotOptionsProperty:
        def __init__(
            self,
            *,
            automated_snapshot_start_hour: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''.. epigraph::

   The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            *DEPRECATED* . For domains running Elasticsearch 5.3 and later, OpenSearch Service takes hourly automated snapshots, making this setting irrelevant. For domains running earlier versions of Elasticsearch, OpenSearch Service takes daily automated snapshots.

            The automated snapshot configuration for the OpenSearch Service domain indices.

            :param automated_snapshot_start_hour: The hour in UTC during which the service takes an automated daily snapshot of the indices in the OpenSearch Service domain. For example, if you specify 0, OpenSearch Service takes an automated snapshot everyday between midnight and 1 am. You can specify a value between 0 and 23.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-snapshotoptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                snapshot_options_property = elasticsearch.CfnDomain.SnapshotOptionsProperty(
                    automated_snapshot_start_hour=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if automated_snapshot_start_hour is not None:
                self._values["automated_snapshot_start_hour"] = automated_snapshot_start_hour

        @builtins.property
        def automated_snapshot_start_hour(self) -> typing.Optional[jsii.Number]:
            '''The hour in UTC during which the service takes an automated daily snapshot of the indices in the OpenSearch Service domain.

            For example, if you specify 0, OpenSearch Service takes an automated snapshot everyday between midnight and 1 am. You can specify a value between 0 and 23.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-snapshotoptions.html#cfn-elasticsearch-domain-snapshotoptions-automatedsnapshotstarthour
            '''
            result = self._values.get("automated_snapshot_start_hour")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SnapshotOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.VPCOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "security_group_ids": "securityGroupIds",
            "subnet_ids": "subnetIds",
        },
    )
    class VPCOptionsProperty:
        def __init__(
            self,
            *,
            security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
            subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The virtual private cloud (VPC) configuration for the OpenSearch Service domain.

            For more information, see `Launching your Amazon OpenSearch Service domains using a VPC <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html>`_ in the *Amazon OpenSearch Service Developer Guide* .
            .. epigraph::

               The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :param security_group_ids: The list of security group IDs that are associated with the VPC endpoints for the domain. If you don't provide a security group ID, OpenSearch Service uses the default security group for the VPC. To learn more, see `Security groups for your VPC <https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html>`_ in the *Amazon VPC User Guide* .
            :param subnet_ids: Provide one subnet ID for each Availability Zone that your domain uses. For example, you must specify three subnet IDs for a three Availability Zone domain. To learn more, see `VPCs and subnets <https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html>`_ in the *Amazon VPC User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-vpcoptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                v_pCOptions_property = elasticsearch.CfnDomain.VPCOptionsProperty(
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if security_group_ids is not None:
                self._values["security_group_ids"] = security_group_ids
            if subnet_ids is not None:
                self._values["subnet_ids"] = subnet_ids

        @builtins.property
        def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The list of security group IDs that are associated with the VPC endpoints for the domain.

            If you don't provide a security group ID, OpenSearch Service uses the default security group for the VPC. To learn more, see `Security groups for your VPC <https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html>`_ in the *Amazon VPC User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-vpcoptions.html#cfn-elasticsearch-domain-vpcoptions-securitygroupids
            '''
            result = self._values.get("security_group_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def subnet_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Provide one subnet ID for each Availability Zone that your domain uses.

            For example, you must specify three subnet IDs for a three Availability Zone domain. To learn more, see `VPCs and subnets <https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html>`_ in the *Amazon VPC User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-vpcoptions.html#cfn-elasticsearch-domain-vpcoptions-subnetids
            '''
            result = self._values.get("subnet_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VPCOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomain.ZoneAwarenessConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"availability_zone_count": "availabilityZoneCount"},
    )
    class ZoneAwarenessConfigProperty:
        def __init__(
            self,
            *,
            availability_zone_count: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies zone awareness configuration options. Only use if ``ZoneAwarenessEnabled`` is ``true`` .

            .. epigraph::

               The ``AWS::Elasticsearch::Domain`` resource is being replaced by the `AWS::OpenSearchService::Domain <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html>`_ resource. While the legacy Elasticsearch resource and options are still supported, we recommend modifying your existing Cloudformation templates to use the new OpenSearch Service resource, which supports both OpenSearch and Elasticsearch. For more information about the service rename, see `New resource types <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html#rename-resource>`_ in the *Amazon OpenSearch Service Developer Guide* .

            :param availability_zone_count: If you enabled multiple Availability Zones (AZs), the number of AZs that you want the domain to use. Valid values are ``2`` and ``3`` . Default is 2.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-zoneawarenessconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticsearch as elasticsearch
                
                zone_awareness_config_property = elasticsearch.CfnDomain.ZoneAwarenessConfigProperty(
                    availability_zone_count=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if availability_zone_count is not None:
                self._values["availability_zone_count"] = availability_zone_count

        @builtins.property
        def availability_zone_count(self) -> typing.Optional[jsii.Number]:
            '''If you enabled multiple Availability Zones (AZs), the number of AZs that you want the domain to use.

            Valid values are ``2`` and ``3`` . Default is 2.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticsearch-domain-zoneawarenessconfig.html#cfn-elasticsearch-domain-zoneawarenessconfig-availabilityzonecount
            '''
            result = self._values.get("availability_zone_count")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ZoneAwarenessConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticsearch.CfnDomainProps",
    jsii_struct_bases=[],
    name_mapping={
        "access_policies": "accessPolicies",
        "advanced_options": "advancedOptions",
        "advanced_security_options": "advancedSecurityOptions",
        "cognito_options": "cognitoOptions",
        "domain_endpoint_options": "domainEndpointOptions",
        "domain_name": "domainName",
        "ebs_options": "ebsOptions",
        "elasticsearch_cluster_config": "elasticsearchClusterConfig",
        "elasticsearch_version": "elasticsearchVersion",
        "encryption_at_rest_options": "encryptionAtRestOptions",
        "log_publishing_options": "logPublishingOptions",
        "node_to_node_encryption_options": "nodeToNodeEncryptionOptions",
        "snapshot_options": "snapshotOptions",
        "tags": "tags",
        "vpc_options": "vpcOptions",
    },
)
class CfnDomainProps:
    def __init__(
        self,
        *,
        access_policies: typing.Any = None,
        advanced_options: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        advanced_security_options: typing.Optional[typing.Union[CfnDomain.AdvancedSecurityOptionsInputProperty, _IResolvable_da3f097b]] = None,
        cognito_options: typing.Optional[typing.Union[CfnDomain.CognitoOptionsProperty, _IResolvable_da3f097b]] = None,
        domain_endpoint_options: typing.Optional[typing.Union[CfnDomain.DomainEndpointOptionsProperty, _IResolvable_da3f097b]] = None,
        domain_name: typing.Optional[builtins.str] = None,
        ebs_options: typing.Optional[typing.Union[CfnDomain.EBSOptionsProperty, _IResolvable_da3f097b]] = None,
        elasticsearch_cluster_config: typing.Optional[typing.Union[CfnDomain.ElasticsearchClusterConfigProperty, _IResolvable_da3f097b]] = None,
        elasticsearch_version: typing.Optional[builtins.str] = None,
        encryption_at_rest_options: typing.Optional[typing.Union[CfnDomain.EncryptionAtRestOptionsProperty, _IResolvable_da3f097b]] = None,
        log_publishing_options: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDomain.LogPublishingOptionProperty, _IResolvable_da3f097b]]]] = None,
        node_to_node_encryption_options: typing.Optional[typing.Union[CfnDomain.NodeToNodeEncryptionOptionsProperty, _IResolvable_da3f097b]] = None,
        snapshot_options: typing.Optional[typing.Union[CfnDomain.SnapshotOptionsProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        vpc_options: typing.Optional[typing.Union[CfnDomain.VPCOptionsProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDomain``.

        :param access_policies: An AWS Identity and Access Management ( IAM ) policy document that specifies who can access the OpenSearch Service domain and their permissions. For more information, see `Configuring access policies <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ac.html#ac-creating>`_ in the *Amazon OpenSearch Service Developer Guid* e.
        :param advanced_options: Additional options to specify for the OpenSearch Service domain. For more information, see `Advanced cluster parameters <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html#createdomain-configure-advanced-options>`_ in the *Amazon OpenSearch Service Developer Guide* .
        :param advanced_security_options: Specifies options for fine-grained access control.
        :param cognito_options: Configures OpenSearch Service to use Amazon Cognito authentication for OpenSearch Dashboards.
        :param domain_endpoint_options: Specifies additional options for the domain endpoint, such as whether to require HTTPS for all traffic or whether to use a custom endpoint rather than the default endpoint.
        :param domain_name: A name for the OpenSearch Service domain. For valid values, see the `DomainName <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/configuration-api.html#configuration-api-datatypes-domainname>`_ data type in the *Amazon OpenSearch Service Developer Guide* . If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the domain name. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ . .. epigraph:: If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.
        :param ebs_options: The configurations of Amazon Elastic Block Store (Amazon EBS) volumes that are attached to data nodes in the OpenSearch Service domain. For more information, see `EBS volume size limits <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/limits.html#ebsresource>`_ in the *Amazon OpenSearch Service Developer Guide* .
        :param elasticsearch_cluster_config: ElasticsearchClusterConfig is a property of the AWS::Elasticsearch::Domain resource that configures the cluster of an Amazon OpenSearch Service domain.
        :param elasticsearch_version: The version of Elasticsearch to use, such as 2.3. If not specified, 1.5 is used as the default. For information about the versions that OpenSearch Service supports, see `Supported versions of OpenSearch and Elasticsearch <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/what-is.html#choosing-version>`_ in the *Amazon OpenSearch Service Developer Guide* . If you set the `EnableVersionUpgrade <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-upgradeopensearchdomain>`_ update policy to ``true`` , you can update ``ElasticsearchVersion`` without interruption. When ``EnableVersionUpgrade`` is set to ``false`` , or is not specified, updating ``ElasticsearchVersion`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .
        :param encryption_at_rest_options: Whether the domain should encrypt data at rest, and if so, the AWS Key Management Service key to use. See `Encryption of data at rest for Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html>`_ .
        :param log_publishing_options: An object with one or more of the following keys: ``SEARCH_SLOW_LOGS`` , ``ES_APPLICATION_LOGS`` , ``INDEX_SLOW_LOGS`` , ``AUDIT_LOGS`` , depending on the types of logs you want to publish. Each key needs a valid ``LogPublishingOption`` value.
        :param node_to_node_encryption_options: Specifies whether node-to-node encryption is enabled. See `Node-to-node encryption for Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ntn.html>`_ .
        :param snapshot_options: *DEPRECATED* . The automated snapshot configuration for the OpenSearch Service domain indices.
        :param tags: An arbitrary set of tags (key–value pairs) to associate with the OpenSearch Service domain.
        :param vpc_options: The virtual private cloud (VPC) configuration for the OpenSearch Service domain. For more information, see `Launching your Amazon OpenSearch Service domains within a VPC <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html>`_ in the *Amazon OpenSearch Service Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticsearch as elasticsearch
            
            # access_policies: Any
            
            cfn_domain_props = elasticsearch.CfnDomainProps(
                access_policies=access_policies,
                advanced_options={
                    "advanced_options_key": "advancedOptions"
                },
                advanced_security_options=elasticsearch.CfnDomain.AdvancedSecurityOptionsInputProperty(
                    enabled=False,
                    internal_user_database_enabled=False,
                    master_user_options=elasticsearch.CfnDomain.MasterUserOptionsProperty(
                        master_user_arn="masterUserArn",
                        master_user_name="masterUserName",
                        master_user_password="masterUserPassword"
                    )
                ),
                cognito_options=elasticsearch.CfnDomain.CognitoOptionsProperty(
                    enabled=False,
                    identity_pool_id="identityPoolId",
                    role_arn="roleArn",
                    user_pool_id="userPoolId"
                ),
                domain_endpoint_options=elasticsearch.CfnDomain.DomainEndpointOptionsProperty(
                    custom_endpoint="customEndpoint",
                    custom_endpoint_certificate_arn="customEndpointCertificateArn",
                    custom_endpoint_enabled=False,
                    enforce_https=False,
                    tls_security_policy="tlsSecurityPolicy"
                ),
                domain_name="domainName",
                ebs_options=elasticsearch.CfnDomain.EBSOptionsProperty(
                    ebs_enabled=False,
                    iops=123,
                    volume_size=123,
                    volume_type="volumeType"
                ),
                elasticsearch_cluster_config=elasticsearch.CfnDomain.ElasticsearchClusterConfigProperty(
                    cold_storage_options=elasticsearch.CfnDomain.ColdStorageOptionsProperty(
                        enabled=False
                    ),
                    dedicated_master_count=123,
                    dedicated_master_enabled=False,
                    dedicated_master_type="dedicatedMasterType",
                    instance_count=123,
                    instance_type="instanceType",
                    warm_count=123,
                    warm_enabled=False,
                    warm_type="warmType",
                    zone_awareness_config=elasticsearch.CfnDomain.ZoneAwarenessConfigProperty(
                        availability_zone_count=123
                    ),
                    zone_awareness_enabled=False
                ),
                elasticsearch_version="elasticsearchVersion",
                encryption_at_rest_options=elasticsearch.CfnDomain.EncryptionAtRestOptionsProperty(
                    enabled=False,
                    kms_key_id="kmsKeyId"
                ),
                log_publishing_options={
                    "log_publishing_options_key": elasticsearch.CfnDomain.LogPublishingOptionProperty(
                        cloud_watch_logs_log_group_arn="cloudWatchLogsLogGroupArn",
                        enabled=False
                    )
                },
                node_to_node_encryption_options=elasticsearch.CfnDomain.NodeToNodeEncryptionOptionsProperty(
                    enabled=False
                ),
                snapshot_options=elasticsearch.CfnDomain.SnapshotOptionsProperty(
                    automated_snapshot_start_hour=123
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                vpc_options=elasticsearch.CfnDomain.VPCOptionsProperty(
                    security_group_ids=["securityGroupIds"],
                    subnet_ids=["subnetIds"]
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if access_policies is not None:
            self._values["access_policies"] = access_policies
        if advanced_options is not None:
            self._values["advanced_options"] = advanced_options
        if advanced_security_options is not None:
            self._values["advanced_security_options"] = advanced_security_options
        if cognito_options is not None:
            self._values["cognito_options"] = cognito_options
        if domain_endpoint_options is not None:
            self._values["domain_endpoint_options"] = domain_endpoint_options
        if domain_name is not None:
            self._values["domain_name"] = domain_name
        if ebs_options is not None:
            self._values["ebs_options"] = ebs_options
        if elasticsearch_cluster_config is not None:
            self._values["elasticsearch_cluster_config"] = elasticsearch_cluster_config
        if elasticsearch_version is not None:
            self._values["elasticsearch_version"] = elasticsearch_version
        if encryption_at_rest_options is not None:
            self._values["encryption_at_rest_options"] = encryption_at_rest_options
        if log_publishing_options is not None:
            self._values["log_publishing_options"] = log_publishing_options
        if node_to_node_encryption_options is not None:
            self._values["node_to_node_encryption_options"] = node_to_node_encryption_options
        if snapshot_options is not None:
            self._values["snapshot_options"] = snapshot_options
        if tags is not None:
            self._values["tags"] = tags
        if vpc_options is not None:
            self._values["vpc_options"] = vpc_options

    @builtins.property
    def access_policies(self) -> typing.Any:
        '''An AWS Identity and Access Management ( IAM ) policy document that specifies who can access the OpenSearch Service domain and their permissions.

        For more information, see `Configuring access policies <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ac.html#ac-creating>`_ in the *Amazon OpenSearch Service Developer Guid* e.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-accesspolicies
        '''
        result = self._values.get("access_policies")
        return typing.cast(typing.Any, result)

    @builtins.property
    def advanced_options(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''Additional options to specify for the OpenSearch Service domain.

        For more information, see `Advanced cluster parameters <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/createupdatedomains.html#createdomain-configure-advanced-options>`_ in the *Amazon OpenSearch Service Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-advancedoptions
        '''
        result = self._values.get("advanced_options")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

    @builtins.property
    def advanced_security_options(
        self,
    ) -> typing.Optional[typing.Union[CfnDomain.AdvancedSecurityOptionsInputProperty, _IResolvable_da3f097b]]:
        '''Specifies options for fine-grained access control.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-advancedsecurityoptions
        '''
        result = self._values.get("advanced_security_options")
        return typing.cast(typing.Optional[typing.Union[CfnDomain.AdvancedSecurityOptionsInputProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def cognito_options(
        self,
    ) -> typing.Optional[typing.Union[CfnDomain.CognitoOptionsProperty, _IResolvable_da3f097b]]:
        '''Configures OpenSearch Service to use Amazon Cognito authentication for OpenSearch Dashboards.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-cognitooptions
        '''
        result = self._values.get("cognito_options")
        return typing.cast(typing.Optional[typing.Union[CfnDomain.CognitoOptionsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def domain_endpoint_options(
        self,
    ) -> typing.Optional[typing.Union[CfnDomain.DomainEndpointOptionsProperty, _IResolvable_da3f097b]]:
        '''Specifies additional options for the domain endpoint, such as whether to require HTTPS for all traffic or whether to use a custom endpoint rather than the default endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-domainendpointoptions
        '''
        result = self._values.get("domain_endpoint_options")
        return typing.cast(typing.Optional[typing.Union[CfnDomain.DomainEndpointOptionsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def domain_name(self) -> typing.Optional[builtins.str]:
        '''A name for the OpenSearch Service domain.

        For valid values, see the `DomainName <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/configuration-api.html#configuration-api-datatypes-domainname>`_ data type in the *Amazon OpenSearch Service Developer Guide* . If you don't specify a name, AWS CloudFormation generates a unique physical ID and uses that ID for the domain name. For more information, see `Name Type <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-name.html>`_ .
        .. epigraph::

           If you specify a name, you cannot perform updates that require replacement of this resource. You can perform updates that require no or some interruption. If you must replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-domainname
        '''
        result = self._values.get("domain_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ebs_options(
        self,
    ) -> typing.Optional[typing.Union[CfnDomain.EBSOptionsProperty, _IResolvable_da3f097b]]:
        '''The configurations of Amazon Elastic Block Store (Amazon EBS) volumes that are attached to data nodes in the OpenSearch Service domain.

        For more information, see `EBS volume size limits <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/limits.html#ebsresource>`_ in the *Amazon OpenSearch Service Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-ebsoptions
        '''
        result = self._values.get("ebs_options")
        return typing.cast(typing.Optional[typing.Union[CfnDomain.EBSOptionsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def elasticsearch_cluster_config(
        self,
    ) -> typing.Optional[typing.Union[CfnDomain.ElasticsearchClusterConfigProperty, _IResolvable_da3f097b]]:
        '''ElasticsearchClusterConfig is a property of the AWS::Elasticsearch::Domain resource that configures the cluster of an Amazon OpenSearch Service domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-elasticsearchclusterconfig
        '''
        result = self._values.get("elasticsearch_cluster_config")
        return typing.cast(typing.Optional[typing.Union[CfnDomain.ElasticsearchClusterConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def elasticsearch_version(self) -> typing.Optional[builtins.str]:
        '''The version of Elasticsearch to use, such as 2.3. If not specified, 1.5 is used as the default. For information about the versions that OpenSearch Service supports, see `Supported versions of OpenSearch and Elasticsearch <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/what-is.html#choosing-version>`_ in the *Amazon OpenSearch Service Developer Guide* .

        If you set the `EnableVersionUpgrade <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-upgradeopensearchdomain>`_ update policy to ``true`` , you can update ``ElasticsearchVersion`` without interruption. When ``EnableVersionUpgrade`` is set to ``false`` , or is not specified, updating ``ElasticsearchVersion`` results in `replacement <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html#update-replacement>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-elasticsearchversion
        '''
        result = self._values.get("elasticsearch_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def encryption_at_rest_options(
        self,
    ) -> typing.Optional[typing.Union[CfnDomain.EncryptionAtRestOptionsProperty, _IResolvable_da3f097b]]:
        '''Whether the domain should encrypt data at rest, and if so, the AWS Key Management Service key to use.

        See `Encryption of data at rest for Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-encryptionatrestoptions
        '''
        result = self._values.get("encryption_at_rest_options")
        return typing.cast(typing.Optional[typing.Union[CfnDomain.EncryptionAtRestOptionsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def log_publishing_options(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDomain.LogPublishingOptionProperty, _IResolvable_da3f097b]]]]:
        '''An object with one or more of the following keys: ``SEARCH_SLOW_LOGS`` , ``ES_APPLICATION_LOGS`` , ``INDEX_SLOW_LOGS`` , ``AUDIT_LOGS`` , depending on the types of logs you want to publish.

        Each key needs a valid ``LogPublishingOption`` value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-logpublishingoptions
        '''
        result = self._values.get("log_publishing_options")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, typing.Union[CfnDomain.LogPublishingOptionProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def node_to_node_encryption_options(
        self,
    ) -> typing.Optional[typing.Union[CfnDomain.NodeToNodeEncryptionOptionsProperty, _IResolvable_da3f097b]]:
        '''Specifies whether node-to-node encryption is enabled.

        See `Node-to-node encryption for Amazon OpenSearch Service <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ntn.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-nodetonodeencryptionoptions
        '''
        result = self._values.get("node_to_node_encryption_options")
        return typing.cast(typing.Optional[typing.Union[CfnDomain.NodeToNodeEncryptionOptionsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def snapshot_options(
        self,
    ) -> typing.Optional[typing.Union[CfnDomain.SnapshotOptionsProperty, _IResolvable_da3f097b]]:
        '''*DEPRECATED* .

        The automated snapshot configuration for the OpenSearch Service domain indices.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-snapshotoptions
        '''
        result = self._values.get("snapshot_options")
        return typing.cast(typing.Optional[typing.Union[CfnDomain.SnapshotOptionsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An arbitrary set of tags (key–value pairs) to associate with the OpenSearch Service domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def vpc_options(
        self,
    ) -> typing.Optional[typing.Union[CfnDomain.VPCOptionsProperty, _IResolvable_da3f097b]]:
        '''The virtual private cloud (VPC) configuration for the OpenSearch Service domain.

        For more information, see `Launching your Amazon OpenSearch Service domains within a VPC <https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html>`_ in the *Amazon OpenSearch Service Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticsearch-domain.html#cfn-elasticsearch-domain-vpcoptions
        '''
        result = self._values.get("vpc_options")
        return typing.cast(typing.Optional[typing.Union[CfnDomain.VPCOptionsProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDomainProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticsearch.CognitoOptions",
    jsii_struct_bases=[],
    name_mapping={
        "identity_pool_id": "identityPoolId",
        "role": "role",
        "user_pool_id": "userPoolId",
    },
)
class CognitoOptions:
    def __init__(
        self,
        *,
        identity_pool_id: builtins.str,
        role: _IRole_235f5d8e,
        user_pool_id: builtins.str,
    ) -> None:
        '''Configures Amazon ES to use Amazon Cognito authentication for Kibana.

        :param identity_pool_id: The Amazon Cognito identity pool ID that you want Amazon ES to use for Kibana authentication.
        :param role: A role that allows Amazon ES to configure your user pool and identity pool. It must have the ``AmazonESCognitoAccess`` policy attached to it.
        :param user_pool_id: The Amazon Cognito user pool ID that you want Amazon ES to use for Kibana authentication.

        :see: https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html
        :exampleMetadata: fixture=migrate-opensearch infused

        Example::

            # Example automatically generated from non-compiling source. May contain errors.
            es.Domain(self, "Domain",
                cognito_kibana_auth=es.CognitoOptions(
                    identity_pool_id="test-identity-pool-id",
                    user_pool_id="test-user-pool-id",
                    role=role
                ),
                version=elasticsearch_version
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "identity_pool_id": identity_pool_id,
            "role": role,
            "user_pool_id": user_pool_id,
        }

    @builtins.property
    def identity_pool_id(self) -> builtins.str:
        '''The Amazon Cognito identity pool ID that you want Amazon ES to use for Kibana authentication.'''
        result = self._values.get("identity_pool_id")
        assert result is not None, "Required property 'identity_pool_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role(self) -> _IRole_235f5d8e:
        '''A role that allows Amazon ES to configure your user pool and identity pool.

        It must have the ``AmazonESCognitoAccess`` policy attached to it.

        :see: https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-cognito-auth.html#es-cognito-auth-prereq
        '''
        result = self._values.get("role")
        assert result is not None, "Required property 'role' is missing"
        return typing.cast(_IRole_235f5d8e, result)

    @builtins.property
    def user_pool_id(self) -> builtins.str:
        '''The Amazon Cognito user pool ID that you want Amazon ES to use for Kibana authentication.'''
        result = self._values.get("user_pool_id")
        assert result is not None, "Required property 'user_pool_id' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CognitoOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticsearch.CustomEndpointOptions",
    jsii_struct_bases=[],
    name_mapping={
        "domain_name": "domainName",
        "certificate": "certificate",
        "hosted_zone": "hostedZone",
    },
)
class CustomEndpointOptions:
    def __init__(
        self,
        *,
        domain_name: builtins.str,
        certificate: typing.Optional[_ICertificate_c194c70b] = None,
        hosted_zone: typing.Optional[_IHostedZone_9a6907ad] = None,
    ) -> None:
        '''Configures a custom domain endpoint for the ES domain.

        :param domain_name: The custom domain name to assign.
        :param certificate: The certificate to use. Default: - create a new one
        :param hosted_zone: The hosted zone in Route53 to create the CNAME record in. Default: - do not create a CNAME

        :exampleMetadata: infused

        Example::

            es.Domain(self, "Domain",
                version=es.ElasticsearchVersion.V7_7,
                custom_endpoint=es.CustomEndpointOptions(
                    domain_name="search.example.com"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain_name": domain_name,
        }
        if certificate is not None:
            self._values["certificate"] = certificate
        if hosted_zone is not None:
            self._values["hosted_zone"] = hosted_zone

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''The custom domain name to assign.'''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def certificate(self) -> typing.Optional[_ICertificate_c194c70b]:
        '''The certificate to use.

        :default: - create a new one
        '''
        result = self._values.get("certificate")
        return typing.cast(typing.Optional[_ICertificate_c194c70b], result)

    @builtins.property
    def hosted_zone(self) -> typing.Optional[_IHostedZone_9a6907ad]:
        '''The hosted zone in Route53 to create the CNAME record in.

        :default: - do not create a CNAME
        '''
        result = self._values.get("hosted_zone")
        return typing.cast(typing.Optional[_IHostedZone_9a6907ad], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CustomEndpointOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticsearch.DomainAttributes",
    jsii_struct_bases=[],
    name_mapping={"domain_arn": "domainArn", "domain_endpoint": "domainEndpoint"},
)
class DomainAttributes:
    def __init__(
        self,
        *,
        domain_arn: builtins.str,
        domain_endpoint: builtins.str,
    ) -> None:
        '''Reference to an Elasticsearch domain.

        :param domain_arn: The ARN of the Elasticsearch domain.
        :param domain_endpoint: The domain endpoint of the Elasticsearch domain.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticsearch as elasticsearch
            
            domain_attributes = elasticsearch.DomainAttributes(
                domain_arn="domainArn",
                domain_endpoint="domainEndpoint"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain_arn": domain_arn,
            "domain_endpoint": domain_endpoint,
        }

    @builtins.property
    def domain_arn(self) -> builtins.str:
        '''The ARN of the Elasticsearch domain.'''
        result = self._values.get("domain_arn")
        assert result is not None, "Required property 'domain_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def domain_endpoint(self) -> builtins.str:
        '''The domain endpoint of the Elasticsearch domain.'''
        result = self._values.get("domain_endpoint")
        assert result is not None, "Required property 'domain_endpoint' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DomainAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticsearch.DomainProps",
    jsii_struct_bases=[],
    name_mapping={
        "version": "version",
        "access_policies": "accessPolicies",
        "advanced_options": "advancedOptions",
        "automated_snapshot_start_hour": "automatedSnapshotStartHour",
        "capacity": "capacity",
        "cognito_kibana_auth": "cognitoKibanaAuth",
        "custom_endpoint": "customEndpoint",
        "domain_name": "domainName",
        "ebs": "ebs",
        "enable_version_upgrade": "enableVersionUpgrade",
        "encryption_at_rest": "encryptionAtRest",
        "enforce_https": "enforceHttps",
        "fine_grained_access_control": "fineGrainedAccessControl",
        "logging": "logging",
        "node_to_node_encryption": "nodeToNodeEncryption",
        "removal_policy": "removalPolicy",
        "security_groups": "securityGroups",
        "tls_security_policy": "tlsSecurityPolicy",
        "use_unsigned_basic_auth": "useUnsignedBasicAuth",
        "vpc": "vpc",
        "vpc_subnets": "vpcSubnets",
        "zone_awareness": "zoneAwareness",
    },
)
class DomainProps:
    def __init__(
        self,
        *,
        version: "ElasticsearchVersion",
        access_policies: typing.Optional[typing.Sequence[_PolicyStatement_0fe33853]] = None,
        advanced_options: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        automated_snapshot_start_hour: typing.Optional[jsii.Number] = None,
        capacity: typing.Optional[CapacityConfig] = None,
        cognito_kibana_auth: typing.Optional[CognitoOptions] = None,
        custom_endpoint: typing.Optional[CustomEndpointOptions] = None,
        domain_name: typing.Optional[builtins.str] = None,
        ebs: typing.Optional["EbsOptions"] = None,
        enable_version_upgrade: typing.Optional[builtins.bool] = None,
        encryption_at_rest: typing.Optional["EncryptionAtRestOptions"] = None,
        enforce_https: typing.Optional[builtins.bool] = None,
        fine_grained_access_control: typing.Optional[AdvancedSecurityOptions] = None,
        logging: typing.Optional["LoggingOptions"] = None,
        node_to_node_encryption: typing.Optional[builtins.bool] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        tls_security_policy: typing.Optional["TLSSecurityPolicy"] = None,
        use_unsigned_basic_auth: typing.Optional[builtins.bool] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[typing.Sequence[_SubnetSelection_e57d76df]] = None,
        zone_awareness: typing.Optional["ZoneAwarenessConfig"] = None,
    ) -> None:
        '''Properties for an AWS Elasticsearch Domain.

        :param version: The Elasticsearch version that your domain will leverage.
        :param access_policies: Domain Access policies. Default: - No access policies.
        :param advanced_options: Additional options to specify for the Amazon ES domain. Default: - no advanced options are specified
        :param automated_snapshot_start_hour: The hour in UTC during which the service takes an automated daily snapshot of the indices in the Amazon ES domain. Only applies for Elasticsearch versions below 5.3. Default: - Hourly automated snapshots not used
        :param capacity: The cluster capacity configuration for the Amazon ES domain. Default: - 1 r5.large.elasticsearch data node; no dedicated master nodes.
        :param cognito_kibana_auth: Configures Amazon ES to use Amazon Cognito authentication for Kibana. Default: - Cognito not used for authentication to Kibana.
        :param custom_endpoint: To configure a custom domain configure these options. If you specify a Route53 hosted zone it will create a CNAME record and use DNS validation for the certificate Default: - no custom domain endpoint will be configured
        :param domain_name: Enforces a particular physical domain name. Default: - A name will be auto-generated.
        :param ebs: The configurations of Amazon Elastic Block Store (Amazon EBS) volumes that are attached to data nodes in the Amazon ES domain. For more information, see [Configuring EBS-based Storage] (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-ebs) in the Amazon Elasticsearch Service Developer Guide. Default: - 10 GiB General Purpose (SSD) volumes per node.
        :param enable_version_upgrade: To upgrade an Amazon ES domain to a new version of Elasticsearch rather than replacing the entire domain resource, use the EnableVersionUpgrade update policy. Default: - false
        :param encryption_at_rest: Encryption at rest options for the cluster. Default: - No encryption at rest
        :param enforce_https: True to require that all traffic to the domain arrive over HTTPS. Default: - false
        :param fine_grained_access_control: Specifies options for fine-grained access control. Requires Elasticsearch version 6.7 or later. Enabling fine-grained access control also requires encryption of data at rest and node-to-node encryption, along with enforced HTTPS. Default: - fine-grained access control is disabled
        :param logging: Configuration log publishing configuration options. Default: - No logs are published
        :param node_to_node_encryption: Specify true to enable node to node encryption. Requires Elasticsearch version 6.0 or later. Default: - Node to node encryption is not enabled.
        :param removal_policy: Policy to apply when the domain is removed from the stack. Default: RemovalPolicy.RETAIN
        :param security_groups: The list of security groups that are associated with the VPC endpoints for the domain. Only used if ``vpc`` is specified. Default: - One new security group is created.
        :param tls_security_policy: The minimum TLS version required for traffic to the domain. Default: - TLSSecurityPolicy.TLS_1_0
        :param use_unsigned_basic_auth: Configures the domain so that unsigned basic auth is enabled. If no master user is provided a default master user with username ``admin`` and a dynamically generated password stored in KMS is created. The password can be retrieved by getting ``masterUserPassword`` from the domain instance. Setting this to true will also add an access policy that allows unsigned access, enable node to node encryption, encryption at rest. If conflicting settings are encountered (like disabling encryption at rest) enabling this setting will cause a failure. Default: - false
        :param vpc: Place the domain inside this VPC. Default: - Domain is not placed in a VPC.
        :param vpc_subnets: The specific vpc subnets the domain will be placed in. You must provide one subnet for each Availability Zone that your domain uses. For example, you must specify three subnet IDs for a three Availability Zone domain. Only used if ``vpc`` is specified. Default: - All private subnets.
        :param zone_awareness: The cluster zone awareness configuration for the Amazon ES domain. Default: - no zone awareness (1 AZ)

        :exampleMetadata: infused

        Example::

            domain = es.Domain(self, "Domain",
                version=es.ElasticsearchVersion.V7_4,
                ebs=es.EbsOptions(
                    volume_size=100,
                    volume_type=ec2.EbsDeviceVolumeType.GENERAL_PURPOSE_SSD
                ),
                node_to_node_encryption=True,
                encryption_at_rest=es.EncryptionAtRestOptions(
                    enabled=True
                )
            )
        '''
        if isinstance(capacity, dict):
            capacity = CapacityConfig(**capacity)
        if isinstance(cognito_kibana_auth, dict):
            cognito_kibana_auth = CognitoOptions(**cognito_kibana_auth)
        if isinstance(custom_endpoint, dict):
            custom_endpoint = CustomEndpointOptions(**custom_endpoint)
        if isinstance(ebs, dict):
            ebs = EbsOptions(**ebs)
        if isinstance(encryption_at_rest, dict):
            encryption_at_rest = EncryptionAtRestOptions(**encryption_at_rest)
        if isinstance(fine_grained_access_control, dict):
            fine_grained_access_control = AdvancedSecurityOptions(**fine_grained_access_control)
        if isinstance(logging, dict):
            logging = LoggingOptions(**logging)
        if isinstance(zone_awareness, dict):
            zone_awareness = ZoneAwarenessConfig(**zone_awareness)
        self._values: typing.Dict[str, typing.Any] = {
            "version": version,
        }
        if access_policies is not None:
            self._values["access_policies"] = access_policies
        if advanced_options is not None:
            self._values["advanced_options"] = advanced_options
        if automated_snapshot_start_hour is not None:
            self._values["automated_snapshot_start_hour"] = automated_snapshot_start_hour
        if capacity is not None:
            self._values["capacity"] = capacity
        if cognito_kibana_auth is not None:
            self._values["cognito_kibana_auth"] = cognito_kibana_auth
        if custom_endpoint is not None:
            self._values["custom_endpoint"] = custom_endpoint
        if domain_name is not None:
            self._values["domain_name"] = domain_name
        if ebs is not None:
            self._values["ebs"] = ebs
        if enable_version_upgrade is not None:
            self._values["enable_version_upgrade"] = enable_version_upgrade
        if encryption_at_rest is not None:
            self._values["encryption_at_rest"] = encryption_at_rest
        if enforce_https is not None:
            self._values["enforce_https"] = enforce_https
        if fine_grained_access_control is not None:
            self._values["fine_grained_access_control"] = fine_grained_access_control
        if logging is not None:
            self._values["logging"] = logging
        if node_to_node_encryption is not None:
            self._values["node_to_node_encryption"] = node_to_node_encryption
        if removal_policy is not None:
            self._values["removal_policy"] = removal_policy
        if security_groups is not None:
            self._values["security_groups"] = security_groups
        if tls_security_policy is not None:
            self._values["tls_security_policy"] = tls_security_policy
        if use_unsigned_basic_auth is not None:
            self._values["use_unsigned_basic_auth"] = use_unsigned_basic_auth
        if vpc is not None:
            self._values["vpc"] = vpc
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets
        if zone_awareness is not None:
            self._values["zone_awareness"] = zone_awareness

    @builtins.property
    def version(self) -> "ElasticsearchVersion":
        '''The Elasticsearch version that your domain will leverage.'''
        result = self._values.get("version")
        assert result is not None, "Required property 'version' is missing"
        return typing.cast("ElasticsearchVersion", result)

    @builtins.property
    def access_policies(
        self,
    ) -> typing.Optional[typing.List[_PolicyStatement_0fe33853]]:
        '''Domain Access policies.

        :default: - No access policies.
        '''
        result = self._values.get("access_policies")
        return typing.cast(typing.Optional[typing.List[_PolicyStatement_0fe33853]], result)

    @builtins.property
    def advanced_options(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Additional options to specify for the Amazon ES domain.

        :default: - no advanced options are specified

        :see: https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-advanced-options
        '''
        result = self._values.get("advanced_options")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def automated_snapshot_start_hour(self) -> typing.Optional[jsii.Number]:
        '''The hour in UTC during which the service takes an automated daily snapshot of the indices in the Amazon ES domain.

        Only applies for Elasticsearch
        versions below 5.3.

        :default: - Hourly automated snapshots not used
        '''
        result = self._values.get("automated_snapshot_start_hour")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def capacity(self) -> typing.Optional[CapacityConfig]:
        '''The cluster capacity configuration for the Amazon ES domain.

        :default: - 1 r5.large.elasticsearch data node; no dedicated master nodes.
        '''
        result = self._values.get("capacity")
        return typing.cast(typing.Optional[CapacityConfig], result)

    @builtins.property
    def cognito_kibana_auth(self) -> typing.Optional[CognitoOptions]:
        '''Configures Amazon ES to use Amazon Cognito authentication for Kibana.

        :default: - Cognito not used for authentication to Kibana.
        '''
        result = self._values.get("cognito_kibana_auth")
        return typing.cast(typing.Optional[CognitoOptions], result)

    @builtins.property
    def custom_endpoint(self) -> typing.Optional[CustomEndpointOptions]:
        '''To configure a custom domain configure these options.

        If you specify a Route53 hosted zone it will create a CNAME record and use DNS validation for the certificate

        :default: - no custom domain endpoint will be configured
        '''
        result = self._values.get("custom_endpoint")
        return typing.cast(typing.Optional[CustomEndpointOptions], result)

    @builtins.property
    def domain_name(self) -> typing.Optional[builtins.str]:
        '''Enforces a particular physical domain name.

        :default: - A name will be auto-generated.
        '''
        result = self._values.get("domain_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ebs(self) -> typing.Optional["EbsOptions"]:
        '''The configurations of Amazon Elastic Block Store (Amazon EBS) volumes that are attached to data nodes in the Amazon ES domain.

        For more information, see
        [Configuring EBS-based Storage]
        (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-ebs)
        in the Amazon Elasticsearch Service Developer Guide.

        :default: - 10 GiB General Purpose (SSD) volumes per node.
        '''
        result = self._values.get("ebs")
        return typing.cast(typing.Optional["EbsOptions"], result)

    @builtins.property
    def enable_version_upgrade(self) -> typing.Optional[builtins.bool]:
        '''To upgrade an Amazon ES domain to a new version of Elasticsearch rather than replacing the entire domain resource, use the EnableVersionUpgrade update policy.

        :default: - false

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html#cfn-attributes-updatepolicy-upgradeelasticsearchdomain
        '''
        result = self._values.get("enable_version_upgrade")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def encryption_at_rest(self) -> typing.Optional["EncryptionAtRestOptions"]:
        '''Encryption at rest options for the cluster.

        :default: - No encryption at rest
        '''
        result = self._values.get("encryption_at_rest")
        return typing.cast(typing.Optional["EncryptionAtRestOptions"], result)

    @builtins.property
    def enforce_https(self) -> typing.Optional[builtins.bool]:
        '''True to require that all traffic to the domain arrive over HTTPS.

        :default: - false
        '''
        result = self._values.get("enforce_https")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def fine_grained_access_control(self) -> typing.Optional[AdvancedSecurityOptions]:
        '''Specifies options for fine-grained access control.

        Requires Elasticsearch version 6.7 or later. Enabling fine-grained access control
        also requires encryption of data at rest and node-to-node encryption, along with
        enforced HTTPS.

        :default: - fine-grained access control is disabled
        '''
        result = self._values.get("fine_grained_access_control")
        return typing.cast(typing.Optional[AdvancedSecurityOptions], result)

    @builtins.property
    def logging(self) -> typing.Optional["LoggingOptions"]:
        '''Configuration log publishing configuration options.

        :default: - No logs are published
        '''
        result = self._values.get("logging")
        return typing.cast(typing.Optional["LoggingOptions"], result)

    @builtins.property
    def node_to_node_encryption(self) -> typing.Optional[builtins.bool]:
        '''Specify true to enable node to node encryption.

        Requires Elasticsearch version 6.0 or later.

        :default: - Node to node encryption is not enabled.
        '''
        result = self._values.get("node_to_node_encryption")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def removal_policy(self) -> typing.Optional[_RemovalPolicy_9f93c814]:
        '''Policy to apply when the domain is removed from the stack.

        :default: RemovalPolicy.RETAIN
        '''
        result = self._values.get("removal_policy")
        return typing.cast(typing.Optional[_RemovalPolicy_9f93c814], result)

    @builtins.property
    def security_groups(self) -> typing.Optional[typing.List[_ISecurityGroup_acf8a799]]:
        '''The list of security groups that are associated with the VPC endpoints for the domain.

        Only used if ``vpc`` is specified.

        :default: - One new security group is created.

        :see: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html
        '''
        result = self._values.get("security_groups")
        return typing.cast(typing.Optional[typing.List[_ISecurityGroup_acf8a799]], result)

    @builtins.property
    def tls_security_policy(self) -> typing.Optional["TLSSecurityPolicy"]:
        '''The minimum TLS version required for traffic to the domain.

        :default: - TLSSecurityPolicy.TLS_1_0
        '''
        result = self._values.get("tls_security_policy")
        return typing.cast(typing.Optional["TLSSecurityPolicy"], result)

    @builtins.property
    def use_unsigned_basic_auth(self) -> typing.Optional[builtins.bool]:
        '''Configures the domain so that unsigned basic auth is enabled.

        If no master user is provided a default master user
        with username ``admin`` and a dynamically generated password stored in KMS is created. The password can be retrieved
        by getting ``masterUserPassword`` from the domain instance.

        Setting this to true will also add an access policy that allows unsigned
        access, enable node to node encryption, encryption at rest. If conflicting
        settings are encountered (like disabling encryption at rest) enabling this
        setting will cause a failure.

        :default: - false
        '''
        result = self._values.get("use_unsigned_basic_auth")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''Place the domain inside this VPC.

        :default: - Domain is not placed in a VPC.

        :see: https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[typing.List[_SubnetSelection_e57d76df]]:
        '''The specific vpc subnets the domain will be placed in.

        You must provide one subnet for each Availability Zone
        that your domain uses. For example, you must specify three subnet IDs for a three Availability Zone
        domain.

        Only used if ``vpc`` is specified.

        :default: - All private subnets.

        :see: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[typing.List[_SubnetSelection_e57d76df]], result)

    @builtins.property
    def zone_awareness(self) -> typing.Optional["ZoneAwarenessConfig"]:
        '''The cluster zone awareness configuration for the Amazon ES domain.

        :default: - no zone awareness (1 AZ)
        '''
        result = self._values.get("zone_awareness")
        return typing.cast(typing.Optional["ZoneAwarenessConfig"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "DomainProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticsearch.EbsOptions",
    jsii_struct_bases=[],
    name_mapping={
        "enabled": "enabled",
        "iops": "iops",
        "volume_size": "volumeSize",
        "volume_type": "volumeType",
    },
)
class EbsOptions:
    def __init__(
        self,
        *,
        enabled: typing.Optional[builtins.bool] = None,
        iops: typing.Optional[jsii.Number] = None,
        volume_size: typing.Optional[jsii.Number] = None,
        volume_type: typing.Optional[_EbsDeviceVolumeType_6792555b] = None,
    ) -> None:
        '''The configurations of Amazon Elastic Block Store (Amazon EBS) volumes that are attached to data nodes in the Amazon ES domain.

        For more information, see
        [Configuring EBS-based Storage]
        (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-ebs)
        in the Amazon Elasticsearch Service Developer Guide.

        :param enabled: Specifies whether Amazon EBS volumes are attached to data nodes in the Amazon ES domain. Default: - true
        :param iops: The number of I/O operations per second (IOPS) that the volume supports. This property applies only to the Provisioned IOPS (SSD) EBS volume type. Default: - iops are not set.
        :param volume_size: The size (in GiB) of the EBS volume for each data node. The minimum and maximum size of an EBS volume depends on the EBS volume type and the instance type to which it is attached. For more information, see [Configuring EBS-based Storage] (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-ebs) in the Amazon Elasticsearch Service Developer Guide. Default: 10
        :param volume_type: The EBS volume type to use with the Amazon ES domain, such as standard, gp2, io1. For more information, see[Configuring EBS-based Storage] (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-ebs) in the Amazon Elasticsearch Service Developer Guide. Default: gp2

        :exampleMetadata: infused

        Example::

            prod_domain = es.Domain(self, "Domain",
                version=es.ElasticsearchVersion.V7_1,
                capacity=es.CapacityConfig(
                    master_nodes=5,
                    data_nodes=20
                ),
                ebs=es.EbsOptions(
                    volume_size=20
                ),
                zone_awareness=es.ZoneAwarenessConfig(
                    availability_zone_count=3
                ),
                logging=es.LoggingOptions(
                    slow_search_log_enabled=True,
                    app_log_enabled=True,
                    slow_index_log_enabled=True
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if enabled is not None:
            self._values["enabled"] = enabled
        if iops is not None:
            self._values["iops"] = iops
        if volume_size is not None:
            self._values["volume_size"] = volume_size
        if volume_type is not None:
            self._values["volume_type"] = volume_type

    @builtins.property
    def enabled(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether Amazon EBS volumes are attached to data nodes in the Amazon ES domain.

        :default: - true
        '''
        result = self._values.get("enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def iops(self) -> typing.Optional[jsii.Number]:
        '''The number of I/O operations per second (IOPS) that the volume supports.

        This property applies only to the Provisioned IOPS (SSD) EBS
        volume type.

        :default: - iops are not set.
        '''
        result = self._values.get("iops")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def volume_size(self) -> typing.Optional[jsii.Number]:
        '''The size (in GiB) of the EBS volume for each data node.

        The minimum and
        maximum size of an EBS volume depends on the EBS volume type and the
        instance type to which it is attached.  For more information, see
        [Configuring EBS-based Storage]
        (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-ebs)
        in the Amazon Elasticsearch Service Developer Guide.

        :default: 10
        '''
        result = self._values.get("volume_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def volume_type(self) -> typing.Optional[_EbsDeviceVolumeType_6792555b]:
        '''The EBS volume type to use with the Amazon ES domain, such as standard, gp2, io1.

        For more information, see[Configuring EBS-based Storage]
        (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-ebs)
        in the Amazon Elasticsearch Service Developer Guide.

        :default: gp2
        '''
        result = self._values.get("volume_type")
        return typing.cast(typing.Optional[_EbsDeviceVolumeType_6792555b], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EbsOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class ElasticsearchVersion(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticsearch.ElasticsearchVersion",
):
    '''Elasticsearch version.

    :exampleMetadata: infused

    Example::

        domain = es.Domain(self, "Domain",
            version=es.ElasticsearchVersion.V7_4,
            ebs=es.EbsOptions(
                volume_size=100,
                volume_type=ec2.EbsDeviceVolumeType.GENERAL_PURPOSE_SSD
            ),
            node_to_node_encryption=True,
            encryption_at_rest=es.EncryptionAtRestOptions(
                enabled=True
            )
        )
    '''

    @jsii.member(jsii_name="of") # type: ignore[misc]
    @builtins.classmethod
    def of(cls, version: builtins.str) -> "ElasticsearchVersion":
        '''Custom Elasticsearch version.

        :param version: custom version number.
        '''
        return typing.cast("ElasticsearchVersion", jsii.sinvoke(cls, "of", [version]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V1_5")
    def V1_5(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 1.5.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V1_5"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_3")
    def V2_3(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 2.3.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V2_3"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V5_1")
    def V5_1(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 5.1.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V5_1"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V5_3")
    def V5_3(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 5.3.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V5_3"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V5_5")
    def V5_5(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 5.5.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V5_5"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V5_6")
    def V5_6(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 5.6.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V5_6"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V6_0")
    def V6_0(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 6.0.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V6_0"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V6_2")
    def V6_2(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 6.2.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V6_2"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V6_3")
    def V6_3(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 6.3.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V6_3"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V6_4")
    def V6_4(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 6.4.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V6_4"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V6_5")
    def V6_5(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 6.5.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V6_5"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V6_7")
    def V6_7(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 6.7.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V6_7"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V6_8")
    def V6_8(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 6.8.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V6_8"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V7_1")
    def V7_1(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 7.1.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V7_1"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V7_10")
    def V7_10(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 7.10.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V7_10"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V7_4")
    def V7_4(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 7.4.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V7_4"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V7_7")
    def V7_7(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 7.7.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V7_7"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V7_8")
    def V7_8(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 7.8.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V7_8"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V7_9")
    def V7_9(cls) -> "ElasticsearchVersion":
        '''AWS Elasticsearch 7.9.'''
        return typing.cast("ElasticsearchVersion", jsii.sget(cls, "V7_9"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="version")
    def version(self) -> builtins.str:
        '''Elasticsearch version number.'''
        return typing.cast(builtins.str, jsii.get(self, "version"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticsearch.EncryptionAtRestOptions",
    jsii_struct_bases=[],
    name_mapping={"enabled": "enabled", "kms_key": "kmsKey"},
)
class EncryptionAtRestOptions:
    def __init__(
        self,
        *,
        enabled: typing.Optional[builtins.bool] = None,
        kms_key: typing.Optional[_IKey_5f11635f] = None,
    ) -> None:
        '''Whether the domain should encrypt data at rest, and if so, the AWS Key Management Service (KMS) key to use.

        Can only be used to create a new domain,
        not update an existing one. Requires Elasticsearch version 5.1 or later.

        :param enabled: Specify true to enable encryption at rest. Default: - encryption at rest is disabled.
        :param kms_key: Supply if using KMS key for encryption at rest. Default: - uses default aws/es KMS key.

        :exampleMetadata: infused

        Example::

            domain = es.Domain(self, "Domain",
                version=es.ElasticsearchVersion.V7_1,
                enforce_https=True,
                node_to_node_encryption=True,
                encryption_at_rest=es.EncryptionAtRestOptions(
                    enabled=True
                ),
                fine_grained_access_control=es.AdvancedSecurityOptions(
                    master_user_name="master-user"
                ),
                logging=es.LoggingOptions(
                    audit_log_enabled=True,
                    slow_search_log_enabled=True,
                    app_log_enabled=True,
                    slow_index_log_enabled=True
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if enabled is not None:
            self._values["enabled"] = enabled
        if kms_key is not None:
            self._values["kms_key"] = kms_key

    @builtins.property
    def enabled(self) -> typing.Optional[builtins.bool]:
        '''Specify true to enable encryption at rest.

        :default: - encryption at rest is disabled.
        '''
        result = self._values.get("enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def kms_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''Supply if using KMS key for encryption at rest.

        :default: - uses default aws/es KMS key.
        '''
        result = self._values.get("kms_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EncryptionAtRestOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_elasticsearch.IDomain")
class IDomain(_IResource_c80c4260, typing_extensions.Protocol):
    '''An interface that represents an Elasticsearch domain - either created with the CDK, or an existing one.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainArn")
    def domain_arn(self) -> builtins.str:
        '''Arn of the Elasticsearch domain.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainEndpoint")
    def domain_endpoint(self) -> builtins.str:
        '''Endpoint of the Elasticsearch domain.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''Domain name of the Elasticsearch domain.

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="grantIndexRead")
    def grant_index_read(
        self,
        index: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read permissions for an index in this domain to an IAM principal (Role/Group/User).

        :param index: The index to grant permissions for.
        :param identity: The principal.
        '''
        ...

    @jsii.member(jsii_name="grantIndexReadWrite")
    def grant_index_read_write(
        self,
        index: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read/write permissions for an index in this domain to an IAM principal (Role/Group/User).

        :param index: The index to grant permissions for.
        :param identity: The principal.
        '''
        ...

    @jsii.member(jsii_name="grantIndexWrite")
    def grant_index_write(
        self,
        index: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant write permissions for an index in this domain to an IAM principal (Role/Group/User).

        :param index: The index to grant permissions for.
        :param identity: The principal.
        '''
        ...

    @jsii.member(jsii_name="grantPathRead")
    def grant_path_read(
        self,
        path: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read permissions for a specific path in this domain to an IAM principal (Role/Group/User).

        :param path: The path to grant permissions for.
        :param identity: The principal.
        '''
        ...

    @jsii.member(jsii_name="grantPathReadWrite")
    def grant_path_read_write(
        self,
        path: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read/write permissions for a specific path in this domain to an IAM principal (Role/Group/User).

        :param path: The path to grant permissions for.
        :param identity: The principal.
        '''
        ...

    @jsii.member(jsii_name="grantPathWrite")
    def grant_path_write(
        self,
        path: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant write permissions for a specific path in this domain to an IAM principal (Role/Group/User).

        :param path: The path to grant permissions for.
        :param identity: The principal.
        '''
        ...

    @jsii.member(jsii_name="grantRead")
    def grant_read(self, identity: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant read permissions for this domain and its contents to an IAM principal (Role/Group/User).

        :param identity: The principal.
        '''
        ...

    @jsii.member(jsii_name="grantReadWrite")
    def grant_read_write(self, identity: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant read/write permissions for this domain and its contents to an IAM principal (Role/Group/User).

        :param identity: The principal.
        '''
        ...

    @jsii.member(jsii_name="grantWrite")
    def grant_write(self, identity: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant write permissions for this domain and its contents to an IAM principal (Role/Group/User).

        :param identity: The principal.
        '''
        ...

    @jsii.member(jsii_name="metric")
    def metric(
        self,
        metric_name: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the given named metric for this Domain.

        :param metric_name: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        ...

    @jsii.member(jsii_name="metricAutomatedSnapshotFailure")
    def metric_automated_snapshot_failure(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for automated snapshot failures.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricClusterIndexWritesBlocked")
    def metric_cluster_index_writes_blocked(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the cluster blocking index writes.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 1 minute
        '''
        ...

    @jsii.member(jsii_name="metricClusterStatusRed")
    def metric_cluster_status_red(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the time the cluster status is red.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricClusterStatusYellow")
    def metric_cluster_status_yellow(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the time the cluster status is yellow.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricCPUUtilization")
    def metric_cpu_utilization(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for CPU utilization.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricFreeStorageSpace")
    def metric_free_storage_space(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the storage space of nodes in the cluster.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: minimum over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricIndexingLatency")
    def metric_indexing_latency(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for indexing latency.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: p99 over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricJVMMemoryPressure")
    def metric_jvm_memory_pressure(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for JVM memory pressure.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricKMSKeyError")
    def metric_kms_key_error(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for KMS key errors.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricKMSKeyInaccessible")
    def metric_kms_key_inaccessible(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for KMS key being inaccessible.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricMasterCPUUtilization")
    def metric_master_cpu_utilization(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for master CPU utilization.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricMasterJVMMemoryPressure")
    def metric_master_jvm_memory_pressure(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for master JVM memory pressure.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricNodes")
    def metric_nodes(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the number of nodes.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: minimum over 1 hour
        '''
        ...

    @jsii.member(jsii_name="metricSearchableDocuments")
    def metric_searchable_documents(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for number of searchable documents.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        ...

    @jsii.member(jsii_name="metricSearchLatency")
    def metric_search_latency(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for search latency.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: p99 over 5 minutes
        '''
        ...


class _IDomainProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''An interface that represents an Elasticsearch domain - either created with the CDK, or an existing one.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticsearch.IDomain"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainArn")
    def domain_arn(self) -> builtins.str:
        '''Arn of the Elasticsearch domain.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "domainArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainEndpoint")
    def domain_endpoint(self) -> builtins.str:
        '''Endpoint of the Elasticsearch domain.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "domainEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''Domain name of the Elasticsearch domain.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))

    @jsii.member(jsii_name="grantIndexRead")
    def grant_index_read(
        self,
        index: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read permissions for an index in this domain to an IAM principal (Role/Group/User).

        :param index: The index to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantIndexRead", [index, identity]))

    @jsii.member(jsii_name="grantIndexReadWrite")
    def grant_index_read_write(
        self,
        index: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read/write permissions for an index in this domain to an IAM principal (Role/Group/User).

        :param index: The index to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantIndexReadWrite", [index, identity]))

    @jsii.member(jsii_name="grantIndexWrite")
    def grant_index_write(
        self,
        index: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant write permissions for an index in this domain to an IAM principal (Role/Group/User).

        :param index: The index to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantIndexWrite", [index, identity]))

    @jsii.member(jsii_name="grantPathRead")
    def grant_path_read(
        self,
        path: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read permissions for a specific path in this domain to an IAM principal (Role/Group/User).

        :param path: The path to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPathRead", [path, identity]))

    @jsii.member(jsii_name="grantPathReadWrite")
    def grant_path_read_write(
        self,
        path: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read/write permissions for a specific path in this domain to an IAM principal (Role/Group/User).

        :param path: The path to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPathReadWrite", [path, identity]))

    @jsii.member(jsii_name="grantPathWrite")
    def grant_path_write(
        self,
        path: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant write permissions for a specific path in this domain to an IAM principal (Role/Group/User).

        :param path: The path to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPathWrite", [path, identity]))

    @jsii.member(jsii_name="grantRead")
    def grant_read(self, identity: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant read permissions for this domain and its contents to an IAM principal (Role/Group/User).

        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantRead", [identity]))

    @jsii.member(jsii_name="grantReadWrite")
    def grant_read_write(self, identity: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant read/write permissions for this domain and its contents to an IAM principal (Role/Group/User).

        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantReadWrite", [identity]))

    @jsii.member(jsii_name="grantWrite")
    def grant_write(self, identity: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant write permissions for this domain and its contents to an IAM principal (Role/Group/User).

        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantWrite", [identity]))

    @jsii.member(jsii_name="metric")
    def metric(
        self,
        metric_name: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the given named metric for this Domain.

        :param metric_name: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metric", [metric_name, props]))

    @jsii.member(jsii_name="metricAutomatedSnapshotFailure")
    def metric_automated_snapshot_failure(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for automated snapshot failures.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricAutomatedSnapshotFailure", [props]))

    @jsii.member(jsii_name="metricClusterIndexWritesBlocked")
    def metric_cluster_index_writes_blocked(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the cluster blocking index writes.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 1 minute
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricClusterIndexWritesBlocked", [props]))

    @jsii.member(jsii_name="metricClusterStatusRed")
    def metric_cluster_status_red(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the time the cluster status is red.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricClusterStatusRed", [props]))

    @jsii.member(jsii_name="metricClusterStatusYellow")
    def metric_cluster_status_yellow(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the time the cluster status is yellow.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricClusterStatusYellow", [props]))

    @jsii.member(jsii_name="metricCPUUtilization")
    def metric_cpu_utilization(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for CPU utilization.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricCPUUtilization", [props]))

    @jsii.member(jsii_name="metricFreeStorageSpace")
    def metric_free_storage_space(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the storage space of nodes in the cluster.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: minimum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricFreeStorageSpace", [props]))

    @jsii.member(jsii_name="metricIndexingLatency")
    def metric_indexing_latency(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for indexing latency.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: p99 over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricIndexingLatency", [props]))

    @jsii.member(jsii_name="metricJVMMemoryPressure")
    def metric_jvm_memory_pressure(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for JVM memory pressure.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricJVMMemoryPressure", [props]))

    @jsii.member(jsii_name="metricKMSKeyError")
    def metric_kms_key_error(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for KMS key errors.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricKMSKeyError", [props]))

    @jsii.member(jsii_name="metricKMSKeyInaccessible")
    def metric_kms_key_inaccessible(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for KMS key being inaccessible.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricKMSKeyInaccessible", [props]))

    @jsii.member(jsii_name="metricMasterCPUUtilization")
    def metric_master_cpu_utilization(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for master CPU utilization.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricMasterCPUUtilization", [props]))

    @jsii.member(jsii_name="metricMasterJVMMemoryPressure")
    def metric_master_jvm_memory_pressure(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for master JVM memory pressure.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricMasterJVMMemoryPressure", [props]))

    @jsii.member(jsii_name="metricNodes")
    def metric_nodes(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the number of nodes.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: minimum over 1 hour
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNodes", [props]))

    @jsii.member(jsii_name="metricSearchableDocuments")
    def metric_searchable_documents(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for number of searchable documents.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricSearchableDocuments", [props]))

    @jsii.member(jsii_name="metricSearchLatency")
    def metric_search_latency(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for search latency.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: p99 over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricSearchLatency", [props]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IDomain).__jsii_proxy_class__ = lambda : _IDomainProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticsearch.LoggingOptions",
    jsii_struct_bases=[],
    name_mapping={
        "app_log_enabled": "appLogEnabled",
        "app_log_group": "appLogGroup",
        "audit_log_enabled": "auditLogEnabled",
        "audit_log_group": "auditLogGroup",
        "slow_index_log_enabled": "slowIndexLogEnabled",
        "slow_index_log_group": "slowIndexLogGroup",
        "slow_search_log_enabled": "slowSearchLogEnabled",
        "slow_search_log_group": "slowSearchLogGroup",
    },
)
class LoggingOptions:
    def __init__(
        self,
        *,
        app_log_enabled: typing.Optional[builtins.bool] = None,
        app_log_group: typing.Optional[_ILogGroup_3c4fa718] = None,
        audit_log_enabled: typing.Optional[builtins.bool] = None,
        audit_log_group: typing.Optional[_ILogGroup_3c4fa718] = None,
        slow_index_log_enabled: typing.Optional[builtins.bool] = None,
        slow_index_log_group: typing.Optional[_ILogGroup_3c4fa718] = None,
        slow_search_log_enabled: typing.Optional[builtins.bool] = None,
        slow_search_log_group: typing.Optional[_ILogGroup_3c4fa718] = None,
    ) -> None:
        '''Configures log settings for the domain.

        :param app_log_enabled: Specify if Elasticsearch application logging should be set up. Requires Elasticsearch version 5.1 or later. Default: - false
        :param app_log_group: Log Elasticsearch application logs to this log group. Default: - a new log group is created if app logging is enabled
        :param audit_log_enabled: Specify if Elasticsearch audit logging should be set up. Requires Elasticsearch version 6.7 or later and fine grained access control to be enabled. Default: - false
        :param audit_log_group: Log Elasticsearch audit logs to this log group. Default: - a new log group is created if audit logging is enabled
        :param slow_index_log_enabled: Specify if slow index logging should be set up. Requires Elasticsearch version 5.1 or later. Default: - false
        :param slow_index_log_group: Log slow indices to this log group. Default: - a new log group is created if slow index logging is enabled
        :param slow_search_log_enabled: Specify if slow search logging should be set up. Requires Elasticsearch version 5.1 or later. Default: - false
        :param slow_search_log_group: Log slow searches to this log group. Default: - a new log group is created if slow search logging is enabled

        :exampleMetadata: infused

        Example::

            prod_domain = es.Domain(self, "Domain",
                version=es.ElasticsearchVersion.V7_1,
                capacity=es.CapacityConfig(
                    master_nodes=5,
                    data_nodes=20
                ),
                ebs=es.EbsOptions(
                    volume_size=20
                ),
                zone_awareness=es.ZoneAwarenessConfig(
                    availability_zone_count=3
                ),
                logging=es.LoggingOptions(
                    slow_search_log_enabled=True,
                    app_log_enabled=True,
                    slow_index_log_enabled=True
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if app_log_enabled is not None:
            self._values["app_log_enabled"] = app_log_enabled
        if app_log_group is not None:
            self._values["app_log_group"] = app_log_group
        if audit_log_enabled is not None:
            self._values["audit_log_enabled"] = audit_log_enabled
        if audit_log_group is not None:
            self._values["audit_log_group"] = audit_log_group
        if slow_index_log_enabled is not None:
            self._values["slow_index_log_enabled"] = slow_index_log_enabled
        if slow_index_log_group is not None:
            self._values["slow_index_log_group"] = slow_index_log_group
        if slow_search_log_enabled is not None:
            self._values["slow_search_log_enabled"] = slow_search_log_enabled
        if slow_search_log_group is not None:
            self._values["slow_search_log_group"] = slow_search_log_group

    @builtins.property
    def app_log_enabled(self) -> typing.Optional[builtins.bool]:
        '''Specify if Elasticsearch application logging should be set up.

        Requires Elasticsearch version 5.1 or later.

        :default: - false
        '''
        result = self._values.get("app_log_enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def app_log_group(self) -> typing.Optional[_ILogGroup_3c4fa718]:
        '''Log Elasticsearch application logs to this log group.

        :default: - a new log group is created if app logging is enabled
        '''
        result = self._values.get("app_log_group")
        return typing.cast(typing.Optional[_ILogGroup_3c4fa718], result)

    @builtins.property
    def audit_log_enabled(self) -> typing.Optional[builtins.bool]:
        '''Specify if Elasticsearch audit logging should be set up.

        Requires Elasticsearch version 6.7 or later and fine grained access control to be enabled.

        :default: - false
        '''
        result = self._values.get("audit_log_enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def audit_log_group(self) -> typing.Optional[_ILogGroup_3c4fa718]:
        '''Log Elasticsearch audit logs to this log group.

        :default: - a new log group is created if audit logging is enabled
        '''
        result = self._values.get("audit_log_group")
        return typing.cast(typing.Optional[_ILogGroup_3c4fa718], result)

    @builtins.property
    def slow_index_log_enabled(self) -> typing.Optional[builtins.bool]:
        '''Specify if slow index logging should be set up.

        Requires Elasticsearch version 5.1 or later.

        :default: - false
        '''
        result = self._values.get("slow_index_log_enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def slow_index_log_group(self) -> typing.Optional[_ILogGroup_3c4fa718]:
        '''Log slow indices to this log group.

        :default: - a new log group is created if slow index logging is enabled
        '''
        result = self._values.get("slow_index_log_group")
        return typing.cast(typing.Optional[_ILogGroup_3c4fa718], result)

    @builtins.property
    def slow_search_log_enabled(self) -> typing.Optional[builtins.bool]:
        '''Specify if slow search logging should be set up.

        Requires Elasticsearch version 5.1 or later.

        :default: - false
        '''
        result = self._values.get("slow_search_log_enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def slow_search_log_group(self) -> typing.Optional[_ILogGroup_3c4fa718]:
        '''Log slow searches to this log group.

        :default: - a new log group is created if slow search logging is enabled
        '''
        result = self._values.get("slow_search_log_group")
        return typing.cast(typing.Optional[_ILogGroup_3c4fa718], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LoggingOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_elasticsearch.TLSSecurityPolicy")
class TLSSecurityPolicy(enum.Enum):
    '''The minimum TLS version required for traffic to the domain.'''

    TLS_1_0 = "TLS_1_0"
    '''Cipher suite TLS 1.0.'''
    TLS_1_2 = "TLS_1_2"
    '''Cipher suite TLS 1.2.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticsearch.ZoneAwarenessConfig",
    jsii_struct_bases=[],
    name_mapping={
        "availability_zone_count": "availabilityZoneCount",
        "enabled": "enabled",
    },
)
class ZoneAwarenessConfig:
    def __init__(
        self,
        *,
        availability_zone_count: typing.Optional[jsii.Number] = None,
        enabled: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Specifies zone awareness configuration options.

        :param availability_zone_count: If you enabled multiple Availability Zones (AZs), the number of AZs that you want the domain to use. Valid values are 2 and 3. Default: - 2 if zone awareness is enabled.
        :param enabled: Indicates whether to enable zone awareness for the Amazon ES domain. When you enable zone awareness, Amazon ES allocates the nodes and replica index shards that belong to a cluster across two Availability Zones (AZs) in the same region to prevent data loss and minimize downtime in the event of node or data center failure. Don't enable zone awareness if your cluster has no replica index shards or is a single-node cluster. For more information, see [Configuring a Multi-AZ Domain] (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-managedomains-multiaz) in the Amazon Elasticsearch Service Developer Guide. Default: - false

        :exampleMetadata: infused

        Example::

            prod_domain = es.Domain(self, "Domain",
                version=es.ElasticsearchVersion.V7_1,
                capacity=es.CapacityConfig(
                    master_nodes=5,
                    data_nodes=20
                ),
                ebs=es.EbsOptions(
                    volume_size=20
                ),
                zone_awareness=es.ZoneAwarenessConfig(
                    availability_zone_count=3
                ),
                logging=es.LoggingOptions(
                    slow_search_log_enabled=True,
                    app_log_enabled=True,
                    slow_index_log_enabled=True
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if availability_zone_count is not None:
            self._values["availability_zone_count"] = availability_zone_count
        if enabled is not None:
            self._values["enabled"] = enabled

    @builtins.property
    def availability_zone_count(self) -> typing.Optional[jsii.Number]:
        '''If you enabled multiple Availability Zones (AZs), the number of AZs that you want the domain to use.

        Valid values are 2 and 3.

        :default: - 2 if zone awareness is enabled.
        '''
        result = self._values.get("availability_zone_count")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def enabled(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether to enable zone awareness for the Amazon ES domain.

        When you enable zone awareness, Amazon ES allocates the nodes and replica
        index shards that belong to a cluster across two Availability Zones (AZs)
        in the same region to prevent data loss and minimize downtime in the event
        of node or data center failure. Don't enable zone awareness if your cluster
        has no replica index shards or is a single-node cluster. For more information,
        see [Configuring a Multi-AZ Domain]
        (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-managedomains-multiaz)
        in the Amazon Elasticsearch Service Developer Guide.

        :default: - false
        '''
        result = self._values.get("enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ZoneAwarenessConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IDomain, _IConnectable_10015a05)
class Domain(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticsearch.Domain",
):
    '''Provides an Elasticsearch domain.

    :exampleMetadata: infused

    Example::

        domain = es.Domain(self, "Domain",
            version=es.ElasticsearchVersion.V7_4,
            ebs=es.EbsOptions(
                volume_size=100,
                volume_type=ec2.EbsDeviceVolumeType.GENERAL_PURPOSE_SSD
            ),
            node_to_node_encryption=True,
            encryption_at_rest=es.EncryptionAtRestOptions(
                enabled=True
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        version: ElasticsearchVersion,
        access_policies: typing.Optional[typing.Sequence[_PolicyStatement_0fe33853]] = None,
        advanced_options: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        automated_snapshot_start_hour: typing.Optional[jsii.Number] = None,
        capacity: typing.Optional[CapacityConfig] = None,
        cognito_kibana_auth: typing.Optional[CognitoOptions] = None,
        custom_endpoint: typing.Optional[CustomEndpointOptions] = None,
        domain_name: typing.Optional[builtins.str] = None,
        ebs: typing.Optional[EbsOptions] = None,
        enable_version_upgrade: typing.Optional[builtins.bool] = None,
        encryption_at_rest: typing.Optional[EncryptionAtRestOptions] = None,
        enforce_https: typing.Optional[builtins.bool] = None,
        fine_grained_access_control: typing.Optional[AdvancedSecurityOptions] = None,
        logging: typing.Optional[LoggingOptions] = None,
        node_to_node_encryption: typing.Optional[builtins.bool] = None,
        removal_policy: typing.Optional[_RemovalPolicy_9f93c814] = None,
        security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
        tls_security_policy: typing.Optional[TLSSecurityPolicy] = None,
        use_unsigned_basic_auth: typing.Optional[builtins.bool] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[typing.Sequence[_SubnetSelection_e57d76df]] = None,
        zone_awareness: typing.Optional[ZoneAwarenessConfig] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param version: The Elasticsearch version that your domain will leverage.
        :param access_policies: Domain Access policies. Default: - No access policies.
        :param advanced_options: Additional options to specify for the Amazon ES domain. Default: - no advanced options are specified
        :param automated_snapshot_start_hour: The hour in UTC during which the service takes an automated daily snapshot of the indices in the Amazon ES domain. Only applies for Elasticsearch versions below 5.3. Default: - Hourly automated snapshots not used
        :param capacity: The cluster capacity configuration for the Amazon ES domain. Default: - 1 r5.large.elasticsearch data node; no dedicated master nodes.
        :param cognito_kibana_auth: Configures Amazon ES to use Amazon Cognito authentication for Kibana. Default: - Cognito not used for authentication to Kibana.
        :param custom_endpoint: To configure a custom domain configure these options. If you specify a Route53 hosted zone it will create a CNAME record and use DNS validation for the certificate Default: - no custom domain endpoint will be configured
        :param domain_name: Enforces a particular physical domain name. Default: - A name will be auto-generated.
        :param ebs: The configurations of Amazon Elastic Block Store (Amazon EBS) volumes that are attached to data nodes in the Amazon ES domain. For more information, see [Configuring EBS-based Storage] (https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-ebs) in the Amazon Elasticsearch Service Developer Guide. Default: - 10 GiB General Purpose (SSD) volumes per node.
        :param enable_version_upgrade: To upgrade an Amazon ES domain to a new version of Elasticsearch rather than replacing the entire domain resource, use the EnableVersionUpgrade update policy. Default: - false
        :param encryption_at_rest: Encryption at rest options for the cluster. Default: - No encryption at rest
        :param enforce_https: True to require that all traffic to the domain arrive over HTTPS. Default: - false
        :param fine_grained_access_control: Specifies options for fine-grained access control. Requires Elasticsearch version 6.7 or later. Enabling fine-grained access control also requires encryption of data at rest and node-to-node encryption, along with enforced HTTPS. Default: - fine-grained access control is disabled
        :param logging: Configuration log publishing configuration options. Default: - No logs are published
        :param node_to_node_encryption: Specify true to enable node to node encryption. Requires Elasticsearch version 6.0 or later. Default: - Node to node encryption is not enabled.
        :param removal_policy: Policy to apply when the domain is removed from the stack. Default: RemovalPolicy.RETAIN
        :param security_groups: The list of security groups that are associated with the VPC endpoints for the domain. Only used if ``vpc`` is specified. Default: - One new security group is created.
        :param tls_security_policy: The minimum TLS version required for traffic to the domain. Default: - TLSSecurityPolicy.TLS_1_0
        :param use_unsigned_basic_auth: Configures the domain so that unsigned basic auth is enabled. If no master user is provided a default master user with username ``admin`` and a dynamically generated password stored in KMS is created. The password can be retrieved by getting ``masterUserPassword`` from the domain instance. Setting this to true will also add an access policy that allows unsigned access, enable node to node encryption, encryption at rest. If conflicting settings are encountered (like disabling encryption at rest) enabling this setting will cause a failure. Default: - false
        :param vpc: Place the domain inside this VPC. Default: - Domain is not placed in a VPC.
        :param vpc_subnets: The specific vpc subnets the domain will be placed in. You must provide one subnet for each Availability Zone that your domain uses. For example, you must specify three subnet IDs for a three Availability Zone domain. Only used if ``vpc`` is specified. Default: - All private subnets.
        :param zone_awareness: The cluster zone awareness configuration for the Amazon ES domain. Default: - no zone awareness (1 AZ)
        '''
        props = DomainProps(
            version=version,
            access_policies=access_policies,
            advanced_options=advanced_options,
            automated_snapshot_start_hour=automated_snapshot_start_hour,
            capacity=capacity,
            cognito_kibana_auth=cognito_kibana_auth,
            custom_endpoint=custom_endpoint,
            domain_name=domain_name,
            ebs=ebs,
            enable_version_upgrade=enable_version_upgrade,
            encryption_at_rest=encryption_at_rest,
            enforce_https=enforce_https,
            fine_grained_access_control=fine_grained_access_control,
            logging=logging,
            node_to_node_encryption=node_to_node_encryption,
            removal_policy=removal_policy,
            security_groups=security_groups,
            tls_security_policy=tls_security_policy,
            use_unsigned_basic_auth=use_unsigned_basic_auth,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
            zone_awareness=zone_awareness,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromDomainAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_domain_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        domain_arn: builtins.str,
        domain_endpoint: builtins.str,
    ) -> IDomain:
        '''Creates a Domain construct that represents an external domain.

        :param scope: The parent creating construct (usually ``this``).
        :param id: The construct's name.
        :param domain_arn: The ARN of the Elasticsearch domain.
        :param domain_endpoint: The domain endpoint of the Elasticsearch domain.
        '''
        attrs = DomainAttributes(
            domain_arn=domain_arn, domain_endpoint=domain_endpoint
        )

        return typing.cast(IDomain, jsii.sinvoke(cls, "fromDomainAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="fromDomainEndpoint") # type: ignore[misc]
    @builtins.classmethod
    def from_domain_endpoint(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        domain_endpoint: builtins.str,
    ) -> IDomain:
        '''Creates a Domain construct that represents an external domain via domain endpoint.

        :param scope: The parent creating construct (usually ``this``).
        :param id: The construct's name.
        :param domain_endpoint: The domain's endpoint.
        '''
        return typing.cast(IDomain, jsii.sinvoke(cls, "fromDomainEndpoint", [scope, id, domain_endpoint]))

    @jsii.member(jsii_name="grantIndexRead")
    def grant_index_read(
        self,
        index: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read permissions for an index in this domain to an IAM principal (Role/Group/User).

        :param index: The index to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantIndexRead", [index, identity]))

    @jsii.member(jsii_name="grantIndexReadWrite")
    def grant_index_read_write(
        self,
        index: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read/write permissions for an index in this domain to an IAM principal (Role/Group/User).

        :param index: The index to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantIndexReadWrite", [index, identity]))

    @jsii.member(jsii_name="grantIndexWrite")
    def grant_index_write(
        self,
        index: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant write permissions for an index in this domain to an IAM principal (Role/Group/User).

        :param index: The index to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantIndexWrite", [index, identity]))

    @jsii.member(jsii_name="grantPathRead")
    def grant_path_read(
        self,
        path: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read permissions for a specific path in this domain to an IAM principal (Role/Group/User).

        :param path: The path to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPathRead", [path, identity]))

    @jsii.member(jsii_name="grantPathReadWrite")
    def grant_path_read_write(
        self,
        path: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant read/write permissions for a specific path in this domain to an IAM principal (Role/Group/User).

        :param path: The path to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPathReadWrite", [path, identity]))

    @jsii.member(jsii_name="grantPathWrite")
    def grant_path_write(
        self,
        path: builtins.str,
        identity: _IGrantable_71c4f5de,
    ) -> _Grant_a7ae64f8:
        '''Grant write permissions for a specific path in this domain to an IAM principal (Role/Group/User).

        :param path: The path to grant permissions for.
        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPathWrite", [path, identity]))

    @jsii.member(jsii_name="grantRead")
    def grant_read(self, identity: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant read permissions for this domain and its contents to an IAM principal (Role/Group/User).

        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantRead", [identity]))

    @jsii.member(jsii_name="grantReadWrite")
    def grant_read_write(self, identity: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant read/write permissions for this domain and its contents to an IAM principal (Role/Group/User).

        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantReadWrite", [identity]))

    @jsii.member(jsii_name="grantWrite")
    def grant_write(self, identity: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grant write permissions for this domain and its contents to an IAM principal (Role/Group/User).

        :param identity: The principal.
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantWrite", [identity]))

    @jsii.member(jsii_name="metric")
    def metric(
        self,
        metric_name: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the given named metric for this Domain.

        :param metric_name: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metric", [metric_name, props]))

    @jsii.member(jsii_name="metricAutomatedSnapshotFailure")
    def metric_automated_snapshot_failure(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for automated snapshot failures.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricAutomatedSnapshotFailure", [props]))

    @jsii.member(jsii_name="metricClusterIndexWritesBlocked")
    def metric_cluster_index_writes_blocked(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the cluster blocking index writes.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 1 minute
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricClusterIndexWritesBlocked", [props]))

    @jsii.member(jsii_name="metricClusterStatusRed")
    def metric_cluster_status_red(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the time the cluster status is red.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricClusterStatusRed", [props]))

    @jsii.member(jsii_name="metricClusterStatusYellow")
    def metric_cluster_status_yellow(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the time the cluster status is yellow.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricClusterStatusYellow", [props]))

    @jsii.member(jsii_name="metricCPUUtilization")
    def metric_cpu_utilization(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for CPU utilization.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricCPUUtilization", [props]))

    @jsii.member(jsii_name="metricFreeStorageSpace")
    def metric_free_storage_space(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the storage space of nodes in the cluster.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: minimum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricFreeStorageSpace", [props]))

    @jsii.member(jsii_name="metricIndexingLatency")
    def metric_indexing_latency(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for indexing latency.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: p99 over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricIndexingLatency", [props]))

    @jsii.member(jsii_name="metricJVMMemoryPressure")
    def metric_jvm_memory_pressure(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for JVM memory pressure.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricJVMMemoryPressure", [props]))

    @jsii.member(jsii_name="metricKMSKeyError")
    def metric_kms_key_error(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for KMS key errors.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricKMSKeyError", [props]))

    @jsii.member(jsii_name="metricKMSKeyInaccessible")
    def metric_kms_key_inaccessible(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for KMS key being inaccessible.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricKMSKeyInaccessible", [props]))

    @jsii.member(jsii_name="metricMasterCPUUtilization")
    def metric_master_cpu_utilization(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for master CPU utilization.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricMasterCPUUtilization", [props]))

    @jsii.member(jsii_name="metricMasterJVMMemoryPressure")
    def metric_master_jvm_memory_pressure(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for master JVM memory pressure.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricMasterJVMMemoryPressure", [props]))

    @jsii.member(jsii_name="metricNodes")
    def metric_nodes(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for the number of nodes.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: minimum over 1 hour
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNodes", [props]))

    @jsii.member(jsii_name="metricSearchableDocuments")
    def metric_searchable_documents(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for number of searchable documents.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: maximum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricSearchableDocuments", [props]))

    @jsii.member(jsii_name="metricSearchLatency")
    def metric_search_latency(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Metric for search latency.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: p99 over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricSearchLatency", [props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connections")
    def connections(self) -> _Connections_0f31fce8:
        '''Manages network connections to the domain.

        This will throw an error in case the domain
        is not placed inside a VPC.
        '''
        return typing.cast(_Connections_0f31fce8, jsii.get(self, "connections"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainArn")
    def domain_arn(self) -> builtins.str:
        '''Arn of the Elasticsearch domain.'''
        return typing.cast(builtins.str, jsii.get(self, "domainArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainEndpoint")
    def domain_endpoint(self) -> builtins.str:
        '''Endpoint of the Elasticsearch domain.'''
        return typing.cast(builtins.str, jsii.get(self, "domainEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''Domain name of the Elasticsearch domain.'''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="appLogGroup")
    def app_log_group(self) -> typing.Optional[_ILogGroup_3c4fa718]:
        '''Log group that application logs are logged to.

        :attribute: true
        '''
        return typing.cast(typing.Optional[_ILogGroup_3c4fa718], jsii.get(self, "appLogGroup"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="auditLogGroup")
    def audit_log_group(self) -> typing.Optional[_ILogGroup_3c4fa718]:
        '''Log group that audit logs are logged to.

        :attribute: true
        '''
        return typing.cast(typing.Optional[_ILogGroup_3c4fa718], jsii.get(self, "auditLogGroup"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="masterUserPassword")
    def master_user_password(self) -> typing.Optional[_SecretValue_3dd0ddae]:
        '''Master user password if fine grained access control is configured.'''
        return typing.cast(typing.Optional[_SecretValue_3dd0ddae], jsii.get(self, "masterUserPassword"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="slowIndexLogGroup")
    def slow_index_log_group(self) -> typing.Optional[_ILogGroup_3c4fa718]:
        '''Log group that slow indices are logged to.

        :attribute: true
        '''
        return typing.cast(typing.Optional[_ILogGroup_3c4fa718], jsii.get(self, "slowIndexLogGroup"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="slowSearchLogGroup")
    def slow_search_log_group(self) -> typing.Optional[_ILogGroup_3c4fa718]:
        '''Log group that slow searches are logged to.

        :attribute: true
        '''
        return typing.cast(typing.Optional[_ILogGroup_3c4fa718], jsii.get(self, "slowSearchLogGroup"))


__all__ = [
    "AdvancedSecurityOptions",
    "CapacityConfig",
    "CfnDomain",
    "CfnDomainProps",
    "CognitoOptions",
    "CustomEndpointOptions",
    "Domain",
    "DomainAttributes",
    "DomainProps",
    "EbsOptions",
    "ElasticsearchVersion",
    "EncryptionAtRestOptions",
    "IDomain",
    "LoggingOptions",
    "TLSSecurityPolicy",
    "ZoneAwarenessConfig",
]

publication.publish()
