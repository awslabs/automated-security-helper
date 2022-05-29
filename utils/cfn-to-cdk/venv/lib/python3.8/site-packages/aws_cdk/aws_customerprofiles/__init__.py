'''
# AWS::CustomerProfiles Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_customerprofiles as customerprofiles
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-customerprofiles-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::CustomerProfiles](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_CustomerProfiles.html).

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
class CfnDomain(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_customerprofiles.CfnDomain",
):
    '''A CloudFormation ``AWS::CustomerProfiles::Domain``.

    The AWS::CustomerProfiles::Domain resource specifies an Amazon Connect Customer Profiles Domain.

    :cloudformationResource: AWS::CustomerProfiles::Domain
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_customerprofiles as customerprofiles
        
        cfn_domain = customerprofiles.CfnDomain(self, "MyCfnDomain",
            domain_name="domainName",
        
            # the properties below are optional
            dead_letter_queue_url="deadLetterQueueUrl",
            default_encryption_key="defaultEncryptionKey",
            default_expiration_days=123,
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
        domain_name: builtins.str,
        dead_letter_queue_url: typing.Optional[builtins.str] = None,
        default_encryption_key: typing.Optional[builtins.str] = None,
        default_expiration_days: typing.Optional[jsii.Number] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::CustomerProfiles::Domain``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param domain_name: The unique name of the domain.
        :param dead_letter_queue_url: The URL of the SQS dead letter queue, which is used for reporting errors associated with ingesting data from third party applications. You must set up a policy on the DeadLetterQueue for the SendMessage operation to enable Amazon Connect Customer Profiles to send messages to the DeadLetterQueue.
        :param default_encryption_key: The default encryption key, which is an AWS managed key, is used when no specific type of encryption key is specified. It is used to encrypt all data before it is placed in permanent or semi-permanent storage.
        :param default_expiration_days: The default number of days until the data within the domain expires.
        :param tags: The tags used to organize, track, or control access for this resource.
        '''
        props = CfnDomainProps(
            domain_name=domain_name,
            dead_letter_queue_url=dead_letter_queue_url,
            default_encryption_key=default_encryption_key,
            default_expiration_days=default_expiration_days,
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
    @jsii.member(jsii_name="attrCreatedAt")
    def attr_created_at(self) -> builtins.str:
        '''The timestamp of when the domain was created.

        :cloudformationAttribute: CreatedAt
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedAt"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastUpdatedAt")
    def attr_last_updated_at(self) -> builtins.str:
        '''The timestamp of when the domain was most recently edited.

        :cloudformationAttribute: LastUpdatedAt
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastUpdatedAt"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html#cfn-customerprofiles-domain-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The unique name of the domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html#cfn-customerprofiles-domain-domainname
        '''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))

    @domain_name.setter
    def domain_name(self, value: builtins.str) -> None:
        jsii.set(self, "domainName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="deadLetterQueueUrl")
    def dead_letter_queue_url(self) -> typing.Optional[builtins.str]:
        '''The URL of the SQS dead letter queue, which is used for reporting errors associated with ingesting data from third party applications.

        You must set up a policy on the DeadLetterQueue for the SendMessage operation to enable Amazon Connect Customer Profiles to send messages to the DeadLetterQueue.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html#cfn-customerprofiles-domain-deadletterqueueurl
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "deadLetterQueueUrl"))

    @dead_letter_queue_url.setter
    def dead_letter_queue_url(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "deadLetterQueueUrl", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultEncryptionKey")
    def default_encryption_key(self) -> typing.Optional[builtins.str]:
        '''The default encryption key, which is an AWS managed key, is used when no specific type of encryption key is specified.

        It is used to encrypt all data before it is placed in permanent or semi-permanent storage.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html#cfn-customerprofiles-domain-defaultencryptionkey
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "defaultEncryptionKey"))

    @default_encryption_key.setter
    def default_encryption_key(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "defaultEncryptionKey", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultExpirationDays")
    def default_expiration_days(self) -> typing.Optional[jsii.Number]:
        '''The default number of days until the data within the domain expires.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html#cfn-customerprofiles-domain-defaultexpirationdays
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "defaultExpirationDays"))

    @default_expiration_days.setter
    def default_expiration_days(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "defaultExpirationDays", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_customerprofiles.CfnDomainProps",
    jsii_struct_bases=[],
    name_mapping={
        "domain_name": "domainName",
        "dead_letter_queue_url": "deadLetterQueueUrl",
        "default_encryption_key": "defaultEncryptionKey",
        "default_expiration_days": "defaultExpirationDays",
        "tags": "tags",
    },
)
class CfnDomainProps:
    def __init__(
        self,
        *,
        domain_name: builtins.str,
        dead_letter_queue_url: typing.Optional[builtins.str] = None,
        default_encryption_key: typing.Optional[builtins.str] = None,
        default_expiration_days: typing.Optional[jsii.Number] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDomain``.

        :param domain_name: The unique name of the domain.
        :param dead_letter_queue_url: The URL of the SQS dead letter queue, which is used for reporting errors associated with ingesting data from third party applications. You must set up a policy on the DeadLetterQueue for the SendMessage operation to enable Amazon Connect Customer Profiles to send messages to the DeadLetterQueue.
        :param default_encryption_key: The default encryption key, which is an AWS managed key, is used when no specific type of encryption key is specified. It is used to encrypt all data before it is placed in permanent or semi-permanent storage.
        :param default_expiration_days: The default number of days until the data within the domain expires.
        :param tags: The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_customerprofiles as customerprofiles
            
            cfn_domain_props = customerprofiles.CfnDomainProps(
                domain_name="domainName",
            
                # the properties below are optional
                dead_letter_queue_url="deadLetterQueueUrl",
                default_encryption_key="defaultEncryptionKey",
                default_expiration_days=123,
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain_name": domain_name,
        }
        if dead_letter_queue_url is not None:
            self._values["dead_letter_queue_url"] = dead_letter_queue_url
        if default_encryption_key is not None:
            self._values["default_encryption_key"] = default_encryption_key
        if default_expiration_days is not None:
            self._values["default_expiration_days"] = default_expiration_days
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''The unique name of the domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html#cfn-customerprofiles-domain-domainname
        '''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def dead_letter_queue_url(self) -> typing.Optional[builtins.str]:
        '''The URL of the SQS dead letter queue, which is used for reporting errors associated with ingesting data from third party applications.

        You must set up a policy on the DeadLetterQueue for the SendMessage operation to enable Amazon Connect Customer Profiles to send messages to the DeadLetterQueue.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html#cfn-customerprofiles-domain-deadletterqueueurl
        '''
        result = self._values.get("dead_letter_queue_url")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def default_encryption_key(self) -> typing.Optional[builtins.str]:
        '''The default encryption key, which is an AWS managed key, is used when no specific type of encryption key is specified.

        It is used to encrypt all data before it is placed in permanent or semi-permanent storage.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html#cfn-customerprofiles-domain-defaultencryptionkey
        '''
        result = self._values.get("default_encryption_key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def default_expiration_days(self) -> typing.Optional[jsii.Number]:
        '''The default number of days until the data within the domain expires.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html#cfn-customerprofiles-domain-defaultexpirationdays
        '''
        result = self._values.get("default_expiration_days")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-domain.html#cfn-customerprofiles-domain-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDomainProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnIntegration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration",
):
    '''A CloudFormation ``AWS::CustomerProfiles::Integration``.

    The AWS::CustomerProfiles::Integration resource specifies an Amazon Connect Customer Profiles Integration.

    :cloudformationResource: AWS::CustomerProfiles::Integration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_customerprofiles as customerprofiles
        
        cfn_integration = customerprofiles.CfnIntegration(self, "MyCfnIntegration",
            domain_name="domainName",
        
            # the properties below are optional
            flow_definition=customerprofiles.CfnIntegration.FlowDefinitionProperty(
                flow_name="flowName",
                kms_arn="kmsArn",
                source_flow_config=customerprofiles.CfnIntegration.SourceFlowConfigProperty(
                    connector_type="connectorType",
                    source_connector_properties=customerprofiles.CfnIntegration.SourceConnectorPropertiesProperty(
                        marketo=customerprofiles.CfnIntegration.MarketoSourcePropertiesProperty(
                            object="object"
                        ),
                        s3=customerprofiles.CfnIntegration.S3SourcePropertiesProperty(
                            bucket_name="bucketName",
        
                            # the properties below are optional
                            bucket_prefix="bucketPrefix"
                        ),
                        salesforce=customerprofiles.CfnIntegration.SalesforceSourcePropertiesProperty(
                            object="object",
        
                            # the properties below are optional
                            enable_dynamic_field_update=False,
                            include_deleted_records=False
                        ),
                        service_now=customerprofiles.CfnIntegration.ServiceNowSourcePropertiesProperty(
                            object="object"
                        ),
                        zendesk=customerprofiles.CfnIntegration.ZendeskSourcePropertiesProperty(
                            object="object"
                        )
                    ),
        
                    # the properties below are optional
                    connector_profile_name="connectorProfileName",
                    incremental_pull_config=customerprofiles.CfnIntegration.IncrementalPullConfigProperty(
                        datetime_type_field_name="datetimeTypeFieldName"
                    )
                ),
                tasks=[customerprofiles.CfnIntegration.TaskProperty(
                    source_fields=["sourceFields"],
                    task_type="taskType",
        
                    # the properties below are optional
                    connector_operator=customerprofiles.CfnIntegration.ConnectorOperatorProperty(
                        marketo="marketo",
                        s3="s3",
                        salesforce="salesforce",
                        service_now="serviceNow",
                        zendesk="zendesk"
                    ),
                    destination_field="destinationField",
                    task_properties=[customerprofiles.CfnIntegration.TaskPropertiesMapProperty(
                        operator_property_key="operatorPropertyKey",
                        property="property"
                    )]
                )],
                trigger_config=customerprofiles.CfnIntegration.TriggerConfigProperty(
                    trigger_type="triggerType",
        
                    # the properties below are optional
                    trigger_properties=customerprofiles.CfnIntegration.TriggerPropertiesProperty(
                        scheduled=customerprofiles.CfnIntegration.ScheduledTriggerPropertiesProperty(
                            schedule_expression="scheduleExpression",
        
                            # the properties below are optional
                            data_pull_mode="dataPullMode",
                            first_execution_from=123,
                            schedule_end_time=123,
                            schedule_offset=123,
                            schedule_start_time=123,
                            timezone="timezone"
                        )
                    )
                ),
        
                # the properties below are optional
                description="description"
            ),
            object_type_name="objectTypeName",
            object_type_names=[customerprofiles.CfnIntegration.ObjectTypeMappingProperty(
                key="key",
                value="value"
            )],
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            uri="uri"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        domain_name: builtins.str,
        flow_definition: typing.Optional[typing.Union["CfnIntegration.FlowDefinitionProperty", _IResolvable_da3f097b]] = None,
        object_type_name: typing.Optional[builtins.str] = None,
        object_type_names: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnIntegration.ObjectTypeMappingProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        uri: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::CustomerProfiles::Integration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param domain_name: The unique name of the domain.
        :param flow_definition: ``AWS::CustomerProfiles::Integration.FlowDefinition``.
        :param object_type_name: The name of the profile object type mapping to use.
        :param object_type_names: ``AWS::CustomerProfiles::Integration.ObjectTypeNames``.
        :param tags: The tags used to organize, track, or control access for this resource.
        :param uri: The URI of the S3 bucket or any other type of data source.
        '''
        props = CfnIntegrationProps(
            domain_name=domain_name,
            flow_definition=flow_definition,
            object_type_name=object_type_name,
            object_type_names=object_type_names,
            tags=tags,
            uri=uri,
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
    @jsii.member(jsii_name="attrCreatedAt")
    def attr_created_at(self) -> builtins.str:
        '''The timestamp of when the integration was created.

        :cloudformationAttribute: CreatedAt
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedAt"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastUpdatedAt")
    def attr_last_updated_at(self) -> builtins.str:
        '''The timestamp of when the integration was most recently edited.

        :cloudformationAttribute: LastUpdatedAt
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastUpdatedAt"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The unique name of the domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-domainname
        '''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))

    @domain_name.setter
    def domain_name(self, value: builtins.str) -> None:
        jsii.set(self, "domainName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="flowDefinition")
    def flow_definition(
        self,
    ) -> typing.Optional[typing.Union["CfnIntegration.FlowDefinitionProperty", _IResolvable_da3f097b]]:
        '''``AWS::CustomerProfiles::Integration.FlowDefinition``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-flowdefinition
        '''
        return typing.cast(typing.Optional[typing.Union["CfnIntegration.FlowDefinitionProperty", _IResolvable_da3f097b]], jsii.get(self, "flowDefinition"))

    @flow_definition.setter
    def flow_definition(
        self,
        value: typing.Optional[typing.Union["CfnIntegration.FlowDefinitionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "flowDefinition", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="objectTypeName")
    def object_type_name(self) -> typing.Optional[builtins.str]:
        '''The name of the profile object type mapping to use.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-objecttypename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "objectTypeName"))

    @object_type_name.setter
    def object_type_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "objectTypeName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="objectTypeNames")
    def object_type_names(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIntegration.ObjectTypeMappingProperty", _IResolvable_da3f097b]]]]:
        '''``AWS::CustomerProfiles::Integration.ObjectTypeNames``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-objecttypenames
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIntegration.ObjectTypeMappingProperty", _IResolvable_da3f097b]]]], jsii.get(self, "objectTypeNames"))

    @object_type_names.setter
    def object_type_names(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIntegration.ObjectTypeMappingProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "objectTypeNames", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="uri")
    def uri(self) -> typing.Optional[builtins.str]:
        '''The URI of the S3 bucket or any other type of data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-uri
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "uri"))

    @uri.setter
    def uri(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "uri", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.ConnectorOperatorProperty",
        jsii_struct_bases=[],
        name_mapping={
            "marketo": "marketo",
            "s3": "s3",
            "salesforce": "salesforce",
            "service_now": "serviceNow",
            "zendesk": "zendesk",
        },
    )
    class ConnectorOperatorProperty:
        def __init__(
            self,
            *,
            marketo: typing.Optional[builtins.str] = None,
            s3: typing.Optional[builtins.str] = None,
            salesforce: typing.Optional[builtins.str] = None,
            service_now: typing.Optional[builtins.str] = None,
            zendesk: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param marketo: ``CfnIntegration.ConnectorOperatorProperty.Marketo``.
            :param s3: ``CfnIntegration.ConnectorOperatorProperty.S3``.
            :param salesforce: ``CfnIntegration.ConnectorOperatorProperty.Salesforce``.
            :param service_now: ``CfnIntegration.ConnectorOperatorProperty.ServiceNow``.
            :param zendesk: ``CfnIntegration.ConnectorOperatorProperty.Zendesk``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-connectoroperator.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                connector_operator_property = customerprofiles.CfnIntegration.ConnectorOperatorProperty(
                    marketo="marketo",
                    s3="s3",
                    salesforce="salesforce",
                    service_now="serviceNow",
                    zendesk="zendesk"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if marketo is not None:
                self._values["marketo"] = marketo
            if s3 is not None:
                self._values["s3"] = s3
            if salesforce is not None:
                self._values["salesforce"] = salesforce
            if service_now is not None:
                self._values["service_now"] = service_now
            if zendesk is not None:
                self._values["zendesk"] = zendesk

        @builtins.property
        def marketo(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.ConnectorOperatorProperty.Marketo``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-connectoroperator.html#cfn-customerprofiles-integration-connectoroperator-marketo
            '''
            result = self._values.get("marketo")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def s3(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.ConnectorOperatorProperty.S3``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-connectoroperator.html#cfn-customerprofiles-integration-connectoroperator-s3
            '''
            result = self._values.get("s3")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def salesforce(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.ConnectorOperatorProperty.Salesforce``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-connectoroperator.html#cfn-customerprofiles-integration-connectoroperator-salesforce
            '''
            result = self._values.get("salesforce")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def service_now(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.ConnectorOperatorProperty.ServiceNow``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-connectoroperator.html#cfn-customerprofiles-integration-connectoroperator-servicenow
            '''
            result = self._values.get("service_now")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def zendesk(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.ConnectorOperatorProperty.Zendesk``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-connectoroperator.html#cfn-customerprofiles-integration-connectoroperator-zendesk
            '''
            result = self._values.get("zendesk")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectorOperatorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.FlowDefinitionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "flow_name": "flowName",
            "kms_arn": "kmsArn",
            "source_flow_config": "sourceFlowConfig",
            "tasks": "tasks",
            "trigger_config": "triggerConfig",
            "description": "description",
        },
    )
    class FlowDefinitionProperty:
        def __init__(
            self,
            *,
            flow_name: builtins.str,
            kms_arn: builtins.str,
            source_flow_config: typing.Union["CfnIntegration.SourceFlowConfigProperty", _IResolvable_da3f097b],
            tasks: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnIntegration.TaskProperty", _IResolvable_da3f097b]]],
            trigger_config: typing.Union["CfnIntegration.TriggerConfigProperty", _IResolvable_da3f097b],
            description: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param flow_name: ``CfnIntegration.FlowDefinitionProperty.FlowName``.
            :param kms_arn: ``CfnIntegration.FlowDefinitionProperty.KmsArn``.
            :param source_flow_config: ``CfnIntegration.FlowDefinitionProperty.SourceFlowConfig``.
            :param tasks: ``CfnIntegration.FlowDefinitionProperty.Tasks``.
            :param trigger_config: ``CfnIntegration.FlowDefinitionProperty.TriggerConfig``.
            :param description: ``CfnIntegration.FlowDefinitionProperty.Description``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-flowdefinition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                flow_definition_property = customerprofiles.CfnIntegration.FlowDefinitionProperty(
                    flow_name="flowName",
                    kms_arn="kmsArn",
                    source_flow_config=customerprofiles.CfnIntegration.SourceFlowConfigProperty(
                        connector_type="connectorType",
                        source_connector_properties=customerprofiles.CfnIntegration.SourceConnectorPropertiesProperty(
                            marketo=customerprofiles.CfnIntegration.MarketoSourcePropertiesProperty(
                                object="object"
                            ),
                            s3=customerprofiles.CfnIntegration.S3SourcePropertiesProperty(
                                bucket_name="bucketName",
                
                                # the properties below are optional
                                bucket_prefix="bucketPrefix"
                            ),
                            salesforce=customerprofiles.CfnIntegration.SalesforceSourcePropertiesProperty(
                                object="object",
                
                                # the properties below are optional
                                enable_dynamic_field_update=False,
                                include_deleted_records=False
                            ),
                            service_now=customerprofiles.CfnIntegration.ServiceNowSourcePropertiesProperty(
                                object="object"
                            ),
                            zendesk=customerprofiles.CfnIntegration.ZendeskSourcePropertiesProperty(
                                object="object"
                            )
                        ),
                
                        # the properties below are optional
                        connector_profile_name="connectorProfileName",
                        incremental_pull_config=customerprofiles.CfnIntegration.IncrementalPullConfigProperty(
                            datetime_type_field_name="datetimeTypeFieldName"
                        )
                    ),
                    tasks=[customerprofiles.CfnIntegration.TaskProperty(
                        source_fields=["sourceFields"],
                        task_type="taskType",
                
                        # the properties below are optional
                        connector_operator=customerprofiles.CfnIntegration.ConnectorOperatorProperty(
                            marketo="marketo",
                            s3="s3",
                            salesforce="salesforce",
                            service_now="serviceNow",
                            zendesk="zendesk"
                        ),
                        destination_field="destinationField",
                        task_properties=[customerprofiles.CfnIntegration.TaskPropertiesMapProperty(
                            operator_property_key="operatorPropertyKey",
                            property="property"
                        )]
                    )],
                    trigger_config=customerprofiles.CfnIntegration.TriggerConfigProperty(
                        trigger_type="triggerType",
                
                        # the properties below are optional
                        trigger_properties=customerprofiles.CfnIntegration.TriggerPropertiesProperty(
                            scheduled=customerprofiles.CfnIntegration.ScheduledTriggerPropertiesProperty(
                                schedule_expression="scheduleExpression",
                
                                # the properties below are optional
                                data_pull_mode="dataPullMode",
                                first_execution_from=123,
                                schedule_end_time=123,
                                schedule_offset=123,
                                schedule_start_time=123,
                                timezone="timezone"
                            )
                        )
                    ),
                
                    # the properties below are optional
                    description="description"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "flow_name": flow_name,
                "kms_arn": kms_arn,
                "source_flow_config": source_flow_config,
                "tasks": tasks,
                "trigger_config": trigger_config,
            }
            if description is not None:
                self._values["description"] = description

        @builtins.property
        def flow_name(self) -> builtins.str:
            '''``CfnIntegration.FlowDefinitionProperty.FlowName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-flowdefinition.html#cfn-customerprofiles-integration-flowdefinition-flowname
            '''
            result = self._values.get("flow_name")
            assert result is not None, "Required property 'flow_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def kms_arn(self) -> builtins.str:
            '''``CfnIntegration.FlowDefinitionProperty.KmsArn``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-flowdefinition.html#cfn-customerprofiles-integration-flowdefinition-kmsarn
            '''
            result = self._values.get("kms_arn")
            assert result is not None, "Required property 'kms_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def source_flow_config(
            self,
        ) -> typing.Union["CfnIntegration.SourceFlowConfigProperty", _IResolvable_da3f097b]:
            '''``CfnIntegration.FlowDefinitionProperty.SourceFlowConfig``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-flowdefinition.html#cfn-customerprofiles-integration-flowdefinition-sourceflowconfig
            '''
            result = self._values.get("source_flow_config")
            assert result is not None, "Required property 'source_flow_config' is missing"
            return typing.cast(typing.Union["CfnIntegration.SourceFlowConfigProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def tasks(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIntegration.TaskProperty", _IResolvable_da3f097b]]]:
            '''``CfnIntegration.FlowDefinitionProperty.Tasks``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-flowdefinition.html#cfn-customerprofiles-integration-flowdefinition-tasks
            '''
            result = self._values.get("tasks")
            assert result is not None, "Required property 'tasks' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIntegration.TaskProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def trigger_config(
            self,
        ) -> typing.Union["CfnIntegration.TriggerConfigProperty", _IResolvable_da3f097b]:
            '''``CfnIntegration.FlowDefinitionProperty.TriggerConfig``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-flowdefinition.html#cfn-customerprofiles-integration-flowdefinition-triggerconfig
            '''
            result = self._values.get("trigger_config")
            assert result is not None, "Required property 'trigger_config' is missing"
            return typing.cast(typing.Union["CfnIntegration.TriggerConfigProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def description(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.FlowDefinitionProperty.Description``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-flowdefinition.html#cfn-customerprofiles-integration-flowdefinition-description
            '''
            result = self._values.get("description")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FlowDefinitionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.IncrementalPullConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"datetime_type_field_name": "datetimeTypeFieldName"},
    )
    class IncrementalPullConfigProperty:
        def __init__(
            self,
            *,
            datetime_type_field_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param datetime_type_field_name: ``CfnIntegration.IncrementalPullConfigProperty.DatetimeTypeFieldName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-incrementalpullconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                incremental_pull_config_property = customerprofiles.CfnIntegration.IncrementalPullConfigProperty(
                    datetime_type_field_name="datetimeTypeFieldName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if datetime_type_field_name is not None:
                self._values["datetime_type_field_name"] = datetime_type_field_name

        @builtins.property
        def datetime_type_field_name(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.IncrementalPullConfigProperty.DatetimeTypeFieldName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-incrementalpullconfig.html#cfn-customerprofiles-integration-incrementalpullconfig-datetimetypefieldname
            '''
            result = self._values.get("datetime_type_field_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IncrementalPullConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.MarketoSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class MarketoSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''
            :param object: ``CfnIntegration.MarketoSourcePropertiesProperty.Object``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-marketosourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                marketo_source_properties_property = customerprofiles.CfnIntegration.MarketoSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''``CfnIntegration.MarketoSourcePropertiesProperty.Object``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-marketosourceproperties.html#cfn-customerprofiles-integration-marketosourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MarketoSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.ObjectTypeMappingProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class ObjectTypeMappingProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''
            :param key: ``CfnIntegration.ObjectTypeMappingProperty.Key``.
            :param value: ``CfnIntegration.ObjectTypeMappingProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-objecttypemapping.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                object_type_mapping_property = customerprofiles.CfnIntegration.ObjectTypeMappingProperty(
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
            '''``CfnIntegration.ObjectTypeMappingProperty.Key``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-objecttypemapping.html#cfn-customerprofiles-integration-objecttypemapping-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''``CfnIntegration.ObjectTypeMappingProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-objecttypemapping.html#cfn-customerprofiles-integration-objecttypemapping-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ObjectTypeMappingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.S3SourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"bucket_name": "bucketName", "bucket_prefix": "bucketPrefix"},
    )
    class S3SourcePropertiesProperty:
        def __init__(
            self,
            *,
            bucket_name: builtins.str,
            bucket_prefix: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param bucket_name: ``CfnIntegration.S3SourcePropertiesProperty.BucketName``.
            :param bucket_prefix: ``CfnIntegration.S3SourcePropertiesProperty.BucketPrefix``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-s3sourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                s3_source_properties_property = customerprofiles.CfnIntegration.S3SourcePropertiesProperty(
                    bucket_name="bucketName",
                
                    # the properties below are optional
                    bucket_prefix="bucketPrefix"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "bucket_name": bucket_name,
            }
            if bucket_prefix is not None:
                self._values["bucket_prefix"] = bucket_prefix

        @builtins.property
        def bucket_name(self) -> builtins.str:
            '''``CfnIntegration.S3SourcePropertiesProperty.BucketName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-s3sourceproperties.html#cfn-customerprofiles-integration-s3sourceproperties-bucketname
            '''
            result = self._values.get("bucket_name")
            assert result is not None, "Required property 'bucket_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def bucket_prefix(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.S3SourcePropertiesProperty.BucketPrefix``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-s3sourceproperties.html#cfn-customerprofiles-integration-s3sourceproperties-bucketprefix
            '''
            result = self._values.get("bucket_prefix")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "S3SourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.SalesforceSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "object": "object",
            "enable_dynamic_field_update": "enableDynamicFieldUpdate",
            "include_deleted_records": "includeDeletedRecords",
        },
    )
    class SalesforceSourcePropertiesProperty:
        def __init__(
            self,
            *,
            object: builtins.str,
            enable_dynamic_field_update: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            include_deleted_records: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param object: ``CfnIntegration.SalesforceSourcePropertiesProperty.Object``.
            :param enable_dynamic_field_update: ``CfnIntegration.SalesforceSourcePropertiesProperty.EnableDynamicFieldUpdate``.
            :param include_deleted_records: ``CfnIntegration.SalesforceSourcePropertiesProperty.IncludeDeletedRecords``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-salesforcesourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                salesforce_source_properties_property = customerprofiles.CfnIntegration.SalesforceSourcePropertiesProperty(
                    object="object",
                
                    # the properties below are optional
                    enable_dynamic_field_update=False,
                    include_deleted_records=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }
            if enable_dynamic_field_update is not None:
                self._values["enable_dynamic_field_update"] = enable_dynamic_field_update
            if include_deleted_records is not None:
                self._values["include_deleted_records"] = include_deleted_records

        @builtins.property
        def object(self) -> builtins.str:
            '''``CfnIntegration.SalesforceSourcePropertiesProperty.Object``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-salesforcesourceproperties.html#cfn-customerprofiles-integration-salesforcesourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def enable_dynamic_field_update(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnIntegration.SalesforceSourcePropertiesProperty.EnableDynamicFieldUpdate``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-salesforcesourceproperties.html#cfn-customerprofiles-integration-salesforcesourceproperties-enabledynamicfieldupdate
            '''
            result = self._values.get("enable_dynamic_field_update")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def include_deleted_records(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnIntegration.SalesforceSourcePropertiesProperty.IncludeDeletedRecords``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-salesforcesourceproperties.html#cfn-customerprofiles-integration-salesforcesourceproperties-includedeletedrecords
            '''
            result = self._values.get("include_deleted_records")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SalesforceSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.ScheduledTriggerPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "schedule_expression": "scheduleExpression",
            "data_pull_mode": "dataPullMode",
            "first_execution_from": "firstExecutionFrom",
            "schedule_end_time": "scheduleEndTime",
            "schedule_offset": "scheduleOffset",
            "schedule_start_time": "scheduleStartTime",
            "timezone": "timezone",
        },
    )
    class ScheduledTriggerPropertiesProperty:
        def __init__(
            self,
            *,
            schedule_expression: builtins.str,
            data_pull_mode: typing.Optional[builtins.str] = None,
            first_execution_from: typing.Optional[jsii.Number] = None,
            schedule_end_time: typing.Optional[jsii.Number] = None,
            schedule_offset: typing.Optional[jsii.Number] = None,
            schedule_start_time: typing.Optional[jsii.Number] = None,
            timezone: typing.Optional[builtins.str] = None,
        ) -> None:
            '''
            :param schedule_expression: ``CfnIntegration.ScheduledTriggerPropertiesProperty.ScheduleExpression``.
            :param data_pull_mode: ``CfnIntegration.ScheduledTriggerPropertiesProperty.DataPullMode``.
            :param first_execution_from: ``CfnIntegration.ScheduledTriggerPropertiesProperty.FirstExecutionFrom``.
            :param schedule_end_time: ``CfnIntegration.ScheduledTriggerPropertiesProperty.ScheduleEndTime``.
            :param schedule_offset: ``CfnIntegration.ScheduledTriggerPropertiesProperty.ScheduleOffset``.
            :param schedule_start_time: ``CfnIntegration.ScheduledTriggerPropertiesProperty.ScheduleStartTime``.
            :param timezone: ``CfnIntegration.ScheduledTriggerPropertiesProperty.Timezone``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-scheduledtriggerproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                scheduled_trigger_properties_property = customerprofiles.CfnIntegration.ScheduledTriggerPropertiesProperty(
                    schedule_expression="scheduleExpression",
                
                    # the properties below are optional
                    data_pull_mode="dataPullMode",
                    first_execution_from=123,
                    schedule_end_time=123,
                    schedule_offset=123,
                    schedule_start_time=123,
                    timezone="timezone"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "schedule_expression": schedule_expression,
            }
            if data_pull_mode is not None:
                self._values["data_pull_mode"] = data_pull_mode
            if first_execution_from is not None:
                self._values["first_execution_from"] = first_execution_from
            if schedule_end_time is not None:
                self._values["schedule_end_time"] = schedule_end_time
            if schedule_offset is not None:
                self._values["schedule_offset"] = schedule_offset
            if schedule_start_time is not None:
                self._values["schedule_start_time"] = schedule_start_time
            if timezone is not None:
                self._values["timezone"] = timezone

        @builtins.property
        def schedule_expression(self) -> builtins.str:
            '''``CfnIntegration.ScheduledTriggerPropertiesProperty.ScheduleExpression``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-scheduledtriggerproperties.html#cfn-customerprofiles-integration-scheduledtriggerproperties-scheduleexpression
            '''
            result = self._values.get("schedule_expression")
            assert result is not None, "Required property 'schedule_expression' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def data_pull_mode(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.ScheduledTriggerPropertiesProperty.DataPullMode``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-scheduledtriggerproperties.html#cfn-customerprofiles-integration-scheduledtriggerproperties-datapullmode
            '''
            result = self._values.get("data_pull_mode")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def first_execution_from(self) -> typing.Optional[jsii.Number]:
            '''``CfnIntegration.ScheduledTriggerPropertiesProperty.FirstExecutionFrom``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-scheduledtriggerproperties.html#cfn-customerprofiles-integration-scheduledtriggerproperties-firstexecutionfrom
            '''
            result = self._values.get("first_execution_from")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def schedule_end_time(self) -> typing.Optional[jsii.Number]:
            '''``CfnIntegration.ScheduledTriggerPropertiesProperty.ScheduleEndTime``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-scheduledtriggerproperties.html#cfn-customerprofiles-integration-scheduledtriggerproperties-scheduleendtime
            '''
            result = self._values.get("schedule_end_time")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def schedule_offset(self) -> typing.Optional[jsii.Number]:
            '''``CfnIntegration.ScheduledTriggerPropertiesProperty.ScheduleOffset``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-scheduledtriggerproperties.html#cfn-customerprofiles-integration-scheduledtriggerproperties-scheduleoffset
            '''
            result = self._values.get("schedule_offset")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def schedule_start_time(self) -> typing.Optional[jsii.Number]:
            '''``CfnIntegration.ScheduledTriggerPropertiesProperty.ScheduleStartTime``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-scheduledtriggerproperties.html#cfn-customerprofiles-integration-scheduledtriggerproperties-schedulestarttime
            '''
            result = self._values.get("schedule_start_time")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def timezone(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.ScheduledTriggerPropertiesProperty.Timezone``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-scheduledtriggerproperties.html#cfn-customerprofiles-integration-scheduledtriggerproperties-timezone
            '''
            result = self._values.get("timezone")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScheduledTriggerPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.ServiceNowSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class ServiceNowSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''
            :param object: ``CfnIntegration.ServiceNowSourcePropertiesProperty.Object``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-servicenowsourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                service_now_source_properties_property = customerprofiles.CfnIntegration.ServiceNowSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''``CfnIntegration.ServiceNowSourcePropertiesProperty.Object``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-servicenowsourceproperties.html#cfn-customerprofiles-integration-servicenowsourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ServiceNowSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.SourceConnectorPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "marketo": "marketo",
            "s3": "s3",
            "salesforce": "salesforce",
            "service_now": "serviceNow",
            "zendesk": "zendesk",
        },
    )
    class SourceConnectorPropertiesProperty:
        def __init__(
            self,
            *,
            marketo: typing.Optional[typing.Union["CfnIntegration.MarketoSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            s3: typing.Optional[typing.Union["CfnIntegration.S3SourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            salesforce: typing.Optional[typing.Union["CfnIntegration.SalesforceSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            service_now: typing.Optional[typing.Union["CfnIntegration.ServiceNowSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
            zendesk: typing.Optional[typing.Union["CfnIntegration.ZendeskSourcePropertiesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param marketo: ``CfnIntegration.SourceConnectorPropertiesProperty.Marketo``.
            :param s3: ``CfnIntegration.SourceConnectorPropertiesProperty.S3``.
            :param salesforce: ``CfnIntegration.SourceConnectorPropertiesProperty.Salesforce``.
            :param service_now: ``CfnIntegration.SourceConnectorPropertiesProperty.ServiceNow``.
            :param zendesk: ``CfnIntegration.SourceConnectorPropertiesProperty.Zendesk``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-sourceconnectorproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                source_connector_properties_property = customerprofiles.CfnIntegration.SourceConnectorPropertiesProperty(
                    marketo=customerprofiles.CfnIntegration.MarketoSourcePropertiesProperty(
                        object="object"
                    ),
                    s3=customerprofiles.CfnIntegration.S3SourcePropertiesProperty(
                        bucket_name="bucketName",
                
                        # the properties below are optional
                        bucket_prefix="bucketPrefix"
                    ),
                    salesforce=customerprofiles.CfnIntegration.SalesforceSourcePropertiesProperty(
                        object="object",
                
                        # the properties below are optional
                        enable_dynamic_field_update=False,
                        include_deleted_records=False
                    ),
                    service_now=customerprofiles.CfnIntegration.ServiceNowSourcePropertiesProperty(
                        object="object"
                    ),
                    zendesk=customerprofiles.CfnIntegration.ZendeskSourcePropertiesProperty(
                        object="object"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if marketo is not None:
                self._values["marketo"] = marketo
            if s3 is not None:
                self._values["s3"] = s3
            if salesforce is not None:
                self._values["salesforce"] = salesforce
            if service_now is not None:
                self._values["service_now"] = service_now
            if zendesk is not None:
                self._values["zendesk"] = zendesk

        @builtins.property
        def marketo(
            self,
        ) -> typing.Optional[typing.Union["CfnIntegration.MarketoSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnIntegration.SourceConnectorPropertiesProperty.Marketo``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-sourceconnectorproperties.html#cfn-customerprofiles-integration-sourceconnectorproperties-marketo
            '''
            result = self._values.get("marketo")
            return typing.cast(typing.Optional[typing.Union["CfnIntegration.MarketoSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def s3(
            self,
        ) -> typing.Optional[typing.Union["CfnIntegration.S3SourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnIntegration.SourceConnectorPropertiesProperty.S3``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-sourceconnectorproperties.html#cfn-customerprofiles-integration-sourceconnectorproperties-s3
            '''
            result = self._values.get("s3")
            return typing.cast(typing.Optional[typing.Union["CfnIntegration.S3SourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def salesforce(
            self,
        ) -> typing.Optional[typing.Union["CfnIntegration.SalesforceSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnIntegration.SourceConnectorPropertiesProperty.Salesforce``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-sourceconnectorproperties.html#cfn-customerprofiles-integration-sourceconnectorproperties-salesforce
            '''
            result = self._values.get("salesforce")
            return typing.cast(typing.Optional[typing.Union["CfnIntegration.SalesforceSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def service_now(
            self,
        ) -> typing.Optional[typing.Union["CfnIntegration.ServiceNowSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnIntegration.SourceConnectorPropertiesProperty.ServiceNow``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-sourceconnectorproperties.html#cfn-customerprofiles-integration-sourceconnectorproperties-servicenow
            '''
            result = self._values.get("service_now")
            return typing.cast(typing.Optional[typing.Union["CfnIntegration.ServiceNowSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def zendesk(
            self,
        ) -> typing.Optional[typing.Union["CfnIntegration.ZendeskSourcePropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnIntegration.SourceConnectorPropertiesProperty.Zendesk``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-sourceconnectorproperties.html#cfn-customerprofiles-integration-sourceconnectorproperties-zendesk
            '''
            result = self._values.get("zendesk")
            return typing.cast(typing.Optional[typing.Union["CfnIntegration.ZendeskSourcePropertiesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SourceConnectorPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.SourceFlowConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "connector_type": "connectorType",
            "source_connector_properties": "sourceConnectorProperties",
            "connector_profile_name": "connectorProfileName",
            "incremental_pull_config": "incrementalPullConfig",
        },
    )
    class SourceFlowConfigProperty:
        def __init__(
            self,
            *,
            connector_type: builtins.str,
            source_connector_properties: typing.Union["CfnIntegration.SourceConnectorPropertiesProperty", _IResolvable_da3f097b],
            connector_profile_name: typing.Optional[builtins.str] = None,
            incremental_pull_config: typing.Optional[typing.Union["CfnIntegration.IncrementalPullConfigProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param connector_type: ``CfnIntegration.SourceFlowConfigProperty.ConnectorType``.
            :param source_connector_properties: ``CfnIntegration.SourceFlowConfigProperty.SourceConnectorProperties``.
            :param connector_profile_name: ``CfnIntegration.SourceFlowConfigProperty.ConnectorProfileName``.
            :param incremental_pull_config: ``CfnIntegration.SourceFlowConfigProperty.IncrementalPullConfig``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-sourceflowconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                source_flow_config_property = customerprofiles.CfnIntegration.SourceFlowConfigProperty(
                    connector_type="connectorType",
                    source_connector_properties=customerprofiles.CfnIntegration.SourceConnectorPropertiesProperty(
                        marketo=customerprofiles.CfnIntegration.MarketoSourcePropertiesProperty(
                            object="object"
                        ),
                        s3=customerprofiles.CfnIntegration.S3SourcePropertiesProperty(
                            bucket_name="bucketName",
                
                            # the properties below are optional
                            bucket_prefix="bucketPrefix"
                        ),
                        salesforce=customerprofiles.CfnIntegration.SalesforceSourcePropertiesProperty(
                            object="object",
                
                            # the properties below are optional
                            enable_dynamic_field_update=False,
                            include_deleted_records=False
                        ),
                        service_now=customerprofiles.CfnIntegration.ServiceNowSourcePropertiesProperty(
                            object="object"
                        ),
                        zendesk=customerprofiles.CfnIntegration.ZendeskSourcePropertiesProperty(
                            object="object"
                        )
                    ),
                
                    # the properties below are optional
                    connector_profile_name="connectorProfileName",
                    incremental_pull_config=customerprofiles.CfnIntegration.IncrementalPullConfigProperty(
                        datetime_type_field_name="datetimeTypeFieldName"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "connector_type": connector_type,
                "source_connector_properties": source_connector_properties,
            }
            if connector_profile_name is not None:
                self._values["connector_profile_name"] = connector_profile_name
            if incremental_pull_config is not None:
                self._values["incremental_pull_config"] = incremental_pull_config

        @builtins.property
        def connector_type(self) -> builtins.str:
            '''``CfnIntegration.SourceFlowConfigProperty.ConnectorType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-sourceflowconfig.html#cfn-customerprofiles-integration-sourceflowconfig-connectortype
            '''
            result = self._values.get("connector_type")
            assert result is not None, "Required property 'connector_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def source_connector_properties(
            self,
        ) -> typing.Union["CfnIntegration.SourceConnectorPropertiesProperty", _IResolvable_da3f097b]:
            '''``CfnIntegration.SourceFlowConfigProperty.SourceConnectorProperties``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-sourceflowconfig.html#cfn-customerprofiles-integration-sourceflowconfig-sourceconnectorproperties
            '''
            result = self._values.get("source_connector_properties")
            assert result is not None, "Required property 'source_connector_properties' is missing"
            return typing.cast(typing.Union["CfnIntegration.SourceConnectorPropertiesProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def connector_profile_name(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.SourceFlowConfigProperty.ConnectorProfileName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-sourceflowconfig.html#cfn-customerprofiles-integration-sourceflowconfig-connectorprofilename
            '''
            result = self._values.get("connector_profile_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def incremental_pull_config(
            self,
        ) -> typing.Optional[typing.Union["CfnIntegration.IncrementalPullConfigProperty", _IResolvable_da3f097b]]:
            '''``CfnIntegration.SourceFlowConfigProperty.IncrementalPullConfig``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-sourceflowconfig.html#cfn-customerprofiles-integration-sourceflowconfig-incrementalpullconfig
            '''
            result = self._values.get("incremental_pull_config")
            return typing.cast(typing.Optional[typing.Union["CfnIntegration.IncrementalPullConfigProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SourceFlowConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.TaskPropertiesMapProperty",
        jsii_struct_bases=[],
        name_mapping={
            "operator_property_key": "operatorPropertyKey",
            "property": "property",
        },
    )
    class TaskPropertiesMapProperty:
        def __init__(
            self,
            *,
            operator_property_key: builtins.str,
            property: builtins.str,
        ) -> None:
            '''
            :param operator_property_key: ``CfnIntegration.TaskPropertiesMapProperty.OperatorPropertyKey``.
            :param property: ``CfnIntegration.TaskPropertiesMapProperty.Property``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-taskpropertiesmap.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                task_properties_map_property = customerprofiles.CfnIntegration.TaskPropertiesMapProperty(
                    operator_property_key="operatorPropertyKey",
                    property="property"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "operator_property_key": operator_property_key,
                "property": property,
            }

        @builtins.property
        def operator_property_key(self) -> builtins.str:
            '''``CfnIntegration.TaskPropertiesMapProperty.OperatorPropertyKey``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-taskpropertiesmap.html#cfn-customerprofiles-integration-taskpropertiesmap-operatorpropertykey
            '''
            result = self._values.get("operator_property_key")
            assert result is not None, "Required property 'operator_property_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def property(self) -> builtins.str:
            '''``CfnIntegration.TaskPropertiesMapProperty.Property``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-taskpropertiesmap.html#cfn-customerprofiles-integration-taskpropertiesmap-property
            '''
            result = self._values.get("property")
            assert result is not None, "Required property 'property' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TaskPropertiesMapProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.TaskProperty",
        jsii_struct_bases=[],
        name_mapping={
            "source_fields": "sourceFields",
            "task_type": "taskType",
            "connector_operator": "connectorOperator",
            "destination_field": "destinationField",
            "task_properties": "taskProperties",
        },
    )
    class TaskProperty:
        def __init__(
            self,
            *,
            source_fields: typing.Sequence[builtins.str],
            task_type: builtins.str,
            connector_operator: typing.Optional[typing.Union["CfnIntegration.ConnectorOperatorProperty", _IResolvable_da3f097b]] = None,
            destination_field: typing.Optional[builtins.str] = None,
            task_properties: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnIntegration.TaskPropertiesMapProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''
            :param source_fields: ``CfnIntegration.TaskProperty.SourceFields``.
            :param task_type: ``CfnIntegration.TaskProperty.TaskType``.
            :param connector_operator: ``CfnIntegration.TaskProperty.ConnectorOperator``.
            :param destination_field: ``CfnIntegration.TaskProperty.DestinationField``.
            :param task_properties: ``CfnIntegration.TaskProperty.TaskProperties``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-task.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                task_property = customerprofiles.CfnIntegration.TaskProperty(
                    source_fields=["sourceFields"],
                    task_type="taskType",
                
                    # the properties below are optional
                    connector_operator=customerprofiles.CfnIntegration.ConnectorOperatorProperty(
                        marketo="marketo",
                        s3="s3",
                        salesforce="salesforce",
                        service_now="serviceNow",
                        zendesk="zendesk"
                    ),
                    destination_field="destinationField",
                    task_properties=[customerprofiles.CfnIntegration.TaskPropertiesMapProperty(
                        operator_property_key="operatorPropertyKey",
                        property="property"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "source_fields": source_fields,
                "task_type": task_type,
            }
            if connector_operator is not None:
                self._values["connector_operator"] = connector_operator
            if destination_field is not None:
                self._values["destination_field"] = destination_field
            if task_properties is not None:
                self._values["task_properties"] = task_properties

        @builtins.property
        def source_fields(self) -> typing.List[builtins.str]:
            '''``CfnIntegration.TaskProperty.SourceFields``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-task.html#cfn-customerprofiles-integration-task-sourcefields
            '''
            result = self._values.get("source_fields")
            assert result is not None, "Required property 'source_fields' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def task_type(self) -> builtins.str:
            '''``CfnIntegration.TaskProperty.TaskType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-task.html#cfn-customerprofiles-integration-task-tasktype
            '''
            result = self._values.get("task_type")
            assert result is not None, "Required property 'task_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def connector_operator(
            self,
        ) -> typing.Optional[typing.Union["CfnIntegration.ConnectorOperatorProperty", _IResolvable_da3f097b]]:
            '''``CfnIntegration.TaskProperty.ConnectorOperator``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-task.html#cfn-customerprofiles-integration-task-connectoroperator
            '''
            result = self._values.get("connector_operator")
            return typing.cast(typing.Optional[typing.Union["CfnIntegration.ConnectorOperatorProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def destination_field(self) -> typing.Optional[builtins.str]:
            '''``CfnIntegration.TaskProperty.DestinationField``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-task.html#cfn-customerprofiles-integration-task-destinationfield
            '''
            result = self._values.get("destination_field")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def task_properties(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIntegration.TaskPropertiesMapProperty", _IResolvable_da3f097b]]]]:
            '''``CfnIntegration.TaskProperty.TaskProperties``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-task.html#cfn-customerprofiles-integration-task-taskproperties
            '''
            result = self._values.get("task_properties")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnIntegration.TaskPropertiesMapProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TaskProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.TriggerConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "trigger_type": "triggerType",
            "trigger_properties": "triggerProperties",
        },
    )
    class TriggerConfigProperty:
        def __init__(
            self,
            *,
            trigger_type: builtins.str,
            trigger_properties: typing.Optional[typing.Union["CfnIntegration.TriggerPropertiesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param trigger_type: ``CfnIntegration.TriggerConfigProperty.TriggerType``.
            :param trigger_properties: ``CfnIntegration.TriggerConfigProperty.TriggerProperties``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-triggerconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                trigger_config_property = customerprofiles.CfnIntegration.TriggerConfigProperty(
                    trigger_type="triggerType",
                
                    # the properties below are optional
                    trigger_properties=customerprofiles.CfnIntegration.TriggerPropertiesProperty(
                        scheduled=customerprofiles.CfnIntegration.ScheduledTriggerPropertiesProperty(
                            schedule_expression="scheduleExpression",
                
                            # the properties below are optional
                            data_pull_mode="dataPullMode",
                            first_execution_from=123,
                            schedule_end_time=123,
                            schedule_offset=123,
                            schedule_start_time=123,
                            timezone="timezone"
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "trigger_type": trigger_type,
            }
            if trigger_properties is not None:
                self._values["trigger_properties"] = trigger_properties

        @builtins.property
        def trigger_type(self) -> builtins.str:
            '''``CfnIntegration.TriggerConfigProperty.TriggerType``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-triggerconfig.html#cfn-customerprofiles-integration-triggerconfig-triggertype
            '''
            result = self._values.get("trigger_type")
            assert result is not None, "Required property 'trigger_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def trigger_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnIntegration.TriggerPropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnIntegration.TriggerConfigProperty.TriggerProperties``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-triggerconfig.html#cfn-customerprofiles-integration-triggerconfig-triggerproperties
            '''
            result = self._values.get("trigger_properties")
            return typing.cast(typing.Optional[typing.Union["CfnIntegration.TriggerPropertiesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TriggerConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.TriggerPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"scheduled": "scheduled"},
    )
    class TriggerPropertiesProperty:
        def __init__(
            self,
            *,
            scheduled: typing.Optional[typing.Union["CfnIntegration.ScheduledTriggerPropertiesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param scheduled: ``CfnIntegration.TriggerPropertiesProperty.Scheduled``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-triggerproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                trigger_properties_property = customerprofiles.CfnIntegration.TriggerPropertiesProperty(
                    scheduled=customerprofiles.CfnIntegration.ScheduledTriggerPropertiesProperty(
                        schedule_expression="scheduleExpression",
                
                        # the properties below are optional
                        data_pull_mode="dataPullMode",
                        first_execution_from=123,
                        schedule_end_time=123,
                        schedule_offset=123,
                        schedule_start_time=123,
                        timezone="timezone"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if scheduled is not None:
                self._values["scheduled"] = scheduled

        @builtins.property
        def scheduled(
            self,
        ) -> typing.Optional[typing.Union["CfnIntegration.ScheduledTriggerPropertiesProperty", _IResolvable_da3f097b]]:
            '''``CfnIntegration.TriggerPropertiesProperty.Scheduled``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-triggerproperties.html#cfn-customerprofiles-integration-triggerproperties-scheduled
            '''
            result = self._values.get("scheduled")
            return typing.cast(typing.Optional[typing.Union["CfnIntegration.ScheduledTriggerPropertiesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TriggerPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegration.ZendeskSourcePropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"object": "object"},
    )
    class ZendeskSourcePropertiesProperty:
        def __init__(self, *, object: builtins.str) -> None:
            '''
            :param object: ``CfnIntegration.ZendeskSourcePropertiesProperty.Object``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-zendesksourceproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                zendesk_source_properties_property = customerprofiles.CfnIntegration.ZendeskSourcePropertiesProperty(
                    object="object"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "object": object,
            }

        @builtins.property
        def object(self) -> builtins.str:
            '''``CfnIntegration.ZendeskSourcePropertiesProperty.Object``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-integration-zendesksourceproperties.html#cfn-customerprofiles-integration-zendesksourceproperties-object
            '''
            result = self._values.get("object")
            assert result is not None, "Required property 'object' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ZendeskSourcePropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_customerprofiles.CfnIntegrationProps",
    jsii_struct_bases=[],
    name_mapping={
        "domain_name": "domainName",
        "flow_definition": "flowDefinition",
        "object_type_name": "objectTypeName",
        "object_type_names": "objectTypeNames",
        "tags": "tags",
        "uri": "uri",
    },
)
class CfnIntegrationProps:
    def __init__(
        self,
        *,
        domain_name: builtins.str,
        flow_definition: typing.Optional[typing.Union[CfnIntegration.FlowDefinitionProperty, _IResolvable_da3f097b]] = None,
        object_type_name: typing.Optional[builtins.str] = None,
        object_type_names: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnIntegration.ObjectTypeMappingProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        uri: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnIntegration``.

        :param domain_name: The unique name of the domain.
        :param flow_definition: ``AWS::CustomerProfiles::Integration.FlowDefinition``.
        :param object_type_name: The name of the profile object type mapping to use.
        :param object_type_names: ``AWS::CustomerProfiles::Integration.ObjectTypeNames``.
        :param tags: The tags used to organize, track, or control access for this resource.
        :param uri: The URI of the S3 bucket or any other type of data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_customerprofiles as customerprofiles
            
            cfn_integration_props = customerprofiles.CfnIntegrationProps(
                domain_name="domainName",
            
                # the properties below are optional
                flow_definition=customerprofiles.CfnIntegration.FlowDefinitionProperty(
                    flow_name="flowName",
                    kms_arn="kmsArn",
                    source_flow_config=customerprofiles.CfnIntegration.SourceFlowConfigProperty(
                        connector_type="connectorType",
                        source_connector_properties=customerprofiles.CfnIntegration.SourceConnectorPropertiesProperty(
                            marketo=customerprofiles.CfnIntegration.MarketoSourcePropertiesProperty(
                                object="object"
                            ),
                            s3=customerprofiles.CfnIntegration.S3SourcePropertiesProperty(
                                bucket_name="bucketName",
            
                                # the properties below are optional
                                bucket_prefix="bucketPrefix"
                            ),
                            salesforce=customerprofiles.CfnIntegration.SalesforceSourcePropertiesProperty(
                                object="object",
            
                                # the properties below are optional
                                enable_dynamic_field_update=False,
                                include_deleted_records=False
                            ),
                            service_now=customerprofiles.CfnIntegration.ServiceNowSourcePropertiesProperty(
                                object="object"
                            ),
                            zendesk=customerprofiles.CfnIntegration.ZendeskSourcePropertiesProperty(
                                object="object"
                            )
                        ),
            
                        # the properties below are optional
                        connector_profile_name="connectorProfileName",
                        incremental_pull_config=customerprofiles.CfnIntegration.IncrementalPullConfigProperty(
                            datetime_type_field_name="datetimeTypeFieldName"
                        )
                    ),
                    tasks=[customerprofiles.CfnIntegration.TaskProperty(
                        source_fields=["sourceFields"],
                        task_type="taskType",
            
                        # the properties below are optional
                        connector_operator=customerprofiles.CfnIntegration.ConnectorOperatorProperty(
                            marketo="marketo",
                            s3="s3",
                            salesforce="salesforce",
                            service_now="serviceNow",
                            zendesk="zendesk"
                        ),
                        destination_field="destinationField",
                        task_properties=[customerprofiles.CfnIntegration.TaskPropertiesMapProperty(
                            operator_property_key="operatorPropertyKey",
                            property="property"
                        )]
                    )],
                    trigger_config=customerprofiles.CfnIntegration.TriggerConfigProperty(
                        trigger_type="triggerType",
            
                        # the properties below are optional
                        trigger_properties=customerprofiles.CfnIntegration.TriggerPropertiesProperty(
                            scheduled=customerprofiles.CfnIntegration.ScheduledTriggerPropertiesProperty(
                                schedule_expression="scheduleExpression",
            
                                # the properties below are optional
                                data_pull_mode="dataPullMode",
                                first_execution_from=123,
                                schedule_end_time=123,
                                schedule_offset=123,
                                schedule_start_time=123,
                                timezone="timezone"
                            )
                        )
                    ),
            
                    # the properties below are optional
                    description="description"
                ),
                object_type_name="objectTypeName",
                object_type_names=[customerprofiles.CfnIntegration.ObjectTypeMappingProperty(
                    key="key",
                    value="value"
                )],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                uri="uri"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain_name": domain_name,
        }
        if flow_definition is not None:
            self._values["flow_definition"] = flow_definition
        if object_type_name is not None:
            self._values["object_type_name"] = object_type_name
        if object_type_names is not None:
            self._values["object_type_names"] = object_type_names
        if tags is not None:
            self._values["tags"] = tags
        if uri is not None:
            self._values["uri"] = uri

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''The unique name of the domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-domainname
        '''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def flow_definition(
        self,
    ) -> typing.Optional[typing.Union[CfnIntegration.FlowDefinitionProperty, _IResolvable_da3f097b]]:
        '''``AWS::CustomerProfiles::Integration.FlowDefinition``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-flowdefinition
        '''
        result = self._values.get("flow_definition")
        return typing.cast(typing.Optional[typing.Union[CfnIntegration.FlowDefinitionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def object_type_name(self) -> typing.Optional[builtins.str]:
        '''The name of the profile object type mapping to use.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-objecttypename
        '''
        result = self._values.get("object_type_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def object_type_names(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnIntegration.ObjectTypeMappingProperty, _IResolvable_da3f097b]]]]:
        '''``AWS::CustomerProfiles::Integration.ObjectTypeNames``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-objecttypenames
        '''
        result = self._values.get("object_type_names")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnIntegration.ObjectTypeMappingProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def uri(self) -> typing.Optional[builtins.str]:
        '''The URI of the S3 bucket or any other type of data source.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-integration.html#cfn-customerprofiles-integration-uri
        '''
        result = self._values.get("uri")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnIntegrationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnObjectType(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_customerprofiles.CfnObjectType",
):
    '''A CloudFormation ``AWS::CustomerProfiles::ObjectType``.

    The AWS::CustomerProfiles::ObjectType resource specifies an Amazon Connect Customer Profiles Object Type Mapping.

    :cloudformationResource: AWS::CustomerProfiles::ObjectType
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_customerprofiles as customerprofiles
        
        cfn_object_type = customerprofiles.CfnObjectType(self, "MyCfnObjectType",
            domain_name="domainName",
        
            # the properties below are optional
            allow_profile_creation=False,
            description="description",
            encryption_key="encryptionKey",
            expiration_days=123,
            fields=[customerprofiles.CfnObjectType.FieldMapProperty(
                name="name",
                object_type_field=customerprofiles.CfnObjectType.ObjectTypeFieldProperty(
                    content_type="contentType",
                    source="source",
                    target="target"
                )
            )],
            keys=[customerprofiles.CfnObjectType.KeyMapProperty(
                name="name",
                object_type_key_list=[customerprofiles.CfnObjectType.ObjectTypeKeyProperty(
                    field_names=["fieldNames"],
                    standard_identifiers=["standardIdentifiers"]
                )]
            )],
            object_type_name="objectTypeName",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            template_id="templateId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        domain_name: builtins.str,
        allow_profile_creation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        encryption_key: typing.Optional[builtins.str] = None,
        expiration_days: typing.Optional[jsii.Number] = None,
        fields: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnObjectType.FieldMapProperty", _IResolvable_da3f097b]]]] = None,
        keys: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnObjectType.KeyMapProperty", _IResolvable_da3f097b]]]] = None,
        object_type_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        template_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::CustomerProfiles::ObjectType``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param domain_name: The unique name of the domain.
        :param allow_profile_creation: Indicates whether a profile should be created when data is received if one doesn’t exist for an object of this type. The default is ``FALSE`` . If the AllowProfileCreation flag is set to ``FALSE`` , then the service tries to fetch a standard profile and associate this object with the profile. If it is set to ``TRUE`` , and if no match is found, then the service creates a new standard profile.
        :param description: The description of the profile object type mapping.
        :param encryption_key: The customer-provided key to encrypt the profile object that will be created in this profile object type mapping. If not specified the system will use the encryption key of the domain.
        :param expiration_days: The number of days until the data of this type expires.
        :param fields: A list of field definitions for the object type mapping.
        :param keys: A list of keys that can be used to map data to the profile or search for the profile.
        :param object_type_name: The name of the profile object type.
        :param tags: The tags used to organize, track, or control access for this resource.
        :param template_id: A unique identifier for the template mapping. This can be used instead of specifying the Keys and Fields properties directly.
        '''
        props = CfnObjectTypeProps(
            domain_name=domain_name,
            allow_profile_creation=allow_profile_creation,
            description=description,
            encryption_key=encryption_key,
            expiration_days=expiration_days,
            fields=fields,
            keys=keys,
            object_type_name=object_type_name,
            tags=tags,
            template_id=template_id,
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
    @jsii.member(jsii_name="attrCreatedAt")
    def attr_created_at(self) -> builtins.str:
        '''The timestamp of when the object type was created.

        :cloudformationAttribute: CreatedAt
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreatedAt"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLastUpdatedAt")
    def attr_last_updated_at(self) -> builtins.str:
        '''The timestamp of when the object type was most recently edited.

        :cloudformationAttribute: LastUpdatedAt
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLastUpdatedAt"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domainName")
    def domain_name(self) -> builtins.str:
        '''The unique name of the domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-domainname
        '''
        return typing.cast(builtins.str, jsii.get(self, "domainName"))

    @domain_name.setter
    def domain_name(self, value: builtins.str) -> None:
        jsii.set(self, "domainName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="allowProfileCreation")
    def allow_profile_creation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether a profile should be created when data is received if one doesn’t exist for an object of this type.

        The default is ``FALSE`` . If the AllowProfileCreation flag is set to ``FALSE`` , then the service tries to fetch a standard profile and associate this object with the profile. If it is set to ``TRUE`` , and if no match is found, then the service creates a new standard profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-allowprofilecreation
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "allowProfileCreation"))

    @allow_profile_creation.setter
    def allow_profile_creation(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "allowProfileCreation", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the profile object type mapping.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionKey")
    def encryption_key(self) -> typing.Optional[builtins.str]:
        '''The customer-provided key to encrypt the profile object that will be created in this profile object type mapping.

        If not specified the system will use the encryption key of the domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-encryptionkey
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "encryptionKey"))

    @encryption_key.setter
    def encryption_key(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "encryptionKey", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="expirationDays")
    def expiration_days(self) -> typing.Optional[jsii.Number]:
        '''The number of days until the data of this type expires.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-expirationdays
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "expirationDays"))

    @expiration_days.setter
    def expiration_days(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "expirationDays", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fields")
    def fields(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnObjectType.FieldMapProperty", _IResolvable_da3f097b]]]]:
        '''A list of field definitions for the object type mapping.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-fields
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnObjectType.FieldMapProperty", _IResolvable_da3f097b]]]], jsii.get(self, "fields"))

    @fields.setter
    def fields(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnObjectType.FieldMapProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "fields", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="keys")
    def keys(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnObjectType.KeyMapProperty", _IResolvable_da3f097b]]]]:
        '''A list of keys that can be used to map data to the profile or search for the profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-keys
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnObjectType.KeyMapProperty", _IResolvable_da3f097b]]]], jsii.get(self, "keys"))

    @keys.setter
    def keys(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnObjectType.KeyMapProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "keys", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="objectTypeName")
    def object_type_name(self) -> typing.Optional[builtins.str]:
        '''The name of the profile object type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-objecttypename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "objectTypeName"))

    @object_type_name.setter
    def object_type_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "objectTypeName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="templateId")
    def template_id(self) -> typing.Optional[builtins.str]:
        '''A unique identifier for the template mapping.

        This can be used instead of specifying the Keys and Fields properties directly.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-templateid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "templateId"))

    @template_id.setter
    def template_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "templateId", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnObjectType.FieldMapProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "object_type_field": "objectTypeField"},
    )
    class FieldMapProperty:
        def __init__(
            self,
            *,
            name: typing.Optional[builtins.str] = None,
            object_type_field: typing.Optional[typing.Union["CfnObjectType.ObjectTypeFieldProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A map of the name and ObjectType field.

            :param name: Name of the field.
            :param object_type_field: Represents a field in a ProfileObjectType.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-fieldmap.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                field_map_property = customerprofiles.CfnObjectType.FieldMapProperty(
                    name="name",
                    object_type_field=customerprofiles.CfnObjectType.ObjectTypeFieldProperty(
                        content_type="contentType",
                        source="source",
                        target="target"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if name is not None:
                self._values["name"] = name
            if object_type_field is not None:
                self._values["object_type_field"] = object_type_field

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''Name of the field.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-fieldmap.html#cfn-customerprofiles-objecttype-fieldmap-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def object_type_field(
            self,
        ) -> typing.Optional[typing.Union["CfnObjectType.ObjectTypeFieldProperty", _IResolvable_da3f097b]]:
            '''Represents a field in a ProfileObjectType.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-fieldmap.html#cfn-customerprofiles-objecttype-fieldmap-objecttypefield
            '''
            result = self._values.get("object_type_field")
            return typing.cast(typing.Optional[typing.Union["CfnObjectType.ObjectTypeFieldProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FieldMapProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnObjectType.KeyMapProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "object_type_key_list": "objectTypeKeyList"},
    )
    class KeyMapProperty:
        def __init__(
            self,
            *,
            name: typing.Optional[builtins.str] = None,
            object_type_key_list: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnObjectType.ObjectTypeKeyProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''A unique key map that can be used to map data to the profile.

            :param name: Name of the key.
            :param object_type_key_list: A list of ObjectTypeKey.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-keymap.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                key_map_property = customerprofiles.CfnObjectType.KeyMapProperty(
                    name="name",
                    object_type_key_list=[customerprofiles.CfnObjectType.ObjectTypeKeyProperty(
                        field_names=["fieldNames"],
                        standard_identifiers=["standardIdentifiers"]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if name is not None:
                self._values["name"] = name
            if object_type_key_list is not None:
                self._values["object_type_key_list"] = object_type_key_list

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''Name of the key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-keymap.html#cfn-customerprofiles-objecttype-keymap-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def object_type_key_list(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnObjectType.ObjectTypeKeyProperty", _IResolvable_da3f097b]]]]:
            '''A list of ObjectTypeKey.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-keymap.html#cfn-customerprofiles-objecttype-keymap-objecttypekeylist
            '''
            result = self._values.get("object_type_key_list")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnObjectType.ObjectTypeKeyProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KeyMapProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnObjectType.ObjectTypeFieldProperty",
        jsii_struct_bases=[],
        name_mapping={
            "content_type": "contentType",
            "source": "source",
            "target": "target",
        },
    )
    class ObjectTypeFieldProperty:
        def __init__(
            self,
            *,
            content_type: typing.Optional[builtins.str] = None,
            source: typing.Optional[builtins.str] = None,
            target: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Represents a field in a ProfileObjectType.

            :param content_type: The content type of the field. Used for determining equality when searching.
            :param source: A field of a ProfileObject. For example: _source.FirstName, where “_source” is a ProfileObjectType of a Zendesk user and “FirstName” is a field in that ObjectType.
            :param target: The location of the data in the standard ProfileObject model. For example: _profile.Address.PostalCode.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-objecttypefield.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                object_type_field_property = customerprofiles.CfnObjectType.ObjectTypeFieldProperty(
                    content_type="contentType",
                    source="source",
                    target="target"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if content_type is not None:
                self._values["content_type"] = content_type
            if source is not None:
                self._values["source"] = source
            if target is not None:
                self._values["target"] = target

        @builtins.property
        def content_type(self) -> typing.Optional[builtins.str]:
            '''The content type of the field.

            Used for determining equality when searching.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-objecttypefield.html#cfn-customerprofiles-objecttype-objecttypefield-contenttype
            '''
            result = self._values.get("content_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def source(self) -> typing.Optional[builtins.str]:
            '''A field of a ProfileObject.

            For example: _source.FirstName, where “_source” is a ProfileObjectType of a Zendesk user and “FirstName” is a field in that ObjectType.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-objecttypefield.html#cfn-customerprofiles-objecttype-objecttypefield-source
            '''
            result = self._values.get("source")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def target(self) -> typing.Optional[builtins.str]:
            '''The location of the data in the standard ProfileObject model.

            For example: _profile.Address.PostalCode.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-objecttypefield.html#cfn-customerprofiles-objecttype-objecttypefield-target
            '''
            result = self._values.get("target")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ObjectTypeFieldProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_customerprofiles.CfnObjectType.ObjectTypeKeyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "field_names": "fieldNames",
            "standard_identifiers": "standardIdentifiers",
        },
    )
    class ObjectTypeKeyProperty:
        def __init__(
            self,
            *,
            field_names: typing.Optional[typing.Sequence[builtins.str]] = None,
            standard_identifiers: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''An object that defines the Key element of a ProfileObject.

            A Key is a special element that can be used to search for a customer profile.

            :param field_names: The reference for the key name of the fields map.
            :param standard_identifiers: The types of keys that a ProfileObject can have. Each ProfileObject can have only 1 UNIQUE key but multiple PROFILE keys. PROFILE means that this key can be used to tie an object to a PROFILE. UNIQUE means that it can be used to uniquely identify an object. If a key a is marked as SECONDARY, it will be used to search for profiles after all other PROFILE keys have been searched. A LOOKUP_ONLY key is only used to match a profile but is not persisted to be used for searching of the profile. A NEW_ONLY key is only used if the profile does not already exist before the object is ingested, otherwise it is only used for matching objects to profiles.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-objecttypekey.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_customerprofiles as customerprofiles
                
                object_type_key_property = customerprofiles.CfnObjectType.ObjectTypeKeyProperty(
                    field_names=["fieldNames"],
                    standard_identifiers=["standardIdentifiers"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if field_names is not None:
                self._values["field_names"] = field_names
            if standard_identifiers is not None:
                self._values["standard_identifiers"] = standard_identifiers

        @builtins.property
        def field_names(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The reference for the key name of the fields map.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-objecttypekey.html#cfn-customerprofiles-objecttype-objecttypekey-fieldnames
            '''
            result = self._values.get("field_names")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def standard_identifiers(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The types of keys that a ProfileObject can have.

            Each ProfileObject can have only 1 UNIQUE key but multiple PROFILE keys. PROFILE means that this key can be used to tie an object to a PROFILE. UNIQUE means that it can be used to uniquely identify an object. If a key a is marked as SECONDARY, it will be used to search for profiles after all other PROFILE keys have been searched. A LOOKUP_ONLY key is only used to match a profile but is not persisted to be used for searching of the profile. A NEW_ONLY key is only used if the profile does not already exist before the object is ingested, otherwise it is only used for matching objects to profiles.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-customerprofiles-objecttype-objecttypekey.html#cfn-customerprofiles-objecttype-objecttypekey-standardidentifiers
            '''
            result = self._values.get("standard_identifiers")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ObjectTypeKeyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_customerprofiles.CfnObjectTypeProps",
    jsii_struct_bases=[],
    name_mapping={
        "domain_name": "domainName",
        "allow_profile_creation": "allowProfileCreation",
        "description": "description",
        "encryption_key": "encryptionKey",
        "expiration_days": "expirationDays",
        "fields": "fields",
        "keys": "keys",
        "object_type_name": "objectTypeName",
        "tags": "tags",
        "template_id": "templateId",
    },
)
class CfnObjectTypeProps:
    def __init__(
        self,
        *,
        domain_name: builtins.str,
        allow_profile_creation: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        description: typing.Optional[builtins.str] = None,
        encryption_key: typing.Optional[builtins.str] = None,
        expiration_days: typing.Optional[jsii.Number] = None,
        fields: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnObjectType.FieldMapProperty, _IResolvable_da3f097b]]]] = None,
        keys: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnObjectType.KeyMapProperty, _IResolvable_da3f097b]]]] = None,
        object_type_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        template_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnObjectType``.

        :param domain_name: The unique name of the domain.
        :param allow_profile_creation: Indicates whether a profile should be created when data is received if one doesn’t exist for an object of this type. The default is ``FALSE`` . If the AllowProfileCreation flag is set to ``FALSE`` , then the service tries to fetch a standard profile and associate this object with the profile. If it is set to ``TRUE`` , and if no match is found, then the service creates a new standard profile.
        :param description: The description of the profile object type mapping.
        :param encryption_key: The customer-provided key to encrypt the profile object that will be created in this profile object type mapping. If not specified the system will use the encryption key of the domain.
        :param expiration_days: The number of days until the data of this type expires.
        :param fields: A list of field definitions for the object type mapping.
        :param keys: A list of keys that can be used to map data to the profile or search for the profile.
        :param object_type_name: The name of the profile object type.
        :param tags: The tags used to organize, track, or control access for this resource.
        :param template_id: A unique identifier for the template mapping. This can be used instead of specifying the Keys and Fields properties directly.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_customerprofiles as customerprofiles
            
            cfn_object_type_props = customerprofiles.CfnObjectTypeProps(
                domain_name="domainName",
            
                # the properties below are optional
                allow_profile_creation=False,
                description="description",
                encryption_key="encryptionKey",
                expiration_days=123,
                fields=[customerprofiles.CfnObjectType.FieldMapProperty(
                    name="name",
                    object_type_field=customerprofiles.CfnObjectType.ObjectTypeFieldProperty(
                        content_type="contentType",
                        source="source",
                        target="target"
                    )
                )],
                keys=[customerprofiles.CfnObjectType.KeyMapProperty(
                    name="name",
                    object_type_key_list=[customerprofiles.CfnObjectType.ObjectTypeKeyProperty(
                        field_names=["fieldNames"],
                        standard_identifiers=["standardIdentifiers"]
                    )]
                )],
                object_type_name="objectTypeName",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                template_id="templateId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain_name": domain_name,
        }
        if allow_profile_creation is not None:
            self._values["allow_profile_creation"] = allow_profile_creation
        if description is not None:
            self._values["description"] = description
        if encryption_key is not None:
            self._values["encryption_key"] = encryption_key
        if expiration_days is not None:
            self._values["expiration_days"] = expiration_days
        if fields is not None:
            self._values["fields"] = fields
        if keys is not None:
            self._values["keys"] = keys
        if object_type_name is not None:
            self._values["object_type_name"] = object_type_name
        if tags is not None:
            self._values["tags"] = tags
        if template_id is not None:
            self._values["template_id"] = template_id

    @builtins.property
    def domain_name(self) -> builtins.str:
        '''The unique name of the domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-domainname
        '''
        result = self._values.get("domain_name")
        assert result is not None, "Required property 'domain_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def allow_profile_creation(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether a profile should be created when data is received if one doesn’t exist for an object of this type.

        The default is ``FALSE`` . If the AllowProfileCreation flag is set to ``FALSE`` , then the service tries to fetch a standard profile and associate this object with the profile. If it is set to ``TRUE`` , and if no match is found, then the service creates a new standard profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-allowprofilecreation
        '''
        result = self._values.get("allow_profile_creation")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the profile object type mapping.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def encryption_key(self) -> typing.Optional[builtins.str]:
        '''The customer-provided key to encrypt the profile object that will be created in this profile object type mapping.

        If not specified the system will use the encryption key of the domain.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-encryptionkey
        '''
        result = self._values.get("encryption_key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def expiration_days(self) -> typing.Optional[jsii.Number]:
        '''The number of days until the data of this type expires.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-expirationdays
        '''
        result = self._values.get("expiration_days")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def fields(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnObjectType.FieldMapProperty, _IResolvable_da3f097b]]]]:
        '''A list of field definitions for the object type mapping.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-fields
        '''
        result = self._values.get("fields")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnObjectType.FieldMapProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def keys(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnObjectType.KeyMapProperty, _IResolvable_da3f097b]]]]:
        '''A list of keys that can be used to map data to the profile or search for the profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-keys
        '''
        result = self._values.get("keys")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnObjectType.KeyMapProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def object_type_name(self) -> typing.Optional[builtins.str]:
        '''The name of the profile object type.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-objecttypename
        '''
        result = self._values.get("object_type_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags used to organize, track, or control access for this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def template_id(self) -> typing.Optional[builtins.str]:
        '''A unique identifier for the template mapping.

        This can be used instead of specifying the Keys and Fields properties directly.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-customerprofiles-objecttype.html#cfn-customerprofiles-objecttype-templateid
        '''
        result = self._values.get("template_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnObjectTypeProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnDomain",
    "CfnDomainProps",
    "CfnIntegration",
    "CfnIntegrationProps",
    "CfnObjectType",
    "CfnObjectTypeProps",
]

publication.publish()
