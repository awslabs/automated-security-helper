'''
# AWS::QLDB Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_qldb as qldb
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-qldb-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::QLDB](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_QLDB.html).

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
class CfnLedger(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_qldb.CfnLedger",
):
    '''A CloudFormation ``AWS::QLDB::Ledger``.

    The ``AWS::QLDB::Ledger`` resource specifies a new Amazon Quantum Ledger Database (Amazon QLDB) ledger in your AWS account . Amazon QLDB is a fully managed ledger database that provides a transparent, immutable, and cryptographically verifiable transaction log owned by a central trusted authority. You can use QLDB to track all application data changes, and maintain a complete and verifiable history of changes over time.

    For more information, see `CreateLedger <https://docs.aws.amazon.com/qldb/latest/developerguide/API_CreateLedger.html>`_ in the *Amazon QLDB API Reference* .

    :cloudformationResource: AWS::QLDB::Ledger
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_qldb as qldb
        
        cfn_ledger = qldb.CfnLedger(self, "MyCfnLedger",
            permissions_mode="permissionsMode",
        
            # the properties below are optional
            deletion_protection=False,
            kms_key="kmsKey",
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
        permissions_mode: builtins.str,
        deletion_protection: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        kms_key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::QLDB::Ledger``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param permissions_mode: The permissions mode to assign to the ledger that you want to create. This parameter can have one of the following values: - ``ALLOW_ALL`` : A legacy permissions mode that enables access control with API-level granularity for ledgers. This mode allows users who have the ``SendCommand`` API permission for this ledger to run all PartiQL commands (hence, ``ALLOW_ALL`` ) on any tables in the specified ledger. This mode disregards any table-level or command-level IAM permissions policies that you create for the ledger. - ``STANDARD`` : ( *Recommended* ) A permissions mode that enables access control with finer granularity for ledgers, tables, and PartiQL commands. By default, this mode denies all user requests to run any PartiQL commands on any tables in this ledger. To allow PartiQL commands to run, you must create IAM permissions policies for specific table resources and PartiQL actions, in addition to the ``SendCommand`` API permission for the ledger. For information, see `Getting started with the standard permissions mode <https://docs.aws.amazon.com/qldb/latest/developerguide/getting-started-standard-mode.html>`_ in the *Amazon QLDB Developer Guide* . .. epigraph:: We strongly recommend using the ``STANDARD`` permissions mode to maximize the security of your ledger data.
        :param deletion_protection: The flag that prevents a ledger from being deleted by any user. If not provided on ledger creation, this feature is enabled ( ``true`` ) by default. If deletion protection is enabled, you must first disable it before you can delete the ledger. You can disable it by calling the ``UpdateLedger`` operation to set the flag to ``false`` .
        :param kms_key: The key in AWS Key Management Service ( AWS KMS ) to use for encryption of data at rest in the ledger. For more information, see `Encryption at rest <https://docs.aws.amazon.com/qldb/latest/developerguide/encryption-at-rest.html>`_ in the *Amazon QLDB Developer Guide* . Use one of the following options to specify this parameter: - ``AWS_OWNED_KMS_KEY`` : Use an AWS KMS key that is owned and managed by AWS on your behalf. - *Undefined* : By default, use an AWS owned KMS key. - *A valid symmetric customer managed KMS key* : Use the specified KMS key in your account that you create, own, and manage. Amazon QLDB does not support asymmetric keys. For more information, see `Using symmetric and asymmetric keys <https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html>`_ in the *AWS Key Management Service Developer Guide* . To specify a customer managed KMS key, you can use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. When using an alias name, prefix it with ``"alias/"`` . To specify a key in a different AWS account , you must use the key ARN or alias ARN. For example: - Key ID: ``1234abcd-12ab-34cd-56ef-1234567890ab`` - Key ARN: ``arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`` - Alias name: ``alias/ExampleAlias`` - Alias ARN: ``arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias`` For more information, see `Key identifiers (KeyId) <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id>`_ in the *AWS Key Management Service Developer Guide* .
        :param name: The name of the ledger that you want to create. The name must be unique among all of the ledgers in your AWS account in the current Region. Naming constraints for ledger names are defined in `Quotas in Amazon QLDB <https://docs.aws.amazon.com/qldb/latest/developerguide/limits.html#limits.naming>`_ in the *Amazon QLDB Developer Guide* .
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnLedgerProps(
            permissions_mode=permissions_mode,
            deletion_protection=deletion_protection,
            kms_key=kms_key,
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
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissionsMode")
    def permissions_mode(self) -> builtins.str:
        '''The permissions mode to assign to the ledger that you want to create.

        This parameter can have one of the following values:

        - ``ALLOW_ALL`` : A legacy permissions mode that enables access control with API-level granularity for ledgers.

        This mode allows users who have the ``SendCommand`` API permission for this ledger to run all PartiQL commands (hence, ``ALLOW_ALL`` ) on any tables in the specified ledger. This mode disregards any table-level or command-level IAM permissions policies that you create for the ledger.

        - ``STANDARD`` : ( *Recommended* ) A permissions mode that enables access control with finer granularity for ledgers, tables, and PartiQL commands.

        By default, this mode denies all user requests to run any PartiQL commands on any tables in this ledger. To allow PartiQL commands to run, you must create IAM permissions policies for specific table resources and PartiQL actions, in addition to the ``SendCommand`` API permission for the ledger. For information, see `Getting started with the standard permissions mode <https://docs.aws.amazon.com/qldb/latest/developerguide/getting-started-standard-mode.html>`_ in the *Amazon QLDB Developer Guide* .
        .. epigraph::

           We strongly recommend using the ``STANDARD`` permissions mode to maximize the security of your ledger data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-permissionsmode
        '''
        return typing.cast(builtins.str, jsii.get(self, "permissionsMode"))

    @permissions_mode.setter
    def permissions_mode(self, value: builtins.str) -> None:
        jsii.set(self, "permissionsMode", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="deletionProtection")
    def deletion_protection(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''The flag that prevents a ledger from being deleted by any user.

        If not provided on ledger creation, this feature is enabled ( ``true`` ) by default.

        If deletion protection is enabled, you must first disable it before you can delete the ledger. You can disable it by calling the ``UpdateLedger`` operation to set the flag to ``false`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-deletionprotection
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "deletionProtection"))

    @deletion_protection.setter
    def deletion_protection(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "deletionProtection", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kmsKey")
    def kms_key(self) -> typing.Optional[builtins.str]:
        '''The key in AWS Key Management Service ( AWS KMS ) to use for encryption of data at rest in the ledger.

        For more information, see `Encryption at rest <https://docs.aws.amazon.com/qldb/latest/developerguide/encryption-at-rest.html>`_ in the *Amazon QLDB Developer Guide* .

        Use one of the following options to specify this parameter:

        - ``AWS_OWNED_KMS_KEY`` : Use an AWS KMS key that is owned and managed by AWS on your behalf.
        - *Undefined* : By default, use an AWS owned KMS key.
        - *A valid symmetric customer managed KMS key* : Use the specified KMS key in your account that you create, own, and manage.

        Amazon QLDB does not support asymmetric keys. For more information, see `Using symmetric and asymmetric keys <https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html>`_ in the *AWS Key Management Service Developer Guide* .

        To specify a customer managed KMS key, you can use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. When using an alias name, prefix it with ``"alias/"`` . To specify a key in a different AWS account , you must use the key ARN or alias ARN.

        For example:

        - Key ID: ``1234abcd-12ab-34cd-56ef-1234567890ab``
        - Key ARN: ``arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab``
        - Alias name: ``alias/ExampleAlias``
        - Alias ARN: ``arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias``

        For more information, see `Key identifiers (KeyId) <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id>`_ in the *AWS Key Management Service Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-kmskey
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kmsKey"))

    @kms_key.setter
    def kms_key(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kmsKey", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the ledger that you want to create.

        The name must be unique among all of the ledgers in your AWS account in the current Region.

        Naming constraints for ledger names are defined in `Quotas in Amazon QLDB <https://docs.aws.amazon.com/qldb/latest/developerguide/limits.html#limits.naming>`_ in the *Amazon QLDB Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_qldb.CfnLedgerProps",
    jsii_struct_bases=[],
    name_mapping={
        "permissions_mode": "permissionsMode",
        "deletion_protection": "deletionProtection",
        "kms_key": "kmsKey",
        "name": "name",
        "tags": "tags",
    },
)
class CfnLedgerProps:
    def __init__(
        self,
        *,
        permissions_mode: builtins.str,
        deletion_protection: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        kms_key: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnLedger``.

        :param permissions_mode: The permissions mode to assign to the ledger that you want to create. This parameter can have one of the following values: - ``ALLOW_ALL`` : A legacy permissions mode that enables access control with API-level granularity for ledgers. This mode allows users who have the ``SendCommand`` API permission for this ledger to run all PartiQL commands (hence, ``ALLOW_ALL`` ) on any tables in the specified ledger. This mode disregards any table-level or command-level IAM permissions policies that you create for the ledger. - ``STANDARD`` : ( *Recommended* ) A permissions mode that enables access control with finer granularity for ledgers, tables, and PartiQL commands. By default, this mode denies all user requests to run any PartiQL commands on any tables in this ledger. To allow PartiQL commands to run, you must create IAM permissions policies for specific table resources and PartiQL actions, in addition to the ``SendCommand`` API permission for the ledger. For information, see `Getting started with the standard permissions mode <https://docs.aws.amazon.com/qldb/latest/developerguide/getting-started-standard-mode.html>`_ in the *Amazon QLDB Developer Guide* . .. epigraph:: We strongly recommend using the ``STANDARD`` permissions mode to maximize the security of your ledger data.
        :param deletion_protection: The flag that prevents a ledger from being deleted by any user. If not provided on ledger creation, this feature is enabled ( ``true`` ) by default. If deletion protection is enabled, you must first disable it before you can delete the ledger. You can disable it by calling the ``UpdateLedger`` operation to set the flag to ``false`` .
        :param kms_key: The key in AWS Key Management Service ( AWS KMS ) to use for encryption of data at rest in the ledger. For more information, see `Encryption at rest <https://docs.aws.amazon.com/qldb/latest/developerguide/encryption-at-rest.html>`_ in the *Amazon QLDB Developer Guide* . Use one of the following options to specify this parameter: - ``AWS_OWNED_KMS_KEY`` : Use an AWS KMS key that is owned and managed by AWS on your behalf. - *Undefined* : By default, use an AWS owned KMS key. - *A valid symmetric customer managed KMS key* : Use the specified KMS key in your account that you create, own, and manage. Amazon QLDB does not support asymmetric keys. For more information, see `Using symmetric and asymmetric keys <https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html>`_ in the *AWS Key Management Service Developer Guide* . To specify a customer managed KMS key, you can use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. When using an alias name, prefix it with ``"alias/"`` . To specify a key in a different AWS account , you must use the key ARN or alias ARN. For example: - Key ID: ``1234abcd-12ab-34cd-56ef-1234567890ab`` - Key ARN: ``arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab`` - Alias name: ``alias/ExampleAlias`` - Alias ARN: ``arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias`` For more information, see `Key identifiers (KeyId) <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id>`_ in the *AWS Key Management Service Developer Guide* .
        :param name: The name of the ledger that you want to create. The name must be unique among all of the ledgers in your AWS account in the current Region. Naming constraints for ledger names are defined in `Quotas in Amazon QLDB <https://docs.aws.amazon.com/qldb/latest/developerguide/limits.html#limits.naming>`_ in the *Amazon QLDB Developer Guide* .
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_qldb as qldb
            
            cfn_ledger_props = qldb.CfnLedgerProps(
                permissions_mode="permissionsMode",
            
                # the properties below are optional
                deletion_protection=False,
                kms_key="kmsKey",
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "permissions_mode": permissions_mode,
        }
        if deletion_protection is not None:
            self._values["deletion_protection"] = deletion_protection
        if kms_key is not None:
            self._values["kms_key"] = kms_key
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def permissions_mode(self) -> builtins.str:
        '''The permissions mode to assign to the ledger that you want to create.

        This parameter can have one of the following values:

        - ``ALLOW_ALL`` : A legacy permissions mode that enables access control with API-level granularity for ledgers.

        This mode allows users who have the ``SendCommand`` API permission for this ledger to run all PartiQL commands (hence, ``ALLOW_ALL`` ) on any tables in the specified ledger. This mode disregards any table-level or command-level IAM permissions policies that you create for the ledger.

        - ``STANDARD`` : ( *Recommended* ) A permissions mode that enables access control with finer granularity for ledgers, tables, and PartiQL commands.

        By default, this mode denies all user requests to run any PartiQL commands on any tables in this ledger. To allow PartiQL commands to run, you must create IAM permissions policies for specific table resources and PartiQL actions, in addition to the ``SendCommand`` API permission for the ledger. For information, see `Getting started with the standard permissions mode <https://docs.aws.amazon.com/qldb/latest/developerguide/getting-started-standard-mode.html>`_ in the *Amazon QLDB Developer Guide* .
        .. epigraph::

           We strongly recommend using the ``STANDARD`` permissions mode to maximize the security of your ledger data.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-permissionsmode
        '''
        result = self._values.get("permissions_mode")
        assert result is not None, "Required property 'permissions_mode' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def deletion_protection(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''The flag that prevents a ledger from being deleted by any user.

        If not provided on ledger creation, this feature is enabled ( ``true`` ) by default.

        If deletion protection is enabled, you must first disable it before you can delete the ledger. You can disable it by calling the ``UpdateLedger`` operation to set the flag to ``false`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-deletionprotection
        '''
        result = self._values.get("deletion_protection")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def kms_key(self) -> typing.Optional[builtins.str]:
        '''The key in AWS Key Management Service ( AWS KMS ) to use for encryption of data at rest in the ledger.

        For more information, see `Encryption at rest <https://docs.aws.amazon.com/qldb/latest/developerguide/encryption-at-rest.html>`_ in the *Amazon QLDB Developer Guide* .

        Use one of the following options to specify this parameter:

        - ``AWS_OWNED_KMS_KEY`` : Use an AWS KMS key that is owned and managed by AWS on your behalf.
        - *Undefined* : By default, use an AWS owned KMS key.
        - *A valid symmetric customer managed KMS key* : Use the specified KMS key in your account that you create, own, and manage.

        Amazon QLDB does not support asymmetric keys. For more information, see `Using symmetric and asymmetric keys <https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html>`_ in the *AWS Key Management Service Developer Guide* .

        To specify a customer managed KMS key, you can use its key ID, Amazon Resource Name (ARN), alias name, or alias ARN. When using an alias name, prefix it with ``"alias/"`` . To specify a key in a different AWS account , you must use the key ARN or alias ARN.

        For example:

        - Key ID: ``1234abcd-12ab-34cd-56ef-1234567890ab``
        - Key ARN: ``arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab``
        - Alias name: ``alias/ExampleAlias``
        - Alias ARN: ``arn:aws:kms:us-east-2:111122223333:alias/ExampleAlias``

        For more information, see `Key identifiers (KeyId) <https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id>`_ in the *AWS Key Management Service Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-kmskey
        '''
        result = self._values.get("kms_key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the ledger that you want to create.

        The name must be unique among all of the ledgers in your AWS account in the current Region.

        Naming constraints for ledger names are defined in `Quotas in Amazon QLDB <https://docs.aws.amazon.com/qldb/latest/developerguide/limits.html#limits.naming>`_ in the *Amazon QLDB Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-ledger.html#cfn-qldb-ledger-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLedgerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnStream(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_qldb.CfnStream",
):
    '''A CloudFormation ``AWS::QLDB::Stream``.

    The ``AWS::QLDB::Stream`` resource specifies a journal stream for a given Amazon Quantum Ledger Database (Amazon QLDB) ledger. The stream captures every document revision that is committed to the ledger's journal and delivers the data to a specified Amazon Kinesis Data Streams resource.

    For more information, see `StreamJournalToKinesis <https://docs.aws.amazon.com/qldb/latest/developerguide/API_StreamJournalToKinesis.html>`_ in the *Amazon QLDB API Reference* .

    :cloudformationResource: AWS::QLDB::Stream
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_qldb as qldb
        
        cfn_stream = qldb.CfnStream(self, "MyCfnStream",
            inclusive_start_time="inclusiveStartTime",
            kinesis_configuration=qldb.CfnStream.KinesisConfigurationProperty(
                aggregation_enabled=False,
                stream_arn="streamArn"
            ),
            ledger_name="ledgerName",
            role_arn="roleArn",
            stream_name="streamName",
        
            # the properties below are optional
            exclusive_end_time="exclusiveEndTime",
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
        inclusive_start_time: builtins.str,
        kinesis_configuration: typing.Union["CfnStream.KinesisConfigurationProperty", _IResolvable_da3f097b],
        ledger_name: builtins.str,
        role_arn: builtins.str,
        stream_name: builtins.str,
        exclusive_end_time: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::QLDB::Stream``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param inclusive_start_time: The inclusive start date and time from which to start streaming journal data. This parameter must be in ``ISO 8601`` date and time format and in Universal Coordinated Time (UTC). For example: ``2019-06-13T21:36:34Z`` . The ``InclusiveStartTime`` cannot be in the future and must be before ``ExclusiveEndTime`` . If you provide an ``InclusiveStartTime`` that is before the ledger's ``CreationDateTime`` , QLDB effectively defaults it to the ledger's ``CreationDateTime`` .
        :param kinesis_configuration: The configuration settings of the Kinesis Data Streams destination for your stream request.
        :param ledger_name: The name of the ledger.
        :param role_arn: The Amazon Resource Name (ARN) of the IAM role that grants QLDB permissions for a journal stream to write data records to a Kinesis Data Streams resource. To pass a role to QLDB when requesting a journal stream, you must have permissions to perform the ``iam:PassRole`` action on the IAM role resource. This is required for all journal stream requests.
        :param stream_name: The name that you want to assign to the QLDB journal stream. User-defined names can help identify and indicate the purpose of a stream. Your stream name must be unique among other *active* streams for a given ledger. Stream names have the same naming constraints as ledger names, as defined in `Quotas in Amazon QLDB <https://docs.aws.amazon.com/qldb/latest/developerguide/limits.html#limits.naming>`_ in the *Amazon QLDB Developer Guide* .
        :param exclusive_end_time: The exclusive date and time that specifies when the stream ends. If you don't define this parameter, the stream runs indefinitely until you cancel it. The ``ExclusiveEndTime`` must be in ``ISO 8601`` date and time format and in Universal Coordinated Time (UTC). For example: ``2019-06-13T21:36:34Z`` .
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .
        '''
        props = CfnStreamProps(
            inclusive_start_time=inclusive_start_time,
            kinesis_configuration=kinesis_configuration,
            ledger_name=ledger_name,
            role_arn=role_arn,
            stream_name=stream_name,
            exclusive_end_time=exclusive_end_time,
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
        '''The Amazon Resource Name (ARN) of the QLDB journal stream.

        For example: ``arn:aws:qldb:us-east-1:123456789012:stream/exampleLedger/IiPT4brpZCqCq3f4MTHbYy`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''The unique ID that QLDB assigns to each QLDB journal stream.

        For example: ``IiPT4brpZCqCq3f4MTHbYy`` .

        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="inclusiveStartTime")
    def inclusive_start_time(self) -> builtins.str:
        '''The inclusive start date and time from which to start streaming journal data.

        This parameter must be in ``ISO 8601`` date and time format and in Universal Coordinated Time (UTC). For example: ``2019-06-13T21:36:34Z`` .

        The ``InclusiveStartTime`` cannot be in the future and must be before ``ExclusiveEndTime`` .

        If you provide an ``InclusiveStartTime`` that is before the ledger's ``CreationDateTime`` , QLDB effectively defaults it to the ledger's ``CreationDateTime`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-inclusivestarttime
        '''
        return typing.cast(builtins.str, jsii.get(self, "inclusiveStartTime"))

    @inclusive_start_time.setter
    def inclusive_start_time(self, value: builtins.str) -> None:
        jsii.set(self, "inclusiveStartTime", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kinesisConfiguration")
    def kinesis_configuration(
        self,
    ) -> typing.Union["CfnStream.KinesisConfigurationProperty", _IResolvable_da3f097b]:
        '''The configuration settings of the Kinesis Data Streams destination for your stream request.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-kinesisconfiguration
        '''
        return typing.cast(typing.Union["CfnStream.KinesisConfigurationProperty", _IResolvable_da3f097b], jsii.get(self, "kinesisConfiguration"))

    @kinesis_configuration.setter
    def kinesis_configuration(
        self,
        value: typing.Union["CfnStream.KinesisConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "kinesisConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ledgerName")
    def ledger_name(self) -> builtins.str:
        '''The name of the ledger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-ledgername
        '''
        return typing.cast(builtins.str, jsii.get(self, "ledgerName"))

    @ledger_name.setter
    def ledger_name(self, value: builtins.str) -> None:
        jsii.set(self, "ledgerName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role that grants QLDB permissions for a journal stream to write data records to a Kinesis Data Streams resource.

        To pass a role to QLDB when requesting a journal stream, you must have permissions to perform the ``iam:PassRole`` action on the IAM role resource. This is required for all journal stream requests.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-rolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "roleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="streamName")
    def stream_name(self) -> builtins.str:
        '''The name that you want to assign to the QLDB journal stream.

        User-defined names can help identify and indicate the purpose of a stream.

        Your stream name must be unique among other *active* streams for a given ledger. Stream names have the same naming constraints as ledger names, as defined in `Quotas in Amazon QLDB <https://docs.aws.amazon.com/qldb/latest/developerguide/limits.html#limits.naming>`_ in the *Amazon QLDB Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-streamname
        '''
        return typing.cast(builtins.str, jsii.get(self, "streamName"))

    @stream_name.setter
    def stream_name(self, value: builtins.str) -> None:
        jsii.set(self, "streamName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="exclusiveEndTime")
    def exclusive_end_time(self) -> typing.Optional[builtins.str]:
        '''The exclusive date and time that specifies when the stream ends.

        If you don't define this parameter, the stream runs indefinitely until you cancel it.

        The ``ExclusiveEndTime`` must be in ``ISO 8601`` date and time format and in Universal Coordinated Time (UTC). For example: ``2019-06-13T21:36:34Z`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-exclusiveendtime
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "exclusiveEndTime"))

    @exclusive_end_time.setter
    def exclusive_end_time(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "exclusiveEndTime", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_qldb.CfnStream.KinesisConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "aggregation_enabled": "aggregationEnabled",
            "stream_arn": "streamArn",
        },
    )
    class KinesisConfigurationProperty:
        def __init__(
            self,
            *,
            aggregation_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            stream_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The configuration settings of the Amazon Kinesis Data Streams destination for an Amazon QLDB journal stream.

            :param aggregation_enabled: Enables QLDB to publish multiple data records in a single Kinesis Data Streams record, increasing the number of records sent per API call. *This option is enabled by default.* Record aggregation has important implications for processing records and requires de-aggregation in your stream consumer. To learn more, see `KPL Key Concepts <https://docs.aws.amazon.com/streams/latest/dev/kinesis-kpl-concepts.html>`_ and `Consumer De-aggregation <https://docs.aws.amazon.com/streams/latest/dev/kinesis-kpl-consumer-deaggregation.html>`_ in the *Amazon Kinesis Data Streams Developer Guide* .
            :param stream_arn: The Amazon Resource Name (ARN) of the Kinesis Data Streams resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-qldb-stream-kinesisconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_qldb as qldb
                
                kinesis_configuration_property = qldb.CfnStream.KinesisConfigurationProperty(
                    aggregation_enabled=False,
                    stream_arn="streamArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if aggregation_enabled is not None:
                self._values["aggregation_enabled"] = aggregation_enabled
            if stream_arn is not None:
                self._values["stream_arn"] = stream_arn

        @builtins.property
        def aggregation_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Enables QLDB to publish multiple data records in a single Kinesis Data Streams record, increasing the number of records sent per API call.

            *This option is enabled by default.* Record aggregation has important implications for processing records and requires de-aggregation in your stream consumer. To learn more, see `KPL Key Concepts <https://docs.aws.amazon.com/streams/latest/dev/kinesis-kpl-concepts.html>`_ and `Consumer De-aggregation <https://docs.aws.amazon.com/streams/latest/dev/kinesis-kpl-consumer-deaggregation.html>`_ in the *Amazon Kinesis Data Streams Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-qldb-stream-kinesisconfiguration.html#cfn-qldb-stream-kinesisconfiguration-aggregationenabled
            '''
            result = self._values.get("aggregation_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def stream_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the Kinesis Data Streams resource.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-qldb-stream-kinesisconfiguration.html#cfn-qldb-stream-kinesisconfiguration-streamarn
            '''
            result = self._values.get("stream_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KinesisConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_qldb.CfnStreamProps",
    jsii_struct_bases=[],
    name_mapping={
        "inclusive_start_time": "inclusiveStartTime",
        "kinesis_configuration": "kinesisConfiguration",
        "ledger_name": "ledgerName",
        "role_arn": "roleArn",
        "stream_name": "streamName",
        "exclusive_end_time": "exclusiveEndTime",
        "tags": "tags",
    },
)
class CfnStreamProps:
    def __init__(
        self,
        *,
        inclusive_start_time: builtins.str,
        kinesis_configuration: typing.Union[CfnStream.KinesisConfigurationProperty, _IResolvable_da3f097b],
        ledger_name: builtins.str,
        role_arn: builtins.str,
        stream_name: builtins.str,
        exclusive_end_time: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnStream``.

        :param inclusive_start_time: The inclusive start date and time from which to start streaming journal data. This parameter must be in ``ISO 8601`` date and time format and in Universal Coordinated Time (UTC). For example: ``2019-06-13T21:36:34Z`` . The ``InclusiveStartTime`` cannot be in the future and must be before ``ExclusiveEndTime`` . If you provide an ``InclusiveStartTime`` that is before the ledger's ``CreationDateTime`` , QLDB effectively defaults it to the ledger's ``CreationDateTime`` .
        :param kinesis_configuration: The configuration settings of the Kinesis Data Streams destination for your stream request.
        :param ledger_name: The name of the ledger.
        :param role_arn: The Amazon Resource Name (ARN) of the IAM role that grants QLDB permissions for a journal stream to write data records to a Kinesis Data Streams resource. To pass a role to QLDB when requesting a journal stream, you must have permissions to perform the ``iam:PassRole`` action on the IAM role resource. This is required for all journal stream requests.
        :param stream_name: The name that you want to assign to the QLDB journal stream. User-defined names can help identify and indicate the purpose of a stream. Your stream name must be unique among other *active* streams for a given ledger. Stream names have the same naming constraints as ledger names, as defined in `Quotas in Amazon QLDB <https://docs.aws.amazon.com/qldb/latest/developerguide/limits.html#limits.naming>`_ in the *Amazon QLDB Developer Guide* .
        :param exclusive_end_time: The exclusive date and time that specifies when the stream ends. If you don't define this parameter, the stream runs indefinitely until you cancel it. The ``ExclusiveEndTime`` must be in ``ISO 8601`` date and time format and in Universal Coordinated Time (UTC). For example: ``2019-06-13T21:36:34Z`` .
        :param tags: An array of key-value pairs to apply to this resource. For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_qldb as qldb
            
            cfn_stream_props = qldb.CfnStreamProps(
                inclusive_start_time="inclusiveStartTime",
                kinesis_configuration=qldb.CfnStream.KinesisConfigurationProperty(
                    aggregation_enabled=False,
                    stream_arn="streamArn"
                ),
                ledger_name="ledgerName",
                role_arn="roleArn",
                stream_name="streamName",
            
                # the properties below are optional
                exclusive_end_time="exclusiveEndTime",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "inclusive_start_time": inclusive_start_time,
            "kinesis_configuration": kinesis_configuration,
            "ledger_name": ledger_name,
            "role_arn": role_arn,
            "stream_name": stream_name,
        }
        if exclusive_end_time is not None:
            self._values["exclusive_end_time"] = exclusive_end_time
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def inclusive_start_time(self) -> builtins.str:
        '''The inclusive start date and time from which to start streaming journal data.

        This parameter must be in ``ISO 8601`` date and time format and in Universal Coordinated Time (UTC). For example: ``2019-06-13T21:36:34Z`` .

        The ``InclusiveStartTime`` cannot be in the future and must be before ``ExclusiveEndTime`` .

        If you provide an ``InclusiveStartTime`` that is before the ledger's ``CreationDateTime`` , QLDB effectively defaults it to the ledger's ``CreationDateTime`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-inclusivestarttime
        '''
        result = self._values.get("inclusive_start_time")
        assert result is not None, "Required property 'inclusive_start_time' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def kinesis_configuration(
        self,
    ) -> typing.Union[CfnStream.KinesisConfigurationProperty, _IResolvable_da3f097b]:
        '''The configuration settings of the Kinesis Data Streams destination for your stream request.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-kinesisconfiguration
        '''
        result = self._values.get("kinesis_configuration")
        assert result is not None, "Required property 'kinesis_configuration' is missing"
        return typing.cast(typing.Union[CfnStream.KinesisConfigurationProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def ledger_name(self) -> builtins.str:
        '''The name of the ledger.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-ledgername
        '''
        result = self._values.get("ledger_name")
        assert result is not None, "Required property 'ledger_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role that grants QLDB permissions for a journal stream to write data records to a Kinesis Data Streams resource.

        To pass a role to QLDB when requesting a journal stream, you must have permissions to perform the ``iam:PassRole`` action on the IAM role resource. This is required for all journal stream requests.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-rolearn
        '''
        result = self._values.get("role_arn")
        assert result is not None, "Required property 'role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def stream_name(self) -> builtins.str:
        '''The name that you want to assign to the QLDB journal stream.

        User-defined names can help identify and indicate the purpose of a stream.

        Your stream name must be unique among other *active* streams for a given ledger. Stream names have the same naming constraints as ledger names, as defined in `Quotas in Amazon QLDB <https://docs.aws.amazon.com/qldb/latest/developerguide/limits.html#limits.naming>`_ in the *Amazon QLDB Developer Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-streamname
        '''
        result = self._values.get("stream_name")
        assert result is not None, "Required property 'stream_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def exclusive_end_time(self) -> typing.Optional[builtins.str]:
        '''The exclusive date and time that specifies when the stream ends.

        If you don't define this parameter, the stream runs indefinitely until you cancel it.

        The ``ExclusiveEndTime`` must be in ``ISO 8601`` date and time format and in Universal Coordinated Time (UTC). For example: ``2019-06-13T21:36:34Z`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-exclusiveendtime
        '''
        result = self._values.get("exclusive_end_time")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''An array of key-value pairs to apply to this resource.

        For more information, see `Tag <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-resource-tags.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-qldb-stream.html#cfn-qldb-stream-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnStreamProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnLedger",
    "CfnLedgerProps",
    "CfnStream",
    "CfnStreamProps",
]

publication.publish()
