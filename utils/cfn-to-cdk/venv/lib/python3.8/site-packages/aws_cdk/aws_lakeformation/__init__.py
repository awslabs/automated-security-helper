'''
# AWS::LakeFormation Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_lakeformation as lakeformation
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-lakeformation-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::LakeFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_LakeFormation.html).

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
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnDataLakeSettings(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_lakeformation.CfnDataLakeSettings",
):
    '''A CloudFormation ``AWS::LakeFormation::DataLakeSettings``.

    The ``AWS::LakeFormation::DataLakeSettings`` resource is an AWS Lake Formation resource type that manages the data lake settings for your account. Note that the CloudFormation template only supports updating the ``Admins`` list. It does not support updating the `CreateDatabaseDefaultPermissions <https://docs.aws.amazon.com/lake-formation/latest/dg/aws-lake-formation-api-aws-lake-formation-api-settings.html#aws-lake-formation-api-aws-lake-formation-api-settings-DataLakeSettings>`_ or `CreateTableDefaultPermissions <https://docs.aws.amazon.com/lake-formation/latest/dg/aws-lake-formation-api-aws-lake-formation-api-settings.html#aws-lake-formation-api-aws-lake-formation-api-settings-DataLakeSettings>`_ . Those permissions can only be edited in the DataLakeSettings resource via the API.

    :cloudformationResource: AWS::LakeFormation::DataLakeSettings
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-datalakesettings.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_lakeformation as lakeformation
        
        cfn_data_lake_settings = lakeformation.CfnDataLakeSettings(self, "MyCfnDataLakeSettings",
            admins=[lakeformation.CfnDataLakeSettings.DataLakePrincipalProperty(
                data_lake_principal_identifier="dataLakePrincipalIdentifier"
            )],
            trusted_resource_owners=["trustedResourceOwners"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        admins: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnDataLakeSettings.DataLakePrincipalProperty", _IResolvable_da3f097b]]]] = None,
        trusted_resource_owners: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::LakeFormation::DataLakeSettings``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param admins: A list of AWS Lake Formation principals.
        :param trusted_resource_owners: ``AWS::LakeFormation::DataLakeSettings.TrustedResourceOwners``.
        '''
        props = CfnDataLakeSettingsProps(
            admins=admins, trusted_resource_owners=trusted_resource_owners
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
    @jsii.member(jsii_name="admins")
    def admins(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataLakeSettings.DataLakePrincipalProperty", _IResolvable_da3f097b]]]]:
        '''A list of AWS Lake Formation principals.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-datalakesettings.html#cfn-lakeformation-datalakesettings-admins
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataLakeSettings.DataLakePrincipalProperty", _IResolvable_da3f097b]]]], jsii.get(self, "admins"))

    @admins.setter
    def admins(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnDataLakeSettings.DataLakePrincipalProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "admins", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="trustedResourceOwners")
    def trusted_resource_owners(self) -> typing.Optional[typing.List[builtins.str]]:
        '''``AWS::LakeFormation::DataLakeSettings.TrustedResourceOwners``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-datalakesettings.html#cfn-lakeformation-datalakesettings-trustedresourceowners
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "trustedResourceOwners"))

    @trusted_resource_owners.setter
    def trusted_resource_owners(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "trustedResourceOwners", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lakeformation.CfnDataLakeSettings.DataLakePrincipalProperty",
        jsii_struct_bases=[],
        name_mapping={"data_lake_principal_identifier": "dataLakePrincipalIdentifier"},
    )
    class DataLakePrincipalProperty:
        def __init__(
            self,
            *,
            data_lake_principal_identifier: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The Lake Formation principal.

            :param data_lake_principal_identifier: An identifier for the Lake Formation principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-datalakesettings-datalakeprincipal.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lakeformation as lakeformation
                
                data_lake_principal_property = lakeformation.CfnDataLakeSettings.DataLakePrincipalProperty(
                    data_lake_principal_identifier="dataLakePrincipalIdentifier"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if data_lake_principal_identifier is not None:
                self._values["data_lake_principal_identifier"] = data_lake_principal_identifier

        @builtins.property
        def data_lake_principal_identifier(self) -> typing.Optional[builtins.str]:
            '''An identifier for the Lake Formation principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-datalakesettings-datalakeprincipal.html#cfn-lakeformation-datalakesettings-datalakeprincipal-datalakeprincipalidentifier
            '''
            result = self._values.get("data_lake_principal_identifier")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataLakePrincipalProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_lakeformation.CfnDataLakeSettingsProps",
    jsii_struct_bases=[],
    name_mapping={
        "admins": "admins",
        "trusted_resource_owners": "trustedResourceOwners",
    },
)
class CfnDataLakeSettingsProps:
    def __init__(
        self,
        *,
        admins: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnDataLakeSettings.DataLakePrincipalProperty, _IResolvable_da3f097b]]]] = None,
        trusted_resource_owners: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDataLakeSettings``.

        :param admins: A list of AWS Lake Formation principals.
        :param trusted_resource_owners: ``AWS::LakeFormation::DataLakeSettings.TrustedResourceOwners``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-datalakesettings.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_lakeformation as lakeformation
            
            cfn_data_lake_settings_props = lakeformation.CfnDataLakeSettingsProps(
                admins=[lakeformation.CfnDataLakeSettings.DataLakePrincipalProperty(
                    data_lake_principal_identifier="dataLakePrincipalIdentifier"
                )],
                trusted_resource_owners=["trustedResourceOwners"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if admins is not None:
            self._values["admins"] = admins
        if trusted_resource_owners is not None:
            self._values["trusted_resource_owners"] = trusted_resource_owners

    @builtins.property
    def admins(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataLakeSettings.DataLakePrincipalProperty, _IResolvable_da3f097b]]]]:
        '''A list of AWS Lake Formation principals.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-datalakesettings.html#cfn-lakeformation-datalakesettings-admins
        '''
        result = self._values.get("admins")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnDataLakeSettings.DataLakePrincipalProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def trusted_resource_owners(self) -> typing.Optional[typing.List[builtins.str]]:
        '''``AWS::LakeFormation::DataLakeSettings.TrustedResourceOwners``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-datalakesettings.html#cfn-lakeformation-datalakesettings-trustedresourceowners
        '''
        result = self._values.get("trusted_resource_owners")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDataLakeSettingsProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPermissions(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_lakeformation.CfnPermissions",
):
    '''A CloudFormation ``AWS::LakeFormation::Permissions``.

    The ``AWS::LakeFormation::Permissions`` resource represents the permissions that a principal has on an AWS Glue Data Catalog resource (such as AWS Glue database or AWS Glue tables). When you upload a permissions stack, the permissions are granted to the principal and when you remove the stack, the permissions are revoked from the principal. If you remove a stack, and the principal does not have the permissions referenced in the stack then AWS Lake Formation will throw an error because you can’t call revoke on non-existing permissions. To successfully remove the stack, you’ll need to regrant those permissions and then remove the stack.

    :cloudformationResource: AWS::LakeFormation::Permissions
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-permissions.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_lakeformation as lakeformation
        
        cfn_permissions = lakeformation.CfnPermissions(self, "MyCfnPermissions",
            data_lake_principal=lakeformation.CfnPermissions.DataLakePrincipalProperty(
                data_lake_principal_identifier="dataLakePrincipalIdentifier"
            ),
            resource=lakeformation.CfnPermissions.ResourceProperty(
                database_resource=lakeformation.CfnPermissions.DatabaseResourceProperty(
                    catalog_id="catalogId",
                    name="name"
                ),
                data_location_resource=lakeformation.CfnPermissions.DataLocationResourceProperty(
                    catalog_id="catalogId",
                    s3_resource="s3Resource"
                ),
                table_resource=lakeformation.CfnPermissions.TableResourceProperty(
                    catalog_id="catalogId",
                    database_name="databaseName",
                    name="name",
                    table_wildcard=lakeformation.CfnPermissions.TableWildcardProperty()
                ),
                table_with_columns_resource=lakeformation.CfnPermissions.TableWithColumnsResourceProperty(
                    catalog_id="catalogId",
                    column_names=["columnNames"],
                    column_wildcard=lakeformation.CfnPermissions.ColumnWildcardProperty(
                        excluded_column_names=["excludedColumnNames"]
                    ),
                    database_name="databaseName",
                    name="name"
                )
            ),
        
            # the properties below are optional
            permissions=["permissions"],
            permissions_with_grant_option=["permissionsWithGrantOption"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        data_lake_principal: typing.Union["CfnPermissions.DataLakePrincipalProperty", _IResolvable_da3f097b],
        resource: typing.Union["CfnPermissions.ResourceProperty", _IResolvable_da3f097b],
        permissions: typing.Optional[typing.Sequence[builtins.str]] = None,
        permissions_with_grant_option: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::LakeFormation::Permissions``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param data_lake_principal: The AWS Lake Formation principal.
        :param resource: A structure for the resource.
        :param permissions: The permissions granted or revoked.
        :param permissions_with_grant_option: Indicates whether to grant the ability to grant permissions (as a subset of permissions granted).
        '''
        props = CfnPermissionsProps(
            data_lake_principal=data_lake_principal,
            resource=resource,
            permissions=permissions,
            permissions_with_grant_option=permissions_with_grant_option,
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
    @jsii.member(jsii_name="dataLakePrincipal")
    def data_lake_principal(
        self,
    ) -> typing.Union["CfnPermissions.DataLakePrincipalProperty", _IResolvable_da3f097b]:
        '''The AWS Lake Formation principal.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-permissions.html#cfn-lakeformation-permissions-datalakeprincipal
        '''
        return typing.cast(typing.Union["CfnPermissions.DataLakePrincipalProperty", _IResolvable_da3f097b], jsii.get(self, "dataLakePrincipal"))

    @data_lake_principal.setter
    def data_lake_principal(
        self,
        value: typing.Union["CfnPermissions.DataLakePrincipalProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "dataLakePrincipal", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resource")
    def resource(
        self,
    ) -> typing.Union["CfnPermissions.ResourceProperty", _IResolvable_da3f097b]:
        '''A structure for the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-permissions.html#cfn-lakeformation-permissions-resource
        '''
        return typing.cast(typing.Union["CfnPermissions.ResourceProperty", _IResolvable_da3f097b], jsii.get(self, "resource"))

    @resource.setter
    def resource(
        self,
        value: typing.Union["CfnPermissions.ResourceProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "resource", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissions")
    def permissions(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The permissions granted or revoked.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-permissions.html#cfn-lakeformation-permissions-permissions
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "permissions"))

    @permissions.setter
    def permissions(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "permissions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="permissionsWithGrantOption")
    def permissions_with_grant_option(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''Indicates whether to grant the ability to grant permissions (as a subset of permissions granted).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-permissions.html#cfn-lakeformation-permissions-permissionswithgrantoption
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "permissionsWithGrantOption"))

    @permissions_with_grant_option.setter
    def permissions_with_grant_option(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "permissionsWithGrantOption", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lakeformation.CfnPermissions.ColumnWildcardProperty",
        jsii_struct_bases=[],
        name_mapping={"excluded_column_names": "excludedColumnNames"},
    )
    class ColumnWildcardProperty:
        def __init__(
            self,
            *,
            excluded_column_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''A wildcard object, consisting of an optional list of excluded column names or indexes.

            :param excluded_column_names: Excludes column names. Any column with this name will be excluded.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-columnwildcard.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lakeformation as lakeformation
                
                column_wildcard_property = lakeformation.CfnPermissions.ColumnWildcardProperty(
                    excluded_column_names=["excludedColumnNames"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if excluded_column_names is not None:
                self._values["excluded_column_names"] = excluded_column_names

        @builtins.property
        def excluded_column_names(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Excludes column names.

            Any column with this name will be excluded.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-columnwildcard.html#cfn-lakeformation-permissions-columnwildcard-excludedcolumnnames
            '''
            result = self._values.get("excluded_column_names")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ColumnWildcardProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lakeformation.CfnPermissions.DataLakePrincipalProperty",
        jsii_struct_bases=[],
        name_mapping={"data_lake_principal_identifier": "dataLakePrincipalIdentifier"},
    )
    class DataLakePrincipalProperty:
        def __init__(
            self,
            *,
            data_lake_principal_identifier: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The Lake Formation principal.

            :param data_lake_principal_identifier: An identifier for the Lake Formation principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-datalakeprincipal.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lakeformation as lakeformation
                
                data_lake_principal_property = lakeformation.CfnPermissions.DataLakePrincipalProperty(
                    data_lake_principal_identifier="dataLakePrincipalIdentifier"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if data_lake_principal_identifier is not None:
                self._values["data_lake_principal_identifier"] = data_lake_principal_identifier

        @builtins.property
        def data_lake_principal_identifier(self) -> typing.Optional[builtins.str]:
            '''An identifier for the Lake Formation principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-datalakeprincipal.html#cfn-lakeformation-permissions-datalakeprincipal-datalakeprincipalidentifier
            '''
            result = self._values.get("data_lake_principal_identifier")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataLakePrincipalProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lakeformation.CfnPermissions.DataLocationResourceProperty",
        jsii_struct_bases=[],
        name_mapping={"catalog_id": "catalogId", "s3_resource": "s3Resource"},
    )
    class DataLocationResourceProperty:
        def __init__(
            self,
            *,
            catalog_id: typing.Optional[builtins.str] = None,
            s3_resource: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure for a data location object where permissions are granted or revoked.

            :param catalog_id: ``CfnPermissions.DataLocationResourceProperty.CatalogId``.
            :param s3_resource: Currently not supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-datalocationresource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lakeformation as lakeformation
                
                data_location_resource_property = lakeformation.CfnPermissions.DataLocationResourceProperty(
                    catalog_id="catalogId",
                    s3_resource="s3Resource"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if catalog_id is not None:
                self._values["catalog_id"] = catalog_id
            if s3_resource is not None:
                self._values["s3_resource"] = s3_resource

        @builtins.property
        def catalog_id(self) -> typing.Optional[builtins.str]:
            '''``CfnPermissions.DataLocationResourceProperty.CatalogId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-datalocationresource.html#cfn-lakeformation-permissions-datalocationresource-catalogid
            '''
            result = self._values.get("catalog_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def s3_resource(self) -> typing.Optional[builtins.str]:
            '''Currently not supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-datalocationresource.html#cfn-lakeformation-permissions-datalocationresource-s3resource
            '''
            result = self._values.get("s3_resource")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DataLocationResourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lakeformation.CfnPermissions.DatabaseResourceProperty",
        jsii_struct_bases=[],
        name_mapping={"catalog_id": "catalogId", "name": "name"},
    )
    class DatabaseResourceProperty:
        def __init__(
            self,
            *,
            catalog_id: typing.Optional[builtins.str] = None,
            name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure for the database object.

            :param catalog_id: ``CfnPermissions.DatabaseResourceProperty.CatalogId``.
            :param name: The name of the database resource. Unique to the Data Catalog.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-databaseresource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lakeformation as lakeformation
                
                database_resource_property = lakeformation.CfnPermissions.DatabaseResourceProperty(
                    catalog_id="catalogId",
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if catalog_id is not None:
                self._values["catalog_id"] = catalog_id
            if name is not None:
                self._values["name"] = name

        @builtins.property
        def catalog_id(self) -> typing.Optional[builtins.str]:
            '''``CfnPermissions.DatabaseResourceProperty.CatalogId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-databaseresource.html#cfn-lakeformation-permissions-databaseresource-catalogid
            '''
            result = self._values.get("catalog_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the database resource.

            Unique to the Data Catalog.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-databaseresource.html#cfn-lakeformation-permissions-databaseresource-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DatabaseResourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lakeformation.CfnPermissions.ResourceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "database_resource": "databaseResource",
            "data_location_resource": "dataLocationResource",
            "table_resource": "tableResource",
            "table_with_columns_resource": "tableWithColumnsResource",
        },
    )
    class ResourceProperty:
        def __init__(
            self,
            *,
            database_resource: typing.Optional[typing.Union["CfnPermissions.DatabaseResourceProperty", _IResolvable_da3f097b]] = None,
            data_location_resource: typing.Optional[typing.Union["CfnPermissions.DataLocationResourceProperty", _IResolvable_da3f097b]] = None,
            table_resource: typing.Optional[typing.Union["CfnPermissions.TableResourceProperty", _IResolvable_da3f097b]] = None,
            table_with_columns_resource: typing.Optional[typing.Union["CfnPermissions.TableWithColumnsResourceProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A structure for the resource.

            :param database_resource: A structure for the database object.
            :param data_location_resource: A structure for a data location object where permissions are granted or revoked.
            :param table_resource: A structure for the table object. A table is a metadata definition that represents your data. You can Grant and Revoke table privileges to a principal.
            :param table_with_columns_resource: Currently not supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-resource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lakeformation as lakeformation
                
                resource_property = lakeformation.CfnPermissions.ResourceProperty(
                    database_resource=lakeformation.CfnPermissions.DatabaseResourceProperty(
                        catalog_id="catalogId",
                        name="name"
                    ),
                    data_location_resource=lakeformation.CfnPermissions.DataLocationResourceProperty(
                        catalog_id="catalogId",
                        s3_resource="s3Resource"
                    ),
                    table_resource=lakeformation.CfnPermissions.TableResourceProperty(
                        catalog_id="catalogId",
                        database_name="databaseName",
                        name="name",
                        table_wildcard=lakeformation.CfnPermissions.TableWildcardProperty()
                    ),
                    table_with_columns_resource=lakeformation.CfnPermissions.TableWithColumnsResourceProperty(
                        catalog_id="catalogId",
                        column_names=["columnNames"],
                        column_wildcard=lakeformation.CfnPermissions.ColumnWildcardProperty(
                            excluded_column_names=["excludedColumnNames"]
                        ),
                        database_name="databaseName",
                        name="name"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if database_resource is not None:
                self._values["database_resource"] = database_resource
            if data_location_resource is not None:
                self._values["data_location_resource"] = data_location_resource
            if table_resource is not None:
                self._values["table_resource"] = table_resource
            if table_with_columns_resource is not None:
                self._values["table_with_columns_resource"] = table_with_columns_resource

        @builtins.property
        def database_resource(
            self,
        ) -> typing.Optional[typing.Union["CfnPermissions.DatabaseResourceProperty", _IResolvable_da3f097b]]:
            '''A structure for the database object.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-resource.html#cfn-lakeformation-permissions-resource-databaseresource
            '''
            result = self._values.get("database_resource")
            return typing.cast(typing.Optional[typing.Union["CfnPermissions.DatabaseResourceProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def data_location_resource(
            self,
        ) -> typing.Optional[typing.Union["CfnPermissions.DataLocationResourceProperty", _IResolvable_da3f097b]]:
            '''A structure for a data location object where permissions are granted or revoked.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-resource.html#cfn-lakeformation-permissions-resource-datalocationresource
            '''
            result = self._values.get("data_location_resource")
            return typing.cast(typing.Optional[typing.Union["CfnPermissions.DataLocationResourceProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def table_resource(
            self,
        ) -> typing.Optional[typing.Union["CfnPermissions.TableResourceProperty", _IResolvable_da3f097b]]:
            '''A structure for the table object.

            A table is a metadata definition that represents your data. You can Grant and Revoke table privileges to a principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-resource.html#cfn-lakeformation-permissions-resource-tableresource
            '''
            result = self._values.get("table_resource")
            return typing.cast(typing.Optional[typing.Union["CfnPermissions.TableResourceProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def table_with_columns_resource(
            self,
        ) -> typing.Optional[typing.Union["CfnPermissions.TableWithColumnsResourceProperty", _IResolvable_da3f097b]]:
            '''Currently not supported by AWS CloudFormation .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-resource.html#cfn-lakeformation-permissions-resource-tablewithcolumnsresource
            '''
            result = self._values.get("table_with_columns_resource")
            return typing.cast(typing.Optional[typing.Union["CfnPermissions.TableWithColumnsResourceProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lakeformation.CfnPermissions.TableResourceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "catalog_id": "catalogId",
            "database_name": "databaseName",
            "name": "name",
            "table_wildcard": "tableWildcard",
        },
    )
    class TableResourceProperty:
        def __init__(
            self,
            *,
            catalog_id: typing.Optional[builtins.str] = None,
            database_name: typing.Optional[builtins.str] = None,
            name: typing.Optional[builtins.str] = None,
            table_wildcard: typing.Optional[typing.Union["CfnPermissions.TableWildcardProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A structure for the table object.

            A table is a metadata definition that represents your data. You can Grant and Revoke table privileges to a principal.

            :param catalog_id: ``CfnPermissions.TableResourceProperty.CatalogId``.
            :param database_name: The name of the database for the table. Unique to a Data Catalog. A database is a set of associated table definitions organized into a logical group. You can Grant and Revoke database privileges to a principal.
            :param name: The name of the table.
            :param table_wildcard: An empty object representing all tables under a database. If this field is specified instead of the ``Name`` field, all tables under ``DatabaseName`` will have permission changes applied.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tableresource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lakeformation as lakeformation
                
                table_resource_property = lakeformation.CfnPermissions.TableResourceProperty(
                    catalog_id="catalogId",
                    database_name="databaseName",
                    name="name",
                    table_wildcard=lakeformation.CfnPermissions.TableWildcardProperty()
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if catalog_id is not None:
                self._values["catalog_id"] = catalog_id
            if database_name is not None:
                self._values["database_name"] = database_name
            if name is not None:
                self._values["name"] = name
            if table_wildcard is not None:
                self._values["table_wildcard"] = table_wildcard

        @builtins.property
        def catalog_id(self) -> typing.Optional[builtins.str]:
            '''``CfnPermissions.TableResourceProperty.CatalogId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tableresource.html#cfn-lakeformation-permissions-tableresource-catalogid
            '''
            result = self._values.get("catalog_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def database_name(self) -> typing.Optional[builtins.str]:
            '''The name of the database for the table.

            Unique to a Data Catalog. A database is a set of associated table definitions organized into a logical group. You can Grant and Revoke database privileges to a principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tableresource.html#cfn-lakeformation-permissions-tableresource-databasename
            '''
            result = self._values.get("database_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the table.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tableresource.html#cfn-lakeformation-permissions-tableresource-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def table_wildcard(
            self,
        ) -> typing.Optional[typing.Union["CfnPermissions.TableWildcardProperty", _IResolvable_da3f097b]]:
            '''An empty object representing all tables under a database.

            If this field is specified instead of the ``Name`` field, all tables under ``DatabaseName`` will have permission changes applied.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tableresource.html#cfn-lakeformation-permissions-tableresource-tablewildcard
            '''
            result = self._values.get("table_wildcard")
            return typing.cast(typing.Optional[typing.Union["CfnPermissions.TableWildcardProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TableResourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lakeformation.CfnPermissions.TableWildcardProperty",
        jsii_struct_bases=[],
        name_mapping={},
    )
    class TableWildcardProperty:
        def __init__(self) -> None:
            '''A wildcard object representing every table under a database.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tablewildcard.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lakeformation as lakeformation
                
                table_wildcard_property = lakeformation.CfnPermissions.TableWildcardProperty()
            '''
            self._values: typing.Dict[str, typing.Any] = {}

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TableWildcardProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_lakeformation.CfnPermissions.TableWithColumnsResourceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "catalog_id": "catalogId",
            "column_names": "columnNames",
            "column_wildcard": "columnWildcard",
            "database_name": "databaseName",
            "name": "name",
        },
    )
    class TableWithColumnsResourceProperty:
        def __init__(
            self,
            *,
            catalog_id: typing.Optional[builtins.str] = None,
            column_names: typing.Optional[typing.Sequence[builtins.str]] = None,
            column_wildcard: typing.Optional[typing.Union["CfnPermissions.ColumnWildcardProperty", _IResolvable_da3f097b]] = None,
            database_name: typing.Optional[builtins.str] = None,
            name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A structure for a table with columns object. This object is only used when granting a SELECT permission.

            This object must take a value for at least one of ``ColumnsNames`` , ``ColumnsIndexes`` , or ``ColumnsWildcard`` .

            :param catalog_id: ``CfnPermissions.TableWithColumnsResourceProperty.CatalogId``.
            :param column_names: The list of column names for the table. At least one of ``ColumnNames`` or ``ColumnWildcard`` is required.
            :param column_wildcard: A wildcard specified by a ``ColumnWildcard`` object. At least one of ``ColumnNames`` or ``ColumnWildcard`` is required.
            :param database_name: The name of the database for the table with columns resource. Unique to the Data Catalog. A database is a set of associated table definitions organized into a logical group. You can Grant and Revoke database privileges to a principal.
            :param name: The name of the table resource. A table is a metadata definition that represents your data. You can Grant and Revoke table privileges to a principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tablewithcolumnsresource.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_lakeformation as lakeformation
                
                table_with_columns_resource_property = lakeformation.CfnPermissions.TableWithColumnsResourceProperty(
                    catalog_id="catalogId",
                    column_names=["columnNames"],
                    column_wildcard=lakeformation.CfnPermissions.ColumnWildcardProperty(
                        excluded_column_names=["excludedColumnNames"]
                    ),
                    database_name="databaseName",
                    name="name"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if catalog_id is not None:
                self._values["catalog_id"] = catalog_id
            if column_names is not None:
                self._values["column_names"] = column_names
            if column_wildcard is not None:
                self._values["column_wildcard"] = column_wildcard
            if database_name is not None:
                self._values["database_name"] = database_name
            if name is not None:
                self._values["name"] = name

        @builtins.property
        def catalog_id(self) -> typing.Optional[builtins.str]:
            '''``CfnPermissions.TableWithColumnsResourceProperty.CatalogId``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tablewithcolumnsresource.html#cfn-lakeformation-permissions-tablewithcolumnsresource-catalogid
            '''
            result = self._values.get("catalog_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def column_names(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The list of column names for the table.

            At least one of ``ColumnNames`` or ``ColumnWildcard`` is required.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tablewithcolumnsresource.html#cfn-lakeformation-permissions-tablewithcolumnsresource-columnnames
            '''
            result = self._values.get("column_names")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def column_wildcard(
            self,
        ) -> typing.Optional[typing.Union["CfnPermissions.ColumnWildcardProperty", _IResolvable_da3f097b]]:
            '''A wildcard specified by a ``ColumnWildcard`` object.

            At least one of ``ColumnNames`` or ``ColumnWildcard`` is required.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tablewithcolumnsresource.html#cfn-lakeformation-permissions-tablewithcolumnsresource-columnwildcard
            '''
            result = self._values.get("column_wildcard")
            return typing.cast(typing.Optional[typing.Union["CfnPermissions.ColumnWildcardProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def database_name(self) -> typing.Optional[builtins.str]:
            '''The name of the database for the table with columns resource.

            Unique to the Data Catalog. A database is a set of associated table definitions organized into a logical group. You can Grant and Revoke database privileges to a principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tablewithcolumnsresource.html#cfn-lakeformation-permissions-tablewithcolumnsresource-databasename
            '''
            result = self._values.get("database_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the table resource.

            A table is a metadata definition that represents your data. You can Grant and Revoke table privileges to a principal.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lakeformation-permissions-tablewithcolumnsresource.html#cfn-lakeformation-permissions-tablewithcolumnsresource-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TableWithColumnsResourceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_lakeformation.CfnPermissionsProps",
    jsii_struct_bases=[],
    name_mapping={
        "data_lake_principal": "dataLakePrincipal",
        "resource": "resource",
        "permissions": "permissions",
        "permissions_with_grant_option": "permissionsWithGrantOption",
    },
)
class CfnPermissionsProps:
    def __init__(
        self,
        *,
        data_lake_principal: typing.Union[CfnPermissions.DataLakePrincipalProperty, _IResolvable_da3f097b],
        resource: typing.Union[CfnPermissions.ResourceProperty, _IResolvable_da3f097b],
        permissions: typing.Optional[typing.Sequence[builtins.str]] = None,
        permissions_with_grant_option: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnPermissions``.

        :param data_lake_principal: The AWS Lake Formation principal.
        :param resource: A structure for the resource.
        :param permissions: The permissions granted or revoked.
        :param permissions_with_grant_option: Indicates whether to grant the ability to grant permissions (as a subset of permissions granted).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-permissions.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_lakeformation as lakeformation
            
            cfn_permissions_props = lakeformation.CfnPermissionsProps(
                data_lake_principal=lakeformation.CfnPermissions.DataLakePrincipalProperty(
                    data_lake_principal_identifier="dataLakePrincipalIdentifier"
                ),
                resource=lakeformation.CfnPermissions.ResourceProperty(
                    database_resource=lakeformation.CfnPermissions.DatabaseResourceProperty(
                        catalog_id="catalogId",
                        name="name"
                    ),
                    data_location_resource=lakeformation.CfnPermissions.DataLocationResourceProperty(
                        catalog_id="catalogId",
                        s3_resource="s3Resource"
                    ),
                    table_resource=lakeformation.CfnPermissions.TableResourceProperty(
                        catalog_id="catalogId",
                        database_name="databaseName",
                        name="name",
                        table_wildcard=lakeformation.CfnPermissions.TableWildcardProperty()
                    ),
                    table_with_columns_resource=lakeformation.CfnPermissions.TableWithColumnsResourceProperty(
                        catalog_id="catalogId",
                        column_names=["columnNames"],
                        column_wildcard=lakeformation.CfnPermissions.ColumnWildcardProperty(
                            excluded_column_names=["excludedColumnNames"]
                        ),
                        database_name="databaseName",
                        name="name"
                    )
                ),
            
                # the properties below are optional
                permissions=["permissions"],
                permissions_with_grant_option=["permissionsWithGrantOption"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "data_lake_principal": data_lake_principal,
            "resource": resource,
        }
        if permissions is not None:
            self._values["permissions"] = permissions
        if permissions_with_grant_option is not None:
            self._values["permissions_with_grant_option"] = permissions_with_grant_option

    @builtins.property
    def data_lake_principal(
        self,
    ) -> typing.Union[CfnPermissions.DataLakePrincipalProperty, _IResolvable_da3f097b]:
        '''The AWS Lake Formation principal.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-permissions.html#cfn-lakeformation-permissions-datalakeprincipal
        '''
        result = self._values.get("data_lake_principal")
        assert result is not None, "Required property 'data_lake_principal' is missing"
        return typing.cast(typing.Union[CfnPermissions.DataLakePrincipalProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def resource(
        self,
    ) -> typing.Union[CfnPermissions.ResourceProperty, _IResolvable_da3f097b]:
        '''A structure for the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-permissions.html#cfn-lakeformation-permissions-resource
        '''
        result = self._values.get("resource")
        assert result is not None, "Required property 'resource' is missing"
        return typing.cast(typing.Union[CfnPermissions.ResourceProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def permissions(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The permissions granted or revoked.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-permissions.html#cfn-lakeformation-permissions-permissions
        '''
        result = self._values.get("permissions")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def permissions_with_grant_option(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''Indicates whether to grant the ability to grant permissions (as a subset of permissions granted).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-permissions.html#cfn-lakeformation-permissions-permissionswithgrantoption
        '''
        result = self._values.get("permissions_with_grant_option")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPermissionsProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnResource(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_lakeformation.CfnResource",
):
    '''A CloudFormation ``AWS::LakeFormation::Resource``.

    The ``AWS::LakeFormation::Resource`` represents the data (Amazon S3 buckets and folders) that is being registered with AWS Lake Formation . When a ``Resource`` type CloudFormation template is uploaded, an AWS Lake Formation ```RegisterResource`` <https://docs.aws.amazon.com/lake-formation/latest/dg/aws-lake-formation-api-credential-vending.html#aws-lake-formation-api-credential-vending-RegisterResource>`_ API call is made to register the resource. When a ``Resource`` type CloudFormation template is removed, the AWS Lake Formation ```DeregisterResource`` <https://docs.aws.amazon.com/lake-formation/latest/dg/aws-lake-formation-api-credential-vending.html#aws-lake-formation-api-credential-vending-DeregisterResource>`_ API is called.

    :cloudformationResource: AWS::LakeFormation::Resource
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-resource.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_lakeformation as lakeformation
        
        cfn_resource = lakeformation.CfnResource(self, "MyCfnResource",
            resource_arn="resourceArn",
            use_service_linked_role=False,
        
            # the properties below are optional
            role_arn="roleArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        resource_arn: builtins.str,
        use_service_linked_role: typing.Union[builtins.bool, _IResolvable_da3f097b],
        role_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::LakeFormation::Resource``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param resource_arn: The Amazon Resource Name (ARN) of the resource.
        :param use_service_linked_role: Designates a trusted caller, an IAM principal, by registering this caller with the Data Catalog.
        :param role_arn: The IAM role that registered a resource.
        '''
        props = CfnResourceProps(
            resource_arn=resource_arn,
            use_service_linked_role=use_service_linked_role,
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
    @jsii.member(jsii_name="resourceArn")
    def resource_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-resource.html#cfn-lakeformation-resource-resourcearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "resourceArn"))

    @resource_arn.setter
    def resource_arn(self, value: builtins.str) -> None:
        jsii.set(self, "resourceArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="useServiceLinkedRole")
    def use_service_linked_role(
        self,
    ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Designates a trusted caller, an IAM principal, by registering this caller with the Data Catalog.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-resource.html#cfn-lakeformation-resource-useservicelinkedrole
        '''
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], jsii.get(self, "useServiceLinkedRole"))

    @use_service_linked_role.setter
    def use_service_linked_role(
        self,
        value: typing.Union[builtins.bool, _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "useServiceLinkedRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The IAM role that registered a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-resource.html#cfn-lakeformation-resource-rolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "roleArn", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_lakeformation.CfnResourceProps",
    jsii_struct_bases=[],
    name_mapping={
        "resource_arn": "resourceArn",
        "use_service_linked_role": "useServiceLinkedRole",
        "role_arn": "roleArn",
    },
)
class CfnResourceProps:
    def __init__(
        self,
        *,
        resource_arn: builtins.str,
        use_service_linked_role: typing.Union[builtins.bool, _IResolvable_da3f097b],
        role_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnResource``.

        :param resource_arn: The Amazon Resource Name (ARN) of the resource.
        :param use_service_linked_role: Designates a trusted caller, an IAM principal, by registering this caller with the Data Catalog.
        :param role_arn: The IAM role that registered a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-resource.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_lakeformation as lakeformation
            
            cfn_resource_props = lakeformation.CfnResourceProps(
                resource_arn="resourceArn",
                use_service_linked_role=False,
            
                # the properties below are optional
                role_arn="roleArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "resource_arn": resource_arn,
            "use_service_linked_role": use_service_linked_role,
        }
        if role_arn is not None:
            self._values["role_arn"] = role_arn

    @builtins.property
    def resource_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-resource.html#cfn-lakeformation-resource-resourcearn
        '''
        result = self._values.get("resource_arn")
        assert result is not None, "Required property 'resource_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def use_service_linked_role(
        self,
    ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
        '''Designates a trusted caller, an IAM principal, by registering this caller with the Data Catalog.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-resource.html#cfn-lakeformation-resource-useservicelinkedrole
        '''
        result = self._values.get("use_service_linked_role")
        assert result is not None, "Required property 'use_service_linked_role' is missing"
        return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

    @builtins.property
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The IAM role that registered a resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lakeformation-resource.html#cfn-lakeformation-resource-rolearn
        '''
        result = self._values.get("role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnResourceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnDataLakeSettings",
    "CfnDataLakeSettingsProps",
    "CfnPermissions",
    "CfnPermissionsProps",
    "CfnResource",
    "CfnResourceProps",
]

publication.publish()
