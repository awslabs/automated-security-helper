'''
# Amazon Athena Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_athena as athena
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-athena-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Athena](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Athena.html).

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
class CfnDataCatalog(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_athena.CfnDataCatalog",
):
    '''A CloudFormation ``AWS::Athena::DataCatalog``.

    The AWS::Athena::DataCatalog resource specifies an Amazon Athena data catalog, which contains a name, description, type, parameters, and tags. For more information, see `DataCatalog <https://docs.aws.amazon.com/athena/latest/APIReference/API_DataCatalog.html>`_ in the *Amazon Athena API Reference* .

    :cloudformationResource: AWS::Athena::DataCatalog
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_athena as athena
        
        cfn_data_catalog = athena.CfnDataCatalog(self, "MyCfnDataCatalog",
            name="name",
            type="type",
        
            # the properties below are optional
            description="description",
            parameters={
                "parameters_key": "parameters"
            },
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
        name: builtins.str,
        type: builtins.str,
        description: typing.Optional[builtins.str] = None,
        parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Athena::DataCatalog``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the data catalog. The catalog name must be unique for the AWS account and can use a maximum of 128 alphanumeric, underscore, at sign, or hyphen characters.
        :param type: The type of data catalog: ``LAMBDA`` for a federated catalog, ``GLUE`` for AWS Glue Catalog, or ``HIVE`` for an external hive metastore.
        :param description: A description of the data catalog.
        :param parameters: Specifies the Lambda function or functions to use for the data catalog. The mapping used depends on the catalog type. - The ``HIVE`` data catalog type uses the following syntax. The ``metadata-function`` parameter is required. ``The sdk-version`` parameter is optional and defaults to the currently supported version. ``metadata-function= *lambda_arn* , sdk-version= *version_number*`` - The ``LAMBDA`` data catalog type uses one of the following sets of required parameters, but not both. - When one Lambda function processes metadata and another Lambda function reads data, the following syntax is used. Both parameters are required. ``metadata-function= *lambda_arn* , record-function= *lambda_arn*`` - A composite Lambda function that processes both metadata and data uses the following syntax. ``function= *lambda_arn*`` - The ``GLUE`` type takes a catalog ID parameter and is required. The ``*catalog_id*`` is the account ID of the AWS account to which the Glue catalog belongs. ``catalog-id= *catalog_id*`` - The ``GLUE`` data catalog type also applies to the default ``AwsDataCatalog`` that already exists in your account, of which you can have only one and cannot modify. - Queries that specify a GLUE data catalog other than the default ``AwsDataCatalog`` must be run on Athena engine version 2. - In Regions where Athena engine version 2 is not available, creating new GLUE data catalogs results in an ``INVALID_INPUT`` error.
        :param tags: The tags (key-value pairs) to associate with this resource.
        '''
        props = CfnDataCatalogProps(
            name=name,
            type=type,
            description=description,
            parameters=parameters,
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
        '''The tags (key-value pairs) to associate with this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html#cfn-athena-datacatalog-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the data catalog.

        The catalog name must be unique for the AWS account and can use a maximum of 128 alphanumeric, underscore, at sign, or hyphen characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html#cfn-athena-datacatalog-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> builtins.str:
        '''The type of data catalog: ``LAMBDA`` for a federated catalog, ``GLUE`` for AWS Glue Catalog, or ``HIVE`` for an external hive metastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html#cfn-athena-datacatalog-type
        '''
        return typing.cast(builtins.str, jsii.get(self, "type"))

    @type.setter
    def type(self, value: builtins.str) -> None:
        jsii.set(self, "type", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the data catalog.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html#cfn-athena-datacatalog-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="parameters")
    def parameters(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''Specifies the Lambda function or functions to use for the data catalog.

        The mapping used depends on the catalog type.

        - The ``HIVE`` data catalog type uses the following syntax. The ``metadata-function`` parameter is required. ``The sdk-version`` parameter is optional and defaults to the currently supported version.

        ``metadata-function= *lambda_arn* , sdk-version= *version_number*``

        - The ``LAMBDA`` data catalog type uses one of the following sets of required parameters, but not both.
        - When one Lambda function processes metadata and another Lambda function reads data, the following syntax is used. Both parameters are required.

        ``metadata-function= *lambda_arn* , record-function= *lambda_arn*``

        - A composite Lambda function that processes both metadata and data uses the following syntax.

        ``function= *lambda_arn*``

        - The ``GLUE`` type takes a catalog ID parameter and is required. The ``*catalog_id*`` is the account ID of the AWS account to which the Glue catalog belongs.

        ``catalog-id= *catalog_id*``

        - The ``GLUE`` data catalog type also applies to the default ``AwsDataCatalog`` that already exists in your account, of which you can have only one and cannot modify.
        - Queries that specify a GLUE data catalog other than the default ``AwsDataCatalog`` must be run on Athena engine version 2.
        - In Regions where Athena engine version 2 is not available, creating new GLUE data catalogs results in an ``INVALID_INPUT`` error.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html#cfn-athena-datacatalog-parameters
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], jsii.get(self, "parameters"))

    @parameters.setter
    def parameters(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]],
    ) -> None:
        jsii.set(self, "parameters", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_athena.CfnDataCatalogProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "type": "type",
        "description": "description",
        "parameters": "parameters",
        "tags": "tags",
    },
)
class CfnDataCatalogProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        type: builtins.str,
        description: typing.Optional[builtins.str] = None,
        parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDataCatalog``.

        :param name: The name of the data catalog. The catalog name must be unique for the AWS account and can use a maximum of 128 alphanumeric, underscore, at sign, or hyphen characters.
        :param type: The type of data catalog: ``LAMBDA`` for a federated catalog, ``GLUE`` for AWS Glue Catalog, or ``HIVE`` for an external hive metastore.
        :param description: A description of the data catalog.
        :param parameters: Specifies the Lambda function or functions to use for the data catalog. The mapping used depends on the catalog type. - The ``HIVE`` data catalog type uses the following syntax. The ``metadata-function`` parameter is required. ``The sdk-version`` parameter is optional and defaults to the currently supported version. ``metadata-function= *lambda_arn* , sdk-version= *version_number*`` - The ``LAMBDA`` data catalog type uses one of the following sets of required parameters, but not both. - When one Lambda function processes metadata and another Lambda function reads data, the following syntax is used. Both parameters are required. ``metadata-function= *lambda_arn* , record-function= *lambda_arn*`` - A composite Lambda function that processes both metadata and data uses the following syntax. ``function= *lambda_arn*`` - The ``GLUE`` type takes a catalog ID parameter and is required. The ``*catalog_id*`` is the account ID of the AWS account to which the Glue catalog belongs. ``catalog-id= *catalog_id*`` - The ``GLUE`` data catalog type also applies to the default ``AwsDataCatalog`` that already exists in your account, of which you can have only one and cannot modify. - Queries that specify a GLUE data catalog other than the default ``AwsDataCatalog`` must be run on Athena engine version 2. - In Regions where Athena engine version 2 is not available, creating new GLUE data catalogs results in an ``INVALID_INPUT`` error.
        :param tags: The tags (key-value pairs) to associate with this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_athena as athena
            
            cfn_data_catalog_props = athena.CfnDataCatalogProps(
                name="name",
                type="type",
            
                # the properties below are optional
                description="description",
                parameters={
                    "parameters_key": "parameters"
                },
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
            "type": type,
        }
        if description is not None:
            self._values["description"] = description
        if parameters is not None:
            self._values["parameters"] = parameters
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the data catalog.

        The catalog name must be unique for the AWS account and can use a maximum of 128 alphanumeric, underscore, at sign, or hyphen characters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html#cfn-athena-datacatalog-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def type(self) -> builtins.str:
        '''The type of data catalog: ``LAMBDA`` for a federated catalog, ``GLUE`` for AWS Glue Catalog, or ``HIVE`` for an external hive metastore.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html#cfn-athena-datacatalog-type
        '''
        result = self._values.get("type")
        assert result is not None, "Required property 'type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the data catalog.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html#cfn-athena-datacatalog-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def parameters(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
        '''Specifies the Lambda function or functions to use for the data catalog.

        The mapping used depends on the catalog type.

        - The ``HIVE`` data catalog type uses the following syntax. The ``metadata-function`` parameter is required. ``The sdk-version`` parameter is optional and defaults to the currently supported version.

        ``metadata-function= *lambda_arn* , sdk-version= *version_number*``

        - The ``LAMBDA`` data catalog type uses one of the following sets of required parameters, but not both.
        - When one Lambda function processes metadata and another Lambda function reads data, the following syntax is used. Both parameters are required.

        ``metadata-function= *lambda_arn* , record-function= *lambda_arn*``

        - A composite Lambda function that processes both metadata and data uses the following syntax.

        ``function= *lambda_arn*``

        - The ``GLUE`` type takes a catalog ID parameter and is required. The ``*catalog_id*`` is the account ID of the AWS account to which the Glue catalog belongs.

        ``catalog-id= *catalog_id*``

        - The ``GLUE`` data catalog type also applies to the default ``AwsDataCatalog`` that already exists in your account, of which you can have only one and cannot modify.
        - Queries that specify a GLUE data catalog other than the default ``AwsDataCatalog`` must be run on Athena engine version 2.
        - In Regions where Athena engine version 2 is not available, creating new GLUE data catalogs results in an ``INVALID_INPUT`` error.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html#cfn-athena-datacatalog-parameters
        '''
        result = self._values.get("parameters")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags (key-value pairs) to associate with this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-datacatalog.html#cfn-athena-datacatalog-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDataCatalogProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnNamedQuery(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_athena.CfnNamedQuery",
):
    '''A CloudFormation ``AWS::Athena::NamedQuery``.

    The ``AWS::Athena::NamedQuery`` resource specifies an Amazon Athena saved query, where ``QueryString`` contains the SQL query statements that make up the query.

    :cloudformationResource: AWS::Athena::NamedQuery
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_athena as athena
        
        cfn_named_query = athena.CfnNamedQuery(self, "MyCfnNamedQuery",
            database="database",
            query_string="queryString",
        
            # the properties below are optional
            description="description",
            name="name",
            work_group="workGroup"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        database: builtins.str,
        query_string: builtins.str,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        work_group: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Athena::NamedQuery``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param database: The database to which the query belongs.
        :param query_string: The SQL statements that make up the query.
        :param description: The query description.
        :param name: The query name.
        :param work_group: The name of the workgroup that contains the named query.
        '''
        props = CfnNamedQueryProps(
            database=database,
            query_string=query_string,
            description=description,
            name=name,
            work_group=work_group,
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
    @jsii.member(jsii_name="attrNamedQueryId")
    def attr_named_query_id(self) -> builtins.str:
        '''The unique ID of the query.

        :cloudformationAttribute: NamedQueryId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrNamedQueryId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="database")
    def database(self) -> builtins.str:
        '''The database to which the query belongs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html#cfn-athena-namedquery-database
        '''
        return typing.cast(builtins.str, jsii.get(self, "database"))

    @database.setter
    def database(self, value: builtins.str) -> None:
        jsii.set(self, "database", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="queryString")
    def query_string(self) -> builtins.str:
        '''The SQL statements that make up the query.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html#cfn-athena-namedquery-querystring
        '''
        return typing.cast(builtins.str, jsii.get(self, "queryString"))

    @query_string.setter
    def query_string(self, value: builtins.str) -> None:
        jsii.set(self, "queryString", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The query description.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html#cfn-athena-namedquery-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The query name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html#cfn-athena-namedquery-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workGroup")
    def work_group(self) -> typing.Optional[builtins.str]:
        '''The name of the workgroup that contains the named query.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html#cfn-athena-namedquery-workgroup
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "workGroup"))

    @work_group.setter
    def work_group(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "workGroup", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_athena.CfnNamedQueryProps",
    jsii_struct_bases=[],
    name_mapping={
        "database": "database",
        "query_string": "queryString",
        "description": "description",
        "name": "name",
        "work_group": "workGroup",
    },
)
class CfnNamedQueryProps:
    def __init__(
        self,
        *,
        database: builtins.str,
        query_string: builtins.str,
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        work_group: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnNamedQuery``.

        :param database: The database to which the query belongs.
        :param query_string: The SQL statements that make up the query.
        :param description: The query description.
        :param name: The query name.
        :param work_group: The name of the workgroup that contains the named query.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_athena as athena
            
            cfn_named_query_props = athena.CfnNamedQueryProps(
                database="database",
                query_string="queryString",
            
                # the properties below are optional
                description="description",
                name="name",
                work_group="workGroup"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "database": database,
            "query_string": query_string,
        }
        if description is not None:
            self._values["description"] = description
        if name is not None:
            self._values["name"] = name
        if work_group is not None:
            self._values["work_group"] = work_group

    @builtins.property
    def database(self) -> builtins.str:
        '''The database to which the query belongs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html#cfn-athena-namedquery-database
        '''
        result = self._values.get("database")
        assert result is not None, "Required property 'database' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def query_string(self) -> builtins.str:
        '''The SQL statements that make up the query.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html#cfn-athena-namedquery-querystring
        '''
        result = self._values.get("query_string")
        assert result is not None, "Required property 'query_string' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The query description.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html#cfn-athena-namedquery-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The query name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html#cfn-athena-namedquery-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def work_group(self) -> typing.Optional[builtins.str]:
        '''The name of the workgroup that contains the named query.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-namedquery.html#cfn-athena-namedquery-workgroup
        '''
        result = self._values.get("work_group")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnNamedQueryProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnPreparedStatement(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_athena.CfnPreparedStatement",
):
    '''A CloudFormation ``AWS::Athena::PreparedStatement``.

    Specifies a prepared statement for use with SQL queries in Athena.

    :cloudformationResource: AWS::Athena::PreparedStatement
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-preparedstatement.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_athena as athena
        
        cfn_prepared_statement = athena.CfnPreparedStatement(self, "MyCfnPreparedStatement",
            query_statement="queryStatement",
            statement_name="statementName",
            work_group="workGroup",
        
            # the properties below are optional
            description="description"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        query_statement: builtins.str,
        statement_name: builtins.str,
        work_group: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Athena::PreparedStatement``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param query_statement: The query string for the prepared statement.
        :param statement_name: The name of the prepared statement.
        :param work_group: The workgroup to which the prepared statement belongs.
        :param description: The description of the prepared statement.
        '''
        props = CfnPreparedStatementProps(
            query_statement=query_statement,
            statement_name=statement_name,
            work_group=work_group,
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
    @jsii.member(jsii_name="queryStatement")
    def query_statement(self) -> builtins.str:
        '''The query string for the prepared statement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-preparedstatement.html#cfn-athena-preparedstatement-querystatement
        '''
        return typing.cast(builtins.str, jsii.get(self, "queryStatement"))

    @query_statement.setter
    def query_statement(self, value: builtins.str) -> None:
        jsii.set(self, "queryStatement", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="statementName")
    def statement_name(self) -> builtins.str:
        '''The name of the prepared statement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-preparedstatement.html#cfn-athena-preparedstatement-statementname
        '''
        return typing.cast(builtins.str, jsii.get(self, "statementName"))

    @statement_name.setter
    def statement_name(self, value: builtins.str) -> None:
        jsii.set(self, "statementName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workGroup")
    def work_group(self) -> builtins.str:
        '''The workgroup to which the prepared statement belongs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-preparedstatement.html#cfn-athena-preparedstatement-workgroup
        '''
        return typing.cast(builtins.str, jsii.get(self, "workGroup"))

    @work_group.setter
    def work_group(self, value: builtins.str) -> None:
        jsii.set(self, "workGroup", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the prepared statement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-preparedstatement.html#cfn-athena-preparedstatement-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_athena.CfnPreparedStatementProps",
    jsii_struct_bases=[],
    name_mapping={
        "query_statement": "queryStatement",
        "statement_name": "statementName",
        "work_group": "workGroup",
        "description": "description",
    },
)
class CfnPreparedStatementProps:
    def __init__(
        self,
        *,
        query_statement: builtins.str,
        statement_name: builtins.str,
        work_group: builtins.str,
        description: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnPreparedStatement``.

        :param query_statement: The query string for the prepared statement.
        :param statement_name: The name of the prepared statement.
        :param work_group: The workgroup to which the prepared statement belongs.
        :param description: The description of the prepared statement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-preparedstatement.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_athena as athena
            
            cfn_prepared_statement_props = athena.CfnPreparedStatementProps(
                query_statement="queryStatement",
                statement_name="statementName",
                work_group="workGroup",
            
                # the properties below are optional
                description="description"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "query_statement": query_statement,
            "statement_name": statement_name,
            "work_group": work_group,
        }
        if description is not None:
            self._values["description"] = description

    @builtins.property
    def query_statement(self) -> builtins.str:
        '''The query string for the prepared statement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-preparedstatement.html#cfn-athena-preparedstatement-querystatement
        '''
        result = self._values.get("query_statement")
        assert result is not None, "Required property 'query_statement' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def statement_name(self) -> builtins.str:
        '''The name of the prepared statement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-preparedstatement.html#cfn-athena-preparedstatement-statementname
        '''
        result = self._values.get("statement_name")
        assert result is not None, "Required property 'statement_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def work_group(self) -> builtins.str:
        '''The workgroup to which the prepared statement belongs.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-preparedstatement.html#cfn-athena-preparedstatement-workgroup
        '''
        result = self._values.get("work_group")
        assert result is not None, "Required property 'work_group' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the prepared statement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-preparedstatement.html#cfn-athena-preparedstatement-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnPreparedStatementProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnWorkGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_athena.CfnWorkGroup",
):
    '''A CloudFormation ``AWS::Athena::WorkGroup``.

    The AWS::Athena::WorkGroup resource specifies an Amazon Athena workgroup, which contains a name, description, creation time, state, and other configuration, listed under ``WorkGroupConfiguration`` . Each workgroup enables you to isolate queries for you or your group from other queries in the same account. For more information, see `CreateWorkGroup <https://docs.aws.amazon.com/athena/latest/APIReference/API_CreateWorkGroup.html>`_ in the *Amazon Athena API Reference* .

    :cloudformationResource: AWS::Athena::WorkGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_athena as athena
        
        cfn_work_group = athena.CfnWorkGroup(self, "MyCfnWorkGroup",
            name="name",
        
            # the properties below are optional
            description="description",
            recursive_delete_option=False,
            state="state",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                bytes_scanned_cutoff_per_query=123,
                enforce_work_group_configuration=False,
                engine_version=athena.CfnWorkGroup.EngineVersionProperty(
                    effective_engine_version="effectiveEngineVersion",
                    selected_engine_version="selectedEngineVersion"
                ),
                publish_cloud_watch_metrics_enabled=False,
                requester_pays_enabled=False,
                result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                    encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="encryptionOption",
        
                        # the properties below are optional
                        kms_key="kmsKey"
                    ),
                    output_location="outputLocation"
                )
            ),
            work_group_configuration_updates=athena.CfnWorkGroup.WorkGroupConfigurationUpdatesProperty(
                bytes_scanned_cutoff_per_query=123,
                enforce_work_group_configuration=False,
                engine_version=athena.CfnWorkGroup.EngineVersionProperty(
                    effective_engine_version="effectiveEngineVersion",
                    selected_engine_version="selectedEngineVersion"
                ),
                publish_cloud_watch_metrics_enabled=False,
                remove_bytes_scanned_cutoff_per_query=False,
                requester_pays_enabled=False,
                result_configuration_updates=athena.CfnWorkGroup.ResultConfigurationUpdatesProperty(
                    encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="encryptionOption",
        
                        # the properties below are optional
                        kms_key="kmsKey"
                    ),
                    output_location="outputLocation",
                    remove_encryption_configuration=False,
                    remove_output_location=False
                )
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        recursive_delete_option: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        state: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        work_group_configuration: typing.Optional[typing.Union["CfnWorkGroup.WorkGroupConfigurationProperty", _IResolvable_da3f097b]] = None,
        work_group_configuration_updates: typing.Optional[typing.Union["CfnWorkGroup.WorkGroupConfigurationUpdatesProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::Athena::WorkGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The workgroup name.
        :param description: The workgroup description.
        :param recursive_delete_option: The option to delete a workgroup and its contents even if the workgroup contains any named queries. The default is false.
        :param state: The state of the workgroup: ENABLED or DISABLED.
        :param tags: The tags (key-value pairs) to associate with this resource.
        :param work_group_configuration: The configuration of the workgroup, which includes the location in Amazon S3 where query results are stored, the encryption option, if any, used for query results, whether Amazon CloudWatch Metrics are enabled for the workgroup, and the limit for the amount of bytes scanned (cutoff) per query, if it is specified. The ``EnforceWorkGroupConfiguration`` option determines whether workgroup settings override client-side query settings.
        :param work_group_configuration_updates: The configuration information that will be updated for this workgroup, which includes the location in Amazon S3 where query results are stored, the encryption option, if any, used for query results, whether the Amazon CloudWatch Metrics are enabled for the workgroup, whether the workgroup settings override the client-side settings, and the data usage limit for the amount of bytes scanned per query, if it is specified.
        '''
        props = CfnWorkGroupProps(
            name=name,
            description=description,
            recursive_delete_option=recursive_delete_option,
            state=state,
            tags=tags,
            work_group_configuration=work_group_configuration,
            work_group_configuration_updates=work_group_configuration_updates,
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
    def attr_creation_time(self) -> builtins.str:
        '''The date and time the workgroup was created, as a UNIX timestamp in seconds.

        For example: ``1582761016`` .

        :cloudformationAttribute: CreationTime
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCreationTime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrWorkGroupConfigurationEngineVersionEffectiveEngineVersion")
    def attr_work_group_configuration_engine_version_effective_engine_version(
        self,
    ) -> builtins.str:
        '''
        :cloudformationAttribute: WorkGroupConfiguration.EngineVersion.EffectiveEngineVersion
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrWorkGroupConfigurationEngineVersionEffectiveEngineVersion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrWorkGroupConfigurationUpdatesEngineVersionEffectiveEngineVersion")
    def attr_work_group_configuration_updates_engine_version_effective_engine_version(
        self,
    ) -> builtins.str:
        '''
        :cloudformationAttribute: WorkGroupConfigurationUpdates.EngineVersion.EffectiveEngineVersion
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrWorkGroupConfigurationUpdatesEngineVersionEffectiveEngineVersion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags (key-value pairs) to associate with this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The workgroup name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The workgroup description.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="recursiveDeleteOption")
    def recursive_delete_option(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''The option to delete a workgroup and its contents even if the workgroup contains any named queries.

        The default is false.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-recursivedeleteoption
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "recursiveDeleteOption"))

    @recursive_delete_option.setter
    def recursive_delete_option(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "recursiveDeleteOption", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="state")
    def state(self) -> typing.Optional[builtins.str]:
        '''The state of the workgroup: ENABLED or DISABLED.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-state
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "state"))

    @state.setter
    def state(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "state", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workGroupConfiguration")
    def work_group_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnWorkGroup.WorkGroupConfigurationProperty", _IResolvable_da3f097b]]:
        '''The configuration of the workgroup, which includes the location in Amazon S3 where query results are stored, the encryption option, if any, used for query results, whether Amazon CloudWatch Metrics are enabled for the workgroup, and the limit for the amount of bytes scanned (cutoff) per query, if it is specified.

        The ``EnforceWorkGroupConfiguration`` option determines whether workgroup settings override client-side query settings.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-workgroupconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnWorkGroup.WorkGroupConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "workGroupConfiguration"))

    @work_group_configuration.setter
    def work_group_configuration(
        self,
        value: typing.Optional[typing.Union["CfnWorkGroup.WorkGroupConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "workGroupConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="workGroupConfigurationUpdates")
    def work_group_configuration_updates(
        self,
    ) -> typing.Optional[typing.Union["CfnWorkGroup.WorkGroupConfigurationUpdatesProperty", _IResolvable_da3f097b]]:
        '''The configuration information that will be updated for this workgroup, which includes the location in Amazon S3 where query results are stored, the encryption option, if any, used for query results, whether the Amazon CloudWatch Metrics are enabled for the workgroup, whether the workgroup settings override the client-side settings, and the data usage limit for the amount of bytes scanned per query, if it is specified.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-workgroupconfigurationupdates
        '''
        return typing.cast(typing.Optional[typing.Union["CfnWorkGroup.WorkGroupConfigurationUpdatesProperty", _IResolvable_da3f097b]], jsii.get(self, "workGroupConfigurationUpdates"))

    @work_group_configuration_updates.setter
    def work_group_configuration_updates(
        self,
        value: typing.Optional[typing.Union["CfnWorkGroup.WorkGroupConfigurationUpdatesProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "workGroupConfigurationUpdates", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_athena.CfnWorkGroup.EncryptionConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"encryption_option": "encryptionOption", "kms_key": "kmsKey"},
    )
    class EncryptionConfigurationProperty:
        def __init__(
            self,
            *,
            encryption_option: builtins.str,
            kms_key: typing.Optional[builtins.str] = None,
        ) -> None:
            '''If query results are encrypted in Amazon S3, indicates the encryption option used (for example, ``SSE-KMS`` or ``CSE-KMS`` ) and key information.

            :param encryption_option: Indicates whether Amazon S3 server-side encryption with Amazon S3-managed keys ( ``SSE-S3`` ), server-side encryption with KMS-managed keys ( ``SSE-KMS`` ), or client-side encryption with KMS-managed keys (CSE-KMS) is used. If a query runs in a workgroup and the workgroup overrides client-side settings, then the workgroup's setting for encryption is used. It specifies whether query results must be encrypted, for all queries that run in this workgroup.
            :param kms_key: For ``SSE-KMS`` and ``CSE-KMS`` , this is the KMS key ARN or ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-encryptionconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_athena as athena
                
                encryption_configuration_property = athena.CfnWorkGroup.EncryptionConfigurationProperty(
                    encryption_option="encryptionOption",
                
                    # the properties below are optional
                    kms_key="kmsKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "encryption_option": encryption_option,
            }
            if kms_key is not None:
                self._values["kms_key"] = kms_key

        @builtins.property
        def encryption_option(self) -> builtins.str:
            '''Indicates whether Amazon S3 server-side encryption with Amazon S3-managed keys ( ``SSE-S3`` ), server-side encryption with KMS-managed keys ( ``SSE-KMS`` ), or client-side encryption with KMS-managed keys (CSE-KMS) is used.

            If a query runs in a workgroup and the workgroup overrides client-side settings, then the workgroup's setting for encryption is used. It specifies whether query results must be encrypted, for all queries that run in this workgroup.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-encryptionconfiguration.html#cfn-athena-workgroup-encryptionconfiguration-encryptionoption
            '''
            result = self._values.get("encryption_option")
            assert result is not None, "Required property 'encryption_option' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def kms_key(self) -> typing.Optional[builtins.str]:
            '''For ``SSE-KMS`` and ``CSE-KMS`` , this is the KMS key ARN or ID.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-encryptionconfiguration.html#cfn-athena-workgroup-encryptionconfiguration-kmskey
            '''
            result = self._values.get("kms_key")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_athena.CfnWorkGroup.EngineVersionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "effective_engine_version": "effectiveEngineVersion",
            "selected_engine_version": "selectedEngineVersion",
        },
    )
    class EngineVersionProperty:
        def __init__(
            self,
            *,
            effective_engine_version: typing.Optional[builtins.str] = None,
            selected_engine_version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The Athena engine version for running queries.

            :param effective_engine_version: Read only. The engine version on which the query runs. If the user requests a valid engine version other than Auto, the effective engine version is the same as the engine version that the user requested. If the user requests Auto, the effective engine version is chosen by Athena. When a request to update the engine version is made by a ``CreateWorkGroup`` or ``UpdateWorkGroup`` operation, the ``EffectiveEngineVersion`` field is ignored.
            :param selected_engine_version: The engine version requested by the user. Possible values are determined by the output of ``ListEngineVersions`` , including Auto. The default is Auto.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-engineversion.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_athena as athena
                
                engine_version_property = athena.CfnWorkGroup.EngineVersionProperty(
                    effective_engine_version="effectiveEngineVersion",
                    selected_engine_version="selectedEngineVersion"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if effective_engine_version is not None:
                self._values["effective_engine_version"] = effective_engine_version
            if selected_engine_version is not None:
                self._values["selected_engine_version"] = selected_engine_version

        @builtins.property
        def effective_engine_version(self) -> typing.Optional[builtins.str]:
            '''Read only.

            The engine version on which the query runs. If the user requests a valid engine version other than Auto, the effective engine version is the same as the engine version that the user requested. If the user requests Auto, the effective engine version is chosen by Athena. When a request to update the engine version is made by a ``CreateWorkGroup`` or ``UpdateWorkGroup`` operation, the ``EffectiveEngineVersion`` field is ignored.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-engineversion.html#cfn-athena-workgroup-engineversion-effectiveengineversion
            '''
            result = self._values.get("effective_engine_version")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def selected_engine_version(self) -> typing.Optional[builtins.str]:
            '''The engine version requested by the user.

            Possible values are determined by the output of ``ListEngineVersions`` , including Auto. The default is Auto.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-engineversion.html#cfn-athena-workgroup-engineversion-selectedengineversion
            '''
            result = self._values.get("selected_engine_version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EngineVersionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_athena.CfnWorkGroup.ResultConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "encryption_configuration": "encryptionConfiguration",
            "output_location": "outputLocation",
        },
    )
    class ResultConfigurationProperty:
        def __init__(
            self,
            *,
            encryption_configuration: typing.Optional[typing.Union["CfnWorkGroup.EncryptionConfigurationProperty", _IResolvable_da3f097b]] = None,
            output_location: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The location in Amazon S3 where query results are stored and the encryption option, if any, used for query results.

            These are known as "client-side settings". If workgroup settings override client-side settings, then the query uses the workgroup settings.

            :param encryption_configuration: If query results are encrypted in Amazon S3, indicates the encryption option used (for example, ``SSE-KMS`` or ``CSE-KMS`` ) and key information. This is a client-side setting. If workgroup settings override client-side settings, then the query uses the encryption configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See ``EnforceWorkGroupConfiguration`` and `Workgroup Settings Override Client-Side Settings <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html>`_ .
            :param output_location: The location in Amazon S3 where your query results are stored, such as ``s3://path/to/query/bucket/`` . To run a query, you must specify the query results location using either a client-side setting for individual queries or a location specified by the workgroup. If workgroup settings override client-side settings, then the query uses the location specified for the workgroup. If no query location is set, Athena issues an error. For more information, see `Working with Query Results, Output Files, and Query History <https://docs.aws.amazon.com/athena/latest/ug/querying.html>`_ and ``EnforceWorkGroupConfiguration`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-resultconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_athena as athena
                
                result_configuration_property = athena.CfnWorkGroup.ResultConfigurationProperty(
                    encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="encryptionOption",
                
                        # the properties below are optional
                        kms_key="kmsKey"
                    ),
                    output_location="outputLocation"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if encryption_configuration is not None:
                self._values["encryption_configuration"] = encryption_configuration
            if output_location is not None:
                self._values["output_location"] = output_location

        @builtins.property
        def encryption_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnWorkGroup.EncryptionConfigurationProperty", _IResolvable_da3f097b]]:
            '''If query results are encrypted in Amazon S3, indicates the encryption option used (for example, ``SSE-KMS`` or ``CSE-KMS`` ) and key information.

            This is a client-side setting. If workgroup settings override client-side settings, then the query uses the encryption configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See ``EnforceWorkGroupConfiguration`` and `Workgroup Settings Override Client-Side Settings <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-resultconfiguration.html#cfn-athena-workgroup-resultconfiguration-encryptionconfiguration
            '''
            result = self._values.get("encryption_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnWorkGroup.EncryptionConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def output_location(self) -> typing.Optional[builtins.str]:
            '''The location in Amazon S3 where your query results are stored, such as ``s3://path/to/query/bucket/`` .

            To run a query, you must specify the query results location using either a client-side setting for individual queries or a location specified by the workgroup. If workgroup settings override client-side settings, then the query uses the location specified for the workgroup. If no query location is set, Athena issues an error. For more information, see `Working with Query Results, Output Files, and Query History <https://docs.aws.amazon.com/athena/latest/ug/querying.html>`_ and ``EnforceWorkGroupConfiguration`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-resultconfiguration.html#cfn-athena-workgroup-resultconfiguration-outputlocation
            '''
            result = self._values.get("output_location")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResultConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_athena.CfnWorkGroup.ResultConfigurationUpdatesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "encryption_configuration": "encryptionConfiguration",
            "output_location": "outputLocation",
            "remove_encryption_configuration": "removeEncryptionConfiguration",
            "remove_output_location": "removeOutputLocation",
        },
    )
    class ResultConfigurationUpdatesProperty:
        def __init__(
            self,
            *,
            encryption_configuration: typing.Optional[typing.Union["CfnWorkGroup.EncryptionConfigurationProperty", _IResolvable_da3f097b]] = None,
            output_location: typing.Optional[builtins.str] = None,
            remove_encryption_configuration: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            remove_output_location: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The information about the updates in the query results, such as output location and encryption configuration for the query results.

            :param encryption_configuration: The encryption configuration for the query results.
            :param output_location: The location in Amazon S3 where your query results are stored, such as ``s3://path/to/query/bucket/`` . For more information, see `Query Results <https://docs.aws.amazon.com/athena/latest/ug/querying.html>`_ If workgroup settings override client-side settings, then the query uses the location for the query results and the encryption configuration that are specified for the workgroup. The "workgroup settings override" is specified in EnforceWorkGroupConfiguration (true/false) in the WorkGroupConfiguration. See ``EnforceWorkGroupConfiguration`` .
            :param remove_encryption_configuration: If set to "true", indicates that the previously-specified encryption configuration (also known as the client-side setting) for queries in this workgroup should be ignored and set to null. If set to "false" or not set, and a value is present in the EncryptionConfiguration in ResultConfigurationUpdates (the client-side setting), the EncryptionConfiguration in the workgroup's ResultConfiguration will be updated with the new value. For more information, see `Workgroup Settings Override Client-Side Settings <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html>`_ .
            :param remove_output_location: If set to "true", indicates that the previously-specified query results location (also known as a client-side setting) for queries in this workgroup should be ignored and set to null. If set to "false" or not set, and a value is present in the OutputLocation in ResultConfigurationUpdates (the client-side setting), the OutputLocation in the workgroup's ResultConfiguration will be updated with the new value. For more information, see `Workgroup Settings Override Client-Side Settings <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-resultconfigurationupdates.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_athena as athena
                
                result_configuration_updates_property = athena.CfnWorkGroup.ResultConfigurationUpdatesProperty(
                    encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                        encryption_option="encryptionOption",
                
                        # the properties below are optional
                        kms_key="kmsKey"
                    ),
                    output_location="outputLocation",
                    remove_encryption_configuration=False,
                    remove_output_location=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if encryption_configuration is not None:
                self._values["encryption_configuration"] = encryption_configuration
            if output_location is not None:
                self._values["output_location"] = output_location
            if remove_encryption_configuration is not None:
                self._values["remove_encryption_configuration"] = remove_encryption_configuration
            if remove_output_location is not None:
                self._values["remove_output_location"] = remove_output_location

        @builtins.property
        def encryption_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnWorkGroup.EncryptionConfigurationProperty", _IResolvable_da3f097b]]:
            '''The encryption configuration for the query results.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-resultconfigurationupdates.html#cfn-athena-workgroup-resultconfigurationupdates-encryptionconfiguration
            '''
            result = self._values.get("encryption_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnWorkGroup.EncryptionConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def output_location(self) -> typing.Optional[builtins.str]:
            '''The location in Amazon S3 where your query results are stored, such as ``s3://path/to/query/bucket/`` .

            For more information, see `Query Results <https://docs.aws.amazon.com/athena/latest/ug/querying.html>`_ If workgroup settings override client-side settings, then the query uses the location for the query results and the encryption configuration that are specified for the workgroup. The "workgroup settings override" is specified in EnforceWorkGroupConfiguration (true/false) in the WorkGroupConfiguration. See ``EnforceWorkGroupConfiguration`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-resultconfigurationupdates.html#cfn-athena-workgroup-resultconfigurationupdates-outputlocation
            '''
            result = self._values.get("output_location")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def remove_encryption_configuration(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If set to "true", indicates that the previously-specified encryption configuration (also known as the client-side setting) for queries in this workgroup should be ignored and set to null.

            If set to "false" or not set, and a value is present in the EncryptionConfiguration in ResultConfigurationUpdates (the client-side setting), the EncryptionConfiguration in the workgroup's ResultConfiguration will be updated with the new value. For more information, see `Workgroup Settings Override Client-Side Settings <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-resultconfigurationupdates.html#cfn-athena-workgroup-resultconfigurationupdates-removeencryptionconfiguration
            '''
            result = self._values.get("remove_encryption_configuration")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def remove_output_location(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If set to "true", indicates that the previously-specified query results location (also known as a client-side setting) for queries in this workgroup should be ignored and set to null.

            If set to "false" or not set, and a value is present in the OutputLocation in ResultConfigurationUpdates (the client-side setting), the OutputLocation in the workgroup's ResultConfiguration will be updated with the new value. For more information, see `Workgroup Settings Override Client-Side Settings <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-resultconfigurationupdates.html#cfn-athena-workgroup-resultconfigurationupdates-removeoutputlocation
            '''
            result = self._values.get("remove_output_location")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResultConfigurationUpdatesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_athena.CfnWorkGroup.WorkGroupConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bytes_scanned_cutoff_per_query": "bytesScannedCutoffPerQuery",
            "enforce_work_group_configuration": "enforceWorkGroupConfiguration",
            "engine_version": "engineVersion",
            "publish_cloud_watch_metrics_enabled": "publishCloudWatchMetricsEnabled",
            "requester_pays_enabled": "requesterPaysEnabled",
            "result_configuration": "resultConfiguration",
        },
    )
    class WorkGroupConfigurationProperty:
        def __init__(
            self,
            *,
            bytes_scanned_cutoff_per_query: typing.Optional[jsii.Number] = None,
            enforce_work_group_configuration: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            engine_version: typing.Optional[typing.Union["CfnWorkGroup.EngineVersionProperty", _IResolvable_da3f097b]] = None,
            publish_cloud_watch_metrics_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            requester_pays_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            result_configuration: typing.Optional[typing.Union["CfnWorkGroup.ResultConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The configuration of the workgroup, which includes the location in Amazon S3 where query results are stored, the encryption option, if any, used for query results, whether Amazon CloudWatch Metrics are enabled for the workgroup, and the limit for the amount of bytes scanned (cutoff) per query, if it is specified.

            The ``EnforceWorkGroupConfiguration`` option determines whether workgroup settings override client-side query settings.

            :param bytes_scanned_cutoff_per_query: The upper limit (cutoff) for the amount of bytes a single query in a workgroup is allowed to scan. No default is defined. .. epigraph:: This property currently supports integer types. Support for long values is planned.
            :param enforce_work_group_configuration: If set to "true", the settings for the workgroup override client-side settings. If set to "false", client-side settings are used. For more information, see `Workgroup Settings Override Client-Side Settings <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html>`_ .
            :param engine_version: The engine version that all queries running on the workgroup use. Queries on the ``AmazonAthenaPreviewFunctionality`` workgroup run on the preview engine regardless of this setting.
            :param publish_cloud_watch_metrics_enabled: Indicates that the Amazon CloudWatch metrics are enabled for the workgroup.
            :param requester_pays_enabled: If set to ``true`` , allows members assigned to a workgroup to reference Amazon S3 Requester Pays buckets in queries. If set to ``false`` , workgroup members cannot query data from Requester Pays buckets, and queries that retrieve data from Requester Pays buckets cause an error. The default is ``false`` . For more information about Requester Pays buckets, see `Requester Pays Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html>`_ in the *Amazon Simple Storage Service Developer Guide* .
            :param result_configuration: Specifies the location in Amazon S3 where query results are stored and the encryption option, if any, used for query results. For more information, see `Working with Query Results, Output Files, and Query History <https://docs.aws.amazon.com/athena/latest/ug/querying.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_athena as athena
                
                work_group_configuration_property = athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                    bytes_scanned_cutoff_per_query=123,
                    enforce_work_group_configuration=False,
                    engine_version=athena.CfnWorkGroup.EngineVersionProperty(
                        effective_engine_version="effectiveEngineVersion",
                        selected_engine_version="selectedEngineVersion"
                    ),
                    publish_cloud_watch_metrics_enabled=False,
                    requester_pays_enabled=False,
                    result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                        encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                            encryption_option="encryptionOption",
                
                            # the properties below are optional
                            kms_key="kmsKey"
                        ),
                        output_location="outputLocation"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if bytes_scanned_cutoff_per_query is not None:
                self._values["bytes_scanned_cutoff_per_query"] = bytes_scanned_cutoff_per_query
            if enforce_work_group_configuration is not None:
                self._values["enforce_work_group_configuration"] = enforce_work_group_configuration
            if engine_version is not None:
                self._values["engine_version"] = engine_version
            if publish_cloud_watch_metrics_enabled is not None:
                self._values["publish_cloud_watch_metrics_enabled"] = publish_cloud_watch_metrics_enabled
            if requester_pays_enabled is not None:
                self._values["requester_pays_enabled"] = requester_pays_enabled
            if result_configuration is not None:
                self._values["result_configuration"] = result_configuration

        @builtins.property
        def bytes_scanned_cutoff_per_query(self) -> typing.Optional[jsii.Number]:
            '''The upper limit (cutoff) for the amount of bytes a single query in a workgroup is allowed to scan.

            No default is defined.
            .. epigraph::

               This property currently supports integer types. Support for long values is planned.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfiguration.html#cfn-athena-workgroup-workgroupconfiguration-bytesscannedcutoffperquery
            '''
            result = self._values.get("bytes_scanned_cutoff_per_query")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def enforce_work_group_configuration(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If set to "true", the settings for the workgroup override client-side settings.

            If set to "false", client-side settings are used. For more information, see `Workgroup Settings Override Client-Side Settings <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfiguration.html#cfn-athena-workgroup-workgroupconfiguration-enforceworkgroupconfiguration
            '''
            result = self._values.get("enforce_work_group_configuration")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def engine_version(
            self,
        ) -> typing.Optional[typing.Union["CfnWorkGroup.EngineVersionProperty", _IResolvable_da3f097b]]:
            '''The engine version that all queries running on the workgroup use.

            Queries on the ``AmazonAthenaPreviewFunctionality`` workgroup run on the preview engine regardless of this setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfiguration.html#cfn-athena-workgroup-workgroupconfiguration-engineversion
            '''
            result = self._values.get("engine_version")
            return typing.cast(typing.Optional[typing.Union["CfnWorkGroup.EngineVersionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def publish_cloud_watch_metrics_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates that the Amazon CloudWatch metrics are enabled for the workgroup.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfiguration.html#cfn-athena-workgroup-workgroupconfiguration-publishcloudwatchmetricsenabled
            '''
            result = self._values.get("publish_cloud_watch_metrics_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def requester_pays_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If set to ``true`` , allows members assigned to a workgroup to reference Amazon S3 Requester Pays buckets in queries.

            If set to ``false`` , workgroup members cannot query data from Requester Pays buckets, and queries that retrieve data from Requester Pays buckets cause an error. The default is ``false`` . For more information about Requester Pays buckets, see `Requester Pays Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html>`_ in the *Amazon Simple Storage Service Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfiguration.html#cfn-athena-workgroup-workgroupconfiguration-requesterpaysenabled
            '''
            result = self._values.get("requester_pays_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def result_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnWorkGroup.ResultConfigurationProperty", _IResolvable_da3f097b]]:
            '''Specifies the location in Amazon S3 where query results are stored and the encryption option, if any, used for query results.

            For more information, see `Working with Query Results, Output Files, and Query History <https://docs.aws.amazon.com/athena/latest/ug/querying.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfiguration.html#cfn-athena-workgroup-workgroupconfiguration-resultconfiguration
            '''
            result = self._values.get("result_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnWorkGroup.ResultConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "WorkGroupConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_athena.CfnWorkGroup.WorkGroupConfigurationUpdatesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "bytes_scanned_cutoff_per_query": "bytesScannedCutoffPerQuery",
            "enforce_work_group_configuration": "enforceWorkGroupConfiguration",
            "engine_version": "engineVersion",
            "publish_cloud_watch_metrics_enabled": "publishCloudWatchMetricsEnabled",
            "remove_bytes_scanned_cutoff_per_query": "removeBytesScannedCutoffPerQuery",
            "requester_pays_enabled": "requesterPaysEnabled",
            "result_configuration_updates": "resultConfigurationUpdates",
        },
    )
    class WorkGroupConfigurationUpdatesProperty:
        def __init__(
            self,
            *,
            bytes_scanned_cutoff_per_query: typing.Optional[jsii.Number] = None,
            enforce_work_group_configuration: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            engine_version: typing.Optional[typing.Union["CfnWorkGroup.EngineVersionProperty", _IResolvable_da3f097b]] = None,
            publish_cloud_watch_metrics_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            remove_bytes_scanned_cutoff_per_query: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            requester_pays_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            result_configuration_updates: typing.Optional[typing.Union["CfnWorkGroup.ResultConfigurationUpdatesProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The configuration information that will be updated for this workgroup, which includes the location in Amazon S3 where query results are stored, the encryption option, if any, used for query results, whether the Amazon CloudWatch Metrics are enabled for the workgroup, whether the workgroup settings override the client-side settings, and the data usage limit for the amount of bytes scanned per query, if it is specified.

            :param bytes_scanned_cutoff_per_query: The upper limit (cutoff) for the amount of bytes a single query in a workgroup is allowed to scan. No default is defined. .. epigraph:: This property currently supports integer types. Support for long values is planned.
            :param enforce_work_group_configuration: If set to "true", the settings for the workgroup override client-side settings. If set to "false" client-side settings are used. For more information, see `Workgroup Settings Override Client-Side Settings <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html>`_ .
            :param engine_version: The engine version requested when a workgroup is updated. After the update, all queries on the workgroup run on the requested engine version. If no value was previously set, the default is Auto. Queries on the ``AmazonAthenaPreviewFunctionality`` workgroup run on the preview engine regardless of this setting.
            :param publish_cloud_watch_metrics_enabled: Indicates whether this workgroup enables publishing metrics to Amazon CloudWatch.
            :param remove_bytes_scanned_cutoff_per_query: Indicates that the data usage control limit per query is removed. See ``BytesScannedCutoffPerQuery`` .
            :param requester_pays_enabled: If set to ``true`` , allows members assigned to a workgroup to specify Amazon S3 Requester Pays buckets in queries. If set to ``false`` , workgroup members cannot query data from Requester Pays buckets, and queries that retrieve data from Requester Pays buckets cause an error. The default is ``false`` . For more information about Requester Pays buckets, see `Requester Pays Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html>`_ in the *Amazon Simple Storage Service Developer Guide* .
            :param result_configuration_updates: The result configuration information about the queries in this workgroup that will be updated. Includes the updated results location and an updated option for encrypting query results.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfigurationupdates.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_athena as athena
                
                work_group_configuration_updates_property = athena.CfnWorkGroup.WorkGroupConfigurationUpdatesProperty(
                    bytes_scanned_cutoff_per_query=123,
                    enforce_work_group_configuration=False,
                    engine_version=athena.CfnWorkGroup.EngineVersionProperty(
                        effective_engine_version="effectiveEngineVersion",
                        selected_engine_version="selectedEngineVersion"
                    ),
                    publish_cloud_watch_metrics_enabled=False,
                    remove_bytes_scanned_cutoff_per_query=False,
                    requester_pays_enabled=False,
                    result_configuration_updates=athena.CfnWorkGroup.ResultConfigurationUpdatesProperty(
                        encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                            encryption_option="encryptionOption",
                
                            # the properties below are optional
                            kms_key="kmsKey"
                        ),
                        output_location="outputLocation",
                        remove_encryption_configuration=False,
                        remove_output_location=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if bytes_scanned_cutoff_per_query is not None:
                self._values["bytes_scanned_cutoff_per_query"] = bytes_scanned_cutoff_per_query
            if enforce_work_group_configuration is not None:
                self._values["enforce_work_group_configuration"] = enforce_work_group_configuration
            if engine_version is not None:
                self._values["engine_version"] = engine_version
            if publish_cloud_watch_metrics_enabled is not None:
                self._values["publish_cloud_watch_metrics_enabled"] = publish_cloud_watch_metrics_enabled
            if remove_bytes_scanned_cutoff_per_query is not None:
                self._values["remove_bytes_scanned_cutoff_per_query"] = remove_bytes_scanned_cutoff_per_query
            if requester_pays_enabled is not None:
                self._values["requester_pays_enabled"] = requester_pays_enabled
            if result_configuration_updates is not None:
                self._values["result_configuration_updates"] = result_configuration_updates

        @builtins.property
        def bytes_scanned_cutoff_per_query(self) -> typing.Optional[jsii.Number]:
            '''The upper limit (cutoff) for the amount of bytes a single query in a workgroup is allowed to scan.

            No default is defined.
            .. epigraph::

               This property currently supports integer types. Support for long values is planned.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfigurationupdates.html#cfn-athena-workgroup-workgroupconfigurationupdates-bytesscannedcutoffperquery
            '''
            result = self._values.get("bytes_scanned_cutoff_per_query")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def enforce_work_group_configuration(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If set to "true", the settings for the workgroup override client-side settings.

            If set to "false" client-side settings are used. For more information, see `Workgroup Settings Override Client-Side Settings <https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfigurationupdates.html#cfn-athena-workgroup-workgroupconfigurationupdates-enforceworkgroupconfiguration
            '''
            result = self._values.get("enforce_work_group_configuration")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def engine_version(
            self,
        ) -> typing.Optional[typing.Union["CfnWorkGroup.EngineVersionProperty", _IResolvable_da3f097b]]:
            '''The engine version requested when a workgroup is updated.

            After the update, all queries on the workgroup run on the requested engine version. If no value was previously set, the default is Auto. Queries on the ``AmazonAthenaPreviewFunctionality`` workgroup run on the preview engine regardless of this setting.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfigurationupdates.html#cfn-athena-workgroup-workgroupconfigurationupdates-engineversion
            '''
            result = self._values.get("engine_version")
            return typing.cast(typing.Optional[typing.Union["CfnWorkGroup.EngineVersionProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def publish_cloud_watch_metrics_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether this workgroup enables publishing metrics to Amazon CloudWatch.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfigurationupdates.html#cfn-athena-workgroup-workgroupconfigurationupdates-publishcloudwatchmetricsenabled
            '''
            result = self._values.get("publish_cloud_watch_metrics_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def remove_bytes_scanned_cutoff_per_query(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates that the data usage control limit per query is removed.

            See ``BytesScannedCutoffPerQuery`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfigurationupdates.html#cfn-athena-workgroup-workgroupconfigurationupdates-removebytesscannedcutoffperquery
            '''
            result = self._values.get("remove_bytes_scanned_cutoff_per_query")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def requester_pays_enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If set to ``true`` , allows members assigned to a workgroup to specify Amazon S3 Requester Pays buckets in queries.

            If set to ``false`` , workgroup members cannot query data from Requester Pays buckets, and queries that retrieve data from Requester Pays buckets cause an error. The default is ``false`` . For more information about Requester Pays buckets, see `Requester Pays Buckets <https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html>`_ in the *Amazon Simple Storage Service Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfigurationupdates.html#cfn-athena-workgroup-workgroupconfigurationupdates-requesterpaysenabled
            '''
            result = self._values.get("requester_pays_enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def result_configuration_updates(
            self,
        ) -> typing.Optional[typing.Union["CfnWorkGroup.ResultConfigurationUpdatesProperty", _IResolvable_da3f097b]]:
            '''The result configuration information about the queries in this workgroup that will be updated.

            Includes the updated results location and an updated option for encrypting query results.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-athena-workgroup-workgroupconfigurationupdates.html#cfn-athena-workgroup-workgroupconfigurationupdates-resultconfigurationupdates
            '''
            result = self._values.get("result_configuration_updates")
            return typing.cast(typing.Optional[typing.Union["CfnWorkGroup.ResultConfigurationUpdatesProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "WorkGroupConfigurationUpdatesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_athena.CfnWorkGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "description": "description",
        "recursive_delete_option": "recursiveDeleteOption",
        "state": "state",
        "tags": "tags",
        "work_group_configuration": "workGroupConfiguration",
        "work_group_configuration_updates": "workGroupConfigurationUpdates",
    },
)
class CfnWorkGroupProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        description: typing.Optional[builtins.str] = None,
        recursive_delete_option: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        state: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        work_group_configuration: typing.Optional[typing.Union[CfnWorkGroup.WorkGroupConfigurationProperty, _IResolvable_da3f097b]] = None,
        work_group_configuration_updates: typing.Optional[typing.Union[CfnWorkGroup.WorkGroupConfigurationUpdatesProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnWorkGroup``.

        :param name: The workgroup name.
        :param description: The workgroup description.
        :param recursive_delete_option: The option to delete a workgroup and its contents even if the workgroup contains any named queries. The default is false.
        :param state: The state of the workgroup: ENABLED or DISABLED.
        :param tags: The tags (key-value pairs) to associate with this resource.
        :param work_group_configuration: The configuration of the workgroup, which includes the location in Amazon S3 where query results are stored, the encryption option, if any, used for query results, whether Amazon CloudWatch Metrics are enabled for the workgroup, and the limit for the amount of bytes scanned (cutoff) per query, if it is specified. The ``EnforceWorkGroupConfiguration`` option determines whether workgroup settings override client-side query settings.
        :param work_group_configuration_updates: The configuration information that will be updated for this workgroup, which includes the location in Amazon S3 where query results are stored, the encryption option, if any, used for query results, whether the Amazon CloudWatch Metrics are enabled for the workgroup, whether the workgroup settings override the client-side settings, and the data usage limit for the amount of bytes scanned per query, if it is specified.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_athena as athena
            
            cfn_work_group_props = athena.CfnWorkGroupProps(
                name="name",
            
                # the properties below are optional
                description="description",
                recursive_delete_option=False,
                state="state",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                work_group_configuration=athena.CfnWorkGroup.WorkGroupConfigurationProperty(
                    bytes_scanned_cutoff_per_query=123,
                    enforce_work_group_configuration=False,
                    engine_version=athena.CfnWorkGroup.EngineVersionProperty(
                        effective_engine_version="effectiveEngineVersion",
                        selected_engine_version="selectedEngineVersion"
                    ),
                    publish_cloud_watch_metrics_enabled=False,
                    requester_pays_enabled=False,
                    result_configuration=athena.CfnWorkGroup.ResultConfigurationProperty(
                        encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                            encryption_option="encryptionOption",
            
                            # the properties below are optional
                            kms_key="kmsKey"
                        ),
                        output_location="outputLocation"
                    )
                ),
                work_group_configuration_updates=athena.CfnWorkGroup.WorkGroupConfigurationUpdatesProperty(
                    bytes_scanned_cutoff_per_query=123,
                    enforce_work_group_configuration=False,
                    engine_version=athena.CfnWorkGroup.EngineVersionProperty(
                        effective_engine_version="effectiveEngineVersion",
                        selected_engine_version="selectedEngineVersion"
                    ),
                    publish_cloud_watch_metrics_enabled=False,
                    remove_bytes_scanned_cutoff_per_query=False,
                    requester_pays_enabled=False,
                    result_configuration_updates=athena.CfnWorkGroup.ResultConfigurationUpdatesProperty(
                        encryption_configuration=athena.CfnWorkGroup.EncryptionConfigurationProperty(
                            encryption_option="encryptionOption",
            
                            # the properties below are optional
                            kms_key="kmsKey"
                        ),
                        output_location="outputLocation",
                        remove_encryption_configuration=False,
                        remove_output_location=False
                    )
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if description is not None:
            self._values["description"] = description
        if recursive_delete_option is not None:
            self._values["recursive_delete_option"] = recursive_delete_option
        if state is not None:
            self._values["state"] = state
        if tags is not None:
            self._values["tags"] = tags
        if work_group_configuration is not None:
            self._values["work_group_configuration"] = work_group_configuration
        if work_group_configuration_updates is not None:
            self._values["work_group_configuration_updates"] = work_group_configuration_updates

    @builtins.property
    def name(self) -> builtins.str:
        '''The workgroup name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The workgroup description.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def recursive_delete_option(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''The option to delete a workgroup and its contents even if the workgroup contains any named queries.

        The default is false.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-recursivedeleteoption
        '''
        result = self._values.get("recursive_delete_option")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def state(self) -> typing.Optional[builtins.str]:
        '''The state of the workgroup: ENABLED or DISABLED.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-state
        '''
        result = self._values.get("state")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags (key-value pairs) to associate with this resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def work_group_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnWorkGroup.WorkGroupConfigurationProperty, _IResolvable_da3f097b]]:
        '''The configuration of the workgroup, which includes the location in Amazon S3 where query results are stored, the encryption option, if any, used for query results, whether Amazon CloudWatch Metrics are enabled for the workgroup, and the limit for the amount of bytes scanned (cutoff) per query, if it is specified.

        The ``EnforceWorkGroupConfiguration`` option determines whether workgroup settings override client-side query settings.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-workgroupconfiguration
        '''
        result = self._values.get("work_group_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnWorkGroup.WorkGroupConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def work_group_configuration_updates(
        self,
    ) -> typing.Optional[typing.Union[CfnWorkGroup.WorkGroupConfigurationUpdatesProperty, _IResolvable_da3f097b]]:
        '''The configuration information that will be updated for this workgroup, which includes the location in Amazon S3 where query results are stored, the encryption option, if any, used for query results, whether the Amazon CloudWatch Metrics are enabled for the workgroup, whether the workgroup settings override the client-side settings, and the data usage limit for the amount of bytes scanned per query, if it is specified.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-athena-workgroup.html#cfn-athena-workgroup-workgroupconfigurationupdates
        '''
        result = self._values.get("work_group_configuration_updates")
        return typing.cast(typing.Optional[typing.Union[CfnWorkGroup.WorkGroupConfigurationUpdatesProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnWorkGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnDataCatalog",
    "CfnDataCatalogProps",
    "CfnNamedQuery",
    "CfnNamedQueryProps",
    "CfnPreparedStatement",
    "CfnPreparedStatementProps",
    "CfnWorkGroup",
    "CfnWorkGroupProps",
]

publication.publish()
