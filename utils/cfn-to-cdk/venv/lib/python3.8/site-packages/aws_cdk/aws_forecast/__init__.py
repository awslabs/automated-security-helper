'''
# AWS::Forecast Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_forecast as forecast
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-forecast-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::Forecast](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_Forecast.html).

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
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnDataset(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_forecast.CfnDataset",
):
    '''A CloudFormation ``AWS::Forecast::Dataset``.

    :cloudformationResource: AWS::Forecast::Dataset
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_forecast as forecast
        
        # encryption_config: Any
        # schema: Any
        # tags: Any
        
        cfn_dataset = forecast.CfnDataset(self, "MyCfnDataset",
            dataset_name="datasetName",
            dataset_type="datasetType",
            domain="domain",
            schema=schema,
        
            # the properties below are optional
            data_frequency="dataFrequency",
            encryption_config=encryption_config,
            tags=[tags]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        dataset_name: builtins.str,
        dataset_type: builtins.str,
        domain: builtins.str,
        schema: typing.Any,
        data_frequency: typing.Optional[builtins.str] = None,
        encryption_config: typing.Any = None,
        tags: typing.Optional[typing.Sequence[typing.Any]] = None,
    ) -> None:
        '''Create a new ``AWS::Forecast::Dataset``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param dataset_name: ``AWS::Forecast::Dataset.DatasetName``.
        :param dataset_type: ``AWS::Forecast::Dataset.DatasetType``.
        :param domain: ``AWS::Forecast::Dataset.Domain``.
        :param schema: ``AWS::Forecast::Dataset.Schema``.
        :param data_frequency: ``AWS::Forecast::Dataset.DataFrequency``.
        :param encryption_config: ``AWS::Forecast::Dataset.EncryptionConfig``.
        :param tags: ``AWS::Forecast::Dataset.Tags``.
        '''
        props = CfnDatasetProps(
            dataset_name=dataset_name,
            dataset_type=dataset_type,
            domain=domain,
            schema=schema,
            data_frequency=data_frequency,
            encryption_config=encryption_config,
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
        '''
        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="datasetName")
    def dataset_name(self) -> builtins.str:
        '''``AWS::Forecast::Dataset.DatasetName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-datasetname
        '''
        return typing.cast(builtins.str, jsii.get(self, "datasetName"))

    @dataset_name.setter
    def dataset_name(self, value: builtins.str) -> None:
        jsii.set(self, "datasetName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="datasetType")
    def dataset_type(self) -> builtins.str:
        '''``AWS::Forecast::Dataset.DatasetType``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-datasettype
        '''
        return typing.cast(builtins.str, jsii.get(self, "datasetType"))

    @dataset_type.setter
    def dataset_type(self, value: builtins.str) -> None:
        jsii.set(self, "datasetType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domain")
    def domain(self) -> builtins.str:
        '''``AWS::Forecast::Dataset.Domain``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-domain
        '''
        return typing.cast(builtins.str, jsii.get(self, "domain"))

    @domain.setter
    def domain(self, value: builtins.str) -> None:
        jsii.set(self, "domain", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionConfig")
    def encryption_config(self) -> typing.Any:
        '''``AWS::Forecast::Dataset.EncryptionConfig``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-encryptionconfig
        '''
        return typing.cast(typing.Any, jsii.get(self, "encryptionConfig"))

    @encryption_config.setter
    def encryption_config(self, value: typing.Any) -> None:
        jsii.set(self, "encryptionConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="schema")
    def schema(self) -> typing.Any:
        '''``AWS::Forecast::Dataset.Schema``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-schema
        '''
        return typing.cast(typing.Any, jsii.get(self, "schema"))

    @schema.setter
    def schema(self, value: typing.Any) -> None:
        jsii.set(self, "schema", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="dataFrequency")
    def data_frequency(self) -> typing.Optional[builtins.str]:
        '''``AWS::Forecast::Dataset.DataFrequency``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-datafrequency
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "dataFrequency"))

    @data_frequency.setter
    def data_frequency(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "dataFrequency", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> typing.Optional[typing.List[typing.Any]]:
        '''``AWS::Forecast::Dataset.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-tags
        '''
        return typing.cast(typing.Optional[typing.List[typing.Any]], jsii.get(self, "tags"))

    @tags.setter
    def tags(self, value: typing.Optional[typing.List[typing.Any]]) -> None:
        jsii.set(self, "tags", value)


@jsii.implements(_IInspectable_c2943556)
class CfnDatasetGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_forecast.CfnDatasetGroup",
):
    '''A CloudFormation ``AWS::Forecast::DatasetGroup``.

    :cloudformationResource: AWS::Forecast::DatasetGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-datasetgroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_forecast as forecast
        
        cfn_dataset_group = forecast.CfnDatasetGroup(self, "MyCfnDatasetGroup",
            dataset_group_name="datasetGroupName",
            domain="domain",
        
            # the properties below are optional
            dataset_arns=["datasetArns"],
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
        dataset_group_name: builtins.str,
        domain: builtins.str,
        dataset_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Forecast::DatasetGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param dataset_group_name: ``AWS::Forecast::DatasetGroup.DatasetGroupName``.
        :param domain: ``AWS::Forecast::DatasetGroup.Domain``.
        :param dataset_arns: ``AWS::Forecast::DatasetGroup.DatasetArns``.
        :param tags: ``AWS::Forecast::DatasetGroup.Tags``.
        '''
        props = CfnDatasetGroupProps(
            dataset_group_name=dataset_group_name,
            domain=domain,
            dataset_arns=dataset_arns,
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
    @jsii.member(jsii_name="attrDatasetGroupArn")
    def attr_dataset_group_arn(self) -> builtins.str:
        '''
        :cloudformationAttribute: DatasetGroupArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDatasetGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''``AWS::Forecast::DatasetGroup.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-datasetgroup.html#cfn-forecast-datasetgroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="datasetGroupName")
    def dataset_group_name(self) -> builtins.str:
        '''``AWS::Forecast::DatasetGroup.DatasetGroupName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-datasetgroup.html#cfn-forecast-datasetgroup-datasetgroupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "datasetGroupName"))

    @dataset_group_name.setter
    def dataset_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "datasetGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domain")
    def domain(self) -> builtins.str:
        '''``AWS::Forecast::DatasetGroup.Domain``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-datasetgroup.html#cfn-forecast-datasetgroup-domain
        '''
        return typing.cast(builtins.str, jsii.get(self, "domain"))

    @domain.setter
    def domain(self, value: builtins.str) -> None:
        jsii.set(self, "domain", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="datasetArns")
    def dataset_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''``AWS::Forecast::DatasetGroup.DatasetArns``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-datasetgroup.html#cfn-forecast-datasetgroup-datasetarns
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "datasetArns"))

    @dataset_arns.setter
    def dataset_arns(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "datasetArns", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_forecast.CfnDatasetGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "dataset_group_name": "datasetGroupName",
        "domain": "domain",
        "dataset_arns": "datasetArns",
        "tags": "tags",
    },
)
class CfnDatasetGroupProps:
    def __init__(
        self,
        *,
        dataset_group_name: builtins.str,
        domain: builtins.str,
        dataset_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDatasetGroup``.

        :param dataset_group_name: ``AWS::Forecast::DatasetGroup.DatasetGroupName``.
        :param domain: ``AWS::Forecast::DatasetGroup.Domain``.
        :param dataset_arns: ``AWS::Forecast::DatasetGroup.DatasetArns``.
        :param tags: ``AWS::Forecast::DatasetGroup.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-datasetgroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_forecast as forecast
            
            cfn_dataset_group_props = forecast.CfnDatasetGroupProps(
                dataset_group_name="datasetGroupName",
                domain="domain",
            
                # the properties below are optional
                dataset_arns=["datasetArns"],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "dataset_group_name": dataset_group_name,
            "domain": domain,
        }
        if dataset_arns is not None:
            self._values["dataset_arns"] = dataset_arns
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def dataset_group_name(self) -> builtins.str:
        '''``AWS::Forecast::DatasetGroup.DatasetGroupName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-datasetgroup.html#cfn-forecast-datasetgroup-datasetgroupname
        '''
        result = self._values.get("dataset_group_name")
        assert result is not None, "Required property 'dataset_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def domain(self) -> builtins.str:
        '''``AWS::Forecast::DatasetGroup.Domain``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-datasetgroup.html#cfn-forecast-datasetgroup-domain
        '''
        result = self._values.get("domain")
        assert result is not None, "Required property 'domain' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def dataset_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''``AWS::Forecast::DatasetGroup.DatasetArns``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-datasetgroup.html#cfn-forecast-datasetgroup-datasetarns
        '''
        result = self._values.get("dataset_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''``AWS::Forecast::DatasetGroup.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-datasetgroup.html#cfn-forecast-datasetgroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDatasetGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_forecast.CfnDatasetProps",
    jsii_struct_bases=[],
    name_mapping={
        "dataset_name": "datasetName",
        "dataset_type": "datasetType",
        "domain": "domain",
        "schema": "schema",
        "data_frequency": "dataFrequency",
        "encryption_config": "encryptionConfig",
        "tags": "tags",
    },
)
class CfnDatasetProps:
    def __init__(
        self,
        *,
        dataset_name: builtins.str,
        dataset_type: builtins.str,
        domain: builtins.str,
        schema: typing.Any,
        data_frequency: typing.Optional[builtins.str] = None,
        encryption_config: typing.Any = None,
        tags: typing.Optional[typing.Sequence[typing.Any]] = None,
    ) -> None:
        '''Properties for defining a ``CfnDataset``.

        :param dataset_name: ``AWS::Forecast::Dataset.DatasetName``.
        :param dataset_type: ``AWS::Forecast::Dataset.DatasetType``.
        :param domain: ``AWS::Forecast::Dataset.Domain``.
        :param schema: ``AWS::Forecast::Dataset.Schema``.
        :param data_frequency: ``AWS::Forecast::Dataset.DataFrequency``.
        :param encryption_config: ``AWS::Forecast::Dataset.EncryptionConfig``.
        :param tags: ``AWS::Forecast::Dataset.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_forecast as forecast
            
            # encryption_config: Any
            # schema: Any
            # tags: Any
            
            cfn_dataset_props = forecast.CfnDatasetProps(
                dataset_name="datasetName",
                dataset_type="datasetType",
                domain="domain",
                schema=schema,
            
                # the properties below are optional
                data_frequency="dataFrequency",
                encryption_config=encryption_config,
                tags=[tags]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "dataset_name": dataset_name,
            "dataset_type": dataset_type,
            "domain": domain,
            "schema": schema,
        }
        if data_frequency is not None:
            self._values["data_frequency"] = data_frequency
        if encryption_config is not None:
            self._values["encryption_config"] = encryption_config
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def dataset_name(self) -> builtins.str:
        '''``AWS::Forecast::Dataset.DatasetName``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-datasetname
        '''
        result = self._values.get("dataset_name")
        assert result is not None, "Required property 'dataset_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def dataset_type(self) -> builtins.str:
        '''``AWS::Forecast::Dataset.DatasetType``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-datasettype
        '''
        result = self._values.get("dataset_type")
        assert result is not None, "Required property 'dataset_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def domain(self) -> builtins.str:
        '''``AWS::Forecast::Dataset.Domain``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-domain
        '''
        result = self._values.get("domain")
        assert result is not None, "Required property 'domain' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def schema(self) -> typing.Any:
        '''``AWS::Forecast::Dataset.Schema``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-schema
        '''
        result = self._values.get("schema")
        assert result is not None, "Required property 'schema' is missing"
        return typing.cast(typing.Any, result)

    @builtins.property
    def data_frequency(self) -> typing.Optional[builtins.str]:
        '''``AWS::Forecast::Dataset.DataFrequency``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-datafrequency
        '''
        result = self._values.get("data_frequency")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def encryption_config(self) -> typing.Any:
        '''``AWS::Forecast::Dataset.EncryptionConfig``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-encryptionconfig
        '''
        result = self._values.get("encryption_config")
        return typing.cast(typing.Any, result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[typing.Any]]:
        '''``AWS::Forecast::Dataset.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-forecast-dataset.html#cfn-forecast-dataset-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[typing.Any]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnDatasetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnDataset",
    "CfnDatasetGroup",
    "CfnDatasetGroupProps",
    "CfnDatasetProps",
]

publication.publish()
