'''
# AWS::LicenseManager Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_licensemanager as licensemanager
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-licensemanager-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::LicenseManager](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_LicenseManager.html).

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
class CfnGrant(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_licensemanager.CfnGrant",
):
    '''A CloudFormation ``AWS::LicenseManager::Grant``.

    Specifies a grant.

    A grant shares the use of license entitlements with specific AWS accounts . For more information, see `Granted licenses <https://docs.aws.amazon.com/license-manager/latest/userguide/granted-licenses.html>`_ in the *AWS License Manager User Guide* .

    :cloudformationResource: AWS::LicenseManager::Grant
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_licensemanager as licensemanager
        
        cfn_grant = licensemanager.CfnGrant(self, "MyCfnGrant",
            allowed_operations=["allowedOperations"],
            grant_name="grantName",
            home_region="homeRegion",
            license_arn="licenseArn",
            principals=["principals"],
            status="status"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        allowed_operations: typing.Optional[typing.Sequence[builtins.str]] = None,
        grant_name: typing.Optional[builtins.str] = None,
        home_region: typing.Optional[builtins.str] = None,
        license_arn: typing.Optional[builtins.str] = None,
        principals: typing.Optional[typing.Sequence[builtins.str]] = None,
        status: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::LicenseManager::Grant``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param allowed_operations: Allowed operations for the grant.
        :param grant_name: Grant name.
        :param home_region: Home Region of the grant.
        :param license_arn: License ARN.
        :param principals: The grant principals.
        :param status: Granted license status.
        '''
        props = CfnGrantProps(
            allowed_operations=allowed_operations,
            grant_name=grant_name,
            home_region=home_region,
            license_arn=license_arn,
            principals=principals,
            status=status,
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
    @jsii.member(jsii_name="attrGrantArn")
    def attr_grant_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the grant.

        :cloudformationAttribute: GrantArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrGrantArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrVersion")
    def attr_version(self) -> builtins.str:
        '''The grant version.

        :cloudformationAttribute: Version
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrVersion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="allowedOperations")
    def allowed_operations(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Allowed operations for the grant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-allowedoperations
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "allowedOperations"))

    @allowed_operations.setter
    def allowed_operations(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "allowedOperations", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantName")
    def grant_name(self) -> typing.Optional[builtins.str]:
        '''Grant name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-grantname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "grantName"))

    @grant_name.setter
    def grant_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "grantName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="homeRegion")
    def home_region(self) -> typing.Optional[builtins.str]:
        '''Home Region of the grant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-homeregion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "homeRegion"))

    @home_region.setter
    def home_region(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "homeRegion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="licenseArn")
    def license_arn(self) -> typing.Optional[builtins.str]:
        '''License ARN.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-licensearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "licenseArn"))

    @license_arn.setter
    def license_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "licenseArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principals")
    def principals(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The grant principals.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-principals
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "principals"))

    @principals.setter
    def principals(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "principals", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="status")
    def status(self) -> typing.Optional[builtins.str]:
        '''Granted license status.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-status
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "status"))

    @status.setter
    def status(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "status", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_licensemanager.CfnGrantProps",
    jsii_struct_bases=[],
    name_mapping={
        "allowed_operations": "allowedOperations",
        "grant_name": "grantName",
        "home_region": "homeRegion",
        "license_arn": "licenseArn",
        "principals": "principals",
        "status": "status",
    },
)
class CfnGrantProps:
    def __init__(
        self,
        *,
        allowed_operations: typing.Optional[typing.Sequence[builtins.str]] = None,
        grant_name: typing.Optional[builtins.str] = None,
        home_region: typing.Optional[builtins.str] = None,
        license_arn: typing.Optional[builtins.str] = None,
        principals: typing.Optional[typing.Sequence[builtins.str]] = None,
        status: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnGrant``.

        :param allowed_operations: Allowed operations for the grant.
        :param grant_name: Grant name.
        :param home_region: Home Region of the grant.
        :param license_arn: License ARN.
        :param principals: The grant principals.
        :param status: Granted license status.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_licensemanager as licensemanager
            
            cfn_grant_props = licensemanager.CfnGrantProps(
                allowed_operations=["allowedOperations"],
                grant_name="grantName",
                home_region="homeRegion",
                license_arn="licenseArn",
                principals=["principals"],
                status="status"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if allowed_operations is not None:
            self._values["allowed_operations"] = allowed_operations
        if grant_name is not None:
            self._values["grant_name"] = grant_name
        if home_region is not None:
            self._values["home_region"] = home_region
        if license_arn is not None:
            self._values["license_arn"] = license_arn
        if principals is not None:
            self._values["principals"] = principals
        if status is not None:
            self._values["status"] = status

    @builtins.property
    def allowed_operations(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Allowed operations for the grant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-allowedoperations
        '''
        result = self._values.get("allowed_operations")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def grant_name(self) -> typing.Optional[builtins.str]:
        '''Grant name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-grantname
        '''
        result = self._values.get("grant_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def home_region(self) -> typing.Optional[builtins.str]:
        '''Home Region of the grant.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-homeregion
        '''
        result = self._values.get("home_region")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def license_arn(self) -> typing.Optional[builtins.str]:
        '''License ARN.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-licensearn
        '''
        result = self._values.get("license_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def principals(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The grant principals.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-principals
        '''
        result = self._values.get("principals")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def status(self) -> typing.Optional[builtins.str]:
        '''Granted license status.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-grant.html#cfn-licensemanager-grant-status
        '''
        result = self._values.get("status")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnGrantProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnLicense(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_licensemanager.CfnLicense",
):
    '''A CloudFormation ``AWS::LicenseManager::License``.

    Specifies a granted license.

    Granted licenses are licenses for products that your organization purchased from AWS Marketplace or directly from a seller who integrated their software with managed entitlements. For more information, see `Granted licenses <https://docs.aws.amazon.com/license-manager/latest/userguide/granted-licenses.html>`_ in the *AWS License Manager User Guide* .

    :cloudformationResource: AWS::LicenseManager::License
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_licensemanager as licensemanager
        
        cfn_license = licensemanager.CfnLicense(self, "MyCfnLicense",
            consumption_configuration=licensemanager.CfnLicense.ConsumptionConfigurationProperty(
                borrow_configuration=licensemanager.CfnLicense.BorrowConfigurationProperty(
                    allow_early_check_in=False,
                    max_time_to_live_in_minutes=123
                ),
                provisional_configuration=licensemanager.CfnLicense.ProvisionalConfigurationProperty(
                    max_time_to_live_in_minutes=123
                ),
                renew_type="renewType"
            ),
            entitlements=[licensemanager.CfnLicense.EntitlementProperty(
                name="name",
                unit="unit",
        
                # the properties below are optional
                allow_check_in=False,
                max_count=123,
                overage=False,
                value="value"
            )],
            home_region="homeRegion",
            issuer=licensemanager.CfnLicense.IssuerDataProperty(
                name="name",
        
                # the properties below are optional
                sign_key="signKey"
            ),
            license_name="licenseName",
            product_name="productName",
            validity=licensemanager.CfnLicense.ValidityDateFormatProperty(
                begin="begin",
                end="end"
            ),
        
            # the properties below are optional
            beneficiary="beneficiary",
            license_metadata=[licensemanager.CfnLicense.MetadataProperty(
                name="name",
                value="value"
            )],
            product_sku="productSku",
            status="status"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        consumption_configuration: typing.Union["CfnLicense.ConsumptionConfigurationProperty", _IResolvable_da3f097b],
        entitlements: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLicense.EntitlementProperty", _IResolvable_da3f097b]]],
        home_region: builtins.str,
        issuer: typing.Union["CfnLicense.IssuerDataProperty", _IResolvable_da3f097b],
        license_name: builtins.str,
        product_name: builtins.str,
        validity: typing.Union["CfnLicense.ValidityDateFormatProperty", _IResolvable_da3f097b],
        beneficiary: typing.Optional[builtins.str] = None,
        license_metadata: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLicense.MetadataProperty", _IResolvable_da3f097b]]]] = None,
        product_sku: typing.Optional[builtins.str] = None,
        status: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::LicenseManager::License``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param consumption_configuration: Configuration for consumption of the license.
        :param entitlements: License entitlements.
        :param home_region: Home Region of the license.
        :param issuer: License issuer.
        :param license_name: License name.
        :param product_name: Product name.
        :param validity: Date and time range during which the license is valid, in ISO8601-UTC format.
        :param beneficiary: License beneficiary.
        :param license_metadata: License metadata.
        :param product_sku: Product SKU.
        :param status: License status.
        '''
        props = CfnLicenseProps(
            consumption_configuration=consumption_configuration,
            entitlements=entitlements,
            home_region=home_region,
            issuer=issuer,
            license_name=license_name,
            product_name=product_name,
            validity=validity,
            beneficiary=beneficiary,
            license_metadata=license_metadata,
            product_sku=product_sku,
            status=status,
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
    @jsii.member(jsii_name="attrLicenseArn")
    def attr_license_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the license.

        :cloudformationAttribute: LicenseArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLicenseArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrVersion")
    def attr_version(self) -> builtins.str:
        '''The license version.

        :cloudformationAttribute: Version
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrVersion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="consumptionConfiguration")
    def consumption_configuration(
        self,
    ) -> typing.Union["CfnLicense.ConsumptionConfigurationProperty", _IResolvable_da3f097b]:
        '''Configuration for consumption of the license.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-consumptionconfiguration
        '''
        return typing.cast(typing.Union["CfnLicense.ConsumptionConfigurationProperty", _IResolvable_da3f097b], jsii.get(self, "consumptionConfiguration"))

    @consumption_configuration.setter
    def consumption_configuration(
        self,
        value: typing.Union["CfnLicense.ConsumptionConfigurationProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "consumptionConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="entitlements")
    def entitlements(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLicense.EntitlementProperty", _IResolvable_da3f097b]]]:
        '''License entitlements.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-entitlements
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLicense.EntitlementProperty", _IResolvable_da3f097b]]], jsii.get(self, "entitlements"))

    @entitlements.setter
    def entitlements(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLicense.EntitlementProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "entitlements", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="homeRegion")
    def home_region(self) -> builtins.str:
        '''Home Region of the license.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-homeregion
        '''
        return typing.cast(builtins.str, jsii.get(self, "homeRegion"))

    @home_region.setter
    def home_region(self, value: builtins.str) -> None:
        jsii.set(self, "homeRegion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="issuer")
    def issuer(
        self,
    ) -> typing.Union["CfnLicense.IssuerDataProperty", _IResolvable_da3f097b]:
        '''License issuer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-issuer
        '''
        return typing.cast(typing.Union["CfnLicense.IssuerDataProperty", _IResolvable_da3f097b], jsii.get(self, "issuer"))

    @issuer.setter
    def issuer(
        self,
        value: typing.Union["CfnLicense.IssuerDataProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "issuer", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="licenseName")
    def license_name(self) -> builtins.str:
        '''License name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-licensename
        '''
        return typing.cast(builtins.str, jsii.get(self, "licenseName"))

    @license_name.setter
    def license_name(self, value: builtins.str) -> None:
        jsii.set(self, "licenseName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="productName")
    def product_name(self) -> builtins.str:
        '''Product name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-productname
        '''
        return typing.cast(builtins.str, jsii.get(self, "productName"))

    @product_name.setter
    def product_name(self, value: builtins.str) -> None:
        jsii.set(self, "productName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="validity")
    def validity(
        self,
    ) -> typing.Union["CfnLicense.ValidityDateFormatProperty", _IResolvable_da3f097b]:
        '''Date and time range during which the license is valid, in ISO8601-UTC format.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-validity
        '''
        return typing.cast(typing.Union["CfnLicense.ValidityDateFormatProperty", _IResolvable_da3f097b], jsii.get(self, "validity"))

    @validity.setter
    def validity(
        self,
        value: typing.Union["CfnLicense.ValidityDateFormatProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "validity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="beneficiary")
    def beneficiary(self) -> typing.Optional[builtins.str]:
        '''License beneficiary.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-beneficiary
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "beneficiary"))

    @beneficiary.setter
    def beneficiary(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "beneficiary", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="licenseMetadata")
    def license_metadata(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLicense.MetadataProperty", _IResolvable_da3f097b]]]]:
        '''License metadata.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-licensemetadata
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLicense.MetadataProperty", _IResolvable_da3f097b]]]], jsii.get(self, "licenseMetadata"))

    @license_metadata.setter
    def license_metadata(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLicense.MetadataProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "licenseMetadata", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="productSku")
    def product_sku(self) -> typing.Optional[builtins.str]:
        '''Product SKU.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-productsku
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "productSku"))

    @product_sku.setter
    def product_sku(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "productSku", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="status")
    def status(self) -> typing.Optional[builtins.str]:
        '''License status.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-status
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "status"))

    @status.setter
    def status(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "status", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_licensemanager.CfnLicense.BorrowConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "allow_early_check_in": "allowEarlyCheckIn",
            "max_time_to_live_in_minutes": "maxTimeToLiveInMinutes",
        },
    )
    class BorrowConfigurationProperty:
        def __init__(
            self,
            *,
            allow_early_check_in: typing.Union[builtins.bool, _IResolvable_da3f097b],
            max_time_to_live_in_minutes: jsii.Number,
        ) -> None:
            '''Details about a borrow configuration.

            :param allow_early_check_in: Indicates whether early check-ins are allowed.
            :param max_time_to_live_in_minutes: Maximum time for the borrow configuration, in minutes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-borrowconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_licensemanager as licensemanager
                
                borrow_configuration_property = licensemanager.CfnLicense.BorrowConfigurationProperty(
                    allow_early_check_in=False,
                    max_time_to_live_in_minutes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "allow_early_check_in": allow_early_check_in,
                "max_time_to_live_in_minutes": max_time_to_live_in_minutes,
            }

        @builtins.property
        def allow_early_check_in(
            self,
        ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Indicates whether early check-ins are allowed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-borrowconfiguration.html#cfn-licensemanager-license-borrowconfiguration-allowearlycheckin
            '''
            result = self._values.get("allow_early_check_in")
            assert result is not None, "Required property 'allow_early_check_in' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def max_time_to_live_in_minutes(self) -> jsii.Number:
            '''Maximum time for the borrow configuration, in minutes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-borrowconfiguration.html#cfn-licensemanager-license-borrowconfiguration-maxtimetoliveinminutes
            '''
            result = self._values.get("max_time_to_live_in_minutes")
            assert result is not None, "Required property 'max_time_to_live_in_minutes' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BorrowConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_licensemanager.CfnLicense.ConsumptionConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "borrow_configuration": "borrowConfiguration",
            "provisional_configuration": "provisionalConfiguration",
            "renew_type": "renewType",
        },
    )
    class ConsumptionConfigurationProperty:
        def __init__(
            self,
            *,
            borrow_configuration: typing.Optional[typing.Union["CfnLicense.BorrowConfigurationProperty", _IResolvable_da3f097b]] = None,
            provisional_configuration: typing.Optional[typing.Union["CfnLicense.ProvisionalConfigurationProperty", _IResolvable_da3f097b]] = None,
            renew_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Details about a consumption configuration.

            :param borrow_configuration: Details about a borrow configuration.
            :param provisional_configuration: Details about a provisional configuration.
            :param renew_type: Renewal frequency.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-consumptionconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_licensemanager as licensemanager
                
                consumption_configuration_property = licensemanager.CfnLicense.ConsumptionConfigurationProperty(
                    borrow_configuration=licensemanager.CfnLicense.BorrowConfigurationProperty(
                        allow_early_check_in=False,
                        max_time_to_live_in_minutes=123
                    ),
                    provisional_configuration=licensemanager.CfnLicense.ProvisionalConfigurationProperty(
                        max_time_to_live_in_minutes=123
                    ),
                    renew_type="renewType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if borrow_configuration is not None:
                self._values["borrow_configuration"] = borrow_configuration
            if provisional_configuration is not None:
                self._values["provisional_configuration"] = provisional_configuration
            if renew_type is not None:
                self._values["renew_type"] = renew_type

        @builtins.property
        def borrow_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnLicense.BorrowConfigurationProperty", _IResolvable_da3f097b]]:
            '''Details about a borrow configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-consumptionconfiguration.html#cfn-licensemanager-license-consumptionconfiguration-borrowconfiguration
            '''
            result = self._values.get("borrow_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnLicense.BorrowConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def provisional_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnLicense.ProvisionalConfigurationProperty", _IResolvable_da3f097b]]:
            '''Details about a provisional configuration.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-consumptionconfiguration.html#cfn-licensemanager-license-consumptionconfiguration-provisionalconfiguration
            '''
            result = self._values.get("provisional_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnLicense.ProvisionalConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def renew_type(self) -> typing.Optional[builtins.str]:
            '''Renewal frequency.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-consumptionconfiguration.html#cfn-licensemanager-license-consumptionconfiguration-renewtype
            '''
            result = self._values.get("renew_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConsumptionConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_licensemanager.CfnLicense.EntitlementProperty",
        jsii_struct_bases=[],
        name_mapping={
            "name": "name",
            "unit": "unit",
            "allow_check_in": "allowCheckIn",
            "max_count": "maxCount",
            "overage": "overage",
            "value": "value",
        },
    )
    class EntitlementProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            unit: builtins.str,
            allow_check_in: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            max_count: typing.Optional[jsii.Number] = None,
            overage: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Describes a resource entitled for use with a license.

            :param name: Entitlement name.
            :param unit: Entitlement unit.
            :param allow_check_in: Indicates whether check-ins are allowed.
            :param max_count: Maximum entitlement count. Use if the unit is not None.
            :param overage: Indicates whether overages are allowed.
            :param value: Entitlement resource. Use only if the unit is None.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-entitlement.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_licensemanager as licensemanager
                
                entitlement_property = licensemanager.CfnLicense.EntitlementProperty(
                    name="name",
                    unit="unit",
                
                    # the properties below are optional
                    allow_check_in=False,
                    max_count=123,
                    overage=False,
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "unit": unit,
            }
            if allow_check_in is not None:
                self._values["allow_check_in"] = allow_check_in
            if max_count is not None:
                self._values["max_count"] = max_count
            if overage is not None:
                self._values["overage"] = overage
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def name(self) -> builtins.str:
            '''Entitlement name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-entitlement.html#cfn-licensemanager-license-entitlement-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def unit(self) -> builtins.str:
            '''Entitlement unit.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-entitlement.html#cfn-licensemanager-license-entitlement-unit
            '''
            result = self._values.get("unit")
            assert result is not None, "Required property 'unit' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def allow_check_in(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether check-ins are allowed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-entitlement.html#cfn-licensemanager-license-entitlement-allowcheckin
            '''
            result = self._values.get("allow_check_in")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def max_count(self) -> typing.Optional[jsii.Number]:
            '''Maximum entitlement count.

            Use if the unit is not None.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-entitlement.html#cfn-licensemanager-license-entitlement-maxcount
            '''
            result = self._values.get("max_count")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def overage(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether overages are allowed.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-entitlement.html#cfn-licensemanager-license-entitlement-overage
            '''
            result = self._values.get("overage")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''Entitlement resource.

            Use only if the unit is None.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-entitlement.html#cfn-licensemanager-license-entitlement-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EntitlementProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_licensemanager.CfnLicense.IssuerDataProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "sign_key": "signKey"},
    )
    class IssuerDataProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            sign_key: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Details associated with the issuer of a license.

            :param name: Issuer name.
            :param sign_key: Asymmetric KMS key from AWS Key Management Service . The KMS key must have a key usage of sign and verify, and support the RSASSA-PSS SHA-256 signing algorithm.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-issuerdata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_licensemanager as licensemanager
                
                issuer_data_property = licensemanager.CfnLicense.IssuerDataProperty(
                    name="name",
                
                    # the properties below are optional
                    sign_key="signKey"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }
            if sign_key is not None:
                self._values["sign_key"] = sign_key

        @builtins.property
        def name(self) -> builtins.str:
            '''Issuer name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-issuerdata.html#cfn-licensemanager-license-issuerdata-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sign_key(self) -> typing.Optional[builtins.str]:
            '''Asymmetric KMS key from AWS Key Management Service .

            The KMS key must have a key usage of sign and verify, and support the RSASSA-PSS SHA-256 signing algorithm.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-issuerdata.html#cfn-licensemanager-license-issuerdata-signkey
            '''
            result = self._values.get("sign_key")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "IssuerDataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_licensemanager.CfnLicense.MetadataProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class MetadataProperty:
        def __init__(self, *, name: builtins.str, value: builtins.str) -> None:
            '''Describes key/value pairs.

            :param name: The key name.
            :param value: The value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-metadata.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_licensemanager as licensemanager
                
                metadata_property = licensemanager.CfnLicense.MetadataProperty(
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
            '''The key name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-metadata.html#cfn-licensemanager-license-metadata-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-metadata.html#cfn-licensemanager-license-metadata-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MetadataProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_licensemanager.CfnLicense.ProvisionalConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"max_time_to_live_in_minutes": "maxTimeToLiveInMinutes"},
    )
    class ProvisionalConfigurationProperty:
        def __init__(self, *, max_time_to_live_in_minutes: jsii.Number) -> None:
            '''Details about a provisional configuration.

            :param max_time_to_live_in_minutes: Maximum time for the provisional configuration, in minutes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-provisionalconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_licensemanager as licensemanager
                
                provisional_configuration_property = licensemanager.CfnLicense.ProvisionalConfigurationProperty(
                    max_time_to_live_in_minutes=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "max_time_to_live_in_minutes": max_time_to_live_in_minutes,
            }

        @builtins.property
        def max_time_to_live_in_minutes(self) -> jsii.Number:
            '''Maximum time for the provisional configuration, in minutes.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-provisionalconfiguration.html#cfn-licensemanager-license-provisionalconfiguration-maxtimetoliveinminutes
            '''
            result = self._values.get("max_time_to_live_in_minutes")
            assert result is not None, "Required property 'max_time_to_live_in_minutes' is missing"
            return typing.cast(jsii.Number, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ProvisionalConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_licensemanager.CfnLicense.ValidityDateFormatProperty",
        jsii_struct_bases=[],
        name_mapping={"begin": "begin", "end": "end"},
    )
    class ValidityDateFormatProperty:
        def __init__(self, *, begin: builtins.str, end: builtins.str) -> None:
            '''Date and time range during which the license is valid, in ISO8601-UTC format.

            :param begin: Start of the time range.
            :param end: End of the time range.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-validitydateformat.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_licensemanager as licensemanager
                
                validity_date_format_property = licensemanager.CfnLicense.ValidityDateFormatProperty(
                    begin="begin",
                    end="end"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "begin": begin,
                "end": end,
            }

        @builtins.property
        def begin(self) -> builtins.str:
            '''Start of the time range.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-validitydateformat.html#cfn-licensemanager-license-validitydateformat-begin
            '''
            result = self._values.get("begin")
            assert result is not None, "Required property 'begin' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def end(self) -> builtins.str:
            '''End of the time range.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-licensemanager-license-validitydateformat.html#cfn-licensemanager-license-validitydateformat-end
            '''
            result = self._values.get("end")
            assert result is not None, "Required property 'end' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ValidityDateFormatProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_licensemanager.CfnLicenseProps",
    jsii_struct_bases=[],
    name_mapping={
        "consumption_configuration": "consumptionConfiguration",
        "entitlements": "entitlements",
        "home_region": "homeRegion",
        "issuer": "issuer",
        "license_name": "licenseName",
        "product_name": "productName",
        "validity": "validity",
        "beneficiary": "beneficiary",
        "license_metadata": "licenseMetadata",
        "product_sku": "productSku",
        "status": "status",
    },
)
class CfnLicenseProps:
    def __init__(
        self,
        *,
        consumption_configuration: typing.Union[CfnLicense.ConsumptionConfigurationProperty, _IResolvable_da3f097b],
        entitlements: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnLicense.EntitlementProperty, _IResolvable_da3f097b]]],
        home_region: builtins.str,
        issuer: typing.Union[CfnLicense.IssuerDataProperty, _IResolvable_da3f097b],
        license_name: builtins.str,
        product_name: builtins.str,
        validity: typing.Union[CfnLicense.ValidityDateFormatProperty, _IResolvable_da3f097b],
        beneficiary: typing.Optional[builtins.str] = None,
        license_metadata: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnLicense.MetadataProperty, _IResolvable_da3f097b]]]] = None,
        product_sku: typing.Optional[builtins.str] = None,
        status: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnLicense``.

        :param consumption_configuration: Configuration for consumption of the license.
        :param entitlements: License entitlements.
        :param home_region: Home Region of the license.
        :param issuer: License issuer.
        :param license_name: License name.
        :param product_name: Product name.
        :param validity: Date and time range during which the license is valid, in ISO8601-UTC format.
        :param beneficiary: License beneficiary.
        :param license_metadata: License metadata.
        :param product_sku: Product SKU.
        :param status: License status.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_licensemanager as licensemanager
            
            cfn_license_props = licensemanager.CfnLicenseProps(
                consumption_configuration=licensemanager.CfnLicense.ConsumptionConfigurationProperty(
                    borrow_configuration=licensemanager.CfnLicense.BorrowConfigurationProperty(
                        allow_early_check_in=False,
                        max_time_to_live_in_minutes=123
                    ),
                    provisional_configuration=licensemanager.CfnLicense.ProvisionalConfigurationProperty(
                        max_time_to_live_in_minutes=123
                    ),
                    renew_type="renewType"
                ),
                entitlements=[licensemanager.CfnLicense.EntitlementProperty(
                    name="name",
                    unit="unit",
            
                    # the properties below are optional
                    allow_check_in=False,
                    max_count=123,
                    overage=False,
                    value="value"
                )],
                home_region="homeRegion",
                issuer=licensemanager.CfnLicense.IssuerDataProperty(
                    name="name",
            
                    # the properties below are optional
                    sign_key="signKey"
                ),
                license_name="licenseName",
                product_name="productName",
                validity=licensemanager.CfnLicense.ValidityDateFormatProperty(
                    begin="begin",
                    end="end"
                ),
            
                # the properties below are optional
                beneficiary="beneficiary",
                license_metadata=[licensemanager.CfnLicense.MetadataProperty(
                    name="name",
                    value="value"
                )],
                product_sku="productSku",
                status="status"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "consumption_configuration": consumption_configuration,
            "entitlements": entitlements,
            "home_region": home_region,
            "issuer": issuer,
            "license_name": license_name,
            "product_name": product_name,
            "validity": validity,
        }
        if beneficiary is not None:
            self._values["beneficiary"] = beneficiary
        if license_metadata is not None:
            self._values["license_metadata"] = license_metadata
        if product_sku is not None:
            self._values["product_sku"] = product_sku
        if status is not None:
            self._values["status"] = status

    @builtins.property
    def consumption_configuration(
        self,
    ) -> typing.Union[CfnLicense.ConsumptionConfigurationProperty, _IResolvable_da3f097b]:
        '''Configuration for consumption of the license.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-consumptionconfiguration
        '''
        result = self._values.get("consumption_configuration")
        assert result is not None, "Required property 'consumption_configuration' is missing"
        return typing.cast(typing.Union[CfnLicense.ConsumptionConfigurationProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def entitlements(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLicense.EntitlementProperty, _IResolvable_da3f097b]]]:
        '''License entitlements.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-entitlements
        '''
        result = self._values.get("entitlements")
        assert result is not None, "Required property 'entitlements' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLicense.EntitlementProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def home_region(self) -> builtins.str:
        '''Home Region of the license.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-homeregion
        '''
        result = self._values.get("home_region")
        assert result is not None, "Required property 'home_region' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def issuer(
        self,
    ) -> typing.Union[CfnLicense.IssuerDataProperty, _IResolvable_da3f097b]:
        '''License issuer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-issuer
        '''
        result = self._values.get("issuer")
        assert result is not None, "Required property 'issuer' is missing"
        return typing.cast(typing.Union[CfnLicense.IssuerDataProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def license_name(self) -> builtins.str:
        '''License name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-licensename
        '''
        result = self._values.get("license_name")
        assert result is not None, "Required property 'license_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def product_name(self) -> builtins.str:
        '''Product name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-productname
        '''
        result = self._values.get("product_name")
        assert result is not None, "Required property 'product_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def validity(
        self,
    ) -> typing.Union[CfnLicense.ValidityDateFormatProperty, _IResolvable_da3f097b]:
        '''Date and time range during which the license is valid, in ISO8601-UTC format.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-validity
        '''
        result = self._values.get("validity")
        assert result is not None, "Required property 'validity' is missing"
        return typing.cast(typing.Union[CfnLicense.ValidityDateFormatProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def beneficiary(self) -> typing.Optional[builtins.str]:
        '''License beneficiary.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-beneficiary
        '''
        result = self._values.get("beneficiary")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def license_metadata(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLicense.MetadataProperty, _IResolvable_da3f097b]]]]:
        '''License metadata.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-licensemetadata
        '''
        result = self._values.get("license_metadata")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLicense.MetadataProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def product_sku(self) -> typing.Optional[builtins.str]:
        '''Product SKU.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-productsku
        '''
        result = self._values.get("product_sku")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def status(self) -> typing.Optional[builtins.str]:
        '''License status.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-licensemanager-license.html#cfn-licensemanager-license-status
        '''
        result = self._values.get("status")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLicenseProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnGrant",
    "CfnGrantProps",
    "CfnLicense",
    "CfnLicenseProps",
]

publication.publish()
