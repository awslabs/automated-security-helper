'''
# AWS::Signer Construct Library

AWS Signer is a fully managed code-signing service to ensure the trust and integrity of your code. Organizations validate code against
a digital signature to confirm that the code is unaltered and from a trusted publisher. For more information, see [What Is AWS
Signer?](https://docs.aws.amazon.com/signer/latest/developerguide/Welcome.html)

## Table of Contents

* [Signing Platform](#signing-platform)
* [Signing Profile](#signing-profile)

## Signing Platform

A signing platform is a predefined set of instructions that specifies the signature format and signing algorithms that AWS Signer should use
to sign a zip file. For more information go to [Signing Platforms in AWS Signer](https://docs.aws.amazon.com/signer/latest/developerguide/gs-platform.html).

AWS Signer provides a pre-defined set of signing platforms. They are available in the CDK as -

```text
Platform.AWS_IOT_DEVICE_MANAGEMENT_SHA256_ECDSA
Platform.AWS_LAMBDA_SHA384_ECDSA
Platform.AMAZON_FREE_RTOS_TI_CC3220SF
Platform.AMAZON_FREE_RTOS_DEFAULT
```

## Signing Profile

A signing profile is a code-signing template that can be used to pre-define the signature specifications for a signing job.
A signing profile includes a signing platform to designate the file type to be signed, the signature format, and the signature algorithms.
For more information, visit [Signing Profiles in AWS Signer](https://docs.aws.amazon.com/signer/latest/developerguide/gs-profile.html).

The following code sets up a signing profile for signing lambda code bundles -

```python
signing_profile = signer.SigningProfile(self, "SigningProfile",
    platform=signer.Platform.AWS_LAMBDA_SHA384_ECDSA
)
```

A signing profile is valid by default for 135 months. This can be modified by specifying the `signatureValidityPeriod` property.
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
    Resource as _Resource_45bc6135,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnProfilePermission(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_signer.CfnProfilePermission",
):
    '''A CloudFormation ``AWS::Signer::ProfilePermission``.

    Adds cross-account permissions to a signing profile.

    :cloudformationResource: AWS::Signer::ProfilePermission
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_signer as signer
        
        cfn_profile_permission = signer.CfnProfilePermission(self, "MyCfnProfilePermission",
            action="action",
            principal="principal",
            profile_name="profileName",
            statement_id="statementId",
        
            # the properties below are optional
            profile_version="profileVersion"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        action: builtins.str,
        principal: builtins.str,
        profile_name: builtins.str,
        statement_id: builtins.str,
        profile_version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Signer::ProfilePermission``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param action: The AWS Signer action permitted as part of cross-account permissions.
        :param principal: The AWS principal receiving cross-account permissions. This may be an IAM role or another AWS account ID.
        :param profile_name: The human-readable name of the signing profile.
        :param statement_id: A unique identifier for the cross-account permission statement.
        :param profile_version: The version of the signing profile.
        '''
        props = CfnProfilePermissionProps(
            action=action,
            principal=principal,
            profile_name=profile_name,
            statement_id=statement_id,
            profile_version=profile_version,
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
    @jsii.member(jsii_name="action")
    def action(self) -> builtins.str:
        '''The AWS Signer action permitted as part of cross-account permissions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html#cfn-signer-profilepermission-action
        '''
        return typing.cast(builtins.str, jsii.get(self, "action"))

    @action.setter
    def action(self, value: builtins.str) -> None:
        jsii.set(self, "action", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principal")
    def principal(self) -> builtins.str:
        '''The AWS principal receiving cross-account permissions.

        This may be an IAM role or another AWS account ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html#cfn-signer-profilepermission-principal
        '''
        return typing.cast(builtins.str, jsii.get(self, "principal"))

    @principal.setter
    def principal(self, value: builtins.str) -> None:
        jsii.set(self, "principal", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="profileName")
    def profile_name(self) -> builtins.str:
        '''The human-readable name of the signing profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html#cfn-signer-profilepermission-profilename
        '''
        return typing.cast(builtins.str, jsii.get(self, "profileName"))

    @profile_name.setter
    def profile_name(self, value: builtins.str) -> None:
        jsii.set(self, "profileName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="statementId")
    def statement_id(self) -> builtins.str:
        '''A unique identifier for the cross-account permission statement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html#cfn-signer-profilepermission-statementid
        '''
        return typing.cast(builtins.str, jsii.get(self, "statementId"))

    @statement_id.setter
    def statement_id(self, value: builtins.str) -> None:
        jsii.set(self, "statementId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="profileVersion")
    def profile_version(self) -> typing.Optional[builtins.str]:
        '''The version of the signing profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html#cfn-signer-profilepermission-profileversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "profileVersion"))

    @profile_version.setter
    def profile_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "profileVersion", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_signer.CfnProfilePermissionProps",
    jsii_struct_bases=[],
    name_mapping={
        "action": "action",
        "principal": "principal",
        "profile_name": "profileName",
        "statement_id": "statementId",
        "profile_version": "profileVersion",
    },
)
class CfnProfilePermissionProps:
    def __init__(
        self,
        *,
        action: builtins.str,
        principal: builtins.str,
        profile_name: builtins.str,
        statement_id: builtins.str,
        profile_version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnProfilePermission``.

        :param action: The AWS Signer action permitted as part of cross-account permissions.
        :param principal: The AWS principal receiving cross-account permissions. This may be an IAM role or another AWS account ID.
        :param profile_name: The human-readable name of the signing profile.
        :param statement_id: A unique identifier for the cross-account permission statement.
        :param profile_version: The version of the signing profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_signer as signer
            
            cfn_profile_permission_props = signer.CfnProfilePermissionProps(
                action="action",
                principal="principal",
                profile_name="profileName",
                statement_id="statementId",
            
                # the properties below are optional
                profile_version="profileVersion"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "action": action,
            "principal": principal,
            "profile_name": profile_name,
            "statement_id": statement_id,
        }
        if profile_version is not None:
            self._values["profile_version"] = profile_version

    @builtins.property
    def action(self) -> builtins.str:
        '''The AWS Signer action permitted as part of cross-account permissions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html#cfn-signer-profilepermission-action
        '''
        result = self._values.get("action")
        assert result is not None, "Required property 'action' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def principal(self) -> builtins.str:
        '''The AWS principal receiving cross-account permissions.

        This may be an IAM role or another AWS account ID.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html#cfn-signer-profilepermission-principal
        '''
        result = self._values.get("principal")
        assert result is not None, "Required property 'principal' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def profile_name(self) -> builtins.str:
        '''The human-readable name of the signing profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html#cfn-signer-profilepermission-profilename
        '''
        result = self._values.get("profile_name")
        assert result is not None, "Required property 'profile_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def statement_id(self) -> builtins.str:
        '''A unique identifier for the cross-account permission statement.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html#cfn-signer-profilepermission-statementid
        '''
        result = self._values.get("statement_id")
        assert result is not None, "Required property 'statement_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def profile_version(self) -> typing.Optional[builtins.str]:
        '''The version of the signing profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-profilepermission.html#cfn-signer-profilepermission-profileversion
        '''
        result = self._values.get("profile_version")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnProfilePermissionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSigningProfile(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_signer.CfnSigningProfile",
):
    '''A CloudFormation ``AWS::Signer::SigningProfile``.

    Creates a signing profile. A signing profile is a code signing template that can be used to carry out a pre-defined signing job.

    :cloudformationResource: AWS::Signer::SigningProfile
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-signingprofile.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_signer as signer
        
        cfn_signing_profile = signer.CfnSigningProfile(self, "MyCfnSigningProfile",
            platform_id="platformId",
        
            # the properties below are optional
            signature_validity_period=signer.CfnSigningProfile.SignatureValidityPeriodProperty(
                type="type",
                value=123
            ),
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
        platform_id: builtins.str,
        signature_validity_period: typing.Optional[typing.Union["CfnSigningProfile.SignatureValidityPeriodProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::Signer::SigningProfile``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param platform_id: The ID of a platform that is available for use by a signing profile.
        :param signature_validity_period: The validity period override for any signature generated using this signing profile. If unspecified, the default is 135 months.
        :param tags: A list of tags associated with the signing profile.
        '''
        props = CfnSigningProfileProps(
            platform_id=platform_id,
            signature_validity_period=signature_validity_period,
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
    @jsii.member(jsii_name="attrProfileName")
    def attr_profile_name(self) -> builtins.str:
        '''
        :cloudformationAttribute: ProfileName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrProfileName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrProfileVersion")
    def attr_profile_version(self) -> builtins.str:
        '''
        :cloudformationAttribute: ProfileVersion
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrProfileVersion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrProfileVersionArn")
    def attr_profile_version_arn(self) -> builtins.str:
        '''
        :cloudformationAttribute: ProfileVersionArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrProfileVersionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A list of tags associated with the signing profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-signingprofile.html#cfn-signer-signingprofile-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="platformId")
    def platform_id(self) -> builtins.str:
        '''The ID of a platform that is available for use by a signing profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-signingprofile.html#cfn-signer-signingprofile-platformid
        '''
        return typing.cast(builtins.str, jsii.get(self, "platformId"))

    @platform_id.setter
    def platform_id(self, value: builtins.str) -> None:
        jsii.set(self, "platformId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signatureValidityPeriod")
    def signature_validity_period(
        self,
    ) -> typing.Optional[typing.Union["CfnSigningProfile.SignatureValidityPeriodProperty", _IResolvable_da3f097b]]:
        '''The validity period override for any signature generated using this signing profile.

        If unspecified, the default is 135 months.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-signingprofile.html#cfn-signer-signingprofile-signaturevalidityperiod
        '''
        return typing.cast(typing.Optional[typing.Union["CfnSigningProfile.SignatureValidityPeriodProperty", _IResolvable_da3f097b]], jsii.get(self, "signatureValidityPeriod"))

    @signature_validity_period.setter
    def signature_validity_period(
        self,
        value: typing.Optional[typing.Union["CfnSigningProfile.SignatureValidityPeriodProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "signatureValidityPeriod", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_signer.CfnSigningProfile.SignatureValidityPeriodProperty",
        jsii_struct_bases=[],
        name_mapping={"type": "type", "value": "value"},
    )
    class SignatureValidityPeriodProperty:
        def __init__(
            self,
            *,
            type: typing.Optional[builtins.str] = None,
            value: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The validity period for the signing job.

            :param type: The time unit for signature validity: DAYS | MONTHS | YEARS.
            :param value: The numerical value of the time unit for signature validity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-signer-signingprofile-signaturevalidityperiod.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_signer as signer
                
                signature_validity_period_property = signer.CfnSigningProfile.SignatureValidityPeriodProperty(
                    type="type",
                    value=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if type is not None:
                self._values["type"] = type
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''The time unit for signature validity: DAYS | MONTHS | YEARS.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-signer-signingprofile-signaturevalidityperiod.html#cfn-signer-signingprofile-signaturevalidityperiod-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[jsii.Number]:
            '''The numerical value of the time unit for signature validity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-signer-signingprofile-signaturevalidityperiod.html#cfn-signer-signingprofile-signaturevalidityperiod-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SignatureValidityPeriodProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_signer.CfnSigningProfileProps",
    jsii_struct_bases=[],
    name_mapping={
        "platform_id": "platformId",
        "signature_validity_period": "signatureValidityPeriod",
        "tags": "tags",
    },
)
class CfnSigningProfileProps:
    def __init__(
        self,
        *,
        platform_id: builtins.str,
        signature_validity_period: typing.Optional[typing.Union[CfnSigningProfile.SignatureValidityPeriodProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnSigningProfile``.

        :param platform_id: The ID of a platform that is available for use by a signing profile.
        :param signature_validity_period: The validity period override for any signature generated using this signing profile. If unspecified, the default is 135 months.
        :param tags: A list of tags associated with the signing profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-signingprofile.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_signer as signer
            
            cfn_signing_profile_props = signer.CfnSigningProfileProps(
                platform_id="platformId",
            
                # the properties below are optional
                signature_validity_period=signer.CfnSigningProfile.SignatureValidityPeriodProperty(
                    type="type",
                    value=123
                ),
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "platform_id": platform_id,
        }
        if signature_validity_period is not None:
            self._values["signature_validity_period"] = signature_validity_period
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def platform_id(self) -> builtins.str:
        '''The ID of a platform that is available for use by a signing profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-signingprofile.html#cfn-signer-signingprofile-platformid
        '''
        result = self._values.get("platform_id")
        assert result is not None, "Required property 'platform_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def signature_validity_period(
        self,
    ) -> typing.Optional[typing.Union[CfnSigningProfile.SignatureValidityPeriodProperty, _IResolvable_da3f097b]]:
        '''The validity period override for any signature generated using this signing profile.

        If unspecified, the default is 135 months.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-signingprofile.html#cfn-signer-signingprofile-signaturevalidityperiod
        '''
        result = self._values.get("signature_validity_period")
        return typing.cast(typing.Optional[typing.Union[CfnSigningProfile.SignatureValidityPeriodProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''A list of tags associated with the signing profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-signingprofile.html#cfn-signer-signingprofile-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSigningProfileProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_signer.ISigningProfile")
class ISigningProfile(_IResource_c80c4260, typing_extensions.Protocol):
    '''A Signer Profile.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileArn")
    def signing_profile_arn(self) -> builtins.str:
        '''The ARN of the signing profile.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileName")
    def signing_profile_name(self) -> builtins.str:
        '''The name of signing profile.

        :attribute: ProfileName
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileVersion")
    def signing_profile_version(self) -> builtins.str:
        '''The version of signing profile.

        :attribute: ProfileVersion
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileVersionArn")
    def signing_profile_version_arn(self) -> builtins.str:
        '''The ARN of signing profile version.

        :attribute: ProfileVersionArn
        '''
        ...


class _ISigningProfileProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''A Signer Profile.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_signer.ISigningProfile"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileArn")
    def signing_profile_arn(self) -> builtins.str:
        '''The ARN of the signing profile.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "signingProfileArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileName")
    def signing_profile_name(self) -> builtins.str:
        '''The name of signing profile.

        :attribute: ProfileName
        '''
        return typing.cast(builtins.str, jsii.get(self, "signingProfileName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileVersion")
    def signing_profile_version(self) -> builtins.str:
        '''The version of signing profile.

        :attribute: ProfileVersion
        '''
        return typing.cast(builtins.str, jsii.get(self, "signingProfileVersion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileVersionArn")
    def signing_profile_version_arn(self) -> builtins.str:
        '''The ARN of signing profile version.

        :attribute: ProfileVersionArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "signingProfileVersionArn"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ISigningProfile).__jsii_proxy_class__ = lambda : _ISigningProfileProxy


class Platform(metaclass=jsii.JSIIMeta, jsii_type="aws-cdk-lib.aws_signer.Platform"):
    '''Platforms that are allowed with signing config.

    :see: https://docs.aws.amazon.com/signer/latest/developerguide/gs-platform.html
    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_signer as signer
        
        
        signing_profile = signer.SigningProfile(self, "SigningProfile",
            platform=signer.Platform.AWS_LAMBDA_SHA384_ECDSA
        )
        
        code_signing_config = lambda_.CodeSigningConfig(self, "CodeSigningConfig",
            signing_profiles=[signing_profile]
        )
        
        lambda_.Function(self, "Function",
            code_signing_config=code_signing_config,
            runtime=lambda_.Runtime.NODEJS_12_X,
            handler="index.handler",
            code=lambda_.Code.from_asset(path.join(__dirname, "lambda-handler"))
        )
    '''

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="AMAZON_FREE_RTOS_DEFAULT")
    def AMAZON_FREE_RTOS_DEFAULT(cls) -> "Platform":
        '''Specification of signature format and signing algorithms with SHA256 hash and ECDSA encryption for Amazon FreeRTOS.'''
        return typing.cast("Platform", jsii.sget(cls, "AMAZON_FREE_RTOS_DEFAULT"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="AMAZON_FREE_RTOS_TI_CC3220SF")
    def AMAZON_FREE_RTOS_TI_CC3220_SF(cls) -> "Platform":
        '''Specification of signature format and signing algorithms with SHA1 hash and RSA encryption for Amazon FreeRTOS.'''
        return typing.cast("Platform", jsii.sget(cls, "AMAZON_FREE_RTOS_TI_CC3220SF"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="AWS_IOT_DEVICE_MANAGEMENT_SHA256_ECDSA")
    def AWS_IOT_DEVICE_MANAGEMENT_SHA256_ECDSA(cls) -> "Platform":
        '''Specification of signature format and signing algorithms for AWS IoT Device.'''
        return typing.cast("Platform", jsii.sget(cls, "AWS_IOT_DEVICE_MANAGEMENT_SHA256_ECDSA"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="AWS_LAMBDA_SHA384_ECDSA")
    def AWS_LAMBDA_SHA384_ECDSA(cls) -> "Platform":
        '''Specification of signature format and signing algorithms for AWS Lambda.'''
        return typing.cast("Platform", jsii.sget(cls, "AWS_LAMBDA_SHA384_ECDSA"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="platformId")
    def platform_id(self) -> builtins.str:
        '''The id of signing platform.

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-signer-signingprofile.html#cfn-signer-signingprofile-platformid
        '''
        return typing.cast(builtins.str, jsii.get(self, "platformId"))


@jsii.implements(ISigningProfile)
class SigningProfile(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_signer.SigningProfile",
):
    '''Defines a Signing Profile.

    :exampleMetadata: infused
    :resource: AWS::Signer::SigningProfile

    Example::

        import aws_cdk.aws_signer as signer
        
        
        signing_profile = signer.SigningProfile(self, "SigningProfile",
            platform=signer.Platform.AWS_LAMBDA_SHA384_ECDSA
        )
        
        code_signing_config = lambda_.CodeSigningConfig(self, "CodeSigningConfig",
            signing_profiles=[signing_profile]
        )
        
        lambda_.Function(self, "Function",
            code_signing_config=code_signing_config,
            runtime=lambda_.Runtime.NODEJS_12_X,
            handler="index.handler",
            code=lambda_.Code.from_asset(path.join(__dirname, "lambda-handler"))
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        platform: Platform,
        signature_validity: typing.Optional[_Duration_4839e8c3] = None,
        signing_profile_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param platform: The Signing Platform available for signing profile.
        :param signature_validity: The validity period for signatures generated using this signing profile. Default: - 135 months
        :param signing_profile_name: Physical name of this Signing Profile. Default: - Assigned by CloudFormation (recommended).
        '''
        props = SigningProfileProps(
            platform=platform,
            signature_validity=signature_validity,
            signing_profile_name=signing_profile_name,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromSigningProfileAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_signing_profile_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        signing_profile_name: builtins.str,
        signing_profile_version: builtins.str,
    ) -> ISigningProfile:
        '''Creates a Signing Profile construct that represents an external Signing Profile.

        :param scope: The parent creating construct (usually ``this``).
        :param id: The construct's name.
        :param signing_profile_name: The name of signing profile.
        :param signing_profile_version: The version of signing profile.
        '''
        attrs = SigningProfileAttributes(
            signing_profile_name=signing_profile_name,
            signing_profile_version=signing_profile_version,
        )

        return typing.cast(ISigningProfile, jsii.sinvoke(cls, "fromSigningProfileAttributes", [scope, id, attrs]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileArn")
    def signing_profile_arn(self) -> builtins.str:
        '''The ARN of the signing profile.'''
        return typing.cast(builtins.str, jsii.get(self, "signingProfileArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileName")
    def signing_profile_name(self) -> builtins.str:
        '''The name of signing profile.'''
        return typing.cast(builtins.str, jsii.get(self, "signingProfileName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileVersion")
    def signing_profile_version(self) -> builtins.str:
        '''The version of signing profile.'''
        return typing.cast(builtins.str, jsii.get(self, "signingProfileVersion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="signingProfileVersionArn")
    def signing_profile_version_arn(self) -> builtins.str:
        '''The ARN of signing profile version.'''
        return typing.cast(builtins.str, jsii.get(self, "signingProfileVersionArn"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_signer.SigningProfileAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "signing_profile_name": "signingProfileName",
        "signing_profile_version": "signingProfileVersion",
    },
)
class SigningProfileAttributes:
    def __init__(
        self,
        *,
        signing_profile_name: builtins.str,
        signing_profile_version: builtins.str,
    ) -> None:
        '''A reference to a Signing Profile.

        :param signing_profile_name: The name of signing profile.
        :param signing_profile_version: The version of signing profile.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_signer as signer
            
            signing_profile_attributes = signer.SigningProfileAttributes(
                signing_profile_name="signingProfileName",
                signing_profile_version="signingProfileVersion"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "signing_profile_name": signing_profile_name,
            "signing_profile_version": signing_profile_version,
        }

    @builtins.property
    def signing_profile_name(self) -> builtins.str:
        '''The name of signing profile.'''
        result = self._values.get("signing_profile_name")
        assert result is not None, "Required property 'signing_profile_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def signing_profile_version(self) -> builtins.str:
        '''The version of signing profile.'''
        result = self._values.get("signing_profile_version")
        assert result is not None, "Required property 'signing_profile_version' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SigningProfileAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_signer.SigningProfileProps",
    jsii_struct_bases=[],
    name_mapping={
        "platform": "platform",
        "signature_validity": "signatureValidity",
        "signing_profile_name": "signingProfileName",
    },
)
class SigningProfileProps:
    def __init__(
        self,
        *,
        platform: Platform,
        signature_validity: typing.Optional[_Duration_4839e8c3] = None,
        signing_profile_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Construction properties for a Signing Profile object.

        :param platform: The Signing Platform available for signing profile.
        :param signature_validity: The validity period for signatures generated using this signing profile. Default: - 135 months
        :param signing_profile_name: Physical name of this Signing Profile. Default: - Assigned by CloudFormation (recommended).

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_signer as signer
            
            
            signing_profile = signer.SigningProfile(self, "SigningProfile",
                platform=signer.Platform.AWS_LAMBDA_SHA384_ECDSA
            )
            
            code_signing_config = lambda_.CodeSigningConfig(self, "CodeSigningConfig",
                signing_profiles=[signing_profile]
            )
            
            lambda_.Function(self, "Function",
                code_signing_config=code_signing_config,
                runtime=lambda_.Runtime.NODEJS_12_X,
                handler="index.handler",
                code=lambda_.Code.from_asset(path.join(__dirname, "lambda-handler"))
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "platform": platform,
        }
        if signature_validity is not None:
            self._values["signature_validity"] = signature_validity
        if signing_profile_name is not None:
            self._values["signing_profile_name"] = signing_profile_name

    @builtins.property
    def platform(self) -> Platform:
        '''The Signing Platform available for signing profile.

        :see: https://docs.aws.amazon.com/signer/latest/developerguide/gs-platform.html
        '''
        result = self._values.get("platform")
        assert result is not None, "Required property 'platform' is missing"
        return typing.cast(Platform, result)

    @builtins.property
    def signature_validity(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The validity period for signatures generated using this signing profile.

        :default: - 135 months
        '''
        result = self._values.get("signature_validity")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def signing_profile_name(self) -> typing.Optional[builtins.str]:
        '''Physical name of this Signing Profile.

        :default: - Assigned by CloudFormation (recommended).
        '''
        result = self._values.get("signing_profile_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SigningProfileProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnProfilePermission",
    "CfnProfilePermissionProps",
    "CfnSigningProfile",
    "CfnSigningProfileProps",
    "ISigningProfile",
    "Platform",
    "SigningProfile",
    "SigningProfileAttributes",
    "SigningProfileProps",
]

publication.publish()
