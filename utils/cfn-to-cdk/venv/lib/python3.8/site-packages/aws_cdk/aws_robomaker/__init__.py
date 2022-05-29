'''
# AWS RoboMaker Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_robomaker as robomaker
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-robomaker-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::RoboMaker](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_RoboMaker.html).

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
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)


@jsii.implements(_IInspectable_c2943556)
class CfnFleet(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_robomaker.CfnFleet",
):
    '''A CloudFormation ``AWS::RoboMaker::Fleet``.

    The ``AWS::RoboMaker::Fleet`` resource creates an AWS RoboMaker fleet. Fleets contain robots and can receive deployments.

    :cloudformationResource: AWS::RoboMaker::Fleet
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-fleet.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_robomaker as robomaker
        
        cfn_fleet = robomaker.CfnFleet(self, "MyCfnFleet",
            name="name",
            tags={
                "tags_key": "tags"
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::RoboMaker::Fleet``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the fleet.
        :param tags: The list of all tags added to the fleet.
        '''
        props = CfnFleetProps(name=name, tags=tags)

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
        '''The Amazon Resource Name (ARN) of the fleet, such as ``arn:aws:robomaker:us-west-2:123456789012:deployment-fleet/MyFleet/1539894765711`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The list of all tags added to the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-fleet.html#cfn-robomaker-fleet-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-fleet.html#cfn-robomaker-fleet-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_robomaker.CfnFleetProps",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "tags": "tags"},
)
class CfnFleetProps:
    def __init__(
        self,
        *,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnFleet``.

        :param name: The name of the fleet.
        :param tags: The list of all tags added to the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-fleet.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_robomaker as robomaker
            
            cfn_fleet_props = robomaker.CfnFleetProps(
                name="name",
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-fleet.html#cfn-robomaker-fleet-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The list of all tags added to the fleet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-fleet.html#cfn-robomaker-fleet-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnFleetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRobot(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_robomaker.CfnRobot",
):
    '''A CloudFormation ``AWS::RoboMaker::Robot``.

    The ``AWS::RoboMaker::RobotApplication`` resource creates an AWS RoboMaker robot.

    :cloudformationResource: AWS::RoboMaker::Robot
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_robomaker as robomaker
        
        cfn_robot = robomaker.CfnRobot(self, "MyCfnRobot",
            architecture="architecture",
            greengrass_group_id="greengrassGroupId",
        
            # the properties below are optional
            fleet="fleet",
            name="name",
            tags={
                "tags_key": "tags"
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        architecture: builtins.str,
        greengrass_group_id: builtins.str,
        fleet: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::RoboMaker::Robot``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param architecture: The architecture of the robot.
        :param greengrass_group_id: The Greengrass group associated with the robot.
        :param fleet: The Amazon Resource Name (ARN) of the fleet to which the robot will be registered.
        :param name: The name of the robot.
        :param tags: A map that contains tag keys and tag values that are attached to the robot.
        '''
        props = CfnRobotProps(
            architecture=architecture,
            greengrass_group_id=greengrass_group_id,
            fleet=fleet,
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
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the robot.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A map that contains tag keys and tag values that are attached to the robot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html#cfn-robomaker-robot-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="architecture")
    def architecture(self) -> builtins.str:
        '''The architecture of the robot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html#cfn-robomaker-robot-architecture
        '''
        return typing.cast(builtins.str, jsii.get(self, "architecture"))

    @architecture.setter
    def architecture(self, value: builtins.str) -> None:
        jsii.set(self, "architecture", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="greengrassGroupId")
    def greengrass_group_id(self) -> builtins.str:
        '''The Greengrass group associated with the robot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html#cfn-robomaker-robot-greengrassgroupid
        '''
        return typing.cast(builtins.str, jsii.get(self, "greengrassGroupId"))

    @greengrass_group_id.setter
    def greengrass_group_id(self, value: builtins.str) -> None:
        jsii.set(self, "greengrassGroupId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fleet")
    def fleet(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the fleet to which the robot will be registered.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html#cfn-robomaker-robot-fleet
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "fleet"))

    @fleet.setter
    def fleet(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "fleet", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the robot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html#cfn-robomaker-robot-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)


@jsii.implements(_IInspectable_c2943556)
class CfnRobotApplication(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_robomaker.CfnRobotApplication",
):
    '''A CloudFormation ``AWS::RoboMaker::RobotApplication``.

    The ``AWS::RoboMaker::RobotApplication`` resource creates an AWS RoboMaker robot application.

    :cloudformationResource: AWS::RoboMaker::RobotApplication
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_robomaker as robomaker
        
        cfn_robot_application = robomaker.CfnRobotApplication(self, "MyCfnRobotApplication",
            robot_software_suite=robomaker.CfnRobotApplication.RobotSoftwareSuiteProperty(
                name="name",
        
                # the properties below are optional
                version="version"
            ),
        
            # the properties below are optional
            current_revision_id="currentRevisionId",
            environment="environment",
            name="name",
            sources=[robomaker.CfnRobotApplication.SourceConfigProperty(
                architecture="architecture",
                s3_bucket="s3Bucket",
                s3_key="s3Key"
            )],
            tags={
                "tags_key": "tags"
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        robot_software_suite: typing.Union["CfnRobotApplication.RobotSoftwareSuiteProperty", _IResolvable_da3f097b],
        current_revision_id: typing.Optional[builtins.str] = None,
        environment: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        sources: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRobotApplication.SourceConfigProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::RoboMaker::RobotApplication``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param robot_software_suite: The robot software suite (ROS distribuition) used by the robot application.
        :param current_revision_id: The current revision id.
        :param environment: The environment of the robot application.
        :param name: The name of the robot application.
        :param sources: The sources of the robot application.
        :param tags: A map that contains tag keys and tag values that are attached to the robot application.
        '''
        props = CfnRobotApplicationProps(
            robot_software_suite=robot_software_suite,
            current_revision_id=current_revision_id,
            environment=environment,
            name=name,
            sources=sources,
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
        '''The Amazon Resource Name (ARN) of the robot application.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCurrentRevisionId")
    def attr_current_revision_id(self) -> builtins.str:
        '''The current revision id.

        :cloudformationAttribute: CurrentRevisionId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCurrentRevisionId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A map that contains tag keys and tag values that are attached to the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="robotSoftwareSuite")
    def robot_software_suite(
        self,
    ) -> typing.Union["CfnRobotApplication.RobotSoftwareSuiteProperty", _IResolvable_da3f097b]:
        '''The robot software suite (ROS distribuition) used by the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-robotsoftwaresuite
        '''
        return typing.cast(typing.Union["CfnRobotApplication.RobotSoftwareSuiteProperty", _IResolvable_da3f097b], jsii.get(self, "robotSoftwareSuite"))

    @robot_software_suite.setter
    def robot_software_suite(
        self,
        value: typing.Union["CfnRobotApplication.RobotSoftwareSuiteProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "robotSoftwareSuite", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="currentRevisionId")
    def current_revision_id(self) -> typing.Optional[builtins.str]:
        '''The current revision id.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-currentrevisionid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "currentRevisionId"))

    @current_revision_id.setter
    def current_revision_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "currentRevisionId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="environment")
    def environment(self) -> typing.Optional[builtins.str]:
        '''The environment of the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-environment
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "environment"))

    @environment.setter
    def environment(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "environment", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sources")
    def sources(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRobotApplication.SourceConfigProperty", _IResolvable_da3f097b]]]]:
        '''The sources of the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-sources
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRobotApplication.SourceConfigProperty", _IResolvable_da3f097b]]]], jsii.get(self, "sources"))

    @sources.setter
    def sources(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRobotApplication.SourceConfigProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "sources", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_robomaker.CfnRobotApplication.RobotSoftwareSuiteProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "version": "version"},
    )
    class RobotSoftwareSuiteProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about a robot software suite (ROS distribution).

            :param name: The name of the robot software suite (ROS distribution).
            :param version: The version of the robot software suite (ROS distribution).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-robotapplication-robotsoftwaresuite.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_robomaker as robomaker
                
                robot_software_suite_property = robomaker.CfnRobotApplication.RobotSoftwareSuiteProperty(
                    name="name",
                
                    # the properties below are optional
                    version="version"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }
            if version is not None:
                self._values["version"] = version

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the robot software suite (ROS distribution).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-robotapplication-robotsoftwaresuite.html#cfn-robomaker-robotapplication-robotsoftwaresuite-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def version(self) -> typing.Optional[builtins.str]:
            '''The version of the robot software suite (ROS distribution).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-robotapplication-robotsoftwaresuite.html#cfn-robomaker-robotapplication-robotsoftwaresuite-version
            '''
            result = self._values.get("version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RobotSoftwareSuiteProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_robomaker.CfnRobotApplication.SourceConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "architecture": "architecture",
            "s3_bucket": "s3Bucket",
            "s3_key": "s3Key",
        },
    )
    class SourceConfigProperty:
        def __init__(
            self,
            *,
            architecture: builtins.str,
            s3_bucket: builtins.str,
            s3_key: builtins.str,
        ) -> None:
            '''Information about a source configuration.

            :param architecture: The target processor architecture for the application.
            :param s3_bucket: The Amazon S3 bucket name.
            :param s3_key: The s3 object key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-robotapplication-sourceconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_robomaker as robomaker
                
                source_config_property = robomaker.CfnRobotApplication.SourceConfigProperty(
                    architecture="architecture",
                    s3_bucket="s3Bucket",
                    s3_key="s3Key"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "architecture": architecture,
                "s3_bucket": s3_bucket,
                "s3_key": s3_key,
            }

        @builtins.property
        def architecture(self) -> builtins.str:
            '''The target processor architecture for the application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-robotapplication-sourceconfig.html#cfn-robomaker-robotapplication-sourceconfig-architecture
            '''
            result = self._values.get("architecture")
            assert result is not None, "Required property 'architecture' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_bucket(self) -> builtins.str:
            '''The Amazon S3 bucket name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-robotapplication-sourceconfig.html#cfn-robomaker-robotapplication-sourceconfig-s3bucket
            '''
            result = self._values.get("s3_bucket")
            assert result is not None, "Required property 's3_bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_key(self) -> builtins.str:
            '''The s3 object key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-robotapplication-sourceconfig.html#cfn-robomaker-robotapplication-sourceconfig-s3key
            '''
            result = self._values.get("s3_key")
            assert result is not None, "Required property 's3_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SourceConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_robomaker.CfnRobotApplicationProps",
    jsii_struct_bases=[],
    name_mapping={
        "robot_software_suite": "robotSoftwareSuite",
        "current_revision_id": "currentRevisionId",
        "environment": "environment",
        "name": "name",
        "sources": "sources",
        "tags": "tags",
    },
)
class CfnRobotApplicationProps:
    def __init__(
        self,
        *,
        robot_software_suite: typing.Union[CfnRobotApplication.RobotSoftwareSuiteProperty, _IResolvable_da3f097b],
        current_revision_id: typing.Optional[builtins.str] = None,
        environment: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        sources: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnRobotApplication.SourceConfigProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRobotApplication``.

        :param robot_software_suite: The robot software suite (ROS distribuition) used by the robot application.
        :param current_revision_id: The current revision id.
        :param environment: The environment of the robot application.
        :param name: The name of the robot application.
        :param sources: The sources of the robot application.
        :param tags: A map that contains tag keys and tag values that are attached to the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_robomaker as robomaker
            
            cfn_robot_application_props = robomaker.CfnRobotApplicationProps(
                robot_software_suite=robomaker.CfnRobotApplication.RobotSoftwareSuiteProperty(
                    name="name",
            
                    # the properties below are optional
                    version="version"
                ),
            
                # the properties below are optional
                current_revision_id="currentRevisionId",
                environment="environment",
                name="name",
                sources=[robomaker.CfnRobotApplication.SourceConfigProperty(
                    architecture="architecture",
                    s3_bucket="s3Bucket",
                    s3_key="s3Key"
                )],
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "robot_software_suite": robot_software_suite,
        }
        if current_revision_id is not None:
            self._values["current_revision_id"] = current_revision_id
        if environment is not None:
            self._values["environment"] = environment
        if name is not None:
            self._values["name"] = name
        if sources is not None:
            self._values["sources"] = sources
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def robot_software_suite(
        self,
    ) -> typing.Union[CfnRobotApplication.RobotSoftwareSuiteProperty, _IResolvable_da3f097b]:
        '''The robot software suite (ROS distribuition) used by the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-robotsoftwaresuite
        '''
        result = self._values.get("robot_software_suite")
        assert result is not None, "Required property 'robot_software_suite' is missing"
        return typing.cast(typing.Union[CfnRobotApplication.RobotSoftwareSuiteProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def current_revision_id(self) -> typing.Optional[builtins.str]:
        '''The current revision id.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-currentrevisionid
        '''
        result = self._values.get("current_revision_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def environment(self) -> typing.Optional[builtins.str]:
        '''The environment of the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-environment
        '''
        result = self._values.get("environment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def sources(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRobotApplication.SourceConfigProperty, _IResolvable_da3f097b]]]]:
        '''The sources of the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-sources
        '''
        result = self._values.get("sources")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRobotApplication.SourceConfigProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''A map that contains tag keys and tag values that are attached to the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplication.html#cfn-robomaker-robotapplication-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRobotApplicationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRobotApplicationVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_robomaker.CfnRobotApplicationVersion",
):
    '''A CloudFormation ``AWS::RoboMaker::RobotApplicationVersion``.

    The ``AWS::RoboMaker::RobotApplicationVersion`` resource creates an AWS RoboMaker robot version.

    :cloudformationResource: AWS::RoboMaker::RobotApplicationVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplicationversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_robomaker as robomaker
        
        cfn_robot_application_version = robomaker.CfnRobotApplicationVersion(self, "MyCfnRobotApplicationVersion",
            application="application",
        
            # the properties below are optional
            current_revision_id="currentRevisionId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        application: builtins.str,
        current_revision_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::RoboMaker::RobotApplicationVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param application: The application information for the robot application.
        :param current_revision_id: The current revision id for the robot application. If you provide a value and it matches the latest revision ID, a new version will be created.
        '''
        props = CfnRobotApplicationVersionProps(
            application=application, current_revision_id=current_revision_id
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
    @jsii.member(jsii_name="attrApplicationVersion")
    def attr_application_version(self) -> builtins.str:
        '''The robot application version.

        :cloudformationAttribute: ApplicationVersion
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrApplicationVersion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the robot application version.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="application")
    def application(self) -> builtins.str:
        '''The application information for the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplicationversion.html#cfn-robomaker-robotapplicationversion-application
        '''
        return typing.cast(builtins.str, jsii.get(self, "application"))

    @application.setter
    def application(self, value: builtins.str) -> None:
        jsii.set(self, "application", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="currentRevisionId")
    def current_revision_id(self) -> typing.Optional[builtins.str]:
        '''The current revision id for the robot application.

        If you provide a value and it matches the latest revision ID, a new version will be created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplicationversion.html#cfn-robomaker-robotapplicationversion-currentrevisionid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "currentRevisionId"))

    @current_revision_id.setter
    def current_revision_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "currentRevisionId", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_robomaker.CfnRobotApplicationVersionProps",
    jsii_struct_bases=[],
    name_mapping={
        "application": "application",
        "current_revision_id": "currentRevisionId",
    },
)
class CfnRobotApplicationVersionProps:
    def __init__(
        self,
        *,
        application: builtins.str,
        current_revision_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnRobotApplicationVersion``.

        :param application: The application information for the robot application.
        :param current_revision_id: The current revision id for the robot application. If you provide a value and it matches the latest revision ID, a new version will be created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplicationversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_robomaker as robomaker
            
            cfn_robot_application_version_props = robomaker.CfnRobotApplicationVersionProps(
                application="application",
            
                # the properties below are optional
                current_revision_id="currentRevisionId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "application": application,
        }
        if current_revision_id is not None:
            self._values["current_revision_id"] = current_revision_id

    @builtins.property
    def application(self) -> builtins.str:
        '''The application information for the robot application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplicationversion.html#cfn-robomaker-robotapplicationversion-application
        '''
        result = self._values.get("application")
        assert result is not None, "Required property 'application' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def current_revision_id(self) -> typing.Optional[builtins.str]:
        '''The current revision id for the robot application.

        If you provide a value and it matches the latest revision ID, a new version will be created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robotapplicationversion.html#cfn-robomaker-robotapplicationversion-currentrevisionid
        '''
        result = self._values.get("current_revision_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRobotApplicationVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_robomaker.CfnRobotProps",
    jsii_struct_bases=[],
    name_mapping={
        "architecture": "architecture",
        "greengrass_group_id": "greengrassGroupId",
        "fleet": "fleet",
        "name": "name",
        "tags": "tags",
    },
)
class CfnRobotProps:
    def __init__(
        self,
        *,
        architecture: builtins.str,
        greengrass_group_id: builtins.str,
        fleet: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRobot``.

        :param architecture: The architecture of the robot.
        :param greengrass_group_id: The Greengrass group associated with the robot.
        :param fleet: The Amazon Resource Name (ARN) of the fleet to which the robot will be registered.
        :param name: The name of the robot.
        :param tags: A map that contains tag keys and tag values that are attached to the robot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_robomaker as robomaker
            
            cfn_robot_props = robomaker.CfnRobotProps(
                architecture="architecture",
                greengrass_group_id="greengrassGroupId",
            
                # the properties below are optional
                fleet="fleet",
                name="name",
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "architecture": architecture,
            "greengrass_group_id": greengrass_group_id,
        }
        if fleet is not None:
            self._values["fleet"] = fleet
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def architecture(self) -> builtins.str:
        '''The architecture of the robot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html#cfn-robomaker-robot-architecture
        '''
        result = self._values.get("architecture")
        assert result is not None, "Required property 'architecture' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def greengrass_group_id(self) -> builtins.str:
        '''The Greengrass group associated with the robot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html#cfn-robomaker-robot-greengrassgroupid
        '''
        result = self._values.get("greengrass_group_id")
        assert result is not None, "Required property 'greengrass_group_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def fleet(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the fleet to which the robot will be registered.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html#cfn-robomaker-robot-fleet
        '''
        result = self._values.get("fleet")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the robot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html#cfn-robomaker-robot-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''A map that contains tag keys and tag values that are attached to the robot.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-robot.html#cfn-robomaker-robot-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRobotProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSimulationApplication(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_robomaker.CfnSimulationApplication",
):
    '''A CloudFormation ``AWS::RoboMaker::SimulationApplication``.

    The ``AWS::RoboMaker::SimulationApplication`` resource creates an AWS RoboMaker simulation application.

    :cloudformationResource: AWS::RoboMaker::SimulationApplication
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_robomaker as robomaker
        
        cfn_simulation_application = robomaker.CfnSimulationApplication(self, "MyCfnSimulationApplication",
            robot_software_suite=robomaker.CfnSimulationApplication.RobotSoftwareSuiteProperty(
                name="name",
        
                # the properties below are optional
                version="version"
            ),
            simulation_software_suite=robomaker.CfnSimulationApplication.SimulationSoftwareSuiteProperty(
                name="name",
        
                # the properties below are optional
                version="version"
            ),
        
            # the properties below are optional
            current_revision_id="currentRevisionId",
            environment="environment",
            name="name",
            rendering_engine=robomaker.CfnSimulationApplication.RenderingEngineProperty(
                name="name",
                version="version"
            ),
            sources=[robomaker.CfnSimulationApplication.SourceConfigProperty(
                architecture="architecture",
                s3_bucket="s3Bucket",
                s3_key="s3Key"
            )],
            tags={
                "tags_key": "tags"
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        robot_software_suite: typing.Union["CfnSimulationApplication.RobotSoftwareSuiteProperty", _IResolvable_da3f097b],
        simulation_software_suite: typing.Union["CfnSimulationApplication.SimulationSoftwareSuiteProperty", _IResolvable_da3f097b],
        current_revision_id: typing.Optional[builtins.str] = None,
        environment: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        rendering_engine: typing.Optional[typing.Union["CfnSimulationApplication.RenderingEngineProperty", _IResolvable_da3f097b]] = None,
        sources: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnSimulationApplication.SourceConfigProperty", _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::RoboMaker::SimulationApplication``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param robot_software_suite: The robot software suite (ROS distribution) used by the simulation application.
        :param simulation_software_suite: The simulation software suite used by the simulation application.
        :param current_revision_id: The current revision id.
        :param environment: The environment of the simulation application.
        :param name: The name of the simulation application.
        :param rendering_engine: The rendering engine for the simulation application.
        :param sources: The sources of the simulation application.
        :param tags: A map that contains tag keys and tag values that are attached to the simulation application.
        '''
        props = CfnSimulationApplicationProps(
            robot_software_suite=robot_software_suite,
            simulation_software_suite=simulation_software_suite,
            current_revision_id=current_revision_id,
            environment=environment,
            name=name,
            rendering_engine=rendering_engine,
            sources=sources,
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
        '''The Amazon Resource Name (ARN) of the simulation application.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCurrentRevisionId")
    def attr_current_revision_id(self) -> builtins.str:
        '''The current revision id.

        :cloudformationAttribute: CurrentRevisionId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCurrentRevisionId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''A map that contains tag keys and tag values that are attached to the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="robotSoftwareSuite")
    def robot_software_suite(
        self,
    ) -> typing.Union["CfnSimulationApplication.RobotSoftwareSuiteProperty", _IResolvable_da3f097b]:
        '''The robot software suite (ROS distribution) used by the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-robotsoftwaresuite
        '''
        return typing.cast(typing.Union["CfnSimulationApplication.RobotSoftwareSuiteProperty", _IResolvable_da3f097b], jsii.get(self, "robotSoftwareSuite"))

    @robot_software_suite.setter
    def robot_software_suite(
        self,
        value: typing.Union["CfnSimulationApplication.RobotSoftwareSuiteProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "robotSoftwareSuite", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="simulationSoftwareSuite")
    def simulation_software_suite(
        self,
    ) -> typing.Union["CfnSimulationApplication.SimulationSoftwareSuiteProperty", _IResolvable_da3f097b]:
        '''The simulation software suite used by the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-simulationsoftwaresuite
        '''
        return typing.cast(typing.Union["CfnSimulationApplication.SimulationSoftwareSuiteProperty", _IResolvable_da3f097b], jsii.get(self, "simulationSoftwareSuite"))

    @simulation_software_suite.setter
    def simulation_software_suite(
        self,
        value: typing.Union["CfnSimulationApplication.SimulationSoftwareSuiteProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "simulationSoftwareSuite", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="currentRevisionId")
    def current_revision_id(self) -> typing.Optional[builtins.str]:
        '''The current revision id.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-currentrevisionid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "currentRevisionId"))

    @current_revision_id.setter
    def current_revision_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "currentRevisionId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="environment")
    def environment(self) -> typing.Optional[builtins.str]:
        '''The environment of the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-environment
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "environment"))

    @environment.setter
    def environment(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "environment", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="renderingEngine")
    def rendering_engine(
        self,
    ) -> typing.Optional[typing.Union["CfnSimulationApplication.RenderingEngineProperty", _IResolvable_da3f097b]]:
        '''The rendering engine for the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-renderingengine
        '''
        return typing.cast(typing.Optional[typing.Union["CfnSimulationApplication.RenderingEngineProperty", _IResolvable_da3f097b]], jsii.get(self, "renderingEngine"))

    @rendering_engine.setter
    def rendering_engine(
        self,
        value: typing.Optional[typing.Union["CfnSimulationApplication.RenderingEngineProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "renderingEngine", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sources")
    def sources(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSimulationApplication.SourceConfigProperty", _IResolvable_da3f097b]]]]:
        '''The sources of the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-sources
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSimulationApplication.SourceConfigProperty", _IResolvable_da3f097b]]]], jsii.get(self, "sources"))

    @sources.setter
    def sources(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnSimulationApplication.SourceConfigProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "sources", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_robomaker.CfnSimulationApplication.RenderingEngineProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "version": "version"},
    )
    class RenderingEngineProperty:
        def __init__(self, *, name: builtins.str, version: builtins.str) -> None:
            '''Information about a rendering engine.

            :param name: The name of the rendering engine.
            :param version: The version of the rendering engine.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-renderingengine.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_robomaker as robomaker
                
                rendering_engine_property = robomaker.CfnSimulationApplication.RenderingEngineProperty(
                    name="name",
                    version="version"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
                "version": version,
            }

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the rendering engine.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-renderingengine.html#cfn-robomaker-simulationapplication-renderingengine-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def version(self) -> builtins.str:
            '''The version of the rendering engine.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-renderingengine.html#cfn-robomaker-simulationapplication-renderingengine-version
            '''
            result = self._values.get("version")
            assert result is not None, "Required property 'version' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RenderingEngineProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_robomaker.CfnSimulationApplication.RobotSoftwareSuiteProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "version": "version"},
    )
    class RobotSoftwareSuiteProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about a robot software suite (ROS distribution).

            :param name: The name of the robot software suite (ROS distribution).
            :param version: The version of the robot software suite (ROS distribution).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-robotsoftwaresuite.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_robomaker as robomaker
                
                robot_software_suite_property = robomaker.CfnSimulationApplication.RobotSoftwareSuiteProperty(
                    name="name",
                
                    # the properties below are optional
                    version="version"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }
            if version is not None:
                self._values["version"] = version

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the robot software suite (ROS distribution).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-robotsoftwaresuite.html#cfn-robomaker-simulationapplication-robotsoftwaresuite-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def version(self) -> typing.Optional[builtins.str]:
            '''The version of the robot software suite (ROS distribution).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-robotsoftwaresuite.html#cfn-robomaker-simulationapplication-robotsoftwaresuite-version
            '''
            result = self._values.get("version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RobotSoftwareSuiteProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_robomaker.CfnSimulationApplication.SimulationSoftwareSuiteProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "version": "version"},
    )
    class SimulationSoftwareSuiteProperty:
        def __init__(
            self,
            *,
            name: builtins.str,
            version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about a simulation software suite.

            :param name: The name of the simulation software suite.
            :param version: The version of the simulation software suite.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-simulationsoftwaresuite.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_robomaker as robomaker
                
                simulation_software_suite_property = robomaker.CfnSimulationApplication.SimulationSoftwareSuiteProperty(
                    name="name",
                
                    # the properties below are optional
                    version="version"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "name": name,
            }
            if version is not None:
                self._values["version"] = version

        @builtins.property
        def name(self) -> builtins.str:
            '''The name of the simulation software suite.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-simulationsoftwaresuite.html#cfn-robomaker-simulationapplication-simulationsoftwaresuite-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def version(self) -> typing.Optional[builtins.str]:
            '''The version of the simulation software suite.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-simulationsoftwaresuite.html#cfn-robomaker-simulationapplication-simulationsoftwaresuite-version
            '''
            result = self._values.get("version")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SimulationSoftwareSuiteProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_robomaker.CfnSimulationApplication.SourceConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "architecture": "architecture",
            "s3_bucket": "s3Bucket",
            "s3_key": "s3Key",
        },
    )
    class SourceConfigProperty:
        def __init__(
            self,
            *,
            architecture: builtins.str,
            s3_bucket: builtins.str,
            s3_key: builtins.str,
        ) -> None:
            '''Information about a source configuration.

            :param architecture: The target processor architecture for the application.
            :param s3_bucket: The Amazon S3 bucket name.
            :param s3_key: The s3 object key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-sourceconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_robomaker as robomaker
                
                source_config_property = robomaker.CfnSimulationApplication.SourceConfigProperty(
                    architecture="architecture",
                    s3_bucket="s3Bucket",
                    s3_key="s3Key"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "architecture": architecture,
                "s3_bucket": s3_bucket,
                "s3_key": s3_key,
            }

        @builtins.property
        def architecture(self) -> builtins.str:
            '''The target processor architecture for the application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-sourceconfig.html#cfn-robomaker-simulationapplication-sourceconfig-architecture
            '''
            result = self._values.get("architecture")
            assert result is not None, "Required property 'architecture' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_bucket(self) -> builtins.str:
            '''The Amazon S3 bucket name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-sourceconfig.html#cfn-robomaker-simulationapplication-sourceconfig-s3bucket
            '''
            result = self._values.get("s3_bucket")
            assert result is not None, "Required property 's3_bucket' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def s3_key(self) -> builtins.str:
            '''The s3 object key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-robomaker-simulationapplication-sourceconfig.html#cfn-robomaker-simulationapplication-sourceconfig-s3key
            '''
            result = self._values.get("s3_key")
            assert result is not None, "Required property 's3_key' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SourceConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_robomaker.CfnSimulationApplicationProps",
    jsii_struct_bases=[],
    name_mapping={
        "robot_software_suite": "robotSoftwareSuite",
        "simulation_software_suite": "simulationSoftwareSuite",
        "current_revision_id": "currentRevisionId",
        "environment": "environment",
        "name": "name",
        "rendering_engine": "renderingEngine",
        "sources": "sources",
        "tags": "tags",
    },
)
class CfnSimulationApplicationProps:
    def __init__(
        self,
        *,
        robot_software_suite: typing.Union[CfnSimulationApplication.RobotSoftwareSuiteProperty, _IResolvable_da3f097b],
        simulation_software_suite: typing.Union[CfnSimulationApplication.SimulationSoftwareSuiteProperty, _IResolvable_da3f097b],
        current_revision_id: typing.Optional[builtins.str] = None,
        environment: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
        rendering_engine: typing.Optional[typing.Union[CfnSimulationApplication.RenderingEngineProperty, _IResolvable_da3f097b]] = None,
        sources: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnSimulationApplication.SourceConfigProperty, _IResolvable_da3f097b]]]] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnSimulationApplication``.

        :param robot_software_suite: The robot software suite (ROS distribution) used by the simulation application.
        :param simulation_software_suite: The simulation software suite used by the simulation application.
        :param current_revision_id: The current revision id.
        :param environment: The environment of the simulation application.
        :param name: The name of the simulation application.
        :param rendering_engine: The rendering engine for the simulation application.
        :param sources: The sources of the simulation application.
        :param tags: A map that contains tag keys and tag values that are attached to the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_robomaker as robomaker
            
            cfn_simulation_application_props = robomaker.CfnSimulationApplicationProps(
                robot_software_suite=robomaker.CfnSimulationApplication.RobotSoftwareSuiteProperty(
                    name="name",
            
                    # the properties below are optional
                    version="version"
                ),
                simulation_software_suite=robomaker.CfnSimulationApplication.SimulationSoftwareSuiteProperty(
                    name="name",
            
                    # the properties below are optional
                    version="version"
                ),
            
                # the properties below are optional
                current_revision_id="currentRevisionId",
                environment="environment",
                name="name",
                rendering_engine=robomaker.CfnSimulationApplication.RenderingEngineProperty(
                    name="name",
                    version="version"
                ),
                sources=[robomaker.CfnSimulationApplication.SourceConfigProperty(
                    architecture="architecture",
                    s3_bucket="s3Bucket",
                    s3_key="s3Key"
                )],
                tags={
                    "tags_key": "tags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "robot_software_suite": robot_software_suite,
            "simulation_software_suite": simulation_software_suite,
        }
        if current_revision_id is not None:
            self._values["current_revision_id"] = current_revision_id
        if environment is not None:
            self._values["environment"] = environment
        if name is not None:
            self._values["name"] = name
        if rendering_engine is not None:
            self._values["rendering_engine"] = rendering_engine
        if sources is not None:
            self._values["sources"] = sources
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def robot_software_suite(
        self,
    ) -> typing.Union[CfnSimulationApplication.RobotSoftwareSuiteProperty, _IResolvable_da3f097b]:
        '''The robot software suite (ROS distribution) used by the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-robotsoftwaresuite
        '''
        result = self._values.get("robot_software_suite")
        assert result is not None, "Required property 'robot_software_suite' is missing"
        return typing.cast(typing.Union[CfnSimulationApplication.RobotSoftwareSuiteProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def simulation_software_suite(
        self,
    ) -> typing.Union[CfnSimulationApplication.SimulationSoftwareSuiteProperty, _IResolvable_da3f097b]:
        '''The simulation software suite used by the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-simulationsoftwaresuite
        '''
        result = self._values.get("simulation_software_suite")
        assert result is not None, "Required property 'simulation_software_suite' is missing"
        return typing.cast(typing.Union[CfnSimulationApplication.SimulationSoftwareSuiteProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def current_revision_id(self) -> typing.Optional[builtins.str]:
        '''The current revision id.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-currentrevisionid
        '''
        result = self._values.get("current_revision_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def environment(self) -> typing.Optional[builtins.str]:
        '''The environment of the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-environment
        '''
        result = self._values.get("environment")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def rendering_engine(
        self,
    ) -> typing.Optional[typing.Union[CfnSimulationApplication.RenderingEngineProperty, _IResolvable_da3f097b]]:
        '''The rendering engine for the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-renderingengine
        '''
        result = self._values.get("rendering_engine")
        return typing.cast(typing.Optional[typing.Union[CfnSimulationApplication.RenderingEngineProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def sources(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnSimulationApplication.SourceConfigProperty, _IResolvable_da3f097b]]]]:
        '''The sources of the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-sources
        '''
        result = self._values.get("sources")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnSimulationApplication.SourceConfigProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''A map that contains tag keys and tag values that are attached to the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplication.html#cfn-robomaker-simulationapplication-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSimulationApplicationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnSimulationApplicationVersion(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_robomaker.CfnSimulationApplicationVersion",
):
    '''A CloudFormation ``AWS::RoboMaker::SimulationApplicationVersion``.

    The ``AWS::RoboMaker::SimulationApplicationVersion`` resource creates a version of an AWS RoboMaker simulation application.

    :cloudformationResource: AWS::RoboMaker::SimulationApplicationVersion
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplicationversion.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_robomaker as robomaker
        
        cfn_simulation_application_version = robomaker.CfnSimulationApplicationVersion(self, "MyCfnSimulationApplicationVersion",
            application="application",
        
            # the properties below are optional
            current_revision_id="currentRevisionId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        application: builtins.str,
        current_revision_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::RoboMaker::SimulationApplicationVersion``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param application: The application information for the simulation application.
        :param current_revision_id: The current revision id for the simulation application. If you provide a value and it matches the latest revision ID, a new version will be created.
        '''
        props = CfnSimulationApplicationVersionProps(
            application=application, current_revision_id=current_revision_id
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
    @jsii.member(jsii_name="attrApplicationVersion")
    def attr_application_version(self) -> builtins.str:
        '''The simulation application version.

        :cloudformationAttribute: ApplicationVersion
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrApplicationVersion"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the simulation application version.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="application")
    def application(self) -> builtins.str:
        '''The application information for the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplicationversion.html#cfn-robomaker-simulationapplicationversion-application
        '''
        return typing.cast(builtins.str, jsii.get(self, "application"))

    @application.setter
    def application(self, value: builtins.str) -> None:
        jsii.set(self, "application", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="currentRevisionId")
    def current_revision_id(self) -> typing.Optional[builtins.str]:
        '''The current revision id for the simulation application.

        If you provide a value and it matches the latest revision ID, a new version will be created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplicationversion.html#cfn-robomaker-simulationapplicationversion-currentrevisionid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "currentRevisionId"))

    @current_revision_id.setter
    def current_revision_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "currentRevisionId", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_robomaker.CfnSimulationApplicationVersionProps",
    jsii_struct_bases=[],
    name_mapping={
        "application": "application",
        "current_revision_id": "currentRevisionId",
    },
)
class CfnSimulationApplicationVersionProps:
    def __init__(
        self,
        *,
        application: builtins.str,
        current_revision_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnSimulationApplicationVersion``.

        :param application: The application information for the simulation application.
        :param current_revision_id: The current revision id for the simulation application. If you provide a value and it matches the latest revision ID, a new version will be created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplicationversion.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_robomaker as robomaker
            
            cfn_simulation_application_version_props = robomaker.CfnSimulationApplicationVersionProps(
                application="application",
            
                # the properties below are optional
                current_revision_id="currentRevisionId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "application": application,
        }
        if current_revision_id is not None:
            self._values["current_revision_id"] = current_revision_id

    @builtins.property
    def application(self) -> builtins.str:
        '''The application information for the simulation application.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplicationversion.html#cfn-robomaker-simulationapplicationversion-application
        '''
        result = self._values.get("application")
        assert result is not None, "Required property 'application' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def current_revision_id(self) -> typing.Optional[builtins.str]:
        '''The current revision id for the simulation application.

        If you provide a value and it matches the latest revision ID, a new version will be created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-robomaker-simulationapplicationversion.html#cfn-robomaker-simulationapplicationversion-currentrevisionid
        '''
        result = self._values.get("current_revision_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnSimulationApplicationVersionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnFleet",
    "CfnFleetProps",
    "CfnRobot",
    "CfnRobotApplication",
    "CfnRobotApplicationProps",
    "CfnRobotApplicationVersion",
    "CfnRobotApplicationVersionProps",
    "CfnRobotProps",
    "CfnSimulationApplication",
    "CfnSimulationApplicationProps",
    "CfnSimulationApplicationVersion",
    "CfnSimulationApplicationVersionProps",
]

publication.publish()
