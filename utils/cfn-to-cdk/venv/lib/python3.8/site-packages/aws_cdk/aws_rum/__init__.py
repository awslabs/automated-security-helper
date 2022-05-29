'''
# AWS::RUM Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

```python
import aws_cdk.aws_rum as rum
```

> The construct library for this service is in preview. Since it is not stable yet, it is distributed
> as a separate package so that you can pin its version independently of the rest of the CDK. See the package:
>
> <span class="package-reference">@aws-cdk/aws-rum-alpha</span>

<!--BEGIN CFNONLY DISCLAIMER-->

There are no hand-written ([L2](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_lib)) constructs for this service yet.
However, you can still use the automatically generated [L1](https://docs.aws.amazon.com/cdk/latest/guide/constructs.html#constructs_l1_using) constructs, and use this service exactly as you would using CloudFormation directly.

For more information on the resources and properties available for this service, see the [CloudFormation documentation for AWS::RUM](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_RUM.html).

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
class CfnAppMonitor(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_rum.CfnAppMonitor",
):
    '''A CloudFormation ``AWS::RUM::AppMonitor``.

    Creates a CloudWatch RUM app monitor, which you can use to collect telemetry data from your application and send it to CloudWatch RUM. The data includes performance and reliability information such as page load time, client-side errors, and user behavior.

    After you create an app monitor, sign in to the CloudWatch RUM console to get the JavaScript code snippet to add to your web application. For more information, see `How do I find a code snippet that I've already generated? <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-find-code-snippet.html>`_

    :cloudformationResource: AWS::RUM::AppMonitor
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_rum as rum
        
        cfn_app_monitor = rum.CfnAppMonitor(self, "MyCfnAppMonitor",
            domain="domain",
            name="name",
        
            # the properties below are optional
            app_monitor_configuration=rum.CfnAppMonitor.AppMonitorConfigurationProperty(
                allow_cookies=False,
                enable_xRay=False,
                excluded_pages=["excludedPages"],
                favorite_pages=["favoritePages"],
                guest_role_arn="guestRoleArn",
                identity_pool_id="identityPoolId",
                included_pages=["includedPages"],
                session_sample_rate=123,
                telemetries=["telemetries"]
            ),
            cw_log_enabled=False,
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
        domain: builtins.str,
        name: builtins.str,
        app_monitor_configuration: typing.Optional[typing.Union["CfnAppMonitor.AppMonitorConfigurationProperty", _IResolvable_da3f097b]] = None,
        cw_log_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::RUM::AppMonitor``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param domain: The top-level internet domain name for which your application has administrative authority. This parameter is required.
        :param name: A name for the app monitor. This parameter is required.
        :param app_monitor_configuration: A structure that contains much of the configuration data for the app monitor. If you are using Amazon Cognito for authorization, you must include this structure in your request, and it must include the ID of the Amazon Cognito identity pool to use for authorization. If you don't include ``AppMonitorConfiguration`` , you must set up your own authorization method. For more information, see `Authorize your application to send data to AWS <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-get-started-authorization.html>`_ . If you omit this argument, the sample rate used for CloudWatch RUM is set to 10% of the user sessions.
        :param cw_log_enabled: Data collected by CloudWatch RUM is kept by RUM for 30 days and then deleted. This parameter specifies whether CloudWatch RUM sends a copy of this telemetry data to Amazon CloudWatch Logs in your account. This enables you to keep the telemetry data for more than 30 days, but it does incur Amazon CloudWatch Logs charges. If you omit this parameter, the default is ``false`` .
        :param tags: Assigns one or more tags (key-value pairs) to the app monitor. Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values. Tags don't have any semantic meaning to AWS and are interpreted strictly as strings of characters. You can associate as many as 50 tags with an app monitor. For more information, see `Tagging AWS resources <https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html>`_ .
        '''
        props = CfnAppMonitorProps(
            domain=domain,
            name=name,
            app_monitor_configuration=app_monitor_configuration,
            cw_log_enabled=cw_log_enabled,
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
        '''Assigns one or more tags (key-value pairs) to the app monitor.

        Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.

        Tags don't have any semantic meaning to AWS and are interpreted strictly as strings of characters.

        You can associate as many as 50 tags with an app monitor.

        For more information, see `Tagging AWS resources <https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html#cfn-rum-appmonitor-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="domain")
    def domain(self) -> builtins.str:
        '''The top-level internet domain name for which your application has administrative authority.

        This parameter is required.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html#cfn-rum-appmonitor-domain
        '''
        return typing.cast(builtins.str, jsii.get(self, "domain"))

    @domain.setter
    def domain(self, value: builtins.str) -> None:
        jsii.set(self, "domain", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''A name for the app monitor.

        This parameter is required.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html#cfn-rum-appmonitor-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="appMonitorConfiguration")
    def app_monitor_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnAppMonitor.AppMonitorConfigurationProperty", _IResolvable_da3f097b]]:
        '''A structure that contains much of the configuration data for the app monitor.

        If you are using Amazon Cognito for authorization, you must include this structure in your request, and it must include the ID of the Amazon Cognito identity pool to use for authorization. If you don't include ``AppMonitorConfiguration`` , you must set up your own authorization method. For more information, see `Authorize your application to send data to AWS <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-get-started-authorization.html>`_ .

        If you omit this argument, the sample rate used for CloudWatch RUM is set to 10% of the user sessions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html#cfn-rum-appmonitor-appmonitorconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnAppMonitor.AppMonitorConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "appMonitorConfiguration"))

    @app_monitor_configuration.setter
    def app_monitor_configuration(
        self,
        value: typing.Optional[typing.Union["CfnAppMonitor.AppMonitorConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "appMonitorConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cwLogEnabled")
    def cw_log_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Data collected by CloudWatch RUM is kept by RUM for 30 days and then deleted.

        This parameter specifies whether CloudWatch RUM sends a copy of this telemetry data to Amazon CloudWatch Logs in your account. This enables you to keep the telemetry data for more than 30 days, but it does incur Amazon CloudWatch Logs charges.

        If you omit this parameter, the default is ``false`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html#cfn-rum-appmonitor-cwlogenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "cwLogEnabled"))

    @cw_log_enabled.setter
    def cw_log_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "cwLogEnabled", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_rum.CfnAppMonitor.AppMonitorConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "allow_cookies": "allowCookies",
            "enable_x_ray": "enableXRay",
            "excluded_pages": "excludedPages",
            "favorite_pages": "favoritePages",
            "guest_role_arn": "guestRoleArn",
            "identity_pool_id": "identityPoolId",
            "included_pages": "includedPages",
            "session_sample_rate": "sessionSampleRate",
            "telemetries": "telemetries",
        },
    )
    class AppMonitorConfigurationProperty:
        def __init__(
            self,
            *,
            allow_cookies: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            enable_x_ray: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            excluded_pages: typing.Optional[typing.Sequence[builtins.str]] = None,
            favorite_pages: typing.Optional[typing.Sequence[builtins.str]] = None,
            guest_role_arn: typing.Optional[builtins.str] = None,
            identity_pool_id: typing.Optional[builtins.str] = None,
            included_pages: typing.Optional[typing.Sequence[builtins.str]] = None,
            session_sample_rate: typing.Optional[jsii.Number] = None,
            telemetries: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''This structure contains much of the configuration data for the app monitor.

            :param allow_cookies: If you set this to ``true`` , the CloudWatch RUM web client sets two cookies, a session cookie and a user cookie. The cookies allow the CloudWatch RUM web client to collect data relating to the number of users an application has and the behavior of the application across a sequence of events. Cookies are stored in the top-level domain of the current page.
            :param enable_x_ray: If you set this to ``true`` , CloudWatch RUM sends client-side traces to X-Ray for each sampled session. You can then see traces and segments from these user sessions in the RUM dashboard and the CloudWatch ServiceLens console. For more information, see `What is AWS X-Ray ? <https://docs.aws.amazon.com/xray/latest/devguide/aws-xray.html>`_
            :param excluded_pages: A list of URLs in your website or application to exclude from RUM data collection. You can't include both ``ExcludedPages`` and ``IncludedPages`` in the same app monitor.
            :param favorite_pages: A list of pages in your application that are to be displayed with a "favorite" icon in the CloudWatch RUM console.
            :param guest_role_arn: The ARN of the guest IAM role that is attached to the Amazon Cognito identity pool that is used to authorize the sending of data to CloudWatch RUM.
            :param identity_pool_id: The ID of the Amazon Cognito identity pool that is used to authorize the sending of data to CloudWatch RUM.
            :param included_pages: If this app monitor is to collect data from only certain pages in your application, this structure lists those pages. You can't include both ``ExcludedPages`` and ``IncludedPages`` in the same app monitor.
            :param session_sample_rate: Specifies the portion of user sessions to use for CloudWatch RUM data collection. Choosing a higher portion gives you more data but also incurs more costs. The range for this value is 0 to 1 inclusive. Setting this to 1 means that 100% of user sessions are sampled, and setting it to 0.1 means that 10% of user sessions are sampled. If you omit this parameter, the default of 0.1 is used, and 10% of sessions will be sampled.
            :param telemetries: An array that lists the types of telemetry data that this app monitor is to collect. - ``errors`` indicates that RUM collects data about unhandled JavaScript errors raised by your application. - ``performance`` indicates that RUM collects performance data about how your application and its resources are loaded and rendered. This includes Core Web Vitals. - ``http`` indicates that RUM collects data about HTTP errors thrown by your application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rum-appmonitor-appmonitorconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_rum as rum
                
                app_monitor_configuration_property = rum.CfnAppMonitor.AppMonitorConfigurationProperty(
                    allow_cookies=False,
                    enable_xRay=False,
                    excluded_pages=["excludedPages"],
                    favorite_pages=["favoritePages"],
                    guest_role_arn="guestRoleArn",
                    identity_pool_id="identityPoolId",
                    included_pages=["includedPages"],
                    session_sample_rate=123,
                    telemetries=["telemetries"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if allow_cookies is not None:
                self._values["allow_cookies"] = allow_cookies
            if enable_x_ray is not None:
                self._values["enable_x_ray"] = enable_x_ray
            if excluded_pages is not None:
                self._values["excluded_pages"] = excluded_pages
            if favorite_pages is not None:
                self._values["favorite_pages"] = favorite_pages
            if guest_role_arn is not None:
                self._values["guest_role_arn"] = guest_role_arn
            if identity_pool_id is not None:
                self._values["identity_pool_id"] = identity_pool_id
            if included_pages is not None:
                self._values["included_pages"] = included_pages
            if session_sample_rate is not None:
                self._values["session_sample_rate"] = session_sample_rate
            if telemetries is not None:
                self._values["telemetries"] = telemetries

        @builtins.property
        def allow_cookies(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If you set this to ``true`` , the CloudWatch RUM web client sets two cookies, a session cookie and a user cookie.

            The cookies allow the CloudWatch RUM web client to collect data relating to the number of users an application has and the behavior of the application across a sequence of events. Cookies are stored in the top-level domain of the current page.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rum-appmonitor-appmonitorconfiguration.html#cfn-rum-appmonitor-appmonitorconfiguration-allowcookies
            '''
            result = self._values.get("allow_cookies")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def enable_x_ray(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''If you set this to ``true`` , CloudWatch RUM sends client-side traces to X-Ray for each sampled session.

            You can then see traces and segments from these user sessions in the RUM dashboard and the CloudWatch ServiceLens console. For more information, see `What is AWS X-Ray ? <https://docs.aws.amazon.com/xray/latest/devguide/aws-xray.html>`_

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rum-appmonitor-appmonitorconfiguration.html#cfn-rum-appmonitor-appmonitorconfiguration-enablexray
            '''
            result = self._values.get("enable_x_ray")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def excluded_pages(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of URLs in your website or application to exclude from RUM data collection.

            You can't include both ``ExcludedPages`` and ``IncludedPages`` in the same app monitor.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rum-appmonitor-appmonitorconfiguration.html#cfn-rum-appmonitor-appmonitorconfiguration-excludedpages
            '''
            result = self._values.get("excluded_pages")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def favorite_pages(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of pages in your application that are to be displayed with a "favorite" icon in the CloudWatch RUM console.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rum-appmonitor-appmonitorconfiguration.html#cfn-rum-appmonitor-appmonitorconfiguration-favoritepages
            '''
            result = self._values.get("favorite_pages")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def guest_role_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the guest IAM role that is attached to the Amazon Cognito identity pool that is used to authorize the sending of data to CloudWatch RUM.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rum-appmonitor-appmonitorconfiguration.html#cfn-rum-appmonitor-appmonitorconfiguration-guestrolearn
            '''
            result = self._values.get("guest_role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def identity_pool_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the Amazon Cognito identity pool that is used to authorize the sending of data to CloudWatch RUM.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rum-appmonitor-appmonitorconfiguration.html#cfn-rum-appmonitor-appmonitorconfiguration-identitypoolid
            '''
            result = self._values.get("identity_pool_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def included_pages(self) -> typing.Optional[typing.List[builtins.str]]:
            '''If this app monitor is to collect data from only certain pages in your application, this structure lists those pages.

            You can't include both ``ExcludedPages`` and ``IncludedPages`` in the same app monitor.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rum-appmonitor-appmonitorconfiguration.html#cfn-rum-appmonitor-appmonitorconfiguration-includedpages
            '''
            result = self._values.get("included_pages")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def session_sample_rate(self) -> typing.Optional[jsii.Number]:
            '''Specifies the portion of user sessions to use for CloudWatch RUM data collection.

            Choosing a higher portion gives you more data but also incurs more costs.

            The range for this value is 0 to 1 inclusive. Setting this to 1 means that 100% of user sessions are sampled, and setting it to 0.1 means that 10% of user sessions are sampled.

            If you omit this parameter, the default of 0.1 is used, and 10% of sessions will be sampled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rum-appmonitor-appmonitorconfiguration.html#cfn-rum-appmonitor-appmonitorconfiguration-sessionsamplerate
            '''
            result = self._values.get("session_sample_rate")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def telemetries(self) -> typing.Optional[typing.List[builtins.str]]:
            '''An array that lists the types of telemetry data that this app monitor is to collect.

            - ``errors`` indicates that RUM collects data about unhandled JavaScript errors raised by your application.
            - ``performance`` indicates that RUM collects performance data about how your application and its resources are loaded and rendered. This includes Core Web Vitals.
            - ``http`` indicates that RUM collects data about HTTP errors thrown by your application.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rum-appmonitor-appmonitorconfiguration.html#cfn-rum-appmonitor-appmonitorconfiguration-telemetries
            '''
            result = self._values.get("telemetries")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AppMonitorConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_rum.CfnAppMonitorProps",
    jsii_struct_bases=[],
    name_mapping={
        "domain": "domain",
        "name": "name",
        "app_monitor_configuration": "appMonitorConfiguration",
        "cw_log_enabled": "cwLogEnabled",
        "tags": "tags",
    },
)
class CfnAppMonitorProps:
    def __init__(
        self,
        *,
        domain: builtins.str,
        name: builtins.str,
        app_monitor_configuration: typing.Optional[typing.Union[CfnAppMonitor.AppMonitorConfigurationProperty, _IResolvable_da3f097b]] = None,
        cw_log_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnAppMonitor``.

        :param domain: The top-level internet domain name for which your application has administrative authority. This parameter is required.
        :param name: A name for the app monitor. This parameter is required.
        :param app_monitor_configuration: A structure that contains much of the configuration data for the app monitor. If you are using Amazon Cognito for authorization, you must include this structure in your request, and it must include the ID of the Amazon Cognito identity pool to use for authorization. If you don't include ``AppMonitorConfiguration`` , you must set up your own authorization method. For more information, see `Authorize your application to send data to AWS <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-get-started-authorization.html>`_ . If you omit this argument, the sample rate used for CloudWatch RUM is set to 10% of the user sessions.
        :param cw_log_enabled: Data collected by CloudWatch RUM is kept by RUM for 30 days and then deleted. This parameter specifies whether CloudWatch RUM sends a copy of this telemetry data to Amazon CloudWatch Logs in your account. This enables you to keep the telemetry data for more than 30 days, but it does incur Amazon CloudWatch Logs charges. If you omit this parameter, the default is ``false`` .
        :param tags: Assigns one or more tags (key-value pairs) to the app monitor. Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values. Tags don't have any semantic meaning to AWS and are interpreted strictly as strings of characters. You can associate as many as 50 tags with an app monitor. For more information, see `Tagging AWS resources <https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_rum as rum
            
            cfn_app_monitor_props = rum.CfnAppMonitorProps(
                domain="domain",
                name="name",
            
                # the properties below are optional
                app_monitor_configuration=rum.CfnAppMonitor.AppMonitorConfigurationProperty(
                    allow_cookies=False,
                    enable_xRay=False,
                    excluded_pages=["excludedPages"],
                    favorite_pages=["favoritePages"],
                    guest_role_arn="guestRoleArn",
                    identity_pool_id="identityPoolId",
                    included_pages=["includedPages"],
                    session_sample_rate=123,
                    telemetries=["telemetries"]
                ),
                cw_log_enabled=False,
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "domain": domain,
            "name": name,
        }
        if app_monitor_configuration is not None:
            self._values["app_monitor_configuration"] = app_monitor_configuration
        if cw_log_enabled is not None:
            self._values["cw_log_enabled"] = cw_log_enabled
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def domain(self) -> builtins.str:
        '''The top-level internet domain name for which your application has administrative authority.

        This parameter is required.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html#cfn-rum-appmonitor-domain
        '''
        result = self._values.get("domain")
        assert result is not None, "Required property 'domain' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def name(self) -> builtins.str:
        '''A name for the app monitor.

        This parameter is required.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html#cfn-rum-appmonitor-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def app_monitor_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnAppMonitor.AppMonitorConfigurationProperty, _IResolvable_da3f097b]]:
        '''A structure that contains much of the configuration data for the app monitor.

        If you are using Amazon Cognito for authorization, you must include this structure in your request, and it must include the ID of the Amazon Cognito identity pool to use for authorization. If you don't include ``AppMonitorConfiguration`` , you must set up your own authorization method. For more information, see `Authorize your application to send data to AWS <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-get-started-authorization.html>`_ .

        If you omit this argument, the sample rate used for CloudWatch RUM is set to 10% of the user sessions.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html#cfn-rum-appmonitor-appmonitorconfiguration
        '''
        result = self._values.get("app_monitor_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnAppMonitor.AppMonitorConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def cw_log_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Data collected by CloudWatch RUM is kept by RUM for 30 days and then deleted.

        This parameter specifies whether CloudWatch RUM sends a copy of this telemetry data to Amazon CloudWatch Logs in your account. This enables you to keep the telemetry data for more than 30 days, but it does incur Amazon CloudWatch Logs charges.

        If you omit this parameter, the default is ``false`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html#cfn-rum-appmonitor-cwlogenabled
        '''
        result = self._values.get("cw_log_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''Assigns one or more tags (key-value pairs) to the app monitor.

        Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.

        Tags don't have any semantic meaning to AWS and are interpreted strictly as strings of characters.

        You can associate as many as 50 tags with an app monitor.

        For more information, see `Tagging AWS resources <https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rum-appmonitor.html#cfn-rum-appmonitor-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAppMonitorProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "CfnAppMonitor",
    "CfnAppMonitorProps",
]

publication.publish()
