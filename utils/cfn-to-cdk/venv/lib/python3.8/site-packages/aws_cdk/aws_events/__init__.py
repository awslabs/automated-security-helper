'''
# Amazon EventBridge Construct Library

Amazon EventBridge delivers a near real-time stream of system events that
describe changes in AWS resources. For example, an AWS CodePipeline emits the
[State
Change](https://docs.aws.amazon.com/eventbridge/latest/userguide/event-types.html#codepipeline-event-type)
event when the pipeline changes its state.

* **Events**: An event indicates a change in your AWS environment. AWS resources
  can generate events when their state changes. For example, Amazon EC2
  generates an event when the state of an EC2 instance changes from pending to
  running, and Amazon EC2 Auto Scaling generates events when it launches or
  terminates instances. AWS CloudTrail publishes events when you make API calls.
  You can generate custom application-level events and publish them to
  EventBridge. You can also set up scheduled events that are generated on
  a periodic basis. For a list of services that generate events, and sample
  events from each service, see [EventBridge Event Examples From Each
  Supported
  Service](https://docs.aws.amazon.com/eventbridge/latest/userguide/event-types.html).
* **Targets**: A target processes events. Targets can include Amazon EC2
  instances, AWS Lambda functions, Kinesis streams, Amazon ECS tasks, Step
  Functions state machines, Amazon SNS topics, Amazon SQS queues, Amazon CloudWatch LogGroups, and built-in
  targets. A target receives events in JSON format.
* **Rules**: A rule matches incoming events and routes them to targets for
  processing. A single rule can route to multiple targets, all of which are
  processed in parallel. Rules are not processed in a particular order. This
  enables different parts of an organization to look for and process the events
  that are of interest to them. A rule can customize the JSON sent to the
  target, by passing only certain parts or by overwriting it with a constant.
* **EventBuses**: An event bus can receive events from your own custom applications
  or it can receive events from applications and services created by AWS SaaS partners.
  See [Creating an Event Bus](https://docs.aws.amazon.com/eventbridge/latest/userguide/create-event-bus.html).

## Rule

The `Rule` construct defines an EventBridge rule which monitors an
event based on an [event
pattern](https://docs.aws.amazon.com/eventbridge/latest/userguide/filtering-examples-structure.html)
and invoke **event targets** when the pattern is matched against a triggered
event. Event targets are objects that implement the `IRuleTarget` interface.

Normally, you will use one of the `source.onXxx(name[, target[, options]]) -> Rule` methods on the event source to define an event rule associated with
the specific activity. You can targets either via props, or add targets using
`rule.addTarget`.

For example, to define an rule that triggers a CodeBuild project build when a
commit is pushed to the "master" branch of a CodeCommit repository:

```python
# repo: codecommit.Repository
# project: codebuild.Project


on_commit_rule = repo.on_commit("OnCommit",
    target=targets.CodeBuildProject(project),
    branches=["master"]
)
```

You can add additional targets, with optional [input
transformer](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_InputTransformer.html)
using `eventRule.addTarget(target[, input])`. For example, we can add a SNS
topic target which formats a human-readable message for the commit.

For example, this adds an SNS topic as a target:

```python
# on_commit_rule: events.Rule
# topic: sns.Topic


on_commit_rule.add_target(targets.SnsTopic(topic,
    message=events.RuleTargetInput.from_text(f"A commit was pushed to the repository {codecommit.ReferenceEvent.repositoryName} on branch {codecommit.ReferenceEvent.referenceName}")
))
```

Or using an Object:

```python
# on_commit_rule: events.Rule
# topic: sns.Topic


on_commit_rule.add_target(targets.SnsTopic(topic,
    message=events.RuleTargetInput.from_object({
        "DataType": f"custom_{events.EventField.fromPath('$.detail-type')}"
    })
))
```

## Scheduling

You can configure a Rule to run on a schedule (cron or rate).
Rate must be specified in minutes, hours or days.

The following example runs a task every day at 4am:

```python
from aws_cdk.aws_events import Rule, Schedule
from aws_cdk.aws_events_targets import EcsTask
from aws_cdk.aws_ecs import Cluster, TaskDefinition
from aws_cdk.aws_iam import Role

# cluster: Cluster
# task_definition: TaskDefinition
# role: Role


ecs_task_target = EcsTask(cluster=cluster, task_definition=task_definition, role=role)

Rule(self, "ScheduleRule",
    schedule=Schedule.cron(minute="0", hour="4"),
    targets=[ecs_task_target]
)
```

If you want to specify Fargate platform version, set `platformVersion` in EcsTask's props like the following example:

```python
# cluster: ecs.Cluster
# task_definition: ecs.TaskDefinition
# role: iam.Role


platform_version = ecs.FargatePlatformVersion.VERSION1_4
ecs_task_target = targets.EcsTask(cluster=cluster, task_definition=task_definition, role=role, platform_version=platform_version)
```

## Event Targets

The `@aws-cdk/aws-events-targets` module includes classes that implement the `IRuleTarget`
interface for various AWS services.

The following targets are supported:

* `targets.CodeBuildProject`: Start an AWS CodeBuild build
* `targets.CodePipeline`: Start an AWS CodePipeline pipeline execution
* `targets.EcsTask`: Start a task on an Amazon ECS cluster
* `targets.LambdaFunction`: Invoke an AWS Lambda function
* `targets.SnsTopic`: Publish into an SNS topic
* `targets.SqsQueue`: Send a message to an Amazon SQS Queue
* `targets.SfnStateMachine`: Trigger an AWS Step Functions state machine
* `targets.BatchJob`: Queue an AWS Batch Job
* `targets.AwsApi`: Make an AWS API call
* `targets.ApiGateway`: Invoke an AWS API Gateway
* `targets.ApiDestination`: Make an call to an external destination

### Cross-account and cross-region targets

It's possible to have the source of the event and a target in separate AWS accounts and regions:

```python
from aws_cdk import Environment, Environment
from aws_cdk import App, Stack
import aws_cdk.aws_codebuild as codebuild
import aws_cdk.aws_codecommit as codecommit
import aws_cdk.aws_events_targets as targets

app = App()

account1 = "11111111111"
account2 = "22222222222"

stack1 = Stack(app, "Stack1", env=Environment(account=account1, region="us-west-1"))
repo = codecommit.Repository(stack1, "Repository",
    repository_name="myrepository"
)

stack2 = Stack(app, "Stack2", env=Environment(account=account2, region="us-east-1"))
project = codebuild.Project(stack2, "Project")

repo.on_commit("OnCommit",
    target=targets.CodeBuildProject(project)
)
```

In this situation, the CDK will wire the 2 accounts together:

* It will generate a rule in the source stack with the event bus of the target account as the target
* It will generate a rule in the target stack, with the provided target
* It will generate a separate stack that gives the source account permissions to publish events
  to the event bus of the target account in the given region,
  and make sure its deployed before the source stack

For more information, see the
[AWS documentation on cross-account events](https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-cross-account-event-delivery.html).

## Archiving

It is possible to archive all or some events sent to an event bus. It is then possible to [replay these events](https://aws.amazon.com/blogs/aws/new-archive-and-replay-events-with-amazon-eventbridge/).

```python
bus = events.EventBus(self, "bus",
    event_bus_name="MyCustomEventBus"
)

bus.archive("MyArchive",
    archive_name="MyCustomEventBusArchive",
    description="MyCustomerEventBus Archive",
    event_pattern=events.EventPattern(
        account=[Stack.of(self).account]
    ),
    retention=Duration.days(365)
)
```

## Granting PutEvents to an existing EventBus

To import an existing EventBus into your CDK application, use `EventBus.fromEventBusArn`, `EventBus.fromEventBusAttributes`
or `EventBus.fromEventBusName` factory method.

Then, you can use the `grantPutEventsTo` method to grant `event:PutEvents` to the eventBus.

```python
# lambda_function: lambda.Function


event_bus = events.EventBus.from_event_bus_arn(self, "ImportedEventBus", "arn:aws:events:us-east-1:111111111:event-bus/my-event-bus")

# now you can just call methods on the eventbus
event_bus.grant_put_events_to(lambda_function)
```
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
    IResolveContext as _IResolveContext_b2df1921,
    IResource as _IResource_c80c4260,
    Resource as _Resource_45bc6135,
    SecretValue as _SecretValue_3dd0ddae,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_iam import (
    Grant as _Grant_a7ae64f8,
    IGrantable as _IGrantable_71c4f5de,
    IRole as _IRole_235f5d8e,
)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.ApiDestinationProps",
    jsii_struct_bases=[],
    name_mapping={
        "connection": "connection",
        "endpoint": "endpoint",
        "api_destination_name": "apiDestinationName",
        "description": "description",
        "http_method": "httpMethod",
        "rate_limit_per_second": "rateLimitPerSecond",
    },
)
class ApiDestinationProps:
    def __init__(
        self,
        *,
        connection: "IConnection",
        endpoint: builtins.str,
        api_destination_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        http_method: typing.Optional["HttpMethod"] = None,
        rate_limit_per_second: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''The event API Destination properties.

        :param connection: The ARN of the connection to use for the API destination.
        :param endpoint: The URL to the HTTP invocation endpoint for the API destination..
        :param api_destination_name: The name for the API destination. Default: - A unique name will be generated
        :param description: A description for the API destination. Default: - none
        :param http_method: The method to use for the request to the HTTP invocation endpoint. Default: HttpMethod.POST
        :param rate_limit_per_second: The maximum number of requests per second to send to the HTTP invocation endpoint. Default: - Not rate limited

        :exampleMetadata: infused

        Example::

            connection = events.Connection(self, "Connection",
                authorization=events.Authorization.api_key("x-api-key", SecretValue.secrets_manager("ApiSecretName")),
                description="Connection with API Key x-api-key"
            )
            
            destination = events.ApiDestination(self, "Destination",
                connection=connection,
                endpoint="https://example.com",
                description="Calling example.com with API key x-api-key"
            )
            
            rule = events.Rule(self, "Rule",
                schedule=events.Schedule.rate(cdk.Duration.minutes(1)),
                targets=[targets.ApiDestination(destination)]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "connection": connection,
            "endpoint": endpoint,
        }
        if api_destination_name is not None:
            self._values["api_destination_name"] = api_destination_name
        if description is not None:
            self._values["description"] = description
        if http_method is not None:
            self._values["http_method"] = http_method
        if rate_limit_per_second is not None:
            self._values["rate_limit_per_second"] = rate_limit_per_second

    @builtins.property
    def connection(self) -> "IConnection":
        '''The ARN of the connection to use for the API destination.'''
        result = self._values.get("connection")
        assert result is not None, "Required property 'connection' is missing"
        return typing.cast("IConnection", result)

    @builtins.property
    def endpoint(self) -> builtins.str:
        '''The URL to the HTTP invocation endpoint for the API destination..'''
        result = self._values.get("endpoint")
        assert result is not None, "Required property 'endpoint' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def api_destination_name(self) -> typing.Optional[builtins.str]:
        '''The name for the API destination.

        :default: - A unique name will be generated
        '''
        result = self._values.get("api_destination_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the API destination.

        :default: - none
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def http_method(self) -> typing.Optional["HttpMethod"]:
        '''The method to use for the request to the HTTP invocation endpoint.

        :default: HttpMethod.POST
        '''
        result = self._values.get("http_method")
        return typing.cast(typing.Optional["HttpMethod"], result)

    @builtins.property
    def rate_limit_per_second(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of requests per second to send to the HTTP invocation endpoint.

        :default: - Not rate limited
        '''
        result = self._values.get("rate_limit_per_second")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApiDestinationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Archive(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.Archive",
):
    '''Define an EventBridge Archive.

    :resource: AWS::Events::Archive
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_events as events
        
        # detail: Any
        # event_bus: events.EventBus
        
        archive = events.Archive(self, "MyArchive",
            event_pattern=events.EventPattern(
                account=["account"],
                detail={
                    "detail_key": detail
                },
                detail_type=["detailType"],
                id=["id"],
                region=["region"],
                resources=["resources"],
                source=["source"],
                time=["time"],
                version=["version"]
            ),
            source_event_bus=event_bus,
        
            # the properties below are optional
            archive_name="archiveName",
            description="description",
            retention=cdk.Duration.minutes(30)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        source_event_bus: "IEventBus",
        event_pattern: "EventPattern",
        archive_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        retention: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param source_event_bus: The event source associated with the archive.
        :param event_pattern: An event pattern to use to filter events sent to the archive.
        :param archive_name: The name of the archive. Default: - Automatically generated
        :param description: A description for the archive. Default: - none
        :param retention: The number of days to retain events for. Default value is 0. If set to 0, events are retained indefinitely. Default: - Infinite
        '''
        props = ArchiveProps(
            source_event_bus=source_event_bus,
            event_pattern=event_pattern,
            archive_name=archive_name,
            description=description,
            retention=retention,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="archiveArn")
    def archive_arn(self) -> builtins.str:
        '''The ARN of the archive created.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "archiveArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="archiveName")
    def archive_name(self) -> builtins.str:
        '''The archive name.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "archiveName"))


class Authorization(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_events.Authorization",
):
    '''Authorization type for an API Destination Connection.

    :exampleMetadata: infused

    Example::

        connection = events.Connection(self, "Connection",
            authorization=events.Authorization.api_key("x-api-key", SecretValue.secrets_manager("ApiSecretName")),
            description="Connection with API Key x-api-key"
        )
        
        destination = events.ApiDestination(self, "Destination",
            connection=connection,
            endpoint="https://example.com",
            description="Calling example.com with API key x-api-key"
        )
        
        rule = events.Rule(self, "Rule",
            schedule=events.Schedule.rate(cdk.Duration.minutes(1)),
            targets=[targets.ApiDestination(destination)]
        )
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="apiKey") # type: ignore[misc]
    @builtins.classmethod
    def api_key(
        cls,
        api_key_name: builtins.str,
        api_key_value: _SecretValue_3dd0ddae,
    ) -> "Authorization":
        '''Use API key authorization.

        API key authorization has two components: an API key name and an API key value.
        What these are depends on the target of your connection.

        :param api_key_name: -
        :param api_key_value: -
        '''
        return typing.cast("Authorization", jsii.sinvoke(cls, "apiKey", [api_key_name, api_key_value]))

    @jsii.member(jsii_name="basic") # type: ignore[misc]
    @builtins.classmethod
    def basic(
        cls,
        username: builtins.str,
        password: _SecretValue_3dd0ddae,
    ) -> "Authorization":
        '''Use username and password authorization.

        :param username: -
        :param password: -
        '''
        return typing.cast("Authorization", jsii.sinvoke(cls, "basic", [username, password]))

    @jsii.member(jsii_name="oauth") # type: ignore[misc]
    @builtins.classmethod
    def oauth(
        cls,
        *,
        authorization_endpoint: builtins.str,
        client_id: builtins.str,
        client_secret: _SecretValue_3dd0ddae,
        http_method: "HttpMethod",
        body_parameters: typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]] = None,
        header_parameters: typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]] = None,
        query_string_parameters: typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]] = None,
    ) -> "Authorization":
        '''Use OAuth authorization.

        :param authorization_endpoint: The URL to the authorization endpoint.
        :param client_id: The client ID to use for OAuth authorization for the connection.
        :param client_secret: The client secret associated with the client ID to use for OAuth authorization for the connection.
        :param http_method: The method to use for the authorization request. (Can only choose POST, GET or PUT).
        :param body_parameters: Additional string parameters to add to the OAuth request body. Default: - No additional parameters
        :param header_parameters: Additional string parameters to add to the OAuth request header. Default: - No additional parameters
        :param query_string_parameters: Additional string parameters to add to the OAuth request query string. Default: - No additional parameters
        '''
        props = OAuthAuthorizationProps(
            authorization_endpoint=authorization_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            http_method=http_method,
            body_parameters=body_parameters,
            header_parameters=header_parameters,
            query_string_parameters=query_string_parameters,
        )

        return typing.cast("Authorization", jsii.sinvoke(cls, "oauth", [props]))


class _AuthorizationProxy(Authorization):
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, Authorization).__jsii_proxy_class__ = lambda : _AuthorizationProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.BaseArchiveProps",
    jsii_struct_bases=[],
    name_mapping={
        "event_pattern": "eventPattern",
        "archive_name": "archiveName",
        "description": "description",
        "retention": "retention",
    },
)
class BaseArchiveProps:
    def __init__(
        self,
        *,
        event_pattern: "EventPattern",
        archive_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        retention: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''The event archive base properties.

        :param event_pattern: An event pattern to use to filter events sent to the archive.
        :param archive_name: The name of the archive. Default: - Automatically generated
        :param description: A description for the archive. Default: - none
        :param retention: The number of days to retain events for. Default value is 0. If set to 0, events are retained indefinitely. Default: - Infinite

        :exampleMetadata: infused

        Example::

            bus = events.EventBus(self, "bus",
                event_bus_name="MyCustomEventBus"
            )
            
            bus.archive("MyArchive",
                archive_name="MyCustomEventBusArchive",
                description="MyCustomerEventBus Archive",
                event_pattern=events.EventPattern(
                    account=[Stack.of(self).account]
                ),
                retention=Duration.days(365)
            )
        '''
        if isinstance(event_pattern, dict):
            event_pattern = EventPattern(**event_pattern)
        self._values: typing.Dict[str, typing.Any] = {
            "event_pattern": event_pattern,
        }
        if archive_name is not None:
            self._values["archive_name"] = archive_name
        if description is not None:
            self._values["description"] = description
        if retention is not None:
            self._values["retention"] = retention

    @builtins.property
    def event_pattern(self) -> "EventPattern":
        '''An event pattern to use to filter events sent to the archive.'''
        result = self._values.get("event_pattern")
        assert result is not None, "Required property 'event_pattern' is missing"
        return typing.cast("EventPattern", result)

    @builtins.property
    def archive_name(self) -> typing.Optional[builtins.str]:
        '''The name of the archive.

        :default: - Automatically generated
        '''
        result = self._values.get("archive_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the archive.

        :default: - none
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def retention(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The number of days to retain events for.

        Default value is 0. If set to 0, events are retained indefinitely.

        :default: - Infinite
        '''
        result = self._values.get("retention")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseArchiveProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnApiDestination(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.CfnApiDestination",
):
    '''A CloudFormation ``AWS::Events::ApiDestination``.

    Creates an API destination, which is an HTTP invocation endpoint configured as a target for events.

    When using ApiDesinations with OAuth authentication we recommend these best practices:

    - Create a secret in Secrets Manager with your OAuth credentials.
    - Reference that secret in your CloudFormation template for ``AWS::Events::Connection`` using CloudFormation dynamic reference syntax. For more information, see `Secrets Manager secrets <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html#dynamic-references-secretsmanager>`_ .

    When the Connection resource is created the secret will be passed to EventBridge and stored in the customer account using “Service Linked Secrets,” effectively creating two secrets. This will minimize the cost because the original secret is only accessed when a CloudFormation template is created or updated, not every time an event is sent to the ApiDestination. The secret stored in the customer account by EventBridge is the one used for each event sent to the ApiDestination and AWS is responsible for the fees.
    .. epigraph::

       The secret stored in the customer account by EventBridge can’t be updated directly, only when a CloudFormation template is updated.

    For examples of CloudFormation templates that use secrets, see `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-connection.html#aws-resource-events-connection--examples>`_ .

    :cloudformationResource: AWS::Events::ApiDestination
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_events as events
        
        cfn_api_destination = events.CfnApiDestination(self, "MyCfnApiDestination",
            connection_arn="connectionArn",
            http_method="httpMethod",
            invocation_endpoint="invocationEndpoint",
        
            # the properties below are optional
            description="description",
            invocation_rate_limit_per_second=123,
            name="name"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        connection_arn: builtins.str,
        http_method: builtins.str,
        invocation_endpoint: builtins.str,
        description: typing.Optional[builtins.str] = None,
        invocation_rate_limit_per_second: typing.Optional[jsii.Number] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Events::ApiDestination``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param connection_arn: The ARN of the connection to use for the API destination. The destination endpoint must support the authorization type specified for the connection.
        :param http_method: The method to use for the request to the HTTP invocation endpoint.
        :param invocation_endpoint: The URL to the HTTP invocation endpoint for the API destination.
        :param description: A description for the API destination to create.
        :param invocation_rate_limit_per_second: The maximum number of requests per second to send to the HTTP invocation endpoint.
        :param name: The name for the API destination to create.
        '''
        props = CfnApiDestinationProps(
            connection_arn=connection_arn,
            http_method=http_method,
            invocation_endpoint=invocation_endpoint,
            description=description,
            invocation_rate_limit_per_second=invocation_rate_limit_per_second,
            name=name,
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
        '''The ARN of the API destination that was created by the request.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionArn")
    def connection_arn(self) -> builtins.str:
        '''The ARN of the connection to use for the API destination.

        The destination endpoint must support the authorization type specified for the connection.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-connectionarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "connectionArn"))

    @connection_arn.setter
    def connection_arn(self, value: builtins.str) -> None:
        jsii.set(self, "connectionArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="httpMethod")
    def http_method(self) -> builtins.str:
        '''The method to use for the request to the HTTP invocation endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-httpmethod
        '''
        return typing.cast(builtins.str, jsii.get(self, "httpMethod"))

    @http_method.setter
    def http_method(self, value: builtins.str) -> None:
        jsii.set(self, "httpMethod", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="invocationEndpoint")
    def invocation_endpoint(self) -> builtins.str:
        '''The URL to the HTTP invocation endpoint for the API destination.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-invocationendpoint
        '''
        return typing.cast(builtins.str, jsii.get(self, "invocationEndpoint"))

    @invocation_endpoint.setter
    def invocation_endpoint(self, value: builtins.str) -> None:
        jsii.set(self, "invocationEndpoint", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the API destination to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="invocationRateLimitPerSecond")
    def invocation_rate_limit_per_second(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of requests per second to send to the HTTP invocation endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-invocationratelimitpersecond
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "invocationRateLimitPerSecond"))

    @invocation_rate_limit_per_second.setter
    def invocation_rate_limit_per_second(
        self,
        value: typing.Optional[jsii.Number],
    ) -> None:
        jsii.set(self, "invocationRateLimitPerSecond", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name for the API destination to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.CfnApiDestinationProps",
    jsii_struct_bases=[],
    name_mapping={
        "connection_arn": "connectionArn",
        "http_method": "httpMethod",
        "invocation_endpoint": "invocationEndpoint",
        "description": "description",
        "invocation_rate_limit_per_second": "invocationRateLimitPerSecond",
        "name": "name",
    },
)
class CfnApiDestinationProps:
    def __init__(
        self,
        *,
        connection_arn: builtins.str,
        http_method: builtins.str,
        invocation_endpoint: builtins.str,
        description: typing.Optional[builtins.str] = None,
        invocation_rate_limit_per_second: typing.Optional[jsii.Number] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnApiDestination``.

        :param connection_arn: The ARN of the connection to use for the API destination. The destination endpoint must support the authorization type specified for the connection.
        :param http_method: The method to use for the request to the HTTP invocation endpoint.
        :param invocation_endpoint: The URL to the HTTP invocation endpoint for the API destination.
        :param description: A description for the API destination to create.
        :param invocation_rate_limit_per_second: The maximum number of requests per second to send to the HTTP invocation endpoint.
        :param name: The name for the API destination to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_events as events
            
            cfn_api_destination_props = events.CfnApiDestinationProps(
                connection_arn="connectionArn",
                http_method="httpMethod",
                invocation_endpoint="invocationEndpoint",
            
                # the properties below are optional
                description="description",
                invocation_rate_limit_per_second=123,
                name="name"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "connection_arn": connection_arn,
            "http_method": http_method,
            "invocation_endpoint": invocation_endpoint,
        }
        if description is not None:
            self._values["description"] = description
        if invocation_rate_limit_per_second is not None:
            self._values["invocation_rate_limit_per_second"] = invocation_rate_limit_per_second
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def connection_arn(self) -> builtins.str:
        '''The ARN of the connection to use for the API destination.

        The destination endpoint must support the authorization type specified for the connection.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-connectionarn
        '''
        result = self._values.get("connection_arn")
        assert result is not None, "Required property 'connection_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def http_method(self) -> builtins.str:
        '''The method to use for the request to the HTTP invocation endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-httpmethod
        '''
        result = self._values.get("http_method")
        assert result is not None, "Required property 'http_method' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def invocation_endpoint(self) -> builtins.str:
        '''The URL to the HTTP invocation endpoint for the API destination.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-invocationendpoint
        '''
        result = self._values.get("invocation_endpoint")
        assert result is not None, "Required property 'invocation_endpoint' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the API destination to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def invocation_rate_limit_per_second(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of requests per second to send to the HTTP invocation endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-invocationratelimitpersecond
        '''
        result = self._values.get("invocation_rate_limit_per_second")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name for the API destination to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-apidestination.html#cfn-events-apidestination-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnApiDestinationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnArchive(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.CfnArchive",
):
    '''A CloudFormation ``AWS::Events::Archive``.

    Creates an archive of events with the specified settings. When you create an archive, incoming events might not immediately start being sent to the archive. Allow a short period of time for changes to take effect. If you do not specify a pattern to filter events sent to the archive, all events are sent to the archive except replayed events. Replayed events are not sent to an archive.

    :cloudformationResource: AWS::Events::Archive
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_events as events
        
        # event_pattern: Any
        
        cfn_archive = events.CfnArchive(self, "MyCfnArchive",
            source_arn="sourceArn",
        
            # the properties below are optional
            archive_name="archiveName",
            description="description",
            event_pattern=event_pattern,
            retention_days=123
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        source_arn: builtins.str,
        archive_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Any = None,
        retention_days: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Create a new ``AWS::Events::Archive``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param source_arn: The ARN of the event bus that sends events to the archive.
        :param archive_name: The name for the archive to create.
        :param description: A description for the archive.
        :param event_pattern: An event pattern to use to filter events sent to the archive.
        :param retention_days: The number of days to retain events for. Default value is 0. If set to 0, events are retained indefinitely
        '''
        props = CfnArchiveProps(
            source_arn=source_arn,
            archive_name=archive_name,
            description=description,
            event_pattern=event_pattern,
            retention_days=retention_days,
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
    @jsii.member(jsii_name="attrArchiveName")
    def attr_archive_name(self) -> builtins.str:
        '''The archive name.

        :cloudformationAttribute: ArchiveName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArchiveName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrArn")
    def attr_arn(self) -> builtins.str:
        '''The ARN of the archive created.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventPattern")
    def event_pattern(self) -> typing.Any:
        '''An event pattern to use to filter events sent to the archive.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html#cfn-events-archive-eventpattern
        '''
        return typing.cast(typing.Any, jsii.get(self, "eventPattern"))

    @event_pattern.setter
    def event_pattern(self, value: typing.Any) -> None:
        jsii.set(self, "eventPattern", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sourceArn")
    def source_arn(self) -> builtins.str:
        '''The ARN of the event bus that sends events to the archive.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html#cfn-events-archive-sourcearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "sourceArn"))

    @source_arn.setter
    def source_arn(self, value: builtins.str) -> None:
        jsii.set(self, "sourceArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="archiveName")
    def archive_name(self) -> typing.Optional[builtins.str]:
        '''The name for the archive to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html#cfn-events-archive-archivename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "archiveName"))

    @archive_name.setter
    def archive_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "archiveName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the archive.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html#cfn-events-archive-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="retentionDays")
    def retention_days(self) -> typing.Optional[jsii.Number]:
        '''The number of days to retain events for.

        Default value is 0. If set to 0, events are retained indefinitely

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html#cfn-events-archive-retentiondays
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "retentionDays"))

    @retention_days.setter
    def retention_days(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "retentionDays", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.CfnArchiveProps",
    jsii_struct_bases=[],
    name_mapping={
        "source_arn": "sourceArn",
        "archive_name": "archiveName",
        "description": "description",
        "event_pattern": "eventPattern",
        "retention_days": "retentionDays",
    },
)
class CfnArchiveProps:
    def __init__(
        self,
        *,
        source_arn: builtins.str,
        archive_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Any = None,
        retention_days: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Properties for defining a ``CfnArchive``.

        :param source_arn: The ARN of the event bus that sends events to the archive.
        :param archive_name: The name for the archive to create.
        :param description: A description for the archive.
        :param event_pattern: An event pattern to use to filter events sent to the archive.
        :param retention_days: The number of days to retain events for. Default value is 0. If set to 0, events are retained indefinitely

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_events as events
            
            # event_pattern: Any
            
            cfn_archive_props = events.CfnArchiveProps(
                source_arn="sourceArn",
            
                # the properties below are optional
                archive_name="archiveName",
                description="description",
                event_pattern=event_pattern,
                retention_days=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "source_arn": source_arn,
        }
        if archive_name is not None:
            self._values["archive_name"] = archive_name
        if description is not None:
            self._values["description"] = description
        if event_pattern is not None:
            self._values["event_pattern"] = event_pattern
        if retention_days is not None:
            self._values["retention_days"] = retention_days

    @builtins.property
    def source_arn(self) -> builtins.str:
        '''The ARN of the event bus that sends events to the archive.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html#cfn-events-archive-sourcearn
        '''
        result = self._values.get("source_arn")
        assert result is not None, "Required property 'source_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def archive_name(self) -> typing.Optional[builtins.str]:
        '''The name for the archive to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html#cfn-events-archive-archivename
        '''
        result = self._values.get("archive_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the archive.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html#cfn-events-archive-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def event_pattern(self) -> typing.Any:
        '''An event pattern to use to filter events sent to the archive.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html#cfn-events-archive-eventpattern
        '''
        result = self._values.get("event_pattern")
        return typing.cast(typing.Any, result)

    @builtins.property
    def retention_days(self) -> typing.Optional[jsii.Number]:
        '''The number of days to retain events for.

        Default value is 0. If set to 0, events are retained indefinitely

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-archive.html#cfn-events-archive-retentiondays
        '''
        result = self._values.get("retention_days")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnArchiveProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnConnection(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.CfnConnection",
):
    '''A CloudFormation ``AWS::Events::Connection``.

    Creates a connection. A connection defines the authorization type and credentials to use for authorization with an API destination HTTP endpoint.

    :cloudformationResource: AWS::Events::Connection
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-connection.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_events as events
        
        cfn_connection = events.CfnConnection(self, "MyCfnConnection",
            authorization_type="authorizationType",
            auth_parameters=events.CfnConnection.AuthParametersProperty(
                api_key_auth_parameters=events.CfnConnection.ApiKeyAuthParametersProperty(
                    api_key_name="apiKeyName",
                    api_key_value="apiKeyValue"
                ),
                basic_auth_parameters=events.CfnConnection.BasicAuthParametersProperty(
                    password="password",
                    username="username"
                ),
                invocation_http_parameters=events.CfnConnection.ConnectionHttpParametersProperty(
                    body_parameters=[events.CfnConnection.ParameterProperty(
                        key="key",
                        value="value",
        
                        # the properties below are optional
                        is_value_secret=False
                    )],
                    header_parameters=[events.CfnConnection.ParameterProperty(
                        key="key",
                        value="value",
        
                        # the properties below are optional
                        is_value_secret=False
                    )],
                    query_string_parameters=[events.CfnConnection.ParameterProperty(
                        key="key",
                        value="value",
        
                        # the properties below are optional
                        is_value_secret=False
                    )]
                ),
                o_auth_parameters=events.CfnConnection.OAuthParametersProperty(
                    authorization_endpoint="authorizationEndpoint",
                    client_parameters=events.CfnConnection.ClientParametersProperty(
                        client_id="clientId",
                        client_secret="clientSecret"
                    ),
                    http_method="httpMethod",
        
                    # the properties below are optional
                    o_auth_http_parameters=events.CfnConnection.ConnectionHttpParametersProperty(
                        body_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
        
                            # the properties below are optional
                            is_value_secret=False
                        )],
                        header_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
        
                            # the properties below are optional
                            is_value_secret=False
                        )],
                        query_string_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
        
                            # the properties below are optional
                            is_value_secret=False
                        )]
                    )
                )
            ),
        
            # the properties below are optional
            description="description",
            name="name"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        authorization_type: builtins.str,
        auth_parameters: typing.Union["CfnConnection.AuthParametersProperty", _IResolvable_da3f097b],
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::Events::Connection``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param authorization_type: The type of authorization to use for the connection.
        :param auth_parameters: A ``CreateConnectionAuthRequestParameters`` object that contains the authorization parameters to use to authorize with the endpoint.
        :param description: A description for the connection to create.
        :param name: The name for the connection to create.
        '''
        props = CfnConnectionProps(
            authorization_type=authorization_type,
            auth_parameters=auth_parameters,
            description=description,
            name=name,
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
        '''The ARN of the connection that was created by the request.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSecretArn")
    def attr_secret_arn(self) -> builtins.str:
        '''The ARN for the secret created for the connection.

        :cloudformationAttribute: SecretArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrSecretArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="authorizationType")
    def authorization_type(self) -> builtins.str:
        '''The type of authorization to use for the connection.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-connection.html#cfn-events-connection-authorizationtype
        '''
        return typing.cast(builtins.str, jsii.get(self, "authorizationType"))

    @authorization_type.setter
    def authorization_type(self, value: builtins.str) -> None:
        jsii.set(self, "authorizationType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="authParameters")
    def auth_parameters(
        self,
    ) -> typing.Union["CfnConnection.AuthParametersProperty", _IResolvable_da3f097b]:
        '''A ``CreateConnectionAuthRequestParameters`` object that contains the authorization parameters to use to authorize with the endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-connection.html#cfn-events-connection-authparameters
        '''
        return typing.cast(typing.Union["CfnConnection.AuthParametersProperty", _IResolvable_da3f097b], jsii.get(self, "authParameters"))

    @auth_parameters.setter
    def auth_parameters(
        self,
        value: typing.Union["CfnConnection.AuthParametersProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "authParameters", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the connection to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-connection.html#cfn-events-connection-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name for the connection to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-connection.html#cfn-events-connection-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnConnection.ApiKeyAuthParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"api_key_name": "apiKeyName", "api_key_value": "apiKeyValue"},
    )
    class ApiKeyAuthParametersProperty:
        def __init__(
            self,
            *,
            api_key_name: builtins.str,
            api_key_value: builtins.str,
        ) -> None:
            '''
            :param api_key_name: ``CfnConnection.ApiKeyAuthParametersProperty.ApiKeyName``.
            :param api_key_value: ``CfnConnection.ApiKeyAuthParametersProperty.ApiKeyValue``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-apikeyauthparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                api_key_auth_parameters_property = events.CfnConnection.ApiKeyAuthParametersProperty(
                    api_key_name="apiKeyName",
                    api_key_value="apiKeyValue"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "api_key_name": api_key_name,
                "api_key_value": api_key_value,
            }

        @builtins.property
        def api_key_name(self) -> builtins.str:
            '''``CfnConnection.ApiKeyAuthParametersProperty.ApiKeyName``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-apikeyauthparameters.html#cfn-events-connection-apikeyauthparameters-apikeyname
            '''
            result = self._values.get("api_key_name")
            assert result is not None, "Required property 'api_key_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def api_key_value(self) -> builtins.str:
            '''``CfnConnection.ApiKeyAuthParametersProperty.ApiKeyValue``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-apikeyauthparameters.html#cfn-events-connection-apikeyauthparameters-apikeyvalue
            '''
            result = self._values.get("api_key_value")
            assert result is not None, "Required property 'api_key_value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ApiKeyAuthParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnConnection.AuthParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "api_key_auth_parameters": "apiKeyAuthParameters",
            "basic_auth_parameters": "basicAuthParameters",
            "invocation_http_parameters": "invocationHttpParameters",
            "o_auth_parameters": "oAuthParameters",
        },
    )
    class AuthParametersProperty:
        def __init__(
            self,
            *,
            api_key_auth_parameters: typing.Optional[typing.Union["CfnConnection.ApiKeyAuthParametersProperty", _IResolvable_da3f097b]] = None,
            basic_auth_parameters: typing.Optional[typing.Union["CfnConnection.BasicAuthParametersProperty", _IResolvable_da3f097b]] = None,
            invocation_http_parameters: typing.Optional[typing.Union["CfnConnection.ConnectionHttpParametersProperty", _IResolvable_da3f097b]] = None,
            o_auth_parameters: typing.Optional[typing.Union["CfnConnection.OAuthParametersProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param api_key_auth_parameters: ``CfnConnection.AuthParametersProperty.ApiKeyAuthParameters``.
            :param basic_auth_parameters: ``CfnConnection.AuthParametersProperty.BasicAuthParameters``.
            :param invocation_http_parameters: ``CfnConnection.AuthParametersProperty.InvocationHttpParameters``.
            :param o_auth_parameters: ``CfnConnection.AuthParametersProperty.OAuthParameters``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-authparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                auth_parameters_property = events.CfnConnection.AuthParametersProperty(
                    api_key_auth_parameters=events.CfnConnection.ApiKeyAuthParametersProperty(
                        api_key_name="apiKeyName",
                        api_key_value="apiKeyValue"
                    ),
                    basic_auth_parameters=events.CfnConnection.BasicAuthParametersProperty(
                        password="password",
                        username="username"
                    ),
                    invocation_http_parameters=events.CfnConnection.ConnectionHttpParametersProperty(
                        body_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
                
                            # the properties below are optional
                            is_value_secret=False
                        )],
                        header_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
                
                            # the properties below are optional
                            is_value_secret=False
                        )],
                        query_string_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
                
                            # the properties below are optional
                            is_value_secret=False
                        )]
                    ),
                    o_auth_parameters=events.CfnConnection.OAuthParametersProperty(
                        authorization_endpoint="authorizationEndpoint",
                        client_parameters=events.CfnConnection.ClientParametersProperty(
                            client_id="clientId",
                            client_secret="clientSecret"
                        ),
                        http_method="httpMethod",
                
                        # the properties below are optional
                        o_auth_http_parameters=events.CfnConnection.ConnectionHttpParametersProperty(
                            body_parameters=[events.CfnConnection.ParameterProperty(
                                key="key",
                                value="value",
                
                                # the properties below are optional
                                is_value_secret=False
                            )],
                            header_parameters=[events.CfnConnection.ParameterProperty(
                                key="key",
                                value="value",
                
                                # the properties below are optional
                                is_value_secret=False
                            )],
                            query_string_parameters=[events.CfnConnection.ParameterProperty(
                                key="key",
                                value="value",
                
                                # the properties below are optional
                                is_value_secret=False
                            )]
                        )
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if api_key_auth_parameters is not None:
                self._values["api_key_auth_parameters"] = api_key_auth_parameters
            if basic_auth_parameters is not None:
                self._values["basic_auth_parameters"] = basic_auth_parameters
            if invocation_http_parameters is not None:
                self._values["invocation_http_parameters"] = invocation_http_parameters
            if o_auth_parameters is not None:
                self._values["o_auth_parameters"] = o_auth_parameters

        @builtins.property
        def api_key_auth_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnConnection.ApiKeyAuthParametersProperty", _IResolvable_da3f097b]]:
            '''``CfnConnection.AuthParametersProperty.ApiKeyAuthParameters``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-authparameters.html#cfn-events-connection-authparameters-apikeyauthparameters
            '''
            result = self._values.get("api_key_auth_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnConnection.ApiKeyAuthParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def basic_auth_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnConnection.BasicAuthParametersProperty", _IResolvable_da3f097b]]:
            '''``CfnConnection.AuthParametersProperty.BasicAuthParameters``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-authparameters.html#cfn-events-connection-authparameters-basicauthparameters
            '''
            result = self._values.get("basic_auth_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnConnection.BasicAuthParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def invocation_http_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnConnection.ConnectionHttpParametersProperty", _IResolvable_da3f097b]]:
            '''``CfnConnection.AuthParametersProperty.InvocationHttpParameters``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-authparameters.html#cfn-events-connection-authparameters-invocationhttpparameters
            '''
            result = self._values.get("invocation_http_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnConnection.ConnectionHttpParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def o_auth_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnConnection.OAuthParametersProperty", _IResolvable_da3f097b]]:
            '''``CfnConnection.AuthParametersProperty.OAuthParameters``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-authparameters.html#cfn-events-connection-authparameters-oauthparameters
            '''
            result = self._values.get("o_auth_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnConnection.OAuthParametersProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AuthParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnConnection.BasicAuthParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"password": "password", "username": "username"},
    )
    class BasicAuthParametersProperty:
        def __init__(self, *, password: builtins.str, username: builtins.str) -> None:
            '''
            :param password: ``CfnConnection.BasicAuthParametersProperty.Password``.
            :param username: ``CfnConnection.BasicAuthParametersProperty.Username``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-basicauthparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                basic_auth_parameters_property = events.CfnConnection.BasicAuthParametersProperty(
                    password="password",
                    username="username"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "password": password,
                "username": username,
            }

        @builtins.property
        def password(self) -> builtins.str:
            '''``CfnConnection.BasicAuthParametersProperty.Password``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-basicauthparameters.html#cfn-events-connection-basicauthparameters-password
            '''
            result = self._values.get("password")
            assert result is not None, "Required property 'password' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def username(self) -> builtins.str:
            '''``CfnConnection.BasicAuthParametersProperty.Username``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-basicauthparameters.html#cfn-events-connection-basicauthparameters-username
            '''
            result = self._values.get("username")
            assert result is not None, "Required property 'username' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BasicAuthParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnConnection.ClientParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"client_id": "clientId", "client_secret": "clientSecret"},
    )
    class ClientParametersProperty:
        def __init__(
            self,
            *,
            client_id: builtins.str,
            client_secret: builtins.str,
        ) -> None:
            '''
            :param client_id: ``CfnConnection.ClientParametersProperty.ClientID``.
            :param client_secret: ``CfnConnection.ClientParametersProperty.ClientSecret``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-clientparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                client_parameters_property = events.CfnConnection.ClientParametersProperty(
                    client_id="clientId",
                    client_secret="clientSecret"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "client_id": client_id,
                "client_secret": client_secret,
            }

        @builtins.property
        def client_id(self) -> builtins.str:
            '''``CfnConnection.ClientParametersProperty.ClientID``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-clientparameters.html#cfn-events-connection-clientparameters-clientid
            '''
            result = self._values.get("client_id")
            assert result is not None, "Required property 'client_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def client_secret(self) -> builtins.str:
            '''``CfnConnection.ClientParametersProperty.ClientSecret``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-clientparameters.html#cfn-events-connection-clientparameters-clientsecret
            '''
            result = self._values.get("client_secret")
            assert result is not None, "Required property 'client_secret' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ClientParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnConnection.ConnectionHttpParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "body_parameters": "bodyParameters",
            "header_parameters": "headerParameters",
            "query_string_parameters": "queryStringParameters",
        },
    )
    class ConnectionHttpParametersProperty:
        def __init__(
            self,
            *,
            body_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnConnection.ParameterProperty", _IResolvable_da3f097b]]]] = None,
            header_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnConnection.ParameterProperty", _IResolvable_da3f097b]]]] = None,
            query_string_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnConnection.ParameterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Contains additional parameters for the connection.

            :param body_parameters: Contains additional body string parameters for the connection.
            :param header_parameters: Contains additional header parameters for the connection.
            :param query_string_parameters: Contains additional query string parameters for the connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-connectionhttpparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                connection_http_parameters_property = events.CfnConnection.ConnectionHttpParametersProperty(
                    body_parameters=[events.CfnConnection.ParameterProperty(
                        key="key",
                        value="value",
                
                        # the properties below are optional
                        is_value_secret=False
                    )],
                    header_parameters=[events.CfnConnection.ParameterProperty(
                        key="key",
                        value="value",
                
                        # the properties below are optional
                        is_value_secret=False
                    )],
                    query_string_parameters=[events.CfnConnection.ParameterProperty(
                        key="key",
                        value="value",
                
                        # the properties below are optional
                        is_value_secret=False
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if body_parameters is not None:
                self._values["body_parameters"] = body_parameters
            if header_parameters is not None:
                self._values["header_parameters"] = header_parameters
            if query_string_parameters is not None:
                self._values["query_string_parameters"] = query_string_parameters

        @builtins.property
        def body_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnConnection.ParameterProperty", _IResolvable_da3f097b]]]]:
            '''Contains additional body string parameters for the connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-connectionhttpparameters.html#cfn-events-connection-connectionhttpparameters-bodyparameters
            '''
            result = self._values.get("body_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnConnection.ParameterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def header_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnConnection.ParameterProperty", _IResolvable_da3f097b]]]]:
            '''Contains additional header parameters for the connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-connectionhttpparameters.html#cfn-events-connection-connectionhttpparameters-headerparameters
            '''
            result = self._values.get("header_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnConnection.ParameterProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def query_string_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnConnection.ParameterProperty", _IResolvable_da3f097b]]]]:
            '''Contains additional query string parameters for the connection.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-connectionhttpparameters.html#cfn-events-connection-connectionhttpparameters-querystringparameters
            '''
            result = self._values.get("query_string_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnConnection.ParameterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConnectionHttpParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnConnection.OAuthParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "authorization_endpoint": "authorizationEndpoint",
            "client_parameters": "clientParameters",
            "http_method": "httpMethod",
            "o_auth_http_parameters": "oAuthHttpParameters",
        },
    )
    class OAuthParametersProperty:
        def __init__(
            self,
            *,
            authorization_endpoint: builtins.str,
            client_parameters: typing.Union["CfnConnection.ClientParametersProperty", _IResolvable_da3f097b],
            http_method: builtins.str,
            o_auth_http_parameters: typing.Optional[typing.Union["CfnConnection.ConnectionHttpParametersProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param authorization_endpoint: ``CfnConnection.OAuthParametersProperty.AuthorizationEndpoint``.
            :param client_parameters: ``CfnConnection.OAuthParametersProperty.ClientParameters``.
            :param http_method: ``CfnConnection.OAuthParametersProperty.HttpMethod``.
            :param o_auth_http_parameters: ``CfnConnection.OAuthParametersProperty.OAuthHttpParameters``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-oauthparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                o_auth_parameters_property = events.CfnConnection.OAuthParametersProperty(
                    authorization_endpoint="authorizationEndpoint",
                    client_parameters=events.CfnConnection.ClientParametersProperty(
                        client_id="clientId",
                        client_secret="clientSecret"
                    ),
                    http_method="httpMethod",
                
                    # the properties below are optional
                    o_auth_http_parameters=events.CfnConnection.ConnectionHttpParametersProperty(
                        body_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
                
                            # the properties below are optional
                            is_value_secret=False
                        )],
                        header_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
                
                            # the properties below are optional
                            is_value_secret=False
                        )],
                        query_string_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
                
                            # the properties below are optional
                            is_value_secret=False
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "authorization_endpoint": authorization_endpoint,
                "client_parameters": client_parameters,
                "http_method": http_method,
            }
            if o_auth_http_parameters is not None:
                self._values["o_auth_http_parameters"] = o_auth_http_parameters

        @builtins.property
        def authorization_endpoint(self) -> builtins.str:
            '''``CfnConnection.OAuthParametersProperty.AuthorizationEndpoint``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-oauthparameters.html#cfn-events-connection-oauthparameters-authorizationendpoint
            '''
            result = self._values.get("authorization_endpoint")
            assert result is not None, "Required property 'authorization_endpoint' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def client_parameters(
            self,
        ) -> typing.Union["CfnConnection.ClientParametersProperty", _IResolvable_da3f097b]:
            '''``CfnConnection.OAuthParametersProperty.ClientParameters``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-oauthparameters.html#cfn-events-connection-oauthparameters-clientparameters
            '''
            result = self._values.get("client_parameters")
            assert result is not None, "Required property 'client_parameters' is missing"
            return typing.cast(typing.Union["CfnConnection.ClientParametersProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def http_method(self) -> builtins.str:
            '''``CfnConnection.OAuthParametersProperty.HttpMethod``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-oauthparameters.html#cfn-events-connection-oauthparameters-httpmethod
            '''
            result = self._values.get("http_method")
            assert result is not None, "Required property 'http_method' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def o_auth_http_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnConnection.ConnectionHttpParametersProperty", _IResolvable_da3f097b]]:
            '''``CfnConnection.OAuthParametersProperty.OAuthHttpParameters``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-oauthparameters.html#cfn-events-connection-oauthparameters-oauthhttpparameters
            '''
            result = self._values.get("o_auth_http_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnConnection.ConnectionHttpParametersProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "OAuthParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnConnection.ParameterProperty",
        jsii_struct_bases=[],
        name_mapping={
            "key": "key",
            "value": "value",
            "is_value_secret": "isValueSecret",
        },
    )
    class ParameterProperty:
        def __init__(
            self,
            *,
            key: builtins.str,
            value: builtins.str,
            is_value_secret: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''
            :param key: ``CfnConnection.ParameterProperty.Key``.
            :param value: ``CfnConnection.ParameterProperty.Value``.
            :param is_value_secret: ``CfnConnection.ParameterProperty.IsValueSecret``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-parameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                parameter_property = events.CfnConnection.ParameterProperty(
                    key="key",
                    value="value",
                
                    # the properties below are optional
                    is_value_secret=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "key": key,
                "value": value,
            }
            if is_value_secret is not None:
                self._values["is_value_secret"] = is_value_secret

        @builtins.property
        def key(self) -> builtins.str:
            '''``CfnConnection.ParameterProperty.Key``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-parameter.html#cfn-events-connection-parameter-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''``CfnConnection.ParameterProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-parameter.html#cfn-events-connection-parameter-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def is_value_secret(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''``CfnConnection.ParameterProperty.IsValueSecret``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-connection-parameter.html#cfn-events-connection-parameter-isvaluesecret
            '''
            result = self._values.get("is_value_secret")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.CfnConnectionProps",
    jsii_struct_bases=[],
    name_mapping={
        "authorization_type": "authorizationType",
        "auth_parameters": "authParameters",
        "description": "description",
        "name": "name",
    },
)
class CfnConnectionProps:
    def __init__(
        self,
        *,
        authorization_type: builtins.str,
        auth_parameters: typing.Union[CfnConnection.AuthParametersProperty, _IResolvable_da3f097b],
        description: typing.Optional[builtins.str] = None,
        name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnConnection``.

        :param authorization_type: The type of authorization to use for the connection.
        :param auth_parameters: A ``CreateConnectionAuthRequestParameters`` object that contains the authorization parameters to use to authorize with the endpoint.
        :param description: A description for the connection to create.
        :param name: The name for the connection to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-connection.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_events as events
            
            cfn_connection_props = events.CfnConnectionProps(
                authorization_type="authorizationType",
                auth_parameters=events.CfnConnection.AuthParametersProperty(
                    api_key_auth_parameters=events.CfnConnection.ApiKeyAuthParametersProperty(
                        api_key_name="apiKeyName",
                        api_key_value="apiKeyValue"
                    ),
                    basic_auth_parameters=events.CfnConnection.BasicAuthParametersProperty(
                        password="password",
                        username="username"
                    ),
                    invocation_http_parameters=events.CfnConnection.ConnectionHttpParametersProperty(
                        body_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
            
                            # the properties below are optional
                            is_value_secret=False
                        )],
                        header_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
            
                            # the properties below are optional
                            is_value_secret=False
                        )],
                        query_string_parameters=[events.CfnConnection.ParameterProperty(
                            key="key",
                            value="value",
            
                            # the properties below are optional
                            is_value_secret=False
                        )]
                    ),
                    o_auth_parameters=events.CfnConnection.OAuthParametersProperty(
                        authorization_endpoint="authorizationEndpoint",
                        client_parameters=events.CfnConnection.ClientParametersProperty(
                            client_id="clientId",
                            client_secret="clientSecret"
                        ),
                        http_method="httpMethod",
            
                        # the properties below are optional
                        o_auth_http_parameters=events.CfnConnection.ConnectionHttpParametersProperty(
                            body_parameters=[events.CfnConnection.ParameterProperty(
                                key="key",
                                value="value",
            
                                # the properties below are optional
                                is_value_secret=False
                            )],
                            header_parameters=[events.CfnConnection.ParameterProperty(
                                key="key",
                                value="value",
            
                                # the properties below are optional
                                is_value_secret=False
                            )],
                            query_string_parameters=[events.CfnConnection.ParameterProperty(
                                key="key",
                                value="value",
            
                                # the properties below are optional
                                is_value_secret=False
                            )]
                        )
                    )
                ),
            
                # the properties below are optional
                description="description",
                name="name"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "authorization_type": authorization_type,
            "auth_parameters": auth_parameters,
        }
        if description is not None:
            self._values["description"] = description
        if name is not None:
            self._values["name"] = name

    @builtins.property
    def authorization_type(self) -> builtins.str:
        '''The type of authorization to use for the connection.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-connection.html#cfn-events-connection-authorizationtype
        '''
        result = self._values.get("authorization_type")
        assert result is not None, "Required property 'authorization_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auth_parameters(
        self,
    ) -> typing.Union[CfnConnection.AuthParametersProperty, _IResolvable_da3f097b]:
        '''A ``CreateConnectionAuthRequestParameters`` object that contains the authorization parameters to use to authorize with the endpoint.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-connection.html#cfn-events-connection-authparameters
        '''
        result = self._values.get("auth_parameters")
        assert result is not None, "Required property 'auth_parameters' is missing"
        return typing.cast(typing.Union[CfnConnection.AuthParametersProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the connection to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-connection.html#cfn-events-connection-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name for the connection to create.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-connection.html#cfn-events-connection-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnConnectionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnEventBus(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.CfnEventBus",
):
    '''A CloudFormation ``AWS::Events::EventBus``.

    Creates a new event bus within your account. This can be a custom event bus which you can use to receive events from your custom applications and services, or it can be a partner event bus which can be matched to a partner event source.

    :cloudformationResource: AWS::Events::EventBus
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_events as events
        
        cfn_event_bus = events.CfnEventBus(self, "MyCfnEventBus",
            name="name",
        
            # the properties below are optional
            event_source_name="eventSourceName",
            tags=[events.CfnEventBus.TagEntryProperty(
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
        event_source_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence["CfnEventBus.TagEntryProperty"]] = None,
    ) -> None:
        '''Create a new ``AWS::Events::EventBus``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param name: The name of the new event bus. Event bus names cannot contain the / character. You can't use the name ``default`` for a custom event bus, as this name is already used for your account's default event bus. If this is a partner event bus, the name must exactly match the name of the partner event source that this event bus is matched to.
        :param event_source_name: If you are creating a partner event bus, this specifies the partner event source that the new event bus will be matched with.
        :param tags: ``AWS::Events::EventBus.Tags``.
        '''
        props = CfnEventBusProps(
            name=name, event_source_name=event_source_name, tags=tags
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
        '''The ARN of the event bus, such as ``arn:aws:events:us-east-2:123456789012:event-bus/aws.partner/PartnerName/acct1/repo1`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrName")
    def attr_name(self) -> builtins.str:
        '''The name of the event bus, such as ``PartnerName/acct1/repo1`` .

        :cloudformationAttribute: Name
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrPolicy")
    def attr_policy(self) -> builtins.str:
        '''The policy for the event bus in JSON form.

        :cloudformationAttribute: Policy
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrPolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the new event bus.

        Event bus names cannot contain the / character. You can't use the name ``default`` for a custom event bus, as this name is already used for your account's default event bus.

        If this is a partner event bus, the name must exactly match the name of the partner event source that this event bus is matched to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "name"))

    @name.setter
    def name(self, value: builtins.str) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventSourceName")
    def event_source_name(self) -> typing.Optional[builtins.str]:
        '''If you are creating a partner event bus, this specifies the partner event source that the new event bus will be matched with.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-eventsourcename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "eventSourceName"))

    @event_source_name.setter
    def event_source_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "eventSourceName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> typing.Optional[typing.List["CfnEventBus.TagEntryProperty"]]:
        '''``AWS::Events::EventBus.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-tags
        '''
        return typing.cast(typing.Optional[typing.List["CfnEventBus.TagEntryProperty"]], jsii.get(self, "tags"))

    @tags.setter
    def tags(
        self,
        value: typing.Optional[typing.List["CfnEventBus.TagEntryProperty"]],
    ) -> None:
        jsii.set(self, "tags", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnEventBus.TagEntryProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class TagEntryProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''
            :param key: ``CfnEventBus.TagEntryProperty.Key``.
            :param value: ``CfnEventBus.TagEntryProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-eventbus-tagentry.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                tag_entry_property = events.CfnEventBus.TagEntryProperty(
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
            '''``CfnEventBus.TagEntryProperty.Key``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-eventbus-tagentry.html#cfn-events-eventbus-tagentry-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''``CfnEventBus.TagEntryProperty.Value``.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-eventbus-tagentry.html#cfn-events-eventbus-tagentry-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TagEntryProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnEventBusPolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.CfnEventBusPolicy",
):
    '''A CloudFormation ``AWS::Events::EventBusPolicy``.

    Running ``PutPermission`` permits the specified AWS account or AWS organization to put events to the specified *event bus* . Amazon EventBridge (CloudWatch Events) rules in your account are triggered by these events arriving to an event bus in your account.

    For another account to send events to your account, that external account must have an EventBridge rule with your account's event bus as a target.

    To enable multiple AWS accounts to put events to your event bus, run ``PutPermission`` once for each of these accounts. Or, if all the accounts are members of the same AWS organization, you can run ``PutPermission`` once specifying ``Principal`` as "*" and specifying the AWS organization ID in ``Condition`` , to grant permissions to all accounts in that organization.

    If you grant permissions using an organization, then accounts in that organization must specify a ``RoleArn`` with proper permissions when they use ``PutTarget`` to add your account's event bus as a target. For more information, see `Sending and Receiving Events Between AWS Accounts <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-cross-account-event-delivery.html>`_ in the *Amazon EventBridge User Guide* .

    The permission policy on the event bus cannot exceed 10 KB in size.

    :cloudformationResource: AWS::Events::EventBusPolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_events as events
        
        # statement: Any
        
        cfn_event_bus_policy = events.CfnEventBusPolicy(self, "MyCfnEventBusPolicy",
            statement_id="statementId",
        
            # the properties below are optional
            action="action",
            condition=events.CfnEventBusPolicy.ConditionProperty(
                key="key",
                type="type",
                value="value"
            ),
            event_bus_name="eventBusName",
            principal="principal",
            statement=statement
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        statement_id: builtins.str,
        action: typing.Optional[builtins.str] = None,
        condition: typing.Optional[typing.Union["CfnEventBusPolicy.ConditionProperty", _IResolvable_da3f097b]] = None,
        event_bus_name: typing.Optional[builtins.str] = None,
        principal: typing.Optional[builtins.str] = None,
        statement: typing.Any = None,
    ) -> None:
        '''Create a new ``AWS::Events::EventBusPolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param statement_id: An identifier string for the external account that you are granting permissions to. If you later want to revoke the permission for this external account, specify this ``StatementId`` when you run `RemovePermission <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_RemovePermission.html>`_ . .. epigraph:: Each ``StatementId`` must be unique.
        :param action: The action that you are enabling the other account to perform.
        :param condition: This parameter enables you to limit the permission to accounts that fulfill a certain condition, such as being a member of a certain AWS organization. For more information about AWS Organizations, see `What Is AWS Organizations <https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html>`_ in the *AWS Organizations User Guide* . If you specify ``Condition`` with an AWS organization ID, and specify "*" as the value for ``Principal`` , you grant permission to all the accounts in the named organization. The ``Condition`` is a JSON string which must contain ``Type`` , ``Key`` , and ``Value`` fields.
        :param event_bus_name: The name of the event bus associated with the rule. If you omit this, the default event bus is used.
        :param principal: The 12-digit AWS account ID that you are permitting to put events to your default event bus. Specify "*" to permit any account to put events to your default event bus. If you specify "*" without specifying ``Condition`` , avoid creating rules that may match undesirable events. To create more secure rules, make sure that the event pattern for each rule contains an ``account`` field with a specific account ID from which to receive events. Rules with an account field do not match any events sent from other accounts.
        :param statement: A JSON string that describes the permission policy statement. You can include a ``Policy`` parameter in the request instead of using the ``StatementId`` , ``Action`` , ``Principal`` , or ``Condition`` parameters.
        '''
        props = CfnEventBusPolicyProps(
            statement_id=statement_id,
            action=action,
            condition=condition,
            event_bus_name=event_bus_name,
            principal=principal,
            statement=statement,
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
    @jsii.member(jsii_name="statement")
    def statement(self) -> typing.Any:
        '''A JSON string that describes the permission policy statement.

        You can include a ``Policy`` parameter in the request instead of using the ``StatementId`` , ``Action`` , ``Principal`` , or ``Condition`` parameters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-statement
        '''
        return typing.cast(typing.Any, jsii.get(self, "statement"))

    @statement.setter
    def statement(self, value: typing.Any) -> None:
        jsii.set(self, "statement", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="statementId")
    def statement_id(self) -> builtins.str:
        '''An identifier string for the external account that you are granting permissions to.

        If you later want to revoke the permission for this external account, specify this ``StatementId`` when you run `RemovePermission <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_RemovePermission.html>`_ .
        .. epigraph::

           Each ``StatementId`` must be unique.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-statementid
        '''
        return typing.cast(builtins.str, jsii.get(self, "statementId"))

    @statement_id.setter
    def statement_id(self, value: builtins.str) -> None:
        jsii.set(self, "statementId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="action")
    def action(self) -> typing.Optional[builtins.str]:
        '''The action that you are enabling the other account to perform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-action
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "action"))

    @action.setter
    def action(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "action", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="condition")
    def condition(
        self,
    ) -> typing.Optional[typing.Union["CfnEventBusPolicy.ConditionProperty", _IResolvable_da3f097b]]:
        '''This parameter enables you to limit the permission to accounts that fulfill a certain condition, such as being a member of a certain AWS organization.

        For more information about AWS Organizations, see `What Is AWS Organizations <https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html>`_ in the *AWS Organizations User Guide* .

        If you specify ``Condition`` with an AWS organization ID, and specify "*" as the value for ``Principal`` , you grant permission to all the accounts in the named organization.

        The ``Condition`` is a JSON string which must contain ``Type`` , ``Key`` , and ``Value`` fields.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-condition
        '''
        return typing.cast(typing.Optional[typing.Union["CfnEventBusPolicy.ConditionProperty", _IResolvable_da3f097b]], jsii.get(self, "condition"))

    @condition.setter
    def condition(
        self,
        value: typing.Optional[typing.Union["CfnEventBusPolicy.ConditionProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "condition", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBusName")
    def event_bus_name(self) -> typing.Optional[builtins.str]:
        '''The name of the event bus associated with the rule.

        If you omit this, the default event bus is used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-eventbusname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "eventBusName"))

    @event_bus_name.setter
    def event_bus_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "eventBusName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="principal")
    def principal(self) -> typing.Optional[builtins.str]:
        '''The 12-digit AWS account ID that you are permitting to put events to your default event bus.

        Specify "*" to permit any account to put events to your default event bus.

        If you specify "*" without specifying ``Condition`` , avoid creating rules that may match undesirable events. To create more secure rules, make sure that the event pattern for each rule contains an ``account`` field with a specific account ID from which to receive events. Rules with an account field do not match any events sent from other accounts.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-principal
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "principal"))

    @principal.setter
    def principal(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "principal", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnEventBusPolicy.ConditionProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "type": "type", "value": "value"},
    )
    class ConditionProperty:
        def __init__(
            self,
            *,
            key: typing.Optional[builtins.str] = None,
            type: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A JSON string which you can use to limit the event bus permissions you are granting to only accounts that fulfill the condition.

            Currently, the only supported condition is membership in a certain AWS organization. The string must contain ``Type`` , ``Key`` , and ``Value`` fields. The ``Value`` field specifies the ID of the AWS organization. Following is an example value for ``Condition`` :

            ``'{"Type" : "StringEquals", "Key": "aws:PrincipalOrgID", "Value": "o-1234567890"}'``

            :param key: Specifies the key for the condition. Currently the only supported key is ``aws:PrincipalOrgID`` .
            :param type: Specifies the type of condition. Currently the only supported value is ``StringEquals`` .
            :param value: Specifies the value for the key. Currently, this must be the ID of the organization.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-eventbuspolicy-condition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                condition_property = events.CfnEventBusPolicy.ConditionProperty(
                    key="key",
                    type="type",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if key is not None:
                self._values["key"] = key
            if type is not None:
                self._values["type"] = type
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def key(self) -> typing.Optional[builtins.str]:
            '''Specifies the key for the condition.

            Currently the only supported key is ``aws:PrincipalOrgID`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-eventbuspolicy-condition.html#cfn-events-eventbuspolicy-condition-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''Specifies the type of condition.

            Currently the only supported value is ``StringEquals`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-eventbuspolicy-condition.html#cfn-events-eventbuspolicy-condition-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''Specifies the value for the key.

            Currently, this must be the ID of the organization.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-eventbuspolicy-condition.html#cfn-events-eventbuspolicy-condition-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ConditionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.CfnEventBusPolicyProps",
    jsii_struct_bases=[],
    name_mapping={
        "statement_id": "statementId",
        "action": "action",
        "condition": "condition",
        "event_bus_name": "eventBusName",
        "principal": "principal",
        "statement": "statement",
    },
)
class CfnEventBusPolicyProps:
    def __init__(
        self,
        *,
        statement_id: builtins.str,
        action: typing.Optional[builtins.str] = None,
        condition: typing.Optional[typing.Union[CfnEventBusPolicy.ConditionProperty, _IResolvable_da3f097b]] = None,
        event_bus_name: typing.Optional[builtins.str] = None,
        principal: typing.Optional[builtins.str] = None,
        statement: typing.Any = None,
    ) -> None:
        '''Properties for defining a ``CfnEventBusPolicy``.

        :param statement_id: An identifier string for the external account that you are granting permissions to. If you later want to revoke the permission for this external account, specify this ``StatementId`` when you run `RemovePermission <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_RemovePermission.html>`_ . .. epigraph:: Each ``StatementId`` must be unique.
        :param action: The action that you are enabling the other account to perform.
        :param condition: This parameter enables you to limit the permission to accounts that fulfill a certain condition, such as being a member of a certain AWS organization. For more information about AWS Organizations, see `What Is AWS Organizations <https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html>`_ in the *AWS Organizations User Guide* . If you specify ``Condition`` with an AWS organization ID, and specify "*" as the value for ``Principal`` , you grant permission to all the accounts in the named organization. The ``Condition`` is a JSON string which must contain ``Type`` , ``Key`` , and ``Value`` fields.
        :param event_bus_name: The name of the event bus associated with the rule. If you omit this, the default event bus is used.
        :param principal: The 12-digit AWS account ID that you are permitting to put events to your default event bus. Specify "*" to permit any account to put events to your default event bus. If you specify "*" without specifying ``Condition`` , avoid creating rules that may match undesirable events. To create more secure rules, make sure that the event pattern for each rule contains an ``account`` field with a specific account ID from which to receive events. Rules with an account field do not match any events sent from other accounts.
        :param statement: A JSON string that describes the permission policy statement. You can include a ``Policy`` parameter in the request instead of using the ``StatementId`` , ``Action`` , ``Principal`` , or ``Condition`` parameters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_events as events
            
            # statement: Any
            
            cfn_event_bus_policy_props = events.CfnEventBusPolicyProps(
                statement_id="statementId",
            
                # the properties below are optional
                action="action",
                condition=events.CfnEventBusPolicy.ConditionProperty(
                    key="key",
                    type="type",
                    value="value"
                ),
                event_bus_name="eventBusName",
                principal="principal",
                statement=statement
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "statement_id": statement_id,
        }
        if action is not None:
            self._values["action"] = action
        if condition is not None:
            self._values["condition"] = condition
        if event_bus_name is not None:
            self._values["event_bus_name"] = event_bus_name
        if principal is not None:
            self._values["principal"] = principal
        if statement is not None:
            self._values["statement"] = statement

    @builtins.property
    def statement_id(self) -> builtins.str:
        '''An identifier string for the external account that you are granting permissions to.

        If you later want to revoke the permission for this external account, specify this ``StatementId`` when you run `RemovePermission <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_RemovePermission.html>`_ .
        .. epigraph::

           Each ``StatementId`` must be unique.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-statementid
        '''
        result = self._values.get("statement_id")
        assert result is not None, "Required property 'statement_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def action(self) -> typing.Optional[builtins.str]:
        '''The action that you are enabling the other account to perform.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-action
        '''
        result = self._values.get("action")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def condition(
        self,
    ) -> typing.Optional[typing.Union[CfnEventBusPolicy.ConditionProperty, _IResolvable_da3f097b]]:
        '''This parameter enables you to limit the permission to accounts that fulfill a certain condition, such as being a member of a certain AWS organization.

        For more information about AWS Organizations, see `What Is AWS Organizations <https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html>`_ in the *AWS Organizations User Guide* .

        If you specify ``Condition`` with an AWS organization ID, and specify "*" as the value for ``Principal`` , you grant permission to all the accounts in the named organization.

        The ``Condition`` is a JSON string which must contain ``Type`` , ``Key`` , and ``Value`` fields.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-condition
        '''
        result = self._values.get("condition")
        return typing.cast(typing.Optional[typing.Union[CfnEventBusPolicy.ConditionProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def event_bus_name(self) -> typing.Optional[builtins.str]:
        '''The name of the event bus associated with the rule.

        If you omit this, the default event bus is used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-eventbusname
        '''
        result = self._values.get("event_bus_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def principal(self) -> typing.Optional[builtins.str]:
        '''The 12-digit AWS account ID that you are permitting to put events to your default event bus.

        Specify "*" to permit any account to put events to your default event bus.

        If you specify "*" without specifying ``Condition`` , avoid creating rules that may match undesirable events. To create more secure rules, make sure that the event pattern for each rule contains an ``account`` field with a specific account ID from which to receive events. Rules with an account field do not match any events sent from other accounts.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-principal
        '''
        result = self._values.get("principal")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def statement(self) -> typing.Any:
        '''A JSON string that describes the permission policy statement.

        You can include a ``Policy`` parameter in the request instead of using the ``StatementId`` , ``Action`` , ``Principal`` , or ``Condition`` parameters.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbuspolicy.html#cfn-events-eventbuspolicy-statement
        '''
        result = self._values.get("statement")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnEventBusPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.CfnEventBusProps",
    jsii_struct_bases=[],
    name_mapping={
        "name": "name",
        "event_source_name": "eventSourceName",
        "tags": "tags",
    },
)
class CfnEventBusProps:
    def __init__(
        self,
        *,
        name: builtins.str,
        event_source_name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[CfnEventBus.TagEntryProperty]] = None,
    ) -> None:
        '''Properties for defining a ``CfnEventBus``.

        :param name: The name of the new event bus. Event bus names cannot contain the / character. You can't use the name ``default`` for a custom event bus, as this name is already used for your account's default event bus. If this is a partner event bus, the name must exactly match the name of the partner event source that this event bus is matched to.
        :param event_source_name: If you are creating a partner event bus, this specifies the partner event source that the new event bus will be matched with.
        :param tags: ``AWS::Events::EventBus.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_events as events
            
            cfn_event_bus_props = events.CfnEventBusProps(
                name="name",
            
                # the properties below are optional
                event_source_name="eventSourceName",
                tags=[events.CfnEventBus.TagEntryProperty(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "name": name,
        }
        if event_source_name is not None:
            self._values["event_source_name"] = event_source_name
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def name(self) -> builtins.str:
        '''The name of the new event bus.

        Event bus names cannot contain the / character. You can't use the name ``default`` for a custom event bus, as this name is already used for your account's default event bus.

        If this is a partner event bus, the name must exactly match the name of the partner event source that this event bus is matched to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-name
        '''
        result = self._values.get("name")
        assert result is not None, "Required property 'name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def event_source_name(self) -> typing.Optional[builtins.str]:
        '''If you are creating a partner event bus, this specifies the partner event source that the new event bus will be matched with.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-eventsourcename
        '''
        result = self._values.get("event_source_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[CfnEventBus.TagEntryProperty]]:
        '''``AWS::Events::EventBus.Tags``.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[CfnEventBus.TagEntryProperty]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnEventBusProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnRule(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.CfnRule",
):
    '''A CloudFormation ``AWS::Events::Rule``.

    Creates or updates the specified rule. Rules are enabled by default, or based on value of the state. You can disable a rule using `DisableRule <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DisableRule.html>`_ .

    A single rule watches for events from a single event bus. Events generated by AWS services go to your account's default event bus. Events generated by SaaS partner services or applications go to the matching partner event bus. If you have custom applications or services, you can specify whether their events go to your default event bus or a custom event bus that you have created. For more information, see `CreateEventBus <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_CreateEventBus.html>`_ .

    If you are updating an existing rule, the rule is replaced with what you specify in this ``PutRule`` command. If you omit arguments in ``PutRule`` , the old values for those arguments are not kept. Instead, they are replaced with null values.

    When you create or update a rule, incoming events might not immediately start matching to new or updated rules. Allow a short period of time for changes to take effect.

    A rule must contain at least an EventPattern or ScheduleExpression. Rules with EventPatterns are triggered when a matching event is observed. Rules with ScheduleExpressions self-trigger based on the given schedule. A rule can have both an EventPattern and a ScheduleExpression, in which case the rule triggers on matching events as well as on a schedule.

    Most services in AWS treat : or / as the same character in Amazon Resource Names (ARNs). However, EventBridge uses an exact match in event patterns and rules. Be sure to use the correct ARN characters when creating event patterns so that they match the ARN syntax in the event you want to match.

    In EventBridge, it is possible to create rules that lead to infinite loops, where a rule is fired repeatedly. For example, a rule might detect that ACLs have changed on an S3 bucket, and trigger software to change them to the desired state. If the rule is not written carefully, the subsequent change to the ACLs fires the rule again, creating an infinite loop.

    To prevent this, write the rules so that the triggered actions do not re-fire the same rule. For example, your rule could fire only if ACLs are found to be in a bad state, instead of after any change.

    An infinite loop can quickly cause higher than expected charges. We recommend that you use budgeting, which alerts you when charges exceed your specified limit. For more information, see `Managing Your Costs with Budgets <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/budgets-managing-costs.html>`_ .

    :cloudformationResource: AWS::Events::Rule
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_events as events
        
        # event_pattern: Any
        
        cfn_rule = events.CfnRule(self, "MyCfnRule",
            description="description",
            event_bus_name="eventBusName",
            event_pattern=event_pattern,
            name="name",
            role_arn="roleArn",
            schedule_expression="scheduleExpression",
            state="state",
            targets=[events.CfnRule.TargetProperty(
                arn="arn",
                id="id",
        
                # the properties below are optional
                batch_parameters=events.CfnRule.BatchParametersProperty(
                    job_definition="jobDefinition",
                    job_name="jobName",
        
                    # the properties below are optional
                    array_properties=events.CfnRule.BatchArrayPropertiesProperty(
                        size=123
                    ),
                    retry_strategy=events.CfnRule.BatchRetryStrategyProperty(
                        attempts=123
                    )
                ),
                dead_letter_config=events.CfnRule.DeadLetterConfigProperty(
                    arn="arn"
                ),
                ecs_parameters=events.CfnRule.EcsParametersProperty(
                    task_definition_arn="taskDefinitionArn",
        
                    # the properties below are optional
                    capacity_provider_strategy=[events.CfnRule.CapacityProviderStrategyItemProperty(
                        capacity_provider="capacityProvider",
        
                        # the properties below are optional
                        base=123,
                        weight=123
                    )],
                    enable_ecs_managed_tags=False,
                    enable_execute_command=False,
                    group="group",
                    launch_type="launchType",
                    network_configuration=events.CfnRule.NetworkConfigurationProperty(
                        aws_vpc_configuration=events.CfnRule.AwsVpcConfigurationProperty(
                            subnets=["subnets"],
        
                            # the properties below are optional
                            assign_public_ip="assignPublicIp",
                            security_groups=["securityGroups"]
                        )
                    ),
                    placement_constraints=[events.CfnRule.PlacementConstraintProperty(
                        expression="expression",
                        type="type"
                    )],
                    placement_strategies=[events.CfnRule.PlacementStrategyProperty(
                        field="field",
                        type="type"
                    )],
                    platform_version="platformVersion",
                    propagate_tags="propagateTags",
                    reference_id="referenceId",
                    tag_list=[CfnTag(
                        key="key",
                        value="value"
                    )],
                    task_count=123
                ),
                http_parameters=events.CfnRule.HttpParametersProperty(
                    header_parameters={
                        "header_parameters_key": "headerParameters"
                    },
                    path_parameter_values=["pathParameterValues"],
                    query_string_parameters={
                        "query_string_parameters_key": "queryStringParameters"
                    }
                ),
                input="input",
                input_path="inputPath",
                input_transformer=events.CfnRule.InputTransformerProperty(
                    input_template="inputTemplate",
        
                    # the properties below are optional
                    input_paths_map={
                        "input_paths_map_key": "inputPathsMap"
                    }
                ),
                kinesis_parameters=events.CfnRule.KinesisParametersProperty(
                    partition_key_path="partitionKeyPath"
                ),
                redshift_data_parameters=events.CfnRule.RedshiftDataParametersProperty(
                    database="database",
                    sql="sql",
        
                    # the properties below are optional
                    db_user="dbUser",
                    secret_manager_arn="secretManagerArn",
                    statement_name="statementName",
                    with_event=False
                ),
                retry_policy=events.CfnRule.RetryPolicyProperty(
                    maximum_event_age_in_seconds=123,
                    maximum_retry_attempts=123
                ),
                role_arn="roleArn",
                run_command_parameters=events.CfnRule.RunCommandParametersProperty(
                    run_command_targets=[events.CfnRule.RunCommandTargetProperty(
                        key="key",
                        values=["values"]
                    )]
                ),
                sage_maker_pipeline_parameters=events.CfnRule.SageMakerPipelineParametersProperty(
                    pipeline_parameter_list=[events.CfnRule.SageMakerPipelineParameterProperty(
                        name="name",
                        value="value"
                    )]
                ),
                sqs_parameters=events.CfnRule.SqsParametersProperty(
                    message_group_id="messageGroupId"
                )
            )]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        event_bus_name: typing.Optional[builtins.str] = None,
        event_pattern: typing.Any = None,
        name: typing.Optional[builtins.str] = None,
        role_arn: typing.Optional[builtins.str] = None,
        schedule_expression: typing.Optional[builtins.str] = None,
        state: typing.Optional[builtins.str] = None,
        targets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRule.TargetProperty", _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Create a new ``AWS::Events::Rule``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param description: The description of the rule.
        :param event_bus_name: The name or ARN of the event bus associated with the rule. If you omit this, the default event bus is used.
        :param event_pattern: The event pattern of the rule. For more information, see `Events and Event Patterns <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-and-event-patterns.html>`_ in the *Amazon EventBridge User Guide* .
        :param name: The name of the rule.
        :param role_arn: The Amazon Resource Name (ARN) of the role that is used for target invocation. If you're setting an event bus in another account as the target and that account granted permission to your account through an organization instead of directly by the account ID, you must specify a ``RoleArn`` with proper permissions in the ``Target`` structure, instead of here in this parameter.
        :param schedule_expression: The scheduling expression. For example, "cron(0 20 * * ? *)", "rate(5 minutes)". For more information, see `Creating an Amazon EventBridge rule that runs on a schedule <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html>`_ .
        :param state: The state of the rule.
        :param targets: Adds the specified targets to the specified rule, or updates the targets if they are already associated with the rule. Targets are the resources that are invoked when a rule is triggered. .. epigraph:: Each rule can have up to five (5) targets associated with it at one time. You can configure the following as targets for Events: - `API destination <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html>`_ - `API Gateway <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-gateway-target.html>`_ - Batch job queue - CloudWatch group - CodeBuild project - CodePipeline - EC2 ``CreateSnapshot`` API call - EC2 Image Builder - EC2 ``RebootInstances`` API call - EC2 ``StopInstances`` API call - EC2 ``TerminateInstances`` API call - ECS task - `Event bus in a different account or Region <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-cross-account.html>`_ - `Event bus in the same account and Region <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-bus-to-bus.html>`_ - Firehose delivery stream - Glue workflow - `Incident Manager response plan <https://docs.aws.amazon.com//incident-manager/latest/userguide/incident-creation.html#incident-tracking-auto-eventbridge>`_ - Inspector assessment template - Kinesis stream - Lambda function - Redshift cluster - SageMaker Pipeline - SNS topic - SQS queue - Step Functions state machine - Systems Manager Automation - Systems Manager OpsItem - Systems Manager Run Command Creating rules with built-in targets is supported only in the AWS Management Console . The built-in targets are ``EC2 CreateSnapshot API call`` , ``EC2 RebootInstances API call`` , ``EC2 StopInstances API call`` , and ``EC2 TerminateInstances API call`` . For some target types, ``PutTargets`` provides target-specific parameters. If the target is a Kinesis data stream, you can optionally specify which shard the event goes to by using the ``KinesisParameters`` argument. To invoke a command on multiple EC2 instances with one rule, you can use the ``RunCommandParameters`` field. To be able to make API calls against the resources that you own, Amazon EventBridge needs the appropriate permissions. For AWS Lambda and Amazon SNS resources, EventBridge relies on resource-based policies. For EC2 instances, Kinesis Data Streams, AWS Step Functions state machines and API Gateway REST APIs, EventBridge relies on IAM roles that you specify in the ``RoleARN`` argument in ``PutTargets`` . For more information, see `Authentication and Access Control <https://docs.aws.amazon.com/eventbridge/latest/userguide/auth-and-access-control-eventbridge.html>`_ in the *Amazon EventBridge User Guide* . If another AWS account is in the same region and has granted you permission (using ``PutPermission`` ), you can send events to that account. Set that account's event bus as a target of the rules in your account. To send the matched events to the other account, specify that account's event bus as the ``Arn`` value when you run ``PutTargets`` . If your account sends events to another account, your account is charged for each sent event. Each event sent to another account is charged as a custom event. The account receiving the event is not charged. For more information, see `Amazon EventBridge Pricing <https://docs.aws.amazon.com/eventbridge/pricing/>`_ . .. epigraph:: ``Input`` , ``InputPath`` , and ``InputTransformer`` are not available with ``PutTarget`` if the target is an event bus of a different AWS account. If you are setting the event bus of another account as the target, and that account granted permission to your account through an organization instead of directly by the account ID, then you must specify a ``RoleArn`` with proper permissions in the ``Target`` structure. For more information, see `Sending and Receiving Events Between AWS Accounts <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-cross-account-event-delivery.html>`_ in the *Amazon EventBridge User Guide* . For more information about enabling cross-account events, see `PutPermission <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutPermission.html>`_ . *Input* , *InputPath* , and *InputTransformer* are mutually exclusive and optional parameters of a target. When a rule is triggered due to a matched event: - If none of the following arguments are specified for a target, then the entire event is passed to the target in JSON format (unless the target is Amazon EC2 Run Command or Amazon ECS task, in which case nothing from the event is passed to the target). - If *Input* is specified in the form of valid JSON, then the matched event is overridden with this constant. - If *InputPath* is specified in the form of JSONPath (for example, ``$.detail`` ), then only the part of the event specified in the path is passed to the target (for example, only the detail part of the event is passed). - If *InputTransformer* is specified, then one or more specified JSONPaths are extracted from the event and used as values in a template that you specify as the input to the target. When you specify ``InputPath`` or ``InputTransformer`` , you must use JSON dot notation, not bracket notation. When you add targets to a rule and the associated rule triggers soon after, new or updated targets might not be immediately invoked. Allow a short period of time for changes to take effect. This action can partially fail if too many requests are made at the same time. If that happens, ``FailedEntryCount`` is non-zero in the response and each entry in ``FailedEntries`` provides the ID of the failed target and the error code.
        '''
        props = CfnRuleProps(
            description=description,
            event_bus_name=event_bus_name,
            event_pattern=event_pattern,
            name=name,
            role_arn=role_arn,
            schedule_expression=schedule_expression,
            state=state,
            targets=targets,
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
        '''The ARN of the rule, such as ``arn:aws:events:us-east-2:123456789012:rule/example`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventPattern")
    def event_pattern(self) -> typing.Any:
        '''The event pattern of the rule.

        For more information, see `Events and Event Patterns <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-and-event-patterns.html>`_ in the *Amazon EventBridge User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-eventpattern
        '''
        return typing.cast(typing.Any, jsii.get(self, "eventPattern"))

    @event_pattern.setter
    def event_pattern(self, value: typing.Any) -> None:
        jsii.set(self, "eventPattern", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="description")
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-description
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "description"))

    @description.setter
    def description(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "description", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBusName")
    def event_bus_name(self) -> typing.Optional[builtins.str]:
        '''The name or ARN of the event bus associated with the rule.

        If you omit this, the default event bus is used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-eventbusname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "eventBusName"))

    @event_bus_name.setter
    def event_bus_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "eventBusName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the role that is used for target invocation.

        If you're setting an event bus in another account as the target and that account granted permission to your account through an organization instead of directly by the account ID, you must specify a ``RoleArn`` with proper permissions in the ``Target`` structure, instead of here in this parameter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-rolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "roleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scheduleExpression")
    def schedule_expression(self) -> typing.Optional[builtins.str]:
        '''The scheduling expression.

        For example, "cron(0 20 * * ? *)", "rate(5 minutes)". For more information, see `Creating an Amazon EventBridge rule that runs on a schedule <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-scheduleexpression
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "scheduleExpression"))

    @schedule_expression.setter
    def schedule_expression(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "scheduleExpression", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="state")
    def state(self) -> typing.Optional[builtins.str]:
        '''The state of the rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-state
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "state"))

    @state.setter
    def state(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "state", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targets")
    def targets(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.TargetProperty", _IResolvable_da3f097b]]]]:
        '''Adds the specified targets to the specified rule, or updates the targets if they are already associated with the rule.

        Targets are the resources that are invoked when a rule is triggered.
        .. epigraph::

           Each rule can have up to five (5) targets associated with it at one time.

        You can configure the following as targets for Events:

        - `API destination <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html>`_
        - `API Gateway <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-gateway-target.html>`_
        - Batch job queue
        - CloudWatch group
        - CodeBuild project
        - CodePipeline
        - EC2 ``CreateSnapshot`` API call
        - EC2 Image Builder
        - EC2 ``RebootInstances`` API call
        - EC2 ``StopInstances`` API call
        - EC2 ``TerminateInstances`` API call
        - ECS task
        - `Event bus in a different account or Region <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-cross-account.html>`_
        - `Event bus in the same account and Region <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-bus-to-bus.html>`_
        - Firehose delivery stream
        - Glue workflow
        - `Incident Manager response plan <https://docs.aws.amazon.com//incident-manager/latest/userguide/incident-creation.html#incident-tracking-auto-eventbridge>`_
        - Inspector assessment template
        - Kinesis stream
        - Lambda function
        - Redshift cluster
        - SageMaker Pipeline
        - SNS topic
        - SQS queue
        - Step Functions state machine
        - Systems Manager Automation
        - Systems Manager OpsItem
        - Systems Manager Run Command

        Creating rules with built-in targets is supported only in the AWS Management Console . The built-in targets are ``EC2 CreateSnapshot API call`` , ``EC2 RebootInstances API call`` , ``EC2 StopInstances API call`` , and ``EC2 TerminateInstances API call`` .

        For some target types, ``PutTargets`` provides target-specific parameters. If the target is a Kinesis data stream, you can optionally specify which shard the event goes to by using the ``KinesisParameters`` argument. To invoke a command on multiple EC2 instances with one rule, you can use the ``RunCommandParameters`` field.

        To be able to make API calls against the resources that you own, Amazon EventBridge needs the appropriate permissions. For AWS Lambda and Amazon SNS resources, EventBridge relies on resource-based policies. For EC2 instances, Kinesis Data Streams, AWS Step Functions state machines and API Gateway REST APIs, EventBridge relies on IAM roles that you specify in the ``RoleARN`` argument in ``PutTargets`` . For more information, see `Authentication and Access Control <https://docs.aws.amazon.com/eventbridge/latest/userguide/auth-and-access-control-eventbridge.html>`_ in the *Amazon EventBridge User Guide* .

        If another AWS account is in the same region and has granted you permission (using ``PutPermission`` ), you can send events to that account. Set that account's event bus as a target of the rules in your account. To send the matched events to the other account, specify that account's event bus as the ``Arn`` value when you run ``PutTargets`` . If your account sends events to another account, your account is charged for each sent event. Each event sent to another account is charged as a custom event. The account receiving the event is not charged. For more information, see `Amazon EventBridge Pricing <https://docs.aws.amazon.com/eventbridge/pricing/>`_ .
        .. epigraph::

           ``Input`` , ``InputPath`` , and ``InputTransformer`` are not available with ``PutTarget`` if the target is an event bus of a different AWS account.

        If you are setting the event bus of another account as the target, and that account granted permission to your account through an organization instead of directly by the account ID, then you must specify a ``RoleArn`` with proper permissions in the ``Target`` structure. For more information, see `Sending and Receiving Events Between AWS Accounts <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-cross-account-event-delivery.html>`_ in the *Amazon EventBridge User Guide* .

        For more information about enabling cross-account events, see `PutPermission <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutPermission.html>`_ .

        *Input* , *InputPath* , and *InputTransformer* are mutually exclusive and optional parameters of a target. When a rule is triggered due to a matched event:

        - If none of the following arguments are specified for a target, then the entire event is passed to the target in JSON format (unless the target is Amazon EC2 Run Command or Amazon ECS task, in which case nothing from the event is passed to the target).
        - If *Input* is specified in the form of valid JSON, then the matched event is overridden with this constant.
        - If *InputPath* is specified in the form of JSONPath (for example, ``$.detail`` ), then only the part of the event specified in the path is passed to the target (for example, only the detail part of the event is passed).
        - If *InputTransformer* is specified, then one or more specified JSONPaths are extracted from the event and used as values in a template that you specify as the input to the target.

        When you specify ``InputPath`` or ``InputTransformer`` , you must use JSON dot notation, not bracket notation.

        When you add targets to a rule and the associated rule triggers soon after, new or updated targets might not be immediately invoked. Allow a short period of time for changes to take effect.

        This action can partially fail if too many requests are made at the same time. If that happens, ``FailedEntryCount`` is non-zero in the response and each entry in ``FailedEntries`` provides the ID of the failed target and the error code.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-targets
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.TargetProperty", _IResolvable_da3f097b]]]], jsii.get(self, "targets"))

    @targets.setter
    def targets(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.TargetProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "targets", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.AwsVpcConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "subnets": "subnets",
            "assign_public_ip": "assignPublicIp",
            "security_groups": "securityGroups",
        },
    )
    class AwsVpcConfigurationProperty:
        def __init__(
            self,
            *,
            subnets: typing.Sequence[builtins.str],
            assign_public_ip: typing.Optional[builtins.str] = None,
            security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''This structure specifies the VPC subnets and security groups for the task, and whether a public IP address is to be used.

            This structure is relevant only for ECS tasks that use the ``awsvpc`` network mode.

            :param subnets: Specifies the subnets associated with the task. These subnets must all be in the same VPC. You can specify as many as 16 subnets.
            :param assign_public_ip: Specifies whether the task's elastic network interface receives a public IP address. You can specify ``ENABLED`` only when ``LaunchType`` in ``EcsParameters`` is set to ``FARGATE`` .
            :param security_groups: Specifies the security groups associated with the task. These security groups must all be in the same VPC. You can specify as many as five security groups. If you do not specify a security group, the default security group for the VPC is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-awsvpcconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                aws_vpc_configuration_property = events.CfnRule.AwsVpcConfigurationProperty(
                    subnets=["subnets"],
                
                    # the properties below are optional
                    assign_public_ip="assignPublicIp",
                    security_groups=["securityGroups"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "subnets": subnets,
            }
            if assign_public_ip is not None:
                self._values["assign_public_ip"] = assign_public_ip
            if security_groups is not None:
                self._values["security_groups"] = security_groups

        @builtins.property
        def subnets(self) -> typing.List[builtins.str]:
            '''Specifies the subnets associated with the task.

            These subnets must all be in the same VPC. You can specify as many as 16 subnets.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-awsvpcconfiguration.html#cfn-events-rule-awsvpcconfiguration-subnets
            '''
            result = self._values.get("subnets")
            assert result is not None, "Required property 'subnets' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def assign_public_ip(self) -> typing.Optional[builtins.str]:
            '''Specifies whether the task's elastic network interface receives a public IP address.

            You can specify ``ENABLED`` only when ``LaunchType`` in ``EcsParameters`` is set to ``FARGATE`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-awsvpcconfiguration.html#cfn-events-rule-awsvpcconfiguration-assignpublicip
            '''
            result = self._values.get("assign_public_ip")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def security_groups(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Specifies the security groups associated with the task.

            These security groups must all be in the same VPC. You can specify as many as five security groups. If you do not specify a security group, the default security group for the VPC is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-awsvpcconfiguration.html#cfn-events-rule-awsvpcconfiguration-securitygroups
            '''
            result = self._values.get("security_groups")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AwsVpcConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.BatchArrayPropertiesProperty",
        jsii_struct_bases=[],
        name_mapping={"size": "size"},
    )
    class BatchArrayPropertiesProperty:
        def __init__(self, *, size: typing.Optional[jsii.Number] = None) -> None:
            '''The array properties for the submitted job, such as the size of the array.

            The array size can be between 2 and 10,000. If you specify array properties for a job, it becomes an array job. This parameter is used only if the target is an AWS Batch job.

            :param size: The size of the array, if this is an array batch job. Valid values are integers between 2 and 10,000.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-batcharrayproperties.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                batch_array_properties_property = events.CfnRule.BatchArrayPropertiesProperty(
                    size=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if size is not None:
                self._values["size"] = size

        @builtins.property
        def size(self) -> typing.Optional[jsii.Number]:
            '''The size of the array, if this is an array batch job.

            Valid values are integers between 2 and 10,000.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-batcharrayproperties.html#cfn-events-rule-batcharrayproperties-size
            '''
            result = self._values.get("size")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BatchArrayPropertiesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.BatchParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "job_definition": "jobDefinition",
            "job_name": "jobName",
            "array_properties": "arrayProperties",
            "retry_strategy": "retryStrategy",
        },
    )
    class BatchParametersProperty:
        def __init__(
            self,
            *,
            job_definition: builtins.str,
            job_name: builtins.str,
            array_properties: typing.Optional[typing.Union["CfnRule.BatchArrayPropertiesProperty", _IResolvable_da3f097b]] = None,
            retry_strategy: typing.Optional[typing.Union["CfnRule.BatchRetryStrategyProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''The custom parameters to be used when the target is an AWS Batch job.

            :param job_definition: The ARN or name of the job definition to use if the event target is an AWS Batch job. This job definition must already exist.
            :param job_name: The name to use for this execution of the job, if the target is an AWS Batch job.
            :param array_properties: The array properties for the submitted job, such as the size of the array. The array size can be between 2 and 10,000. If you specify array properties for a job, it becomes an array job. This parameter is used only if the target is an AWS Batch job.
            :param retry_strategy: The retry strategy to use for failed jobs, if the target is an AWS Batch job. The retry strategy is the number of times to retry the failed job execution. Valid values are 1–10. When you specify a retry strategy here, it overrides the retry strategy defined in the job definition.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-batchparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                batch_parameters_property = events.CfnRule.BatchParametersProperty(
                    job_definition="jobDefinition",
                    job_name="jobName",
                
                    # the properties below are optional
                    array_properties=events.CfnRule.BatchArrayPropertiesProperty(
                        size=123
                    ),
                    retry_strategy=events.CfnRule.BatchRetryStrategyProperty(
                        attempts=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "job_definition": job_definition,
                "job_name": job_name,
            }
            if array_properties is not None:
                self._values["array_properties"] = array_properties
            if retry_strategy is not None:
                self._values["retry_strategy"] = retry_strategy

        @builtins.property
        def job_definition(self) -> builtins.str:
            '''The ARN or name of the job definition to use if the event target is an AWS Batch job.

            This job definition must already exist.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-batchparameters.html#cfn-events-rule-batchparameters-jobdefinition
            '''
            result = self._values.get("job_definition")
            assert result is not None, "Required property 'job_definition' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def job_name(self) -> builtins.str:
            '''The name to use for this execution of the job, if the target is an AWS Batch job.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-batchparameters.html#cfn-events-rule-batchparameters-jobname
            '''
            result = self._values.get("job_name")
            assert result is not None, "Required property 'job_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def array_properties(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.BatchArrayPropertiesProperty", _IResolvable_da3f097b]]:
            '''The array properties for the submitted job, such as the size of the array.

            The array size can be between 2 and 10,000. If you specify array properties for a job, it becomes an array job. This parameter is used only if the target is an AWS Batch job.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-batchparameters.html#cfn-events-rule-batchparameters-arrayproperties
            '''
            result = self._values.get("array_properties")
            return typing.cast(typing.Optional[typing.Union["CfnRule.BatchArrayPropertiesProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def retry_strategy(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.BatchRetryStrategyProperty", _IResolvable_da3f097b]]:
            '''The retry strategy to use for failed jobs, if the target is an AWS Batch job.

            The retry strategy is the number of times to retry the failed job execution. Valid values are 1–10. When you specify a retry strategy here, it overrides the retry strategy defined in the job definition.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-batchparameters.html#cfn-events-rule-batchparameters-retrystrategy
            '''
            result = self._values.get("retry_strategy")
            return typing.cast(typing.Optional[typing.Union["CfnRule.BatchRetryStrategyProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BatchParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.BatchRetryStrategyProperty",
        jsii_struct_bases=[],
        name_mapping={"attempts": "attempts"},
    )
    class BatchRetryStrategyProperty:
        def __init__(self, *, attempts: typing.Optional[jsii.Number] = None) -> None:
            '''The retry strategy to use for failed jobs, if the target is an AWS Batch job.

            If you specify a retry strategy here, it overrides the retry strategy defined in the job definition.

            :param attempts: The number of times to attempt to retry, if the job fails. Valid values are 1–10.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-batchretrystrategy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                batch_retry_strategy_property = events.CfnRule.BatchRetryStrategyProperty(
                    attempts=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if attempts is not None:
                self._values["attempts"] = attempts

        @builtins.property
        def attempts(self) -> typing.Optional[jsii.Number]:
            '''The number of times to attempt to retry, if the job fails.

            Valid values are 1–10.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-batchretrystrategy.html#cfn-events-rule-batchretrystrategy-attempts
            '''
            result = self._values.get("attempts")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BatchRetryStrategyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.CapacityProviderStrategyItemProperty",
        jsii_struct_bases=[],
        name_mapping={
            "capacity_provider": "capacityProvider",
            "base": "base",
            "weight": "weight",
        },
    )
    class CapacityProviderStrategyItemProperty:
        def __init__(
            self,
            *,
            capacity_provider: builtins.str,
            base: typing.Optional[jsii.Number] = None,
            weight: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The details of a capacity provider strategy.

            To learn more, see `CapacityProviderStrategyItem <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CapacityProviderStrategyItem.html>`_ in the Amazon ECS API Reference.

            :param capacity_provider: The short name of the capacity provider.
            :param base: The base value designates how many tasks, at a minimum, to run on the specified capacity provider. Only one capacity provider in a capacity provider strategy can have a base defined. If no value is specified, the default value of 0 is used.
            :param weight: The weight value designates the relative percentage of the total number of tasks launched that should use the specified capacity provider. The weight value is taken into consideration after the base value, if defined, is satisfied.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-capacityproviderstrategyitem.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                capacity_provider_strategy_item_property = events.CfnRule.CapacityProviderStrategyItemProperty(
                    capacity_provider="capacityProvider",
                
                    # the properties below are optional
                    base=123,
                    weight=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "capacity_provider": capacity_provider,
            }
            if base is not None:
                self._values["base"] = base
            if weight is not None:
                self._values["weight"] = weight

        @builtins.property
        def capacity_provider(self) -> builtins.str:
            '''The short name of the capacity provider.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-capacityproviderstrategyitem.html#cfn-events-rule-capacityproviderstrategyitem-capacityprovider
            '''
            result = self._values.get("capacity_provider")
            assert result is not None, "Required property 'capacity_provider' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def base(self) -> typing.Optional[jsii.Number]:
            '''The base value designates how many tasks, at a minimum, to run on the specified capacity provider.

            Only one capacity provider in a capacity provider strategy can have a base defined. If no value is specified, the default value of 0 is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-capacityproviderstrategyitem.html#cfn-events-rule-capacityproviderstrategyitem-base
            '''
            result = self._values.get("base")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def weight(self) -> typing.Optional[jsii.Number]:
            '''The weight value designates the relative percentage of the total number of tasks launched that should use the specified capacity provider.

            The weight value is taken into consideration after the base value, if defined, is satisfied.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-capacityproviderstrategyitem.html#cfn-events-rule-capacityproviderstrategyitem-weight
            '''
            result = self._values.get("weight")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CapacityProviderStrategyItemProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.DeadLetterConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"arn": "arn"},
    )
    class DeadLetterConfigProperty:
        def __init__(self, *, arn: typing.Optional[builtins.str] = None) -> None:
            '''A ``DeadLetterConfig`` object that contains information about a dead-letter queue configuration.

            :param arn: The ARN of the SQS queue specified as the target for the dead-letter queue.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-deadletterconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                dead_letter_config_property = events.CfnRule.DeadLetterConfigProperty(
                    arn="arn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if arn is not None:
                self._values["arn"] = arn

        @builtins.property
        def arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the SQS queue specified as the target for the dead-letter queue.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-deadletterconfig.html#cfn-events-rule-deadletterconfig-arn
            '''
            result = self._values.get("arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "DeadLetterConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.EcsParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "task_definition_arn": "taskDefinitionArn",
            "capacity_provider_strategy": "capacityProviderStrategy",
            "enable_ecs_managed_tags": "enableEcsManagedTags",
            "enable_execute_command": "enableExecuteCommand",
            "group": "group",
            "launch_type": "launchType",
            "network_configuration": "networkConfiguration",
            "placement_constraints": "placementConstraints",
            "placement_strategies": "placementStrategies",
            "platform_version": "platformVersion",
            "propagate_tags": "propagateTags",
            "reference_id": "referenceId",
            "tag_list": "tagList",
            "task_count": "taskCount",
        },
    )
    class EcsParametersProperty:
        def __init__(
            self,
            *,
            task_definition_arn: builtins.str,
            capacity_provider_strategy: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRule.CapacityProviderStrategyItemProperty", _IResolvable_da3f097b]]]] = None,
            enable_ecs_managed_tags: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            enable_execute_command: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            group: typing.Optional[builtins.str] = None,
            launch_type: typing.Optional[builtins.str] = None,
            network_configuration: typing.Optional[typing.Union["CfnRule.NetworkConfigurationProperty", _IResolvable_da3f097b]] = None,
            placement_constraints: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRule.PlacementConstraintProperty", _IResolvable_da3f097b]]]] = None,
            placement_strategies: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRule.PlacementStrategyProperty", _IResolvable_da3f097b]]]] = None,
            platform_version: typing.Optional[builtins.str] = None,
            propagate_tags: typing.Optional[builtins.str] = None,
            reference_id: typing.Optional[builtins.str] = None,
            tag_list: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]] = None,
            task_count: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The custom parameters to be used when the target is an Amazon ECS task.

            :param task_definition_arn: The ARN of the task definition to use if the event target is an Amazon ECS task.
            :param capacity_provider_strategy: The capacity provider strategy to use for the task. If a ``capacityProviderStrategy`` is specified, the ``launchType`` parameter must be omitted. If no ``capacityProviderStrategy`` or launchType is specified, the ``defaultCapacityProviderStrategy`` for the cluster is used.
            :param enable_ecs_managed_tags: Specifies whether to enable Amazon ECS managed tags for the task. For more information, see `Tagging Your Amazon ECS Resources <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-using-tags.html>`_ in the Amazon Elastic Container Service Developer Guide.
            :param enable_execute_command: Whether or not to enable the execute command functionality for the containers in this task. If true, this enables execute command functionality on all containers in the task.
            :param group: Specifies an ECS task group for the task. The maximum length is 255 characters.
            :param launch_type: Specifies the launch type on which your task is running. The launch type that you specify here must match one of the launch type (compatibilities) of the target task. The ``FARGATE`` value is supported only in the Regions where AWS Fargate with Amazon ECS is supported. For more information, see `AWS Fargate on Amazon ECS <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS-Fargate.html>`_ in the *Amazon Elastic Container Service Developer Guide* .
            :param network_configuration: Use this structure if the Amazon ECS task uses the ``awsvpc`` network mode. This structure specifies the VPC subnets and security groups associated with the task, and whether a public IP address is to be used. This structure is required if ``LaunchType`` is ``FARGATE`` because the ``awsvpc`` mode is required for Fargate tasks. If you specify ``NetworkConfiguration`` when the target ECS task does not use the ``awsvpc`` network mode, the task fails.
            :param placement_constraints: An array of placement constraint objects to use for the task. You can specify up to 10 constraints per task (including constraints in the task definition and those specified at runtime).
            :param placement_strategies: The placement strategy objects to use for the task. You can specify a maximum of five strategy rules per task.
            :param platform_version: Specifies the platform version for the task. Specify only the numeric portion of the platform version, such as ``1.1.0`` . This structure is used only if ``LaunchType`` is ``FARGATE`` . For more information about valid platform versions, see `AWS Fargate Platform Versions <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform_versions.html>`_ in the *Amazon Elastic Container Service Developer Guide* .
            :param propagate_tags: Specifies whether to propagate the tags from the task definition to the task. If no value is specified, the tags are not propagated. Tags can only be propagated to the task during task creation. To add tags to a task after task creation, use the TagResource API action.
            :param reference_id: The reference ID to use for the task.
            :param tag_list: The metadata that you apply to the task to help you categorize and organize them. Each tag consists of a key and an optional value, both of which you define. To learn more, see `RunTask <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html#ECS-RunTask-request-tags>`_ in the Amazon ECS API Reference.
            :param task_count: The number of tasks to create based on ``TaskDefinition`` . The default is 1.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                ecs_parameters_property = events.CfnRule.EcsParametersProperty(
                    task_definition_arn="taskDefinitionArn",
                
                    # the properties below are optional
                    capacity_provider_strategy=[events.CfnRule.CapacityProviderStrategyItemProperty(
                        capacity_provider="capacityProvider",
                
                        # the properties below are optional
                        base=123,
                        weight=123
                    )],
                    enable_ecs_managed_tags=False,
                    enable_execute_command=False,
                    group="group",
                    launch_type="launchType",
                    network_configuration=events.CfnRule.NetworkConfigurationProperty(
                        aws_vpc_configuration=events.CfnRule.AwsVpcConfigurationProperty(
                            subnets=["subnets"],
                
                            # the properties below are optional
                            assign_public_ip="assignPublicIp",
                            security_groups=["securityGroups"]
                        )
                    ),
                    placement_constraints=[events.CfnRule.PlacementConstraintProperty(
                        expression="expression",
                        type="type"
                    )],
                    placement_strategies=[events.CfnRule.PlacementStrategyProperty(
                        field="field",
                        type="type"
                    )],
                    platform_version="platformVersion",
                    propagate_tags="propagateTags",
                    reference_id="referenceId",
                    tag_list=[CfnTag(
                        key="key",
                        value="value"
                    )],
                    task_count=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "task_definition_arn": task_definition_arn,
            }
            if capacity_provider_strategy is not None:
                self._values["capacity_provider_strategy"] = capacity_provider_strategy
            if enable_ecs_managed_tags is not None:
                self._values["enable_ecs_managed_tags"] = enable_ecs_managed_tags
            if enable_execute_command is not None:
                self._values["enable_execute_command"] = enable_execute_command
            if group is not None:
                self._values["group"] = group
            if launch_type is not None:
                self._values["launch_type"] = launch_type
            if network_configuration is not None:
                self._values["network_configuration"] = network_configuration
            if placement_constraints is not None:
                self._values["placement_constraints"] = placement_constraints
            if placement_strategies is not None:
                self._values["placement_strategies"] = placement_strategies
            if platform_version is not None:
                self._values["platform_version"] = platform_version
            if propagate_tags is not None:
                self._values["propagate_tags"] = propagate_tags
            if reference_id is not None:
                self._values["reference_id"] = reference_id
            if tag_list is not None:
                self._values["tag_list"] = tag_list
            if task_count is not None:
                self._values["task_count"] = task_count

        @builtins.property
        def task_definition_arn(self) -> builtins.str:
            '''The ARN of the task definition to use if the event target is an Amazon ECS task.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-taskdefinitionarn
            '''
            result = self._values.get("task_definition_arn")
            assert result is not None, "Required property 'task_definition_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def capacity_provider_strategy(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.CapacityProviderStrategyItemProperty", _IResolvable_da3f097b]]]]:
            '''The capacity provider strategy to use for the task.

            If a ``capacityProviderStrategy`` is specified, the ``launchType`` parameter must be omitted. If no ``capacityProviderStrategy`` or launchType is specified, the ``defaultCapacityProviderStrategy`` for the cluster is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-capacityproviderstrategy
            '''
            result = self._values.get("capacity_provider_strategy")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.CapacityProviderStrategyItemProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def enable_ecs_managed_tags(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether to enable Amazon ECS managed tags for the task.

            For more information, see `Tagging Your Amazon ECS Resources <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-using-tags.html>`_ in the Amazon Elastic Container Service Developer Guide.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-enableecsmanagedtags
            '''
            result = self._values.get("enable_ecs_managed_tags")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def enable_execute_command(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Whether or not to enable the execute command functionality for the containers in this task.

            If true, this enables execute command functionality on all containers in the task.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-enableexecutecommand
            '''
            result = self._values.get("enable_execute_command")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def group(self) -> typing.Optional[builtins.str]:
            '''Specifies an ECS task group for the task.

            The maximum length is 255 characters.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-group
            '''
            result = self._values.get("group")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def launch_type(self) -> typing.Optional[builtins.str]:
            '''Specifies the launch type on which your task is running.

            The launch type that you specify here must match one of the launch type (compatibilities) of the target task. The ``FARGATE`` value is supported only in the Regions where AWS Fargate with Amazon ECS is supported. For more information, see `AWS Fargate on Amazon ECS <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/AWS-Fargate.html>`_ in the *Amazon Elastic Container Service Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-launchtype
            '''
            result = self._values.get("launch_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def network_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.NetworkConfigurationProperty", _IResolvable_da3f097b]]:
            '''Use this structure if the Amazon ECS task uses the ``awsvpc`` network mode.

            This structure specifies the VPC subnets and security groups associated with the task, and whether a public IP address is to be used. This structure is required if ``LaunchType`` is ``FARGATE`` because the ``awsvpc`` mode is required for Fargate tasks.

            If you specify ``NetworkConfiguration`` when the target ECS task does not use the ``awsvpc`` network mode, the task fails.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-networkconfiguration
            '''
            result = self._values.get("network_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnRule.NetworkConfigurationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def placement_constraints(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.PlacementConstraintProperty", _IResolvable_da3f097b]]]]:
            '''An array of placement constraint objects to use for the task.

            You can specify up to 10 constraints per task (including constraints in the task definition and those specified at runtime).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-placementconstraints
            '''
            result = self._values.get("placement_constraints")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.PlacementConstraintProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def placement_strategies(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.PlacementStrategyProperty", _IResolvable_da3f097b]]]]:
            '''The placement strategy objects to use for the task.

            You can specify a maximum of five strategy rules per task.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-placementstrategies
            '''
            result = self._values.get("placement_strategies")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.PlacementStrategyProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def platform_version(self) -> typing.Optional[builtins.str]:
            '''Specifies the platform version for the task.

            Specify only the numeric portion of the platform version, such as ``1.1.0`` .

            This structure is used only if ``LaunchType`` is ``FARGATE`` . For more information about valid platform versions, see `AWS Fargate Platform Versions <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform_versions.html>`_ in the *Amazon Elastic Container Service Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-platformversion
            '''
            result = self._values.get("platform_version")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def propagate_tags(self) -> typing.Optional[builtins.str]:
            '''Specifies whether to propagate the tags from the task definition to the task.

            If no value is specified, the tags are not propagated. Tags can only be propagated to the task during task creation. To add tags to a task after task creation, use the TagResource API action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-propagatetags
            '''
            result = self._values.get("propagate_tags")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def reference_id(self) -> typing.Optional[builtins.str]:
            '''The reference ID to use for the task.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-referenceid
            '''
            result = self._values.get("reference_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def tag_list(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]]:
            '''The metadata that you apply to the task to help you categorize and organize them.

            Each tag consists of a key and an optional value, both of which you define. To learn more, see `RunTask <https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html#ECS-RunTask-request-tags>`_ in the Amazon ECS API Reference.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-taglist
            '''
            result = self._values.get("tag_list")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[_IResolvable_da3f097b, _CfnTag_f6864754]]]], result)

        @builtins.property
        def task_count(self) -> typing.Optional[jsii.Number]:
            '''The number of tasks to create based on ``TaskDefinition`` .

            The default is 1.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-ecsparameters.html#cfn-events-rule-ecsparameters-taskcount
            '''
            result = self._values.get("task_count")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EcsParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.HttpParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "header_parameters": "headerParameters",
            "path_parameter_values": "pathParameterValues",
            "query_string_parameters": "queryStringParameters",
        },
    )
    class HttpParametersProperty:
        def __init__(
            self,
            *,
            header_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            path_parameter_values: typing.Optional[typing.Sequence[builtins.str]] = None,
            query_string_parameters: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        ) -> None:
            '''These are custom parameter to be used when the target is an API Gateway REST APIs or EventBridge ApiDestinations.

            In the latter case, these are merged with any InvocationParameters specified on the Connection, with any values from the Connection taking precedence.

            :param header_parameters: The headers that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.
            :param path_parameter_values: The path parameter values to be used to populate API Gateway REST API or EventBridge ApiDestination path wildcards ("*").
            :param query_string_parameters: The query string keys/values that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-httpparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                http_parameters_property = events.CfnRule.HttpParametersProperty(
                    header_parameters={
                        "header_parameters_key": "headerParameters"
                    },
                    path_parameter_values=["pathParameterValues"],
                    query_string_parameters={
                        "query_string_parameters_key": "queryStringParameters"
                    }
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if header_parameters is not None:
                self._values["header_parameters"] = header_parameters
            if path_parameter_values is not None:
                self._values["path_parameter_values"] = path_parameter_values
            if query_string_parameters is not None:
                self._values["query_string_parameters"] = query_string_parameters

        @builtins.property
        def header_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''The headers that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-httpparameters.html#cfn-events-rule-httpparameters-headerparameters
            '''
            result = self._values.get("header_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def path_parameter_values(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The path parameter values to be used to populate API Gateway REST API or EventBridge ApiDestination path wildcards ("*").

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-httpparameters.html#cfn-events-rule-httpparameters-pathparametervalues
            '''
            result = self._values.get("path_parameter_values")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def query_string_parameters(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''The query string keys/values that need to be sent as part of request invoking the API Gateway REST API or EventBridge ApiDestination.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-httpparameters.html#cfn-events-rule-httpparameters-querystringparameters
            '''
            result = self._values.get("query_string_parameters")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HttpParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.InputTransformerProperty",
        jsii_struct_bases=[],
        name_mapping={
            "input_template": "inputTemplate",
            "input_paths_map": "inputPathsMap",
        },
    )
    class InputTransformerProperty:
        def __init__(
            self,
            *,
            input_template: builtins.str,
            input_paths_map: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
        ) -> None:
            '''Contains the parameters needed for you to provide custom input to a target based on one or more pieces of data extracted from the event.

            :param input_template: Input template where you specify placeholders that will be filled with the values of the keys from ``InputPathsMap`` to customize the data sent to the target. Enclose each ``InputPathsMaps`` value in brackets: < *value* > The InputTemplate must be valid JSON. If ``InputTemplate`` is a JSON object (surrounded by curly braces), the following restrictions apply: - The placeholder cannot be used as an object key. The following example shows the syntax for using ``InputPathsMap`` and ``InputTemplate`` . ``"InputTransformer":`` ``{`` ``"InputPathsMap": {"instance": "$.detail.instance","status": "$.detail.status"},`` ``"InputTemplate": "<instance> is in state <status>"`` ``}`` To have the ``InputTemplate`` include quote marks within a JSON string, escape each quote marks with a slash, as in the following example: ``"InputTransformer":`` ``{`` ``"InputPathsMap": {"instance": "$.detail.instance","status": "$.detail.status"},`` ``"InputTemplate": "<instance> is in state \\"<status>\\""`` ``}`` The ``InputTemplate`` can also be valid JSON with varibles in quotes or out, as in the following example: ``"InputTransformer":`` ``{`` ``"InputPathsMap": {"instance": "$.detail.instance","status": "$.detail.status"},`` ``"InputTemplate": '{"myInstance": <instance>,"myStatus": "<instance> is in state \\"<status>\\""}'`` ``}``
            :param input_paths_map: Map of JSON paths to be extracted from the event. You can then insert these in the template in ``InputTemplate`` to produce the output you want to be sent to the target. ``InputPathsMap`` is an array key-value pairs, where each value is a valid JSON path. You can have as many as 100 key-value pairs. You must use JSON dot notation, not bracket notation. The keys cannot start with " AWS ."

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-inputtransformer.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                input_transformer_property = events.CfnRule.InputTransformerProperty(
                    input_template="inputTemplate",
                
                    # the properties below are optional
                    input_paths_map={
                        "input_paths_map_key": "inputPathsMap"
                    }
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "input_template": input_template,
            }
            if input_paths_map is not None:
                self._values["input_paths_map"] = input_paths_map

        @builtins.property
        def input_template(self) -> builtins.str:
            '''Input template where you specify placeholders that will be filled with the values of the keys from ``InputPathsMap`` to customize the data sent to the target.

            Enclose each ``InputPathsMaps`` value in brackets: < *value* > The InputTemplate must be valid JSON.

            If ``InputTemplate`` is a JSON object (surrounded by curly braces), the following restrictions apply:

            - The placeholder cannot be used as an object key.

            The following example shows the syntax for using ``InputPathsMap`` and ``InputTemplate`` .

            ``"InputTransformer":``

            ``{``

            ``"InputPathsMap": {"instance": "$.detail.instance","status": "$.detail.status"},``

            ``"InputTemplate": "<instance> is in state <status>"``

            ``}``

            To have the ``InputTemplate`` include quote marks within a JSON string, escape each quote marks with a slash, as in the following example:

            ``"InputTransformer":``

            ``{``

            ``"InputPathsMap": {"instance": "$.detail.instance","status": "$.detail.status"},``

            ``"InputTemplate": "<instance> is in state \\"<status>\\""``

            ``}``

            The ``InputTemplate`` can also be valid JSON with varibles in quotes or out, as in the following example:

            ``"InputTransformer":``

            ``{``

            ``"InputPathsMap": {"instance": "$.detail.instance","status": "$.detail.status"},``

            ``"InputTemplate": '{"myInstance": <instance>,"myStatus": "<instance> is in state \\"<status>\\""}'``

            ``}``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-inputtransformer.html#cfn-events-rule-inputtransformer-inputtemplate
            '''
            result = self._values.get("input_template")
            assert result is not None, "Required property 'input_template' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def input_paths_map(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''Map of JSON paths to be extracted from the event.

            You can then insert these in the template in ``InputTemplate`` to produce the output you want to be sent to the target.

            ``InputPathsMap`` is an array key-value pairs, where each value is a valid JSON path. You can have as many as 100 key-value pairs. You must use JSON dot notation, not bracket notation.

            The keys cannot start with " AWS ."

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-inputtransformer.html#cfn-events-rule-inputtransformer-inputpathsmap
            '''
            result = self._values.get("input_paths_map")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InputTransformerProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.KinesisParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"partition_key_path": "partitionKeyPath"},
    )
    class KinesisParametersProperty:
        def __init__(self, *, partition_key_path: builtins.str) -> None:
            '''This object enables you to specify a JSON path to extract from the event and use as the partition key for the Amazon Kinesis data stream, so that you can control the shard to which the event goes.

            If you do not include this parameter, the default is to use the ``eventId`` as the partition key.

            :param partition_key_path: The JSON path to be extracted from the event and used as the partition key. For more information, see `Amazon Kinesis Streams Key Concepts <https://docs.aws.amazon.com/streams/latest/dev/key-concepts.html#partition-key>`_ in the *Amazon Kinesis Streams Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-kinesisparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                kinesis_parameters_property = events.CfnRule.KinesisParametersProperty(
                    partition_key_path="partitionKeyPath"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "partition_key_path": partition_key_path,
            }

        @builtins.property
        def partition_key_path(self) -> builtins.str:
            '''The JSON path to be extracted from the event and used as the partition key.

            For more information, see `Amazon Kinesis Streams Key Concepts <https://docs.aws.amazon.com/streams/latest/dev/key-concepts.html#partition-key>`_ in the *Amazon Kinesis Streams Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-kinesisparameters.html#cfn-events-rule-kinesisparameters-partitionkeypath
            '''
            result = self._values.get("partition_key_path")
            assert result is not None, "Required property 'partition_key_path' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KinesisParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.NetworkConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={"aws_vpc_configuration": "awsVpcConfiguration"},
    )
    class NetworkConfigurationProperty:
        def __init__(
            self,
            *,
            aws_vpc_configuration: typing.Optional[typing.Union["CfnRule.AwsVpcConfigurationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''This structure specifies the network configuration for an ECS task.

            :param aws_vpc_configuration: Use this structure to specify the VPC subnets and security groups for the task, and whether a public IP address is to be used. This structure is relevant only for ECS tasks that use the ``awsvpc`` network mode.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-networkconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                network_configuration_property = events.CfnRule.NetworkConfigurationProperty(
                    aws_vpc_configuration=events.CfnRule.AwsVpcConfigurationProperty(
                        subnets=["subnets"],
                
                        # the properties below are optional
                        assign_public_ip="assignPublicIp",
                        security_groups=["securityGroups"]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if aws_vpc_configuration is not None:
                self._values["aws_vpc_configuration"] = aws_vpc_configuration

        @builtins.property
        def aws_vpc_configuration(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.AwsVpcConfigurationProperty", _IResolvable_da3f097b]]:
            '''Use this structure to specify the VPC subnets and security groups for the task, and whether a public IP address is to be used.

            This structure is relevant only for ECS tasks that use the ``awsvpc`` network mode.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-networkconfiguration.html#cfn-events-rule-networkconfiguration-awsvpcconfiguration
            '''
            result = self._values.get("aws_vpc_configuration")
            return typing.cast(typing.Optional[typing.Union["CfnRule.AwsVpcConfigurationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NetworkConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.PlacementConstraintProperty",
        jsii_struct_bases=[],
        name_mapping={"expression": "expression", "type": "type"},
    )
    class PlacementConstraintProperty:
        def __init__(
            self,
            *,
            expression: typing.Optional[builtins.str] = None,
            type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An object representing a constraint on task placement.

            To learn more, see `Task Placement Constraints <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-placement-constraints.html>`_ in the Amazon Elastic Container Service Developer Guide.

            :param expression: A cluster query language expression to apply to the constraint. You cannot specify an expression if the constraint type is ``distinctInstance`` . To learn more, see `Cluster Query Language <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cluster-query-language.html>`_ in the Amazon Elastic Container Service Developer Guide.
            :param type: The type of constraint. Use distinctInstance to ensure that each task in a particular group is running on a different container instance. Use memberOf to restrict the selection to a group of valid candidates.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-placementconstraint.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                placement_constraint_property = events.CfnRule.PlacementConstraintProperty(
                    expression="expression",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if expression is not None:
                self._values["expression"] = expression
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def expression(self) -> typing.Optional[builtins.str]:
            '''A cluster query language expression to apply to the constraint.

            You cannot specify an expression if the constraint type is ``distinctInstance`` . To learn more, see `Cluster Query Language <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cluster-query-language.html>`_ in the Amazon Elastic Container Service Developer Guide.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-placementconstraint.html#cfn-events-rule-placementconstraint-expression
            '''
            result = self._values.get("expression")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''The type of constraint.

            Use distinctInstance to ensure that each task in a particular group is running on a different container instance. Use memberOf to restrict the selection to a group of valid candidates.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-placementconstraint.html#cfn-events-rule-placementconstraint-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PlacementConstraintProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.PlacementStrategyProperty",
        jsii_struct_bases=[],
        name_mapping={"field": "field", "type": "type"},
    )
    class PlacementStrategyProperty:
        def __init__(
            self,
            *,
            field: typing.Optional[builtins.str] = None,
            type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The task placement strategy for a task or service.

            To learn more, see `Task Placement Strategies <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-placement-strategies.html>`_ in the Amazon Elastic Container Service Service Developer Guide.

            :param field: The field to apply the placement strategy against. For the spread placement strategy, valid values are instanceId (or host, which has the same effect), or any platform or custom attribute that is applied to a container instance, such as attribute:ecs.availability-zone. For the binpack placement strategy, valid values are cpu and memory. For the random placement strategy, this field is not used.
            :param type: The type of placement strategy. The random placement strategy randomly places tasks on available candidates. The spread placement strategy spreads placement across available candidates evenly based on the field parameter. The binpack strategy places tasks on available candidates that have the least available amount of the resource that is specified with the field parameter. For example, if you binpack on memory, a task is placed on the instance with the least amount of remaining memory (but still enough to run the task).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-placementstrategy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                placement_strategy_property = events.CfnRule.PlacementStrategyProperty(
                    field="field",
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if field is not None:
                self._values["field"] = field
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def field(self) -> typing.Optional[builtins.str]:
            '''The field to apply the placement strategy against.

            For the spread placement strategy, valid values are instanceId (or host, which has the same effect), or any platform or custom attribute that is applied to a container instance, such as attribute:ecs.availability-zone. For the binpack placement strategy, valid values are cpu and memory. For the random placement strategy, this field is not used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-placementstrategy.html#cfn-events-rule-placementstrategy-field
            '''
            result = self._values.get("field")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''The type of placement strategy.

            The random placement strategy randomly places tasks on available candidates. The spread placement strategy spreads placement across available candidates evenly based on the field parameter. The binpack strategy places tasks on available candidates that have the least available amount of the resource that is specified with the field parameter. For example, if you binpack on memory, a task is placed on the instance with the least amount of remaining memory (but still enough to run the task).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-placementstrategy.html#cfn-events-rule-placementstrategy-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PlacementStrategyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.RedshiftDataParametersProperty",
        jsii_struct_bases=[],
        name_mapping={
            "database": "database",
            "sql": "sql",
            "db_user": "dbUser",
            "secret_manager_arn": "secretManagerArn",
            "statement_name": "statementName",
            "with_event": "withEvent",
        },
    )
    class RedshiftDataParametersProperty:
        def __init__(
            self,
            *,
            database: builtins.str,
            sql: builtins.str,
            db_user: typing.Optional[builtins.str] = None,
            secret_manager_arn: typing.Optional[builtins.str] = None,
            statement_name: typing.Optional[builtins.str] = None,
            with_event: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''These are custom parameters to be used when the target is a Amazon Redshift cluster to invoke the Amazon Redshift Data API ExecuteStatement based on EventBridge events.

            :param database: The name of the database. Required when authenticating using temporary credentials.
            :param sql: The SQL statement text to run.
            :param db_user: The database user name. Required when authenticating using temporary credentials.
            :param secret_manager_arn: The name or ARN of the secret that enables access to the database. Required when authenticating using AWS Secrets Manager.
            :param statement_name: The name of the SQL statement. You can name the SQL statement when you create it to identify the query.
            :param with_event: Indicates whether to send an event back to EventBridge after the SQL statement runs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-redshiftdataparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                redshift_data_parameters_property = events.CfnRule.RedshiftDataParametersProperty(
                    database="database",
                    sql="sql",
                
                    # the properties below are optional
                    db_user="dbUser",
                    secret_manager_arn="secretManagerArn",
                    statement_name="statementName",
                    with_event=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "database": database,
                "sql": sql,
            }
            if db_user is not None:
                self._values["db_user"] = db_user
            if secret_manager_arn is not None:
                self._values["secret_manager_arn"] = secret_manager_arn
            if statement_name is not None:
                self._values["statement_name"] = statement_name
            if with_event is not None:
                self._values["with_event"] = with_event

        @builtins.property
        def database(self) -> builtins.str:
            '''The name of the database.

            Required when authenticating using temporary credentials.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-redshiftdataparameters.html#cfn-events-rule-redshiftdataparameters-database
            '''
            result = self._values.get("database")
            assert result is not None, "Required property 'database' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def sql(self) -> builtins.str:
            '''The SQL statement text to run.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-redshiftdataparameters.html#cfn-events-rule-redshiftdataparameters-sql
            '''
            result = self._values.get("sql")
            assert result is not None, "Required property 'sql' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def db_user(self) -> typing.Optional[builtins.str]:
            '''The database user name.

            Required when authenticating using temporary credentials.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-redshiftdataparameters.html#cfn-events-rule-redshiftdataparameters-dbuser
            '''
            result = self._values.get("db_user")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def secret_manager_arn(self) -> typing.Optional[builtins.str]:
            '''The name or ARN of the secret that enables access to the database.

            Required when authenticating using AWS Secrets Manager.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-redshiftdataparameters.html#cfn-events-rule-redshiftdataparameters-secretmanagerarn
            '''
            result = self._values.get("secret_manager_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def statement_name(self) -> typing.Optional[builtins.str]:
            '''The name of the SQL statement.

            You can name the SQL statement when you create it to identify the query.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-redshiftdataparameters.html#cfn-events-rule-redshiftdataparameters-statementname
            '''
            result = self._values.get("statement_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def with_event(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether to send an event back to EventBridge after the SQL statement runs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-redshiftdataparameters.html#cfn-events-rule-redshiftdataparameters-withevent
            '''
            result = self._values.get("with_event")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RedshiftDataParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.RetryPolicyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "maximum_event_age_in_seconds": "maximumEventAgeInSeconds",
            "maximum_retry_attempts": "maximumRetryAttempts",
        },
    )
    class RetryPolicyProperty:
        def __init__(
            self,
            *,
            maximum_event_age_in_seconds: typing.Optional[jsii.Number] = None,
            maximum_retry_attempts: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''A ``RetryPolicy`` object that includes information about the retry policy settings.

            :param maximum_event_age_in_seconds: The maximum amount of time, in seconds, to continue to make retry attempts.
            :param maximum_retry_attempts: The maximum number of retry attempts to make before the request fails. Retry attempts continue until either the maximum number of attempts is made or until the duration of the ``MaximumEventAgeInSeconds`` is met.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-retrypolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                retry_policy_property = events.CfnRule.RetryPolicyProperty(
                    maximum_event_age_in_seconds=123,
                    maximum_retry_attempts=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if maximum_event_age_in_seconds is not None:
                self._values["maximum_event_age_in_seconds"] = maximum_event_age_in_seconds
            if maximum_retry_attempts is not None:
                self._values["maximum_retry_attempts"] = maximum_retry_attempts

        @builtins.property
        def maximum_event_age_in_seconds(self) -> typing.Optional[jsii.Number]:
            '''The maximum amount of time, in seconds, to continue to make retry attempts.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-retrypolicy.html#cfn-events-rule-retrypolicy-maximumeventageinseconds
            '''
            result = self._values.get("maximum_event_age_in_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def maximum_retry_attempts(self) -> typing.Optional[jsii.Number]:
            '''The maximum number of retry attempts to make before the request fails.

            Retry attempts continue until either the maximum number of attempts is made or until the duration of the ``MaximumEventAgeInSeconds`` is met.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-retrypolicy.html#cfn-events-rule-retrypolicy-maximumretryattempts
            '''
            result = self._values.get("maximum_retry_attempts")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RetryPolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.RunCommandParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"run_command_targets": "runCommandTargets"},
    )
    class RunCommandParametersProperty:
        def __init__(
            self,
            *,
            run_command_targets: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRule.RunCommandTargetProperty", _IResolvable_da3f097b]]],
        ) -> None:
            '''This parameter contains the criteria (either InstanceIds or a tag) used to specify which EC2 instances are to be sent the command.

            :param run_command_targets: Currently, we support including only one RunCommandTarget block, which specifies either an array of InstanceIds or a tag.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-runcommandparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                run_command_parameters_property = events.CfnRule.RunCommandParametersProperty(
                    run_command_targets=[events.CfnRule.RunCommandTargetProperty(
                        key="key",
                        values=["values"]
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "run_command_targets": run_command_targets,
            }

        @builtins.property
        def run_command_targets(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.RunCommandTargetProperty", _IResolvable_da3f097b]]]:
            '''Currently, we support including only one RunCommandTarget block, which specifies either an array of InstanceIds or a tag.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-runcommandparameters.html#cfn-events-rule-runcommandparameters-runcommandtargets
            '''
            result = self._values.get("run_command_targets")
            assert result is not None, "Required property 'run_command_targets' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.RunCommandTargetProperty", _IResolvable_da3f097b]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RunCommandParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.RunCommandTargetProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "values": "values"},
    )
    class RunCommandTargetProperty:
        def __init__(
            self,
            *,
            key: builtins.str,
            values: typing.Sequence[builtins.str],
        ) -> None:
            '''Information about the EC2 instances that are to be sent the command, specified as key-value pairs.

            Each ``RunCommandTarget`` block can include only one key, but this key may specify multiple values.

            :param key: Can be either ``tag:`` *tag-key* or ``InstanceIds`` .
            :param values: If ``Key`` is ``tag:`` *tag-key* , ``Values`` is a list of tag values. If ``Key`` is ``InstanceIds`` , ``Values`` is a list of Amazon EC2 instance IDs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-runcommandtarget.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                run_command_target_property = events.CfnRule.RunCommandTargetProperty(
                    key="key",
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "key": key,
                "values": values,
            }

        @builtins.property
        def key(self) -> builtins.str:
            '''Can be either ``tag:`` *tag-key* or ``InstanceIds`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-runcommandtarget.html#cfn-events-rule-runcommandtarget-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def values(self) -> typing.List[builtins.str]:
            '''If ``Key`` is ``tag:`` *tag-key* , ``Values`` is a list of tag values.

            If ``Key`` is ``InstanceIds`` , ``Values`` is a list of Amazon EC2 instance IDs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-runcommandtarget.html#cfn-events-rule-runcommandtarget-values
            '''
            result = self._values.get("values")
            assert result is not None, "Required property 'values' is missing"
            return typing.cast(typing.List[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RunCommandTargetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.SageMakerPipelineParameterProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class SageMakerPipelineParameterProperty:
        def __init__(self, *, name: builtins.str, value: builtins.str) -> None:
            '''Name/Value pair of a parameter to start execution of a SageMaker Model Building Pipeline.

            :param name: Name of parameter to start execution of a SageMaker Model Building Pipeline.
            :param value: Value of parameter to start execution of a SageMaker Model Building Pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-sagemakerpipelineparameter.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                sage_maker_pipeline_parameter_property = events.CfnRule.SageMakerPipelineParameterProperty(
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
            '''Name of parameter to start execution of a SageMaker Model Building Pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-sagemakerpipelineparameter.html#cfn-events-rule-sagemakerpipelineparameter-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''Value of parameter to start execution of a SageMaker Model Building Pipeline.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-sagemakerpipelineparameter.html#cfn-events-rule-sagemakerpipelineparameter-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SageMakerPipelineParameterProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.SageMakerPipelineParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"pipeline_parameter_list": "pipelineParameterList"},
    )
    class SageMakerPipelineParametersProperty:
        def __init__(
            self,
            *,
            pipeline_parameter_list: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnRule.SageMakerPipelineParameterProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''These are custom parameters to use when the target is a SageMaker Model Building Pipeline that starts based on EventBridge events.

            :param pipeline_parameter_list: List of Parameter names and values for SageMaker Model Building Pipeline execution.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-sagemakerpipelineparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                sage_maker_pipeline_parameters_property = events.CfnRule.SageMakerPipelineParametersProperty(
                    pipeline_parameter_list=[events.CfnRule.SageMakerPipelineParameterProperty(
                        name="name",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if pipeline_parameter_list is not None:
                self._values["pipeline_parameter_list"] = pipeline_parameter_list

        @builtins.property
        def pipeline_parameter_list(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.SageMakerPipelineParameterProperty", _IResolvable_da3f097b]]]]:
            '''List of Parameter names and values for SageMaker Model Building Pipeline execution.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-sagemakerpipelineparameters.html#cfn-events-rule-sagemakerpipelineparameters-pipelineparameterlist
            '''
            result = self._values.get("pipeline_parameter_list")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnRule.SageMakerPipelineParameterProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SageMakerPipelineParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.SqsParametersProperty",
        jsii_struct_bases=[],
        name_mapping={"message_group_id": "messageGroupId"},
    )
    class SqsParametersProperty:
        def __init__(self, *, message_group_id: builtins.str) -> None:
            '''This structure includes the custom parameter to be used when the target is an SQS FIFO queue.

            :param message_group_id: The FIFO message group ID to use as the target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-sqsparameters.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                sqs_parameters_property = events.CfnRule.SqsParametersProperty(
                    message_group_id="messageGroupId"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "message_group_id": message_group_id,
            }

        @builtins.property
        def message_group_id(self) -> builtins.str:
            '''The FIFO message group ID to use as the target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-sqsparameters.html#cfn-events-rule-sqsparameters-messagegroupid
            '''
            result = self._values.get("message_group_id")
            assert result is not None, "Required property 'message_group_id' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SqsParametersProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.TagProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class TagProperty:
        def __init__(
            self,
            *,
            key: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A key-value pair associated with an ECS Target of an EventBridge rule.

            The tag will be propagated to ECS by EventBridge when starting an ECS task based on a matched event.
            .. epigraph::

               Currently, tags are only available when using ECS with EventBridge .

            :param key: A string you can use to assign a value. The combination of tag keys and values can help you organize and categorize your resources.
            :param value: The value for the specified tag key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-tag.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                tag_property = events.CfnRule.TagProperty(
                    key="key",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if key is not None:
                self._values["key"] = key
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def key(self) -> typing.Optional[builtins.str]:
            '''A string you can use to assign a value.

            The combination of tag keys and values can help you organize and categorize your resources.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-tag.html#cfn-events-rule-tag-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The value for the specified tag key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-tag.html#cfn-events-rule-tag-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TagProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_events.CfnRule.TargetProperty",
        jsii_struct_bases=[],
        name_mapping={
            "arn": "arn",
            "id": "id",
            "batch_parameters": "batchParameters",
            "dead_letter_config": "deadLetterConfig",
            "ecs_parameters": "ecsParameters",
            "http_parameters": "httpParameters",
            "input": "input",
            "input_path": "inputPath",
            "input_transformer": "inputTransformer",
            "kinesis_parameters": "kinesisParameters",
            "redshift_data_parameters": "redshiftDataParameters",
            "retry_policy": "retryPolicy",
            "role_arn": "roleArn",
            "run_command_parameters": "runCommandParameters",
            "sage_maker_pipeline_parameters": "sageMakerPipelineParameters",
            "sqs_parameters": "sqsParameters",
        },
    )
    class TargetProperty:
        def __init__(
            self,
            *,
            arn: builtins.str,
            id: builtins.str,
            batch_parameters: typing.Optional[typing.Union["CfnRule.BatchParametersProperty", _IResolvable_da3f097b]] = None,
            dead_letter_config: typing.Optional[typing.Union["CfnRule.DeadLetterConfigProperty", _IResolvable_da3f097b]] = None,
            ecs_parameters: typing.Optional[typing.Union["CfnRule.EcsParametersProperty", _IResolvable_da3f097b]] = None,
            http_parameters: typing.Optional[typing.Union["CfnRule.HttpParametersProperty", _IResolvable_da3f097b]] = None,
            input: typing.Optional[builtins.str] = None,
            input_path: typing.Optional[builtins.str] = None,
            input_transformer: typing.Optional[typing.Union["CfnRule.InputTransformerProperty", _IResolvable_da3f097b]] = None,
            kinesis_parameters: typing.Optional[typing.Union["CfnRule.KinesisParametersProperty", _IResolvable_da3f097b]] = None,
            redshift_data_parameters: typing.Optional[typing.Union["CfnRule.RedshiftDataParametersProperty", _IResolvable_da3f097b]] = None,
            retry_policy: typing.Optional[typing.Union["CfnRule.RetryPolicyProperty", _IResolvable_da3f097b]] = None,
            role_arn: typing.Optional[builtins.str] = None,
            run_command_parameters: typing.Optional[typing.Union["CfnRule.RunCommandParametersProperty", _IResolvable_da3f097b]] = None,
            sage_maker_pipeline_parameters: typing.Optional[typing.Union["CfnRule.SageMakerPipelineParametersProperty", _IResolvable_da3f097b]] = None,
            sqs_parameters: typing.Optional[typing.Union["CfnRule.SqsParametersProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Targets are the resources to be invoked when a rule is triggered.

            For a complete list of services and resources that can be set as a target, see `PutTargets <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutTargets.html>`_ .

            If you are setting the event bus of another account as the target, and that account granted permission to your account through an organization instead of directly by the account ID, then you must specify a ``RoleArn`` with proper permissions in the ``Target`` structure. For more information, see `Sending and Receiving Events Between AWS Accounts <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-cross-account-event-delivery.html>`_ in the *Amazon EventBridge User Guide* .

            :param arn: The Amazon Resource Name (ARN) of the target.
            :param id: The ID of the target within the specified rule. Use this ID to reference the target when updating the rule. We recommend using a memorable and unique string.
            :param batch_parameters: If the event target is an AWS Batch job, this contains the job definition, job name, and other parameters. For more information, see `Jobs <https://docs.aws.amazon.com/batch/latest/userguide/jobs.html>`_ in the *AWS Batch User Guide* .
            :param dead_letter_config: The ``DeadLetterConfig`` that defines the target queue to send dead-letter queue events to.
            :param ecs_parameters: Contains the Amazon ECS task definition and task count to be used, if the event target is an Amazon ECS task. For more information about Amazon ECS tasks, see `Task Definitions <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_defintions.html>`_ in the *Amazon EC2 Container Service Developer Guide* .
            :param http_parameters: Contains the HTTP parameters to use when the target is a API Gateway REST endpoint or EventBridge ApiDestination. If you specify an API Gateway REST API or EventBridge ApiDestination as a target, you can use this parameter to specify headers, path parameters, and query string keys/values as part of your target invoking request. If you're using ApiDestinations, the corresponding Connection can also have these values configured. In case of any conflicting keys, values from the Connection take precedence.
            :param input: Valid JSON text passed to the target. In this case, nothing from the event itself is passed to the target. For more information, see `The JavaScript Object Notation (JSON) Data Interchange Format <https://docs.aws.amazon.com/http://www.rfc-editor.org/rfc/rfc7159.txt>`_ .
            :param input_path: The value of the JSONPath that is used for extracting part of the matched event when passing it to the target. You must use JSON dot notation, not bracket notation. For more information about JSON paths, see `JSONPath <https://docs.aws.amazon.com/http://goessner.net/articles/JsonPath/>`_ .
            :param input_transformer: Settings to enable you to provide custom input to a target based on certain event data. You can extract one or more key-value pairs from the event and then use that data to send customized input to the target.
            :param kinesis_parameters: The custom parameter you can use to control the shard assignment, when the target is a Kinesis data stream. If you do not include this parameter, the default is to use the ``eventId`` as the partition key.
            :param redshift_data_parameters: Contains the Amazon Redshift Data API parameters to use when the target is a Amazon Redshift cluster. If you specify a Amazon Redshift Cluster as a Target, you can use this to specify parameters to invoke the Amazon Redshift Data API ExecuteStatement based on EventBridge events.
            :param retry_policy: The ``RetryPolicy`` object that contains the retry policy configuration to use for the dead-letter queue.
            :param role_arn: The Amazon Resource Name (ARN) of the IAM role to be used for this target when the rule is triggered. If one rule triggers multiple targets, you can use a different IAM role for each target.
            :param run_command_parameters: Parameters used when you are using the rule to invoke Amazon EC2 Run Command.
            :param sage_maker_pipeline_parameters: Contains the SageMaker Model Building Pipeline parameters to start execution of a SageMaker Model Building Pipeline. If you specify a SageMaker Model Building Pipeline as a target, you can use this to specify parameters to start a pipeline execution based on EventBridge events.
            :param sqs_parameters: Contains the message group ID to use when the target is a FIFO queue. If you specify an SQS FIFO queue as a target, the queue must have content-based deduplication enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_events as events
                
                target_property = events.CfnRule.TargetProperty(
                    arn="arn",
                    id="id",
                
                    # the properties below are optional
                    batch_parameters=events.CfnRule.BatchParametersProperty(
                        job_definition="jobDefinition",
                        job_name="jobName",
                
                        # the properties below are optional
                        array_properties=events.CfnRule.BatchArrayPropertiesProperty(
                            size=123
                        ),
                        retry_strategy=events.CfnRule.BatchRetryStrategyProperty(
                            attempts=123
                        )
                    ),
                    dead_letter_config=events.CfnRule.DeadLetterConfigProperty(
                        arn="arn"
                    ),
                    ecs_parameters=events.CfnRule.EcsParametersProperty(
                        task_definition_arn="taskDefinitionArn",
                
                        # the properties below are optional
                        capacity_provider_strategy=[events.CfnRule.CapacityProviderStrategyItemProperty(
                            capacity_provider="capacityProvider",
                
                            # the properties below are optional
                            base=123,
                            weight=123
                        )],
                        enable_ecs_managed_tags=False,
                        enable_execute_command=False,
                        group="group",
                        launch_type="launchType",
                        network_configuration=events.CfnRule.NetworkConfigurationProperty(
                            aws_vpc_configuration=events.CfnRule.AwsVpcConfigurationProperty(
                                subnets=["subnets"],
                
                                # the properties below are optional
                                assign_public_ip="assignPublicIp",
                                security_groups=["securityGroups"]
                            )
                        ),
                        placement_constraints=[events.CfnRule.PlacementConstraintProperty(
                            expression="expression",
                            type="type"
                        )],
                        placement_strategies=[events.CfnRule.PlacementStrategyProperty(
                            field="field",
                            type="type"
                        )],
                        platform_version="platformVersion",
                        propagate_tags="propagateTags",
                        reference_id="referenceId",
                        tag_list=[CfnTag(
                            key="key",
                            value="value"
                        )],
                        task_count=123
                    ),
                    http_parameters=events.CfnRule.HttpParametersProperty(
                        header_parameters={
                            "header_parameters_key": "headerParameters"
                        },
                        path_parameter_values=["pathParameterValues"],
                        query_string_parameters={
                            "query_string_parameters_key": "queryStringParameters"
                        }
                    ),
                    input="input",
                    input_path="inputPath",
                    input_transformer=events.CfnRule.InputTransformerProperty(
                        input_template="inputTemplate",
                
                        # the properties below are optional
                        input_paths_map={
                            "input_paths_map_key": "inputPathsMap"
                        }
                    ),
                    kinesis_parameters=events.CfnRule.KinesisParametersProperty(
                        partition_key_path="partitionKeyPath"
                    ),
                    redshift_data_parameters=events.CfnRule.RedshiftDataParametersProperty(
                        database="database",
                        sql="sql",
                
                        # the properties below are optional
                        db_user="dbUser",
                        secret_manager_arn="secretManagerArn",
                        statement_name="statementName",
                        with_event=False
                    ),
                    retry_policy=events.CfnRule.RetryPolicyProperty(
                        maximum_event_age_in_seconds=123,
                        maximum_retry_attempts=123
                    ),
                    role_arn="roleArn",
                    run_command_parameters=events.CfnRule.RunCommandParametersProperty(
                        run_command_targets=[events.CfnRule.RunCommandTargetProperty(
                            key="key",
                            values=["values"]
                        )]
                    ),
                    sage_maker_pipeline_parameters=events.CfnRule.SageMakerPipelineParametersProperty(
                        pipeline_parameter_list=[events.CfnRule.SageMakerPipelineParameterProperty(
                            name="name",
                            value="value"
                        )]
                    ),
                    sqs_parameters=events.CfnRule.SqsParametersProperty(
                        message_group_id="messageGroupId"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "arn": arn,
                "id": id,
            }
            if batch_parameters is not None:
                self._values["batch_parameters"] = batch_parameters
            if dead_letter_config is not None:
                self._values["dead_letter_config"] = dead_letter_config
            if ecs_parameters is not None:
                self._values["ecs_parameters"] = ecs_parameters
            if http_parameters is not None:
                self._values["http_parameters"] = http_parameters
            if input is not None:
                self._values["input"] = input
            if input_path is not None:
                self._values["input_path"] = input_path
            if input_transformer is not None:
                self._values["input_transformer"] = input_transformer
            if kinesis_parameters is not None:
                self._values["kinesis_parameters"] = kinesis_parameters
            if redshift_data_parameters is not None:
                self._values["redshift_data_parameters"] = redshift_data_parameters
            if retry_policy is not None:
                self._values["retry_policy"] = retry_policy
            if role_arn is not None:
                self._values["role_arn"] = role_arn
            if run_command_parameters is not None:
                self._values["run_command_parameters"] = run_command_parameters
            if sage_maker_pipeline_parameters is not None:
                self._values["sage_maker_pipeline_parameters"] = sage_maker_pipeline_parameters
            if sqs_parameters is not None:
                self._values["sqs_parameters"] = sqs_parameters

        @builtins.property
        def arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-arn
            '''
            result = self._values.get("arn")
            assert result is not None, "Required property 'arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def id(self) -> builtins.str:
            '''The ID of the target within the specified rule.

            Use this ID to reference the target when updating the rule. We recommend using a memorable and unique string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def batch_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.BatchParametersProperty", _IResolvable_da3f097b]]:
            '''If the event target is an AWS Batch job, this contains the job definition, job name, and other parameters.

            For more information, see `Jobs <https://docs.aws.amazon.com/batch/latest/userguide/jobs.html>`_ in the *AWS Batch User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-batchparameters
            '''
            result = self._values.get("batch_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnRule.BatchParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def dead_letter_config(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.DeadLetterConfigProperty", _IResolvable_da3f097b]]:
            '''The ``DeadLetterConfig`` that defines the target queue to send dead-letter queue events to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-deadletterconfig
            '''
            result = self._values.get("dead_letter_config")
            return typing.cast(typing.Optional[typing.Union["CfnRule.DeadLetterConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def ecs_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.EcsParametersProperty", _IResolvable_da3f097b]]:
            '''Contains the Amazon ECS task definition and task count to be used, if the event target is an Amazon ECS task.

            For more information about Amazon ECS tasks, see `Task Definitions <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_defintions.html>`_ in the *Amazon EC2 Container Service Developer Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-ecsparameters
            '''
            result = self._values.get("ecs_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnRule.EcsParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def http_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.HttpParametersProperty", _IResolvable_da3f097b]]:
            '''Contains the HTTP parameters to use when the target is a API Gateway REST endpoint or EventBridge ApiDestination.

            If you specify an API Gateway REST API or EventBridge ApiDestination as a target, you can use this parameter to specify headers, path parameters, and query string keys/values as part of your target invoking request. If you're using ApiDestinations, the corresponding Connection can also have these values configured. In case of any conflicting keys, values from the Connection take precedence.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-httpparameters
            '''
            result = self._values.get("http_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnRule.HttpParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def input(self) -> typing.Optional[builtins.str]:
            '''Valid JSON text passed to the target.

            In this case, nothing from the event itself is passed to the target. For more information, see `The JavaScript Object Notation (JSON) Data Interchange Format <https://docs.aws.amazon.com/http://www.rfc-editor.org/rfc/rfc7159.txt>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-input
            '''
            result = self._values.get("input")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def input_path(self) -> typing.Optional[builtins.str]:
            '''The value of the JSONPath that is used for extracting part of the matched event when passing it to the target.

            You must use JSON dot notation, not bracket notation. For more information about JSON paths, see `JSONPath <https://docs.aws.amazon.com/http://goessner.net/articles/JsonPath/>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-inputpath
            '''
            result = self._values.get("input_path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def input_transformer(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.InputTransformerProperty", _IResolvable_da3f097b]]:
            '''Settings to enable you to provide custom input to a target based on certain event data.

            You can extract one or more key-value pairs from the event and then use that data to send customized input to the target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-inputtransformer
            '''
            result = self._values.get("input_transformer")
            return typing.cast(typing.Optional[typing.Union["CfnRule.InputTransformerProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def kinesis_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.KinesisParametersProperty", _IResolvable_da3f097b]]:
            '''The custom parameter you can use to control the shard assignment, when the target is a Kinesis data stream.

            If you do not include this parameter, the default is to use the ``eventId`` as the partition key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-kinesisparameters
            '''
            result = self._values.get("kinesis_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnRule.KinesisParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def redshift_data_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.RedshiftDataParametersProperty", _IResolvable_da3f097b]]:
            '''Contains the Amazon Redshift Data API parameters to use when the target is a Amazon Redshift cluster.

            If you specify a Amazon Redshift Cluster as a Target, you can use this to specify parameters to invoke the Amazon Redshift Data API ExecuteStatement based on EventBridge events.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-redshiftdataparameters
            '''
            result = self._values.get("redshift_data_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnRule.RedshiftDataParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def retry_policy(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.RetryPolicyProperty", _IResolvable_da3f097b]]:
            '''The ``RetryPolicy`` object that contains the retry policy configuration to use for the dead-letter queue.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-retrypolicy
            '''
            result = self._values.get("retry_policy")
            return typing.cast(typing.Optional[typing.Union["CfnRule.RetryPolicyProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def role_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the IAM role to be used for this target when the rule is triggered.

            If one rule triggers multiple targets, you can use a different IAM role for each target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-rolearn
            '''
            result = self._values.get("role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def run_command_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.RunCommandParametersProperty", _IResolvable_da3f097b]]:
            '''Parameters used when you are using the rule to invoke Amazon EC2 Run Command.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-runcommandparameters
            '''
            result = self._values.get("run_command_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnRule.RunCommandParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sage_maker_pipeline_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.SageMakerPipelineParametersProperty", _IResolvable_da3f097b]]:
            '''Contains the SageMaker Model Building Pipeline parameters to start execution of a SageMaker Model Building Pipeline.

            If you specify a SageMaker Model Building Pipeline as a target, you can use this to specify parameters to start a pipeline execution based on EventBridge events.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-sagemakerpipelineparameters
            '''
            result = self._values.get("sage_maker_pipeline_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnRule.SageMakerPipelineParametersProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def sqs_parameters(
            self,
        ) -> typing.Optional[typing.Union["CfnRule.SqsParametersProperty", _IResolvable_da3f097b]]:
            '''Contains the message group ID to use when the target is a FIFO queue.

            If you specify an SQS FIFO queue as a target, the queue must have content-based deduplication enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-events-rule-target.html#cfn-events-rule-target-sqsparameters
            '''
            result = self._values.get("sqs_parameters")
            return typing.cast(typing.Optional[typing.Union["CfnRule.SqsParametersProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.CfnRuleProps",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "event_bus_name": "eventBusName",
        "event_pattern": "eventPattern",
        "name": "name",
        "role_arn": "roleArn",
        "schedule_expression": "scheduleExpression",
        "state": "state",
        "targets": "targets",
    },
)
class CfnRuleProps:
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        event_bus_name: typing.Optional[builtins.str] = None,
        event_pattern: typing.Any = None,
        name: typing.Optional[builtins.str] = None,
        role_arn: typing.Optional[builtins.str] = None,
        schedule_expression: typing.Optional[builtins.str] = None,
        state: typing.Optional[builtins.str] = None,
        targets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnRule.TargetProperty, _IResolvable_da3f097b]]]] = None,
    ) -> None:
        '''Properties for defining a ``CfnRule``.

        :param description: The description of the rule.
        :param event_bus_name: The name or ARN of the event bus associated with the rule. If you omit this, the default event bus is used.
        :param event_pattern: The event pattern of the rule. For more information, see `Events and Event Patterns <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-and-event-patterns.html>`_ in the *Amazon EventBridge User Guide* .
        :param name: The name of the rule.
        :param role_arn: The Amazon Resource Name (ARN) of the role that is used for target invocation. If you're setting an event bus in another account as the target and that account granted permission to your account through an organization instead of directly by the account ID, you must specify a ``RoleArn`` with proper permissions in the ``Target`` structure, instead of here in this parameter.
        :param schedule_expression: The scheduling expression. For example, "cron(0 20 * * ? *)", "rate(5 minutes)". For more information, see `Creating an Amazon EventBridge rule that runs on a schedule <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html>`_ .
        :param state: The state of the rule.
        :param targets: Adds the specified targets to the specified rule, or updates the targets if they are already associated with the rule. Targets are the resources that are invoked when a rule is triggered. .. epigraph:: Each rule can have up to five (5) targets associated with it at one time. You can configure the following as targets for Events: - `API destination <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html>`_ - `API Gateway <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-gateway-target.html>`_ - Batch job queue - CloudWatch group - CodeBuild project - CodePipeline - EC2 ``CreateSnapshot`` API call - EC2 Image Builder - EC2 ``RebootInstances`` API call - EC2 ``StopInstances`` API call - EC2 ``TerminateInstances`` API call - ECS task - `Event bus in a different account or Region <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-cross-account.html>`_ - `Event bus in the same account and Region <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-bus-to-bus.html>`_ - Firehose delivery stream - Glue workflow - `Incident Manager response plan <https://docs.aws.amazon.com//incident-manager/latest/userguide/incident-creation.html#incident-tracking-auto-eventbridge>`_ - Inspector assessment template - Kinesis stream - Lambda function - Redshift cluster - SageMaker Pipeline - SNS topic - SQS queue - Step Functions state machine - Systems Manager Automation - Systems Manager OpsItem - Systems Manager Run Command Creating rules with built-in targets is supported only in the AWS Management Console . The built-in targets are ``EC2 CreateSnapshot API call`` , ``EC2 RebootInstances API call`` , ``EC2 StopInstances API call`` , and ``EC2 TerminateInstances API call`` . For some target types, ``PutTargets`` provides target-specific parameters. If the target is a Kinesis data stream, you can optionally specify which shard the event goes to by using the ``KinesisParameters`` argument. To invoke a command on multiple EC2 instances with one rule, you can use the ``RunCommandParameters`` field. To be able to make API calls against the resources that you own, Amazon EventBridge needs the appropriate permissions. For AWS Lambda and Amazon SNS resources, EventBridge relies on resource-based policies. For EC2 instances, Kinesis Data Streams, AWS Step Functions state machines and API Gateway REST APIs, EventBridge relies on IAM roles that you specify in the ``RoleARN`` argument in ``PutTargets`` . For more information, see `Authentication and Access Control <https://docs.aws.amazon.com/eventbridge/latest/userguide/auth-and-access-control-eventbridge.html>`_ in the *Amazon EventBridge User Guide* . If another AWS account is in the same region and has granted you permission (using ``PutPermission`` ), you can send events to that account. Set that account's event bus as a target of the rules in your account. To send the matched events to the other account, specify that account's event bus as the ``Arn`` value when you run ``PutTargets`` . If your account sends events to another account, your account is charged for each sent event. Each event sent to another account is charged as a custom event. The account receiving the event is not charged. For more information, see `Amazon EventBridge Pricing <https://docs.aws.amazon.com/eventbridge/pricing/>`_ . .. epigraph:: ``Input`` , ``InputPath`` , and ``InputTransformer`` are not available with ``PutTarget`` if the target is an event bus of a different AWS account. If you are setting the event bus of another account as the target, and that account granted permission to your account through an organization instead of directly by the account ID, then you must specify a ``RoleArn`` with proper permissions in the ``Target`` structure. For more information, see `Sending and Receiving Events Between AWS Accounts <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-cross-account-event-delivery.html>`_ in the *Amazon EventBridge User Guide* . For more information about enabling cross-account events, see `PutPermission <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutPermission.html>`_ . *Input* , *InputPath* , and *InputTransformer* are mutually exclusive and optional parameters of a target. When a rule is triggered due to a matched event: - If none of the following arguments are specified for a target, then the entire event is passed to the target in JSON format (unless the target is Amazon EC2 Run Command or Amazon ECS task, in which case nothing from the event is passed to the target). - If *Input* is specified in the form of valid JSON, then the matched event is overridden with this constant. - If *InputPath* is specified in the form of JSONPath (for example, ``$.detail`` ), then only the part of the event specified in the path is passed to the target (for example, only the detail part of the event is passed). - If *InputTransformer* is specified, then one or more specified JSONPaths are extracted from the event and used as values in a template that you specify as the input to the target. When you specify ``InputPath`` or ``InputTransformer`` , you must use JSON dot notation, not bracket notation. When you add targets to a rule and the associated rule triggers soon after, new or updated targets might not be immediately invoked. Allow a short period of time for changes to take effect. This action can partially fail if too many requests are made at the same time. If that happens, ``FailedEntryCount`` is non-zero in the response and each entry in ``FailedEntries`` provides the ID of the failed target and the error code.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_events as events
            
            # event_pattern: Any
            
            cfn_rule_props = events.CfnRuleProps(
                description="description",
                event_bus_name="eventBusName",
                event_pattern=event_pattern,
                name="name",
                role_arn="roleArn",
                schedule_expression="scheduleExpression",
                state="state",
                targets=[events.CfnRule.TargetProperty(
                    arn="arn",
                    id="id",
            
                    # the properties below are optional
                    batch_parameters=events.CfnRule.BatchParametersProperty(
                        job_definition="jobDefinition",
                        job_name="jobName",
            
                        # the properties below are optional
                        array_properties=events.CfnRule.BatchArrayPropertiesProperty(
                            size=123
                        ),
                        retry_strategy=events.CfnRule.BatchRetryStrategyProperty(
                            attempts=123
                        )
                    ),
                    dead_letter_config=events.CfnRule.DeadLetterConfigProperty(
                        arn="arn"
                    ),
                    ecs_parameters=events.CfnRule.EcsParametersProperty(
                        task_definition_arn="taskDefinitionArn",
            
                        # the properties below are optional
                        capacity_provider_strategy=[events.CfnRule.CapacityProviderStrategyItemProperty(
                            capacity_provider="capacityProvider",
            
                            # the properties below are optional
                            base=123,
                            weight=123
                        )],
                        enable_ecs_managed_tags=False,
                        enable_execute_command=False,
                        group="group",
                        launch_type="launchType",
                        network_configuration=events.CfnRule.NetworkConfigurationProperty(
                            aws_vpc_configuration=events.CfnRule.AwsVpcConfigurationProperty(
                                subnets=["subnets"],
            
                                # the properties below are optional
                                assign_public_ip="assignPublicIp",
                                security_groups=["securityGroups"]
                            )
                        ),
                        placement_constraints=[events.CfnRule.PlacementConstraintProperty(
                            expression="expression",
                            type="type"
                        )],
                        placement_strategies=[events.CfnRule.PlacementStrategyProperty(
                            field="field",
                            type="type"
                        )],
                        platform_version="platformVersion",
                        propagate_tags="propagateTags",
                        reference_id="referenceId",
                        tag_list=[CfnTag(
                            key="key",
                            value="value"
                        )],
                        task_count=123
                    ),
                    http_parameters=events.CfnRule.HttpParametersProperty(
                        header_parameters={
                            "header_parameters_key": "headerParameters"
                        },
                        path_parameter_values=["pathParameterValues"],
                        query_string_parameters={
                            "query_string_parameters_key": "queryStringParameters"
                        }
                    ),
                    input="input",
                    input_path="inputPath",
                    input_transformer=events.CfnRule.InputTransformerProperty(
                        input_template="inputTemplate",
            
                        # the properties below are optional
                        input_paths_map={
                            "input_paths_map_key": "inputPathsMap"
                        }
                    ),
                    kinesis_parameters=events.CfnRule.KinesisParametersProperty(
                        partition_key_path="partitionKeyPath"
                    ),
                    redshift_data_parameters=events.CfnRule.RedshiftDataParametersProperty(
                        database="database",
                        sql="sql",
            
                        # the properties below are optional
                        db_user="dbUser",
                        secret_manager_arn="secretManagerArn",
                        statement_name="statementName",
                        with_event=False
                    ),
                    retry_policy=events.CfnRule.RetryPolicyProperty(
                        maximum_event_age_in_seconds=123,
                        maximum_retry_attempts=123
                    ),
                    role_arn="roleArn",
                    run_command_parameters=events.CfnRule.RunCommandParametersProperty(
                        run_command_targets=[events.CfnRule.RunCommandTargetProperty(
                            key="key",
                            values=["values"]
                        )]
                    ),
                    sage_maker_pipeline_parameters=events.CfnRule.SageMakerPipelineParametersProperty(
                        pipeline_parameter_list=[events.CfnRule.SageMakerPipelineParameterProperty(
                            name="name",
                            value="value"
                        )]
                    ),
                    sqs_parameters=events.CfnRule.SqsParametersProperty(
                        message_group_id="messageGroupId"
                    )
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if event_bus_name is not None:
            self._values["event_bus_name"] = event_bus_name
        if event_pattern is not None:
            self._values["event_pattern"] = event_pattern
        if name is not None:
            self._values["name"] = name
        if role_arn is not None:
            self._values["role_arn"] = role_arn
        if schedule_expression is not None:
            self._values["schedule_expression"] = schedule_expression
        if state is not None:
            self._values["state"] = state
        if targets is not None:
            self._values["targets"] = targets

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The description of the rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def event_bus_name(self) -> typing.Optional[builtins.str]:
        '''The name or ARN of the event bus associated with the rule.

        If you omit this, the default event bus is used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-eventbusname
        '''
        result = self._values.get("event_bus_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def event_pattern(self) -> typing.Any:
        '''The event pattern of the rule.

        For more information, see `Events and Event Patterns <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-and-event-patterns.html>`_ in the *Amazon EventBridge User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-eventpattern
        '''
        result = self._values.get("event_pattern")
        return typing.cast(typing.Any, result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the role that is used for target invocation.

        If you're setting an event bus in another account as the target and that account granted permission to your account through an organization instead of directly by the account ID, you must specify a ``RoleArn`` with proper permissions in the ``Target`` structure, instead of here in this parameter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-rolearn
        '''
        result = self._values.get("role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def schedule_expression(self) -> typing.Optional[builtins.str]:
        '''The scheduling expression.

        For example, "cron(0 20 * * ? *)", "rate(5 minutes)". For more information, see `Creating an Amazon EventBridge rule that runs on a schedule <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-scheduleexpression
        '''
        result = self._values.get("schedule_expression")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def state(self) -> typing.Optional[builtins.str]:
        '''The state of the rule.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-state
        '''
        result = self._values.get("state")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def targets(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRule.TargetProperty, _IResolvable_da3f097b]]]]:
        '''Adds the specified targets to the specified rule, or updates the targets if they are already associated with the rule.

        Targets are the resources that are invoked when a rule is triggered.
        .. epigraph::

           Each rule can have up to five (5) targets associated with it at one time.

        You can configure the following as targets for Events:

        - `API destination <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html>`_
        - `API Gateway <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-gateway-target.html>`_
        - Batch job queue
        - CloudWatch group
        - CodeBuild project
        - CodePipeline
        - EC2 ``CreateSnapshot`` API call
        - EC2 Image Builder
        - EC2 ``RebootInstances`` API call
        - EC2 ``StopInstances`` API call
        - EC2 ``TerminateInstances`` API call
        - ECS task
        - `Event bus in a different account or Region <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-cross-account.html>`_
        - `Event bus in the same account and Region <https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-bus-to-bus.html>`_
        - Firehose delivery stream
        - Glue workflow
        - `Incident Manager response plan <https://docs.aws.amazon.com//incident-manager/latest/userguide/incident-creation.html#incident-tracking-auto-eventbridge>`_
        - Inspector assessment template
        - Kinesis stream
        - Lambda function
        - Redshift cluster
        - SageMaker Pipeline
        - SNS topic
        - SQS queue
        - Step Functions state machine
        - Systems Manager Automation
        - Systems Manager OpsItem
        - Systems Manager Run Command

        Creating rules with built-in targets is supported only in the AWS Management Console . The built-in targets are ``EC2 CreateSnapshot API call`` , ``EC2 RebootInstances API call`` , ``EC2 StopInstances API call`` , and ``EC2 TerminateInstances API call`` .

        For some target types, ``PutTargets`` provides target-specific parameters. If the target is a Kinesis data stream, you can optionally specify which shard the event goes to by using the ``KinesisParameters`` argument. To invoke a command on multiple EC2 instances with one rule, you can use the ``RunCommandParameters`` field.

        To be able to make API calls against the resources that you own, Amazon EventBridge needs the appropriate permissions. For AWS Lambda and Amazon SNS resources, EventBridge relies on resource-based policies. For EC2 instances, Kinesis Data Streams, AWS Step Functions state machines and API Gateway REST APIs, EventBridge relies on IAM roles that you specify in the ``RoleARN`` argument in ``PutTargets`` . For more information, see `Authentication and Access Control <https://docs.aws.amazon.com/eventbridge/latest/userguide/auth-and-access-control-eventbridge.html>`_ in the *Amazon EventBridge User Guide* .

        If another AWS account is in the same region and has granted you permission (using ``PutPermission`` ), you can send events to that account. Set that account's event bus as a target of the rules in your account. To send the matched events to the other account, specify that account's event bus as the ``Arn`` value when you run ``PutTargets`` . If your account sends events to another account, your account is charged for each sent event. Each event sent to another account is charged as a custom event. The account receiving the event is not charged. For more information, see `Amazon EventBridge Pricing <https://docs.aws.amazon.com/eventbridge/pricing/>`_ .
        .. epigraph::

           ``Input`` , ``InputPath`` , and ``InputTransformer`` are not available with ``PutTarget`` if the target is an event bus of a different AWS account.

        If you are setting the event bus of another account as the target, and that account granted permission to your account through an organization instead of directly by the account ID, then you must specify a ``RoleArn`` with proper permissions in the ``Target`` structure. For more information, see `Sending and Receiving Events Between AWS Accounts <https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-cross-account-event-delivery.html>`_ in the *Amazon EventBridge User Guide* .

        For more information about enabling cross-account events, see `PutPermission <https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutPermission.html>`_ .

        *Input* , *InputPath* , and *InputTransformer* are mutually exclusive and optional parameters of a target. When a rule is triggered due to a matched event:

        - If none of the following arguments are specified for a target, then the entire event is passed to the target in JSON format (unless the target is Amazon EC2 Run Command or Amazon ECS task, in which case nothing from the event is passed to the target).
        - If *Input* is specified in the form of valid JSON, then the matched event is overridden with this constant.
        - If *InputPath* is specified in the form of JSONPath (for example, ``$.detail`` ), then only the part of the event specified in the path is passed to the target (for example, only the detail part of the event is passed).
        - If *InputTransformer* is specified, then one or more specified JSONPaths are extracted from the event and used as values in a template that you specify as the input to the target.

        When you specify ``InputPath`` or ``InputTransformer`` , you must use JSON dot notation, not bracket notation.

        When you add targets to a rule and the associated rule triggers soon after, new or updated targets might not be immediately invoked. Allow a short period of time for changes to take effect.

        This action can partially fail if too many requests are made at the same time. If that happens, ``FailedEntryCount`` is non-zero in the response and each entry in ``FailedEntries`` provides the ID of the failed target and the error code.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-rule.html#cfn-events-rule-targets
        '''
        result = self._values.get("targets")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnRule.TargetProperty, _IResolvable_da3f097b]]]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnRuleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.ConnectionAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "connection_arn": "connectionArn",
        "connection_name": "connectionName",
        "connection_secret_arn": "connectionSecretArn",
    },
)
class ConnectionAttributes:
    def __init__(
        self,
        *,
        connection_arn: builtins.str,
        connection_name: builtins.str,
        connection_secret_arn: builtins.str,
    ) -> None:
        '''Interface with properties necessary to import a reusable Connection.

        :param connection_arn: The ARN of the connection created.
        :param connection_name: The Name for the connection.
        :param connection_secret_arn: The ARN for the secret created for the connection.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_events as events
            
            connection_attributes = events.ConnectionAttributes(
                connection_arn="connectionArn",
                connection_name="connectionName",
                connection_secret_arn="connectionSecretArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "connection_arn": connection_arn,
            "connection_name": connection_name,
            "connection_secret_arn": connection_secret_arn,
        }

    @builtins.property
    def connection_arn(self) -> builtins.str:
        '''The ARN of the connection created.'''
        result = self._values.get("connection_arn")
        assert result is not None, "Required property 'connection_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def connection_name(self) -> builtins.str:
        '''The Name for the connection.'''
        result = self._values.get("connection_name")
        assert result is not None, "Required property 'connection_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def connection_secret_arn(self) -> builtins.str:
        '''The ARN for the secret created for the connection.'''
        result = self._values.get("connection_secret_arn")
        assert result is not None, "Required property 'connection_secret_arn' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ConnectionAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.ConnectionProps",
    jsii_struct_bases=[],
    name_mapping={
        "authorization": "authorization",
        "body_parameters": "bodyParameters",
        "connection_name": "connectionName",
        "description": "description",
        "header_parameters": "headerParameters",
        "query_string_parameters": "queryStringParameters",
    },
)
class ConnectionProps:
    def __init__(
        self,
        *,
        authorization: Authorization,
        body_parameters: typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]] = None,
        connection_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        header_parameters: typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]] = None,
        query_string_parameters: typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]] = None,
    ) -> None:
        '''An API Destination Connection.

        A connection defines the authorization type and credentials to use for authorization with an API destination HTTP endpoint.

        :param authorization: The authorization type for the connection.
        :param body_parameters: Additional string parameters to add to the invocation bodies. Default: - No additional parameters
        :param connection_name: The name of the connection. Default: - A name is automatically generated
        :param description: The name of the connection. Default: - none
        :param header_parameters: Additional string parameters to add to the invocation headers. Default: - No additional parameters
        :param query_string_parameters: Additional string parameters to add to the invocation query strings. Default: - No additional parameters

        :exampleMetadata: infused

        Example::

            connection = events.Connection(self, "Connection",
                authorization=events.Authorization.api_key("x-api-key", SecretValue.secrets_manager("ApiSecretName")),
                description="Connection with API Key x-api-key"
            )
            
            destination = events.ApiDestination(self, "Destination",
                connection=connection,
                endpoint="https://example.com",
                description="Calling example.com with API key x-api-key"
            )
            
            rule = events.Rule(self, "Rule",
                schedule=events.Schedule.rate(cdk.Duration.minutes(1)),
                targets=[targets.ApiDestination(destination)]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "authorization": authorization,
        }
        if body_parameters is not None:
            self._values["body_parameters"] = body_parameters
        if connection_name is not None:
            self._values["connection_name"] = connection_name
        if description is not None:
            self._values["description"] = description
        if header_parameters is not None:
            self._values["header_parameters"] = header_parameters
        if query_string_parameters is not None:
            self._values["query_string_parameters"] = query_string_parameters

    @builtins.property
    def authorization(self) -> Authorization:
        '''The authorization type for the connection.'''
        result = self._values.get("authorization")
        assert result is not None, "Required property 'authorization' is missing"
        return typing.cast(Authorization, result)

    @builtins.property
    def body_parameters(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]]:
        '''Additional string parameters to add to the invocation bodies.

        :default: - No additional parameters
        '''
        result = self._values.get("body_parameters")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]], result)

    @builtins.property
    def connection_name(self) -> typing.Optional[builtins.str]:
        '''The name of the connection.

        :default: - A name is automatically generated
        '''
        result = self._values.get("connection_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''The name of the connection.

        :default: - none
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def header_parameters(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]]:
        '''Additional string parameters to add to the invocation headers.

        :default: - No additional parameters
        '''
        result = self._values.get("header_parameters")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]], result)

    @builtins.property
    def query_string_parameters(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]]:
        '''Additional string parameters to add to the invocation query strings.

        :default: - No additional parameters
        '''
        result = self._values.get("query_string_parameters")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, "HttpParameter"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ConnectionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.CronOptions",
    jsii_struct_bases=[],
    name_mapping={
        "day": "day",
        "hour": "hour",
        "minute": "minute",
        "month": "month",
        "week_day": "weekDay",
        "year": "year",
    },
)
class CronOptions:
    def __init__(
        self,
        *,
        day: typing.Optional[builtins.str] = None,
        hour: typing.Optional[builtins.str] = None,
        minute: typing.Optional[builtins.str] = None,
        month: typing.Optional[builtins.str] = None,
        week_day: typing.Optional[builtins.str] = None,
        year: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Options to configure a cron expression.

        All fields are strings so you can use complex expressions. Absence of
        a field implies '*' or '?', whichever one is appropriate.

        :param day: The day of the month to run this rule at. Default: - Every day of the month
        :param hour: The hour to run this rule at. Default: - Every hour
        :param minute: The minute to run this rule at. Default: - Every minute
        :param month: The month to run this rule at. Default: - Every month
        :param week_day: The day of the week to run this rule at. Default: - Any day of the week
        :param year: The year to run this rule at. Default: - Every year

        :see: https://docs.aws.amazon.com/eventbridge/latest/userguide/scheduled-events.html#cron-expressions
        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_events as events
            import aws_cdk.aws_events_targets as targets
            
            # fn: lambda.Function
            
            rule = events.Rule(self, "Schedule Rule",
                schedule=events.Schedule.cron(minute="0", hour="4")
            )
            rule.add_target(targets.LambdaFunction(fn))
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if day is not None:
            self._values["day"] = day
        if hour is not None:
            self._values["hour"] = hour
        if minute is not None:
            self._values["minute"] = minute
        if month is not None:
            self._values["month"] = month
        if week_day is not None:
            self._values["week_day"] = week_day
        if year is not None:
            self._values["year"] = year

    @builtins.property
    def day(self) -> typing.Optional[builtins.str]:
        '''The day of the month to run this rule at.

        :default: - Every day of the month
        '''
        result = self._values.get("day")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def hour(self) -> typing.Optional[builtins.str]:
        '''The hour to run this rule at.

        :default: - Every hour
        '''
        result = self._values.get("hour")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def minute(self) -> typing.Optional[builtins.str]:
        '''The minute to run this rule at.

        :default: - Every minute
        '''
        result = self._values.get("minute")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def month(self) -> typing.Optional[builtins.str]:
        '''The month to run this rule at.

        :default: - Every month
        '''
        result = self._values.get("month")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def week_day(self) -> typing.Optional[builtins.str]:
        '''The day of the week to run this rule at.

        :default: - Any day of the week
        '''
        result = self._values.get("week_day")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def year(self) -> typing.Optional[builtins.str]:
        '''The year to run this rule at.

        :default: - Every year
        '''
        result = self._values.get("year")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CronOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.EventBusAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "event_bus_arn": "eventBusArn",
        "event_bus_name": "eventBusName",
        "event_bus_policy": "eventBusPolicy",
        "event_source_name": "eventSourceName",
    },
)
class EventBusAttributes:
    def __init__(
        self,
        *,
        event_bus_arn: builtins.str,
        event_bus_name: builtins.str,
        event_bus_policy: builtins.str,
        event_source_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Interface with properties necessary to import a reusable EventBus.

        :param event_bus_arn: The ARN of this event bus resource.
        :param event_bus_name: The physical ID of this event bus resource.
        :param event_bus_policy: The JSON policy of this event bus resource.
        :param event_source_name: The partner event source to associate with this event bus resource. Default: - no partner event source

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_events as events
            
            event_bus_attributes = events.EventBusAttributes(
                event_bus_arn="eventBusArn",
                event_bus_name="eventBusName",
                event_bus_policy="eventBusPolicy",
            
                # the properties below are optional
                event_source_name="eventSourceName"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "event_bus_arn": event_bus_arn,
            "event_bus_name": event_bus_name,
            "event_bus_policy": event_bus_policy,
        }
        if event_source_name is not None:
            self._values["event_source_name"] = event_source_name

    @builtins.property
    def event_bus_arn(self) -> builtins.str:
        '''The ARN of this event bus resource.

        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#Arn-fn::getatt
        '''
        result = self._values.get("event_bus_arn")
        assert result is not None, "Required property 'event_bus_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def event_bus_name(self) -> builtins.str:
        '''The physical ID of this event bus resource.

        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-name
        '''
        result = self._values.get("event_bus_name")
        assert result is not None, "Required property 'event_bus_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def event_bus_policy(self) -> builtins.str:
        '''The JSON policy of this event bus resource.

        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#Policy-fn::getatt
        '''
        result = self._values.get("event_bus_policy")
        assert result is not None, "Required property 'event_bus_policy' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def event_source_name(self) -> typing.Optional[builtins.str]:
        '''The partner event source to associate with this event bus resource.

        :default: - no partner event source

        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-eventsourcename
        '''
        result = self._values.get("event_source_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EventBusAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.EventBusProps",
    jsii_struct_bases=[],
    name_mapping={
        "event_bus_name": "eventBusName",
        "event_source_name": "eventSourceName",
    },
)
class EventBusProps:
    def __init__(
        self,
        *,
        event_bus_name: typing.Optional[builtins.str] = None,
        event_source_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties to define an event bus.

        :param event_bus_name: The name of the event bus you are creating Note: If 'eventSourceName' is passed in, you cannot set this. Default: - automatically generated name
        :param event_source_name: The partner event source to associate with this event bus resource Note: If 'eventBusName' is passed in, you cannot set this. Default: - no partner event source

        :exampleMetadata: infused

        Example::

            bus = events.EventBus(self, "bus",
                event_bus_name="MyCustomEventBus"
            )
            
            bus.archive("MyArchive",
                archive_name="MyCustomEventBusArchive",
                description="MyCustomerEventBus Archive",
                event_pattern=events.EventPattern(
                    account=[Stack.of(self).account]
                ),
                retention=Duration.days(365)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if event_bus_name is not None:
            self._values["event_bus_name"] = event_bus_name
        if event_source_name is not None:
            self._values["event_source_name"] = event_source_name

    @builtins.property
    def event_bus_name(self) -> typing.Optional[builtins.str]:
        '''The name of the event bus you are creating Note: If 'eventSourceName' is passed in, you cannot set this.

        :default: - automatically generated name

        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-name
        '''
        result = self._values.get("event_bus_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def event_source_name(self) -> typing.Optional[builtins.str]:
        '''The partner event source to associate with this event bus resource Note: If 'eventBusName' is passed in, you cannot set this.

        :default: - no partner event source

        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-eventsourcename
        '''
        result = self._values.get("event_source_name")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EventBusProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IResolvable_da3f097b)
class EventField(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.EventField",
):
    '''Represents a field in the event pattern.'''

    @jsii.member(jsii_name="fromPath") # type: ignore[misc]
    @builtins.classmethod
    def from_path(cls, path: builtins.str) -> builtins.str:
        '''Extract a custom JSON path from the event.

        :param path: -
        '''
        return typing.cast(builtins.str, jsii.sinvoke(cls, "fromPath", [path]))

    @jsii.member(jsii_name="resolve")
    def resolve(self, _ctx: _IResolveContext_b2df1921) -> typing.Any:
        '''Produce the Token's value at resolution time.

        :param _ctx: -
        '''
        return typing.cast(typing.Any, jsii.invoke(self, "resolve", [_ctx]))

    @jsii.member(jsii_name="toJSON")
    def to_json(self) -> builtins.str:
        '''Convert the path to the field in the event pattern to JSON.'''
        return typing.cast(builtins.str, jsii.invoke(self, "toJSON", []))

    @jsii.member(jsii_name="toString")
    def to_string(self) -> builtins.str:
        '''Return a string representation of this resolvable object.

        Returns a reversible string representation.
        '''
        return typing.cast(builtins.str, jsii.invoke(self, "toString", []))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="account")
    def account(cls) -> builtins.str:
        '''Extract the account from the event.'''
        return typing.cast(builtins.str, jsii.sget(cls, "account"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="detailType")
    def detail_type(cls) -> builtins.str:
        '''Extract the detail type from the event.'''
        return typing.cast(builtins.str, jsii.sget(cls, "detailType"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="eventId")
    def event_id(cls) -> builtins.str:
        '''Extract the event ID from the event.'''
        return typing.cast(builtins.str, jsii.sget(cls, "eventId"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="region")
    def region(cls) -> builtins.str:
        '''Extract the region from the event.'''
        return typing.cast(builtins.str, jsii.sget(cls, "region"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="source")
    def source(cls) -> builtins.str:
        '''Extract the source from the event.'''
        return typing.cast(builtins.str, jsii.sget(cls, "source"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="time")
    def time(cls) -> builtins.str:
        '''Extract the time from the event.'''
        return typing.cast(builtins.str, jsii.sget(cls, "time"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="creationStack")
    def creation_stack(self) -> typing.List[builtins.str]:
        '''The creation stack of this resolvable which will be appended to errors thrown during resolution.

        This may return an array with a single informational element indicating how
        to get this property populated, if it was skipped for performance reasons.
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "creationStack"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="displayHint")
    def display_hint(self) -> builtins.str:
        '''Human readable display hint about the event pattern.'''
        return typing.cast(builtins.str, jsii.get(self, "displayHint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="path")
    def path(self) -> builtins.str:
        '''the path to a field in the event pattern.'''
        return typing.cast(builtins.str, jsii.get(self, "path"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.EventPattern",
    jsii_struct_bases=[],
    name_mapping={
        "account": "account",
        "detail": "detail",
        "detail_type": "detailType",
        "id": "id",
        "region": "region",
        "resources": "resources",
        "source": "source",
        "time": "time",
        "version": "version",
    },
)
class EventPattern:
    def __init__(
        self,
        *,
        account: typing.Optional[typing.Sequence[builtins.str]] = None,
        detail: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        detail_type: typing.Optional[typing.Sequence[builtins.str]] = None,
        id: typing.Optional[typing.Sequence[builtins.str]] = None,
        region: typing.Optional[typing.Sequence[builtins.str]] = None,
        resources: typing.Optional[typing.Sequence[builtins.str]] = None,
        source: typing.Optional[typing.Sequence[builtins.str]] = None,
        time: typing.Optional[typing.Sequence[builtins.str]] = None,
        version: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Events in Amazon CloudWatch Events are represented as JSON objects. For more information about JSON objects, see RFC 7159.

        **Important**: this class can only be used with a ``Rule`` class. In particular,
        do not use it with ``CfnRule`` class: your pattern will not be rendered
        correctly. In a ``CfnRule`` class, write the pattern as you normally would when
        directly writing CloudFormation.

        Rules use event patterns to select events and route them to targets. A
        pattern either matches an event or it doesn't. Event patterns are represented
        as JSON objects with a structure that is similar to that of events.

        It is important to remember the following about event pattern matching:

        - For a pattern to match an event, the event must contain all the field names
          listed in the pattern. The field names must appear in the event with the
          same nesting structure.
        - Other fields of the event not mentioned in the pattern are ignored;
          effectively, there is a ``"*": "*"`` wildcard for fields not mentioned.
        - The matching is exact (character-by-character), without case-folding or any
          other string normalization.
        - The values being matched follow JSON rules: Strings enclosed in quotes,
          numbers, and the unquoted keywords true, false, and null.
        - Number matching is at the string representation level. For example, 300,
          300.0, and 3.0e2 are not considered equal.

        :param account: The 12-digit number identifying an AWS account. Default: - No filtering on account
        :param detail: A JSON object, whose content is at the discretion of the service originating the event. Default: - No filtering on detail
        :param detail_type: Identifies, in combination with the source field, the fields and values that appear in the detail field. Represents the "detail-type" event field. Default: - No filtering on detail type
        :param id: A unique value is generated for every event. This can be helpful in tracing events as they move through rules to targets, and are processed. Default: - No filtering on id
        :param region: Identifies the AWS region where the event originated. Default: - No filtering on region
        :param resources: This JSON array contains ARNs that identify resources that are involved in the event. Inclusion of these ARNs is at the discretion of the service. For example, Amazon EC2 instance state-changes include Amazon EC2 instance ARNs, Auto Scaling events include ARNs for both instances and Auto Scaling groups, but API calls with AWS CloudTrail do not include resource ARNs. Default: - No filtering on resource
        :param source: Identifies the service that sourced the event. All events sourced from within AWS begin with "aws." Customer-generated events can have any value here, as long as it doesn't begin with "aws." We recommend the use of Java package-name style reverse domain-name strings. To find the correct value for source for an AWS service, see the table in AWS Service Namespaces. For example, the source value for Amazon CloudFront is aws.cloudfront. Default: - No filtering on source
        :param time: The event timestamp, which can be specified by the service originating the event. If the event spans a time interval, the service might choose to report the start time, so this value can be noticeably before the time the event is actually received. Default: - No filtering on time
        :param version: By default, this is set to 0 (zero) in all events. Default: - No filtering on version

        :see: https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/CloudWatchEventsandEventPatterns.html
        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_lambda as lambda_
            
            
            fn = lambda_.Function(self, "MyFunc",
                runtime=lambda_.Runtime.NODEJS_12_X,
                handler="index.handler",
                code=lambda_.Code.from_inline("exports.handler = handler.toString()")
            )
            
            rule = events.Rule(self, "rule",
                event_pattern=events.EventPattern(
                    source=["aws.ec2"]
                )
            )
            
            queue = sqs.Queue(self, "Queue")
            
            rule.add_target(targets.LambdaFunction(fn,
                dead_letter_queue=queue,  # Optional: add a dead letter queue
                max_event_age=cdk.Duration.hours(2),  # Optional: set the maxEventAge retry policy
                retry_attempts=2
            ))
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if account is not None:
            self._values["account"] = account
        if detail is not None:
            self._values["detail"] = detail
        if detail_type is not None:
            self._values["detail_type"] = detail_type
        if id is not None:
            self._values["id"] = id
        if region is not None:
            self._values["region"] = region
        if resources is not None:
            self._values["resources"] = resources
        if source is not None:
            self._values["source"] = source
        if time is not None:
            self._values["time"] = time
        if version is not None:
            self._values["version"] = version

    @builtins.property
    def account(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The 12-digit number identifying an AWS account.

        :default: - No filtering on account
        '''
        result = self._values.get("account")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def detail(self) -> typing.Optional[typing.Mapping[builtins.str, typing.Any]]:
        '''A JSON object, whose content is at the discretion of the service originating the event.

        :default: - No filtering on detail
        '''
        result = self._values.get("detail")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, typing.Any]], result)

    @builtins.property
    def detail_type(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Identifies, in combination with the source field, the fields and values that appear in the detail field.

        Represents the "detail-type" event field.

        :default: - No filtering on detail type
        '''
        result = self._values.get("detail_type")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def id(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A unique value is generated for every event.

        This can be helpful in
        tracing events as they move through rules to targets, and are processed.

        :default: - No filtering on id
        '''
        result = self._values.get("id")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def region(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Identifies the AWS region where the event originated.

        :default: - No filtering on region
        '''
        result = self._values.get("region")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def resources(self) -> typing.Optional[typing.List[builtins.str]]:
        '''This JSON array contains ARNs that identify resources that are involved in the event.

        Inclusion of these ARNs is at the discretion of the
        service.

        For example, Amazon EC2 instance state-changes include Amazon EC2
        instance ARNs, Auto Scaling events include ARNs for both instances and
        Auto Scaling groups, but API calls with AWS CloudTrail do not include
        resource ARNs.

        :default: - No filtering on resource
        '''
        result = self._values.get("resources")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def source(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Identifies the service that sourced the event.

        All events sourced from
        within AWS begin with "aws." Customer-generated events can have any value
        here, as long as it doesn't begin with "aws." We recommend the use of
        Java package-name style reverse domain-name strings.

        To find the correct value for source for an AWS service, see the table in
        AWS Service Namespaces. For example, the source value for Amazon
        CloudFront is aws.cloudfront.

        :default: - No filtering on source

        :see: http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#genref-aws-service-namespaces
        '''
        result = self._values.get("source")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def time(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The event timestamp, which can be specified by the service originating the event.

        If the event spans a time interval, the service might choose
        to report the start time, so this value can be noticeably before the time
        the event is actually received.

        :default: - No filtering on time
        '''
        result = self._values.get("time")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def version(self) -> typing.Optional[typing.List[builtins.str]]:
        '''By default, this is set to 0 (zero) in all events.

        :default: - No filtering on version
        '''
        result = self._values.get("version")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EventPattern(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_events.HttpMethod")
class HttpMethod(enum.Enum):
    '''Supported HTTP operations.'''

    POST = "POST"
    '''POST.'''
    GET = "GET"
    '''GET.'''
    HEAD = "HEAD"
    '''HEAD.'''
    OPTIONS = "OPTIONS"
    '''OPTIONS.'''
    PUT = "PUT"
    '''PUT.'''
    PATCH = "PATCH"
    '''PATCH.'''
    DELETE = "DELETE"
    '''DELETE.'''


class HttpParameter(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_events.HttpParameter",
):
    '''An additional HTTP parameter to send along with the OAuth request.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_events as events
        
        # secret_value: cdk.SecretValue
        
        http_parameter = events.HttpParameter.from_secret(secret_value)
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="fromSecret") # type: ignore[misc]
    @builtins.classmethod
    def from_secret(cls, value: _SecretValue_3dd0ddae) -> "HttpParameter":
        '''Make an OAuthParameter from a secret.

        :param value: -
        '''
        return typing.cast("HttpParameter", jsii.sinvoke(cls, "fromSecret", [value]))

    @jsii.member(jsii_name="fromString") # type: ignore[misc]
    @builtins.classmethod
    def from_string(cls, value: builtins.str) -> "HttpParameter":
        '''Make an OAuthParameter from a string value.

        The value is not treated as a secret.

        :param value: -
        '''
        return typing.cast("HttpParameter", jsii.sinvoke(cls, "fromString", [value]))


class _HttpParameterProxy(HttpParameter):
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, HttpParameter).__jsii_proxy_class__ = lambda : _HttpParameterProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_events.IApiDestination")
class IApiDestination(_IResource_c80c4260, typing_extensions.Protocol):
    '''Interface for API Destinations.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="apiDestinationArn")
    def api_destination_arn(self) -> builtins.str:
        '''The ARN of the Api Destination created.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="apiDestinationName")
    def api_destination_name(self) -> builtins.str:
        '''The Name of the Api Destination created.

        :attribute: true
        '''
        ...


class _IApiDestinationProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Interface for API Destinations.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_events.IApiDestination"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="apiDestinationArn")
    def api_destination_arn(self) -> builtins.str:
        '''The ARN of the Api Destination created.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "apiDestinationArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="apiDestinationName")
    def api_destination_name(self) -> builtins.str:
        '''The Name of the Api Destination created.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "apiDestinationName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IApiDestination).__jsii_proxy_class__ = lambda : _IApiDestinationProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_events.IConnection")
class IConnection(_IResource_c80c4260, typing_extensions.Protocol):
    '''Interface for EventBus Connections.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionArn")
    def connection_arn(self) -> builtins.str:
        '''The ARN of the connection created.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionName")
    def connection_name(self) -> builtins.str:
        '''The Name for the connection.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionSecretArn")
    def connection_secret_arn(self) -> builtins.str:
        '''The ARN for the secret created for the connection.

        :attribute: true
        '''
        ...


class _IConnectionProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Interface for EventBus Connections.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_events.IConnection"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionArn")
    def connection_arn(self) -> builtins.str:
        '''The ARN of the connection created.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "connectionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionName")
    def connection_name(self) -> builtins.str:
        '''The Name for the connection.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "connectionName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionSecretArn")
    def connection_secret_arn(self) -> builtins.str:
        '''The ARN for the secret created for the connection.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "connectionSecretArn"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IConnection).__jsii_proxy_class__ = lambda : _IConnectionProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_events.IEventBus")
class IEventBus(_IResource_c80c4260, typing_extensions.Protocol):
    '''Interface which all EventBus based classes MUST implement.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBusArn")
    def event_bus_arn(self) -> builtins.str:
        '''The ARN of this event bus resource.

        :attribute: true
        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#Arn-fn::getatt
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBusName")
    def event_bus_name(self) -> builtins.str:
        '''The physical ID of this event bus resource.

        :attribute: true
        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-name
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBusPolicy")
    def event_bus_policy(self) -> builtins.str:
        '''The JSON policy of this event bus resource.

        :attribute: true
        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#Policy-fn::getatt
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventSourceName")
    def event_source_name(self) -> typing.Optional[builtins.str]:
        '''The partner event source to associate with this event bus resource.

        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-eventsourcename
        '''
        ...

    @jsii.member(jsii_name="archive")
    def archive(
        self,
        id: builtins.str,
        *,
        event_pattern: EventPattern,
        archive_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        retention: typing.Optional[_Duration_4839e8c3] = None,
    ) -> Archive:
        '''Create an EventBridge archive to send events to.

        When you create an archive, incoming events might not immediately start being sent to the archive.
        Allow a short period of time for changes to take effect.

        :param id: -
        :param event_pattern: An event pattern to use to filter events sent to the archive.
        :param archive_name: The name of the archive. Default: - Automatically generated
        :param description: A description for the archive. Default: - none
        :param retention: The number of days to retain events for. Default value is 0. If set to 0, events are retained indefinitely. Default: - Infinite
        '''
        ...

    @jsii.member(jsii_name="grantPutEventsTo")
    def grant_put_events_to(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grants an IAM Principal to send custom events to the eventBus so that they can be matched to rules.

        :param grantee: The principal (no-op if undefined).
        '''
        ...


class _IEventBusProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Interface which all EventBus based classes MUST implement.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_events.IEventBus"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBusArn")
    def event_bus_arn(self) -> builtins.str:
        '''The ARN of this event bus resource.

        :attribute: true
        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#Arn-fn::getatt
        '''
        return typing.cast(builtins.str, jsii.get(self, "eventBusArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBusName")
    def event_bus_name(self) -> builtins.str:
        '''The physical ID of this event bus resource.

        :attribute: true
        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-name
        '''
        return typing.cast(builtins.str, jsii.get(self, "eventBusName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBusPolicy")
    def event_bus_policy(self) -> builtins.str:
        '''The JSON policy of this event bus resource.

        :attribute: true
        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#Policy-fn::getatt
        '''
        return typing.cast(builtins.str, jsii.get(self, "eventBusPolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventSourceName")
    def event_source_name(self) -> typing.Optional[builtins.str]:
        '''The partner event source to associate with this event bus resource.

        :link: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-events-eventbus.html#cfn-events-eventbus-eventsourcename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "eventSourceName"))

    @jsii.member(jsii_name="archive")
    def archive(
        self,
        id: builtins.str,
        *,
        event_pattern: EventPattern,
        archive_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        retention: typing.Optional[_Duration_4839e8c3] = None,
    ) -> Archive:
        '''Create an EventBridge archive to send events to.

        When you create an archive, incoming events might not immediately start being sent to the archive.
        Allow a short period of time for changes to take effect.

        :param id: -
        :param event_pattern: An event pattern to use to filter events sent to the archive.
        :param archive_name: The name of the archive. Default: - Automatically generated
        :param description: A description for the archive. Default: - none
        :param retention: The number of days to retain events for. Default value is 0. If set to 0, events are retained indefinitely. Default: - Infinite
        '''
        props = BaseArchiveProps(
            event_pattern=event_pattern,
            archive_name=archive_name,
            description=description,
            retention=retention,
        )

        return typing.cast(Archive, jsii.invoke(self, "archive", [id, props]))

    @jsii.member(jsii_name="grantPutEventsTo")
    def grant_put_events_to(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grants an IAM Principal to send custom events to the eventBus so that they can be matched to rules.

        :param grantee: The principal (no-op if undefined).
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPutEventsTo", [grantee]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IEventBus).__jsii_proxy_class__ = lambda : _IEventBusProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_events.IRule")
class IRule(_IResource_c80c4260, typing_extensions.Protocol):
    '''Represents an EventBridge Rule.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ruleArn")
    def rule_arn(self) -> builtins.str:
        '''The value of the event rule Amazon Resource Name (ARN), such as arn:aws:events:us-east-2:123456789012:rule/example.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ruleName")
    def rule_name(self) -> builtins.str:
        '''The name event rule.

        :attribute: true
        '''
        ...


class _IRuleProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Represents an EventBridge Rule.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_events.IRule"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ruleArn")
    def rule_arn(self) -> builtins.str:
        '''The value of the event rule Amazon Resource Name (ARN), such as arn:aws:events:us-east-2:123456789012:rule/example.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "ruleArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ruleName")
    def rule_name(self) -> builtins.str:
        '''The name event rule.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "ruleName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IRule).__jsii_proxy_class__ = lambda : _IRuleProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_events.IRuleTarget")
class IRuleTarget(typing_extensions.Protocol):
    '''An abstract target for EventRules.'''

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        rule: IRule,
        id: typing.Optional[builtins.str] = None,
    ) -> "RuleTargetConfig":
        '''Returns the rule target specification.

        NOTE: Do not use the various ``inputXxx`` options. They can be set in a call to ``addTarget``.

        :param rule: The EventBridge Rule that would trigger this target.
        :param id: The id of the target that will be attached to the rule.
        '''
        ...


class _IRuleTargetProxy:
    '''An abstract target for EventRules.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_events.IRuleTarget"

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        rule: IRule,
        id: typing.Optional[builtins.str] = None,
    ) -> "RuleTargetConfig":
        '''Returns the rule target specification.

        NOTE: Do not use the various ``inputXxx`` options. They can be set in a call to ``addTarget``.

        :param rule: The EventBridge Rule that would trigger this target.
        :param id: The id of the target that will be attached to the rule.
        '''
        return typing.cast("RuleTargetConfig", jsii.invoke(self, "bind", [rule, id]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IRuleTarget).__jsii_proxy_class__ = lambda : _IRuleTargetProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.OAuthAuthorizationProps",
    jsii_struct_bases=[],
    name_mapping={
        "authorization_endpoint": "authorizationEndpoint",
        "client_id": "clientId",
        "client_secret": "clientSecret",
        "http_method": "httpMethod",
        "body_parameters": "bodyParameters",
        "header_parameters": "headerParameters",
        "query_string_parameters": "queryStringParameters",
    },
)
class OAuthAuthorizationProps:
    def __init__(
        self,
        *,
        authorization_endpoint: builtins.str,
        client_id: builtins.str,
        client_secret: _SecretValue_3dd0ddae,
        http_method: HttpMethod,
        body_parameters: typing.Optional[typing.Mapping[builtins.str, HttpParameter]] = None,
        header_parameters: typing.Optional[typing.Mapping[builtins.str, HttpParameter]] = None,
        query_string_parameters: typing.Optional[typing.Mapping[builtins.str, HttpParameter]] = None,
    ) -> None:
        '''Properties for ``Authorization.oauth()``.

        :param authorization_endpoint: The URL to the authorization endpoint.
        :param client_id: The client ID to use for OAuth authorization for the connection.
        :param client_secret: The client secret associated with the client ID to use for OAuth authorization for the connection.
        :param http_method: The method to use for the authorization request. (Can only choose POST, GET or PUT).
        :param body_parameters: Additional string parameters to add to the OAuth request body. Default: - No additional parameters
        :param header_parameters: Additional string parameters to add to the OAuth request header. Default: - No additional parameters
        :param query_string_parameters: Additional string parameters to add to the OAuth request query string. Default: - No additional parameters

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_events as events
            
            # http_parameter: events.HttpParameter
            # secret_value: cdk.SecretValue
            
            o_auth_authorization_props = events.OAuthAuthorizationProps(
                authorization_endpoint="authorizationEndpoint",
                client_id="clientId",
                client_secret=secret_value,
                http_method=events.HttpMethod.POST,
            
                # the properties below are optional
                body_parameters={
                    "body_parameters_key": http_parameter
                },
                header_parameters={
                    "header_parameters_key": http_parameter
                },
                query_string_parameters={
                    "query_string_parameters_key": http_parameter
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "authorization_endpoint": authorization_endpoint,
            "client_id": client_id,
            "client_secret": client_secret,
            "http_method": http_method,
        }
        if body_parameters is not None:
            self._values["body_parameters"] = body_parameters
        if header_parameters is not None:
            self._values["header_parameters"] = header_parameters
        if query_string_parameters is not None:
            self._values["query_string_parameters"] = query_string_parameters

    @builtins.property
    def authorization_endpoint(self) -> builtins.str:
        '''The URL to the authorization endpoint.'''
        result = self._values.get("authorization_endpoint")
        assert result is not None, "Required property 'authorization_endpoint' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def client_id(self) -> builtins.str:
        '''The client ID to use for OAuth authorization for the connection.'''
        result = self._values.get("client_id")
        assert result is not None, "Required property 'client_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def client_secret(self) -> _SecretValue_3dd0ddae:
        '''The client secret associated with the client ID to use for OAuth authorization for the connection.'''
        result = self._values.get("client_secret")
        assert result is not None, "Required property 'client_secret' is missing"
        return typing.cast(_SecretValue_3dd0ddae, result)

    @builtins.property
    def http_method(self) -> HttpMethod:
        '''The method to use for the authorization request.

        (Can only choose POST, GET or PUT).
        '''
        result = self._values.get("http_method")
        assert result is not None, "Required property 'http_method' is missing"
        return typing.cast(HttpMethod, result)

    @builtins.property
    def body_parameters(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, HttpParameter]]:
        '''Additional string parameters to add to the OAuth request body.

        :default: - No additional parameters
        '''
        result = self._values.get("body_parameters")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, HttpParameter]], result)

    @builtins.property
    def header_parameters(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, HttpParameter]]:
        '''Additional string parameters to add to the OAuth request header.

        :default: - No additional parameters
        '''
        result = self._values.get("header_parameters")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, HttpParameter]], result)

    @builtins.property
    def query_string_parameters(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, HttpParameter]]:
        '''Additional string parameters to add to the OAuth request query string.

        :default: - No additional parameters
        '''
        result = self._values.get("query_string_parameters")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, HttpParameter]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "OAuthAuthorizationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.OnEventOptions",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "event_pattern": "eventPattern",
        "rule_name": "ruleName",
        "target": "target",
    },
)
class OnEventOptions:
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        event_pattern: typing.Optional[EventPattern] = None,
        rule_name: typing.Optional[builtins.str] = None,
        target: typing.Optional[IRuleTarget] = None,
    ) -> None:
        '''Standard set of options for ``onXxx`` event handlers on construct.

        :param description: A description of the rule's purpose. Default: - No description
        :param event_pattern: Additional restrictions for the event to route to the specified target. The method that generates the rule probably imposes some type of event filtering. The filtering implied by what you pass here is added on top of that filtering. Default: - No additional filtering based on an event pattern.
        :param rule_name: A name for the rule. Default: AWS CloudFormation generates a unique physical ID.
        :param target: The target to register for the event. Default: - No target is added to the rule. Use ``addTarget()`` to add a target.

        :exampleMetadata: infused

        Example::

            # Lambda function containing logic that evaluates compliance with the rule.
            eval_compliance_fn = lambda_.Function(self, "CustomFunction",
                code=lambda_.AssetCode.from_inline("exports.handler = (event) => console.log(event);"),
                handler="index.handler",
                runtime=lambda_.Runtime.NODEJS_12_X
            )
            
            # A custom rule that runs on configuration changes of EC2 instances
            custom_rule = config.CustomRule(self, "Custom",
                configuration_changes=True,
                lambda_function=eval_compliance_fn,
                rule_scope=config.RuleScope.from_resource(config.ResourceType.EC2_INSTANCE)
            )
            
            # A rule to detect stack drifts
            drift_rule = config.CloudFormationStackDriftDetectionCheck(self, "Drift")
            
            # Topic to which compliance notification events will be published
            compliance_topic = sns.Topic(self, "ComplianceTopic")
            
            # Send notification on compliance change events
            drift_rule.on_compliance_change("ComplianceChange",
                target=targets.SnsTopic(compliance_topic)
            )
        '''
        if isinstance(event_pattern, dict):
            event_pattern = EventPattern(**event_pattern)
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if event_pattern is not None:
            self._values["event_pattern"] = event_pattern
        if rule_name is not None:
            self._values["rule_name"] = rule_name
        if target is not None:
            self._values["target"] = target

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the rule's purpose.

        :default: - No description
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def event_pattern(self) -> typing.Optional[EventPattern]:
        '''Additional restrictions for the event to route to the specified target.

        The method that generates the rule probably imposes some type of event
        filtering. The filtering implied by what you pass here is added
        on top of that filtering.

        :default: - No additional filtering based on an event pattern.

        :see: https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-and-event-patterns.html
        '''
        result = self._values.get("event_pattern")
        return typing.cast(typing.Optional[EventPattern], result)

    @builtins.property
    def rule_name(self) -> typing.Optional[builtins.str]:
        '''A name for the rule.

        :default: AWS CloudFormation generates a unique physical ID.
        '''
        result = self._values.get("rule_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def target(self) -> typing.Optional[IRuleTarget]:
        '''The target to register for the event.

        :default: - No target is added to the rule. Use ``addTarget()`` to add a target.
        '''
        result = self._values.get("target")
        return typing.cast(typing.Optional[IRuleTarget], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "OnEventOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IRule)
class Rule(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.Rule",
):
    '''Defines an EventBridge Rule in this stack.

    :exampleMetadata: infused
    :resource: AWS::Events::Rule

    Example::

        import aws_cdk.aws_lambda as lambda_
        
        
        fn = lambda_.Function(self, "MyFunc",
            runtime=lambda_.Runtime.NODEJS_12_X,
            handler="index.handler",
            code=lambda_.Code.from_inline("exports.handler = handler.toString()")
        )
        
        rule = events.Rule(self, "rule",
            event_pattern=events.EventPattern(
                source=["aws.ec2"]
            )
        )
        
        queue = sqs.Queue(self, "Queue")
        
        rule.add_target(targets.LambdaFunction(fn,
            dead_letter_queue=queue,  # Optional: add a dead letter queue
            max_event_age=cdk.Duration.hours(2),  # Optional: set the maxEventAge retry policy
            retry_attempts=2
        ))
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        description: typing.Optional[builtins.str] = None,
        enabled: typing.Optional[builtins.bool] = None,
        event_bus: typing.Optional[IEventBus] = None,
        event_pattern: typing.Optional[EventPattern] = None,
        rule_name: typing.Optional[builtins.str] = None,
        schedule: typing.Optional["Schedule"] = None,
        targets: typing.Optional[typing.Sequence[IRuleTarget]] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param description: A description of the rule's purpose. Default: - No description.
        :param enabled: Indicates whether the rule is enabled. Default: true
        :param event_bus: The event bus to associate with this rule. Default: - The default event bus.
        :param event_pattern: Describes which events EventBridge routes to the specified target. These routed events are matched events. For more information, see Events and Event Patterns in the Amazon EventBridge User Guide. Default: - None.
        :param rule_name: A name for the rule. Default: - AWS CloudFormation generates a unique physical ID and uses that ID for the rule name. For more information, see Name Type.
        :param schedule: The schedule or rate (frequency) that determines when EventBridge runs the rule. For more information, see Schedule Expression Syntax for Rules in the Amazon EventBridge User Guide. Default: - None.
        :param targets: Targets to invoke when this rule matches an event. Input will be the full matched event. If you wish to specify custom target input, use ``addTarget(target[, inputOptions])``. Default: - No targets.
        '''
        props = RuleProps(
            description=description,
            enabled=enabled,
            event_bus=event_bus,
            event_pattern=event_pattern,
            rule_name=rule_name,
            schedule=schedule,
            targets=targets,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromEventRuleArn") # type: ignore[misc]
    @builtins.classmethod
    def from_event_rule_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        event_rule_arn: builtins.str,
    ) -> IRule:
        '''Import an existing EventBridge Rule provided an ARN.

        :param scope: The parent creating construct (usually ``this``).
        :param id: The construct's name.
        :param event_rule_arn: Event Rule ARN (i.e. arn:aws:events:::rule/MyScheduledRule).
        '''
        return typing.cast(IRule, jsii.sinvoke(cls, "fromEventRuleArn", [scope, id, event_rule_arn]))

    @jsii.member(jsii_name="addEventPattern")
    def add_event_pattern(
        self,
        *,
        account: typing.Optional[typing.Sequence[builtins.str]] = None,
        detail: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        detail_type: typing.Optional[typing.Sequence[builtins.str]] = None,
        id: typing.Optional[typing.Sequence[builtins.str]] = None,
        region: typing.Optional[typing.Sequence[builtins.str]] = None,
        resources: typing.Optional[typing.Sequence[builtins.str]] = None,
        source: typing.Optional[typing.Sequence[builtins.str]] = None,
        time: typing.Optional[typing.Sequence[builtins.str]] = None,
        version: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Adds an event pattern filter to this rule.

        If a pattern was already specified,
        these values are merged into the existing pattern.

        For example, if the rule already contains the pattern::

           {
             "resources": [ "r1" ],
             "detail": {
               "hello": [ 1 ]
             }
           }

        And ``addEventPattern`` is called with the pattern::

           {
             "resources": [ "r2" ],
             "detail": {
               "foo": [ "bar" ]
             }
           }

        The resulting event pattern will be::

           {
             "resources": [ "r1", "r2" ],
             "detail": {
               "hello": [ 1 ],
               "foo": [ "bar" ]
             }
           }

        :param account: The 12-digit number identifying an AWS account. Default: - No filtering on account
        :param detail: A JSON object, whose content is at the discretion of the service originating the event. Default: - No filtering on detail
        :param detail_type: Identifies, in combination with the source field, the fields and values that appear in the detail field. Represents the "detail-type" event field. Default: - No filtering on detail type
        :param id: A unique value is generated for every event. This can be helpful in tracing events as they move through rules to targets, and are processed. Default: - No filtering on id
        :param region: Identifies the AWS region where the event originated. Default: - No filtering on region
        :param resources: This JSON array contains ARNs that identify resources that are involved in the event. Inclusion of these ARNs is at the discretion of the service. For example, Amazon EC2 instance state-changes include Amazon EC2 instance ARNs, Auto Scaling events include ARNs for both instances and Auto Scaling groups, but API calls with AWS CloudTrail do not include resource ARNs. Default: - No filtering on resource
        :param source: Identifies the service that sourced the event. All events sourced from within AWS begin with "aws." Customer-generated events can have any value here, as long as it doesn't begin with "aws." We recommend the use of Java package-name style reverse domain-name strings. To find the correct value for source for an AWS service, see the table in AWS Service Namespaces. For example, the source value for Amazon CloudFront is aws.cloudfront. Default: - No filtering on source
        :param time: The event timestamp, which can be specified by the service originating the event. If the event spans a time interval, the service might choose to report the start time, so this value can be noticeably before the time the event is actually received. Default: - No filtering on time
        :param version: By default, this is set to 0 (zero) in all events. Default: - No filtering on version
        '''
        event_pattern = EventPattern(
            account=account,
            detail=detail,
            detail_type=detail_type,
            id=id,
            region=region,
            resources=resources,
            source=source,
            time=time,
            version=version,
        )

        return typing.cast(None, jsii.invoke(self, "addEventPattern", [event_pattern]))

    @jsii.member(jsii_name="addTarget")
    def add_target(self, target: typing.Optional[IRuleTarget] = None) -> None:
        '''Adds a target to the rule. The abstract class RuleTarget can be extended to define new targets.

        No-op if target is undefined.

        :param target: -
        '''
        return typing.cast(None, jsii.invoke(self, "addTarget", [target]))

    @jsii.member(jsii_name="validateRule")
    def _validate_rule(self) -> typing.List[builtins.str]:
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateRule", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ruleArn")
    def rule_arn(self) -> builtins.str:
        '''The value of the event rule Amazon Resource Name (ARN), such as arn:aws:events:us-east-2:123456789012:rule/example.'''
        return typing.cast(builtins.str, jsii.get(self, "ruleArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ruleName")
    def rule_name(self) -> builtins.str:
        '''The name event rule.'''
        return typing.cast(builtins.str, jsii.get(self, "ruleName"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.RuleProps",
    jsii_struct_bases=[],
    name_mapping={
        "description": "description",
        "enabled": "enabled",
        "event_bus": "eventBus",
        "event_pattern": "eventPattern",
        "rule_name": "ruleName",
        "schedule": "schedule",
        "targets": "targets",
    },
)
class RuleProps:
    def __init__(
        self,
        *,
        description: typing.Optional[builtins.str] = None,
        enabled: typing.Optional[builtins.bool] = None,
        event_bus: typing.Optional[IEventBus] = None,
        event_pattern: typing.Optional[EventPattern] = None,
        rule_name: typing.Optional[builtins.str] = None,
        schedule: typing.Optional["Schedule"] = None,
        targets: typing.Optional[typing.Sequence[IRuleTarget]] = None,
    ) -> None:
        '''Properties for defining an EventBridge Rule.

        :param description: A description of the rule's purpose. Default: - No description.
        :param enabled: Indicates whether the rule is enabled. Default: true
        :param event_bus: The event bus to associate with this rule. Default: - The default event bus.
        :param event_pattern: Describes which events EventBridge routes to the specified target. These routed events are matched events. For more information, see Events and Event Patterns in the Amazon EventBridge User Guide. Default: - None.
        :param rule_name: A name for the rule. Default: - AWS CloudFormation generates a unique physical ID and uses that ID for the rule name. For more information, see Name Type.
        :param schedule: The schedule or rate (frequency) that determines when EventBridge runs the rule. For more information, see Schedule Expression Syntax for Rules in the Amazon EventBridge User Guide. Default: - None.
        :param targets: Targets to invoke when this rule matches an event. Input will be the full matched event. If you wish to specify custom target input, use ``addTarget(target[, inputOptions])``. Default: - No targets.

        :exampleMetadata: infused

        Example::

            connection = events.Connection(self, "Connection",
                authorization=events.Authorization.api_key("x-api-key", SecretValue.secrets_manager("ApiSecretName")),
                description="Connection with API Key x-api-key"
            )
            
            destination = events.ApiDestination(self, "Destination",
                connection=connection,
                endpoint="https://example.com",
                description="Calling example.com with API key x-api-key"
            )
            
            rule = events.Rule(self, "Rule",
                schedule=events.Schedule.rate(cdk.Duration.minutes(1)),
                targets=[targets.ApiDestination(destination)]
            )
        '''
        if isinstance(event_pattern, dict):
            event_pattern = EventPattern(**event_pattern)
        self._values: typing.Dict[str, typing.Any] = {}
        if description is not None:
            self._values["description"] = description
        if enabled is not None:
            self._values["enabled"] = enabled
        if event_bus is not None:
            self._values["event_bus"] = event_bus
        if event_pattern is not None:
            self._values["event_pattern"] = event_pattern
        if rule_name is not None:
            self._values["rule_name"] = rule_name
        if schedule is not None:
            self._values["schedule"] = schedule
        if targets is not None:
            self._values["targets"] = targets

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description of the rule's purpose.

        :default: - No description.
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enabled(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether the rule is enabled.

        :default: true
        '''
        result = self._values.get("enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def event_bus(self) -> typing.Optional[IEventBus]:
        '''The event bus to associate with this rule.

        :default: - The default event bus.
        '''
        result = self._values.get("event_bus")
        return typing.cast(typing.Optional[IEventBus], result)

    @builtins.property
    def event_pattern(self) -> typing.Optional[EventPattern]:
        '''Describes which events EventBridge routes to the specified target.

        These routed events are matched events. For more information, see Events
        and Event Patterns in the Amazon EventBridge User Guide.

        :default: - None.

        :see:

        https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-and-event-patterns.html

        You must specify this property (either via props or via
        ``addEventPattern``), the ``scheduleExpression`` property, or both. The
        method ``addEventPattern`` can be used to add filter values to the event
        pattern.
        '''
        result = self._values.get("event_pattern")
        return typing.cast(typing.Optional[EventPattern], result)

    @builtins.property
    def rule_name(self) -> typing.Optional[builtins.str]:
        '''A name for the rule.

        :default:

        - AWS CloudFormation generates a unique physical ID and uses that ID
        for the rule name. For more information, see Name Type.
        '''
        result = self._values.get("rule_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def schedule(self) -> typing.Optional["Schedule"]:
        '''The schedule or rate (frequency) that determines when EventBridge runs the rule.

        For more information, see Schedule Expression Syntax for
        Rules in the Amazon EventBridge User Guide.

        :default: - None.

        :see:

        https://docs.aws.amazon.com/eventbridge/latest/userguide/scheduled-events.html

        You must specify this property, the ``eventPattern`` property, or both.
        '''
        result = self._values.get("schedule")
        return typing.cast(typing.Optional["Schedule"], result)

    @builtins.property
    def targets(self) -> typing.Optional[typing.List[IRuleTarget]]:
        '''Targets to invoke when this rule matches an event.

        Input will be the full matched event. If you wish to specify custom
        target input, use ``addTarget(target[, inputOptions])``.

        :default: - No targets.
        '''
        result = self._values.get("targets")
        return typing.cast(typing.Optional[typing.List[IRuleTarget]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RuleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.RuleTargetConfig",
    jsii_struct_bases=[],
    name_mapping={
        "arn": "arn",
        "batch_parameters": "batchParameters",
        "dead_letter_config": "deadLetterConfig",
        "ecs_parameters": "ecsParameters",
        "http_parameters": "httpParameters",
        "input": "input",
        "kinesis_parameters": "kinesisParameters",
        "retry_policy": "retryPolicy",
        "role": "role",
        "run_command_parameters": "runCommandParameters",
        "sqs_parameters": "sqsParameters",
        "target_resource": "targetResource",
    },
)
class RuleTargetConfig:
    def __init__(
        self,
        *,
        arn: builtins.str,
        batch_parameters: typing.Optional[CfnRule.BatchParametersProperty] = None,
        dead_letter_config: typing.Optional[CfnRule.DeadLetterConfigProperty] = None,
        ecs_parameters: typing.Optional[CfnRule.EcsParametersProperty] = None,
        http_parameters: typing.Optional[CfnRule.HttpParametersProperty] = None,
        input: typing.Optional["RuleTargetInput"] = None,
        kinesis_parameters: typing.Optional[CfnRule.KinesisParametersProperty] = None,
        retry_policy: typing.Optional[CfnRule.RetryPolicyProperty] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        run_command_parameters: typing.Optional[CfnRule.RunCommandParametersProperty] = None,
        sqs_parameters: typing.Optional[CfnRule.SqsParametersProperty] = None,
        target_resource: typing.Optional[constructs.IConstruct] = None,
    ) -> None:
        '''Properties for an event rule target.

        :param arn: The Amazon Resource Name (ARN) of the target.
        :param batch_parameters: Parameters used when the rule invokes Amazon AWS Batch Job/Queue. Default: no parameters set
        :param dead_letter_config: Contains information about a dead-letter queue configuration. Default: no dead-letter queue set
        :param ecs_parameters: The Amazon ECS task definition and task count to use, if the event target is an Amazon ECS task.
        :param http_parameters: Contains the HTTP parameters to use when the target is a API Gateway REST endpoint or EventBridge API destination. Default: - None
        :param input: What input to send to the event target. Default: the entire event
        :param kinesis_parameters: Settings that control shard assignment, when the target is a Kinesis stream. If you don't include this parameter, eventId is used as the partition key.
        :param retry_policy: A RetryPolicy object that includes information about the retry policy settings. Default: EventBridge default retry policy
        :param role: Role to use to invoke this event target.
        :param run_command_parameters: Parameters used when the rule invokes Amazon EC2 Systems Manager Run Command.
        :param sqs_parameters: Parameters used when the FIFO sqs queue is used an event target by the rule.
        :param target_resource: The resource that is backing this target. This is the resource that will actually have some action performed on it when used as a target (for example, start a build for a CodeBuild project). We need it to determine whether the rule belongs to a different account than the target - if so, we generate a more complex setup, including an additional stack containing the EventBusPolicy. Default: the target is not backed by any resource

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_events as events
            from aws_cdk import aws_iam as iam
            import constructs as constructs
            
            # construct: constructs.Construct
            # role: iam.Role
            # rule_target_input: events.RuleTargetInput
            
            rule_target_config = events.RuleTargetConfig(
                arn="arn",
            
                # the properties below are optional
                batch_parameters=events.CfnRule.BatchParametersProperty(
                    job_definition="jobDefinition",
                    job_name="jobName",
            
                    # the properties below are optional
                    array_properties=events.CfnRule.BatchArrayPropertiesProperty(
                        size=123
                    ),
                    retry_strategy=events.CfnRule.BatchRetryStrategyProperty(
                        attempts=123
                    )
                ),
                dead_letter_config=events.CfnRule.DeadLetterConfigProperty(
                    arn="arn"
                ),
                ecs_parameters=events.CfnRule.EcsParametersProperty(
                    task_definition_arn="taskDefinitionArn",
            
                    # the properties below are optional
                    capacity_provider_strategy=[events.CfnRule.CapacityProviderStrategyItemProperty(
                        capacity_provider="capacityProvider",
            
                        # the properties below are optional
                        base=123,
                        weight=123
                    )],
                    enable_ecs_managed_tags=False,
                    enable_execute_command=False,
                    group="group",
                    launch_type="launchType",
                    network_configuration=events.CfnRule.NetworkConfigurationProperty(
                        aws_vpc_configuration=events.CfnRule.AwsVpcConfigurationProperty(
                            subnets=["subnets"],
            
                            # the properties below are optional
                            assign_public_ip="assignPublicIp",
                            security_groups=["securityGroups"]
                        )
                    ),
                    placement_constraints=[events.CfnRule.PlacementConstraintProperty(
                        expression="expression",
                        type="type"
                    )],
                    placement_strategies=[events.CfnRule.PlacementStrategyProperty(
                        field="field",
                        type="type"
                    )],
                    platform_version="platformVersion",
                    propagate_tags="propagateTags",
                    reference_id="referenceId",
                    tag_list=[CfnTag(
                        key="key",
                        value="value"
                    )],
                    task_count=123
                ),
                http_parameters=events.CfnRule.HttpParametersProperty(
                    header_parameters={
                        "header_parameters_key": "headerParameters"
                    },
                    path_parameter_values=["pathParameterValues"],
                    query_string_parameters={
                        "query_string_parameters_key": "queryStringParameters"
                    }
                ),
                input=rule_target_input,
                kinesis_parameters=events.CfnRule.KinesisParametersProperty(
                    partition_key_path="partitionKeyPath"
                ),
                retry_policy=events.CfnRule.RetryPolicyProperty(
                    maximum_event_age_in_seconds=123,
                    maximum_retry_attempts=123
                ),
                role=role,
                run_command_parameters=events.CfnRule.RunCommandParametersProperty(
                    run_command_targets=[events.CfnRule.RunCommandTargetProperty(
                        key="key",
                        values=["values"]
                    )]
                ),
                sqs_parameters=events.CfnRule.SqsParametersProperty(
                    message_group_id="messageGroupId"
                ),
                target_resource=construct
            )
        '''
        if isinstance(batch_parameters, dict):
            batch_parameters = CfnRule.BatchParametersProperty(**batch_parameters)
        if isinstance(dead_letter_config, dict):
            dead_letter_config = CfnRule.DeadLetterConfigProperty(**dead_letter_config)
        if isinstance(ecs_parameters, dict):
            ecs_parameters = CfnRule.EcsParametersProperty(**ecs_parameters)
        if isinstance(http_parameters, dict):
            http_parameters = CfnRule.HttpParametersProperty(**http_parameters)
        if isinstance(kinesis_parameters, dict):
            kinesis_parameters = CfnRule.KinesisParametersProperty(**kinesis_parameters)
        if isinstance(retry_policy, dict):
            retry_policy = CfnRule.RetryPolicyProperty(**retry_policy)
        if isinstance(run_command_parameters, dict):
            run_command_parameters = CfnRule.RunCommandParametersProperty(**run_command_parameters)
        if isinstance(sqs_parameters, dict):
            sqs_parameters = CfnRule.SqsParametersProperty(**sqs_parameters)
        self._values: typing.Dict[str, typing.Any] = {
            "arn": arn,
        }
        if batch_parameters is not None:
            self._values["batch_parameters"] = batch_parameters
        if dead_letter_config is not None:
            self._values["dead_letter_config"] = dead_letter_config
        if ecs_parameters is not None:
            self._values["ecs_parameters"] = ecs_parameters
        if http_parameters is not None:
            self._values["http_parameters"] = http_parameters
        if input is not None:
            self._values["input"] = input
        if kinesis_parameters is not None:
            self._values["kinesis_parameters"] = kinesis_parameters
        if retry_policy is not None:
            self._values["retry_policy"] = retry_policy
        if role is not None:
            self._values["role"] = role
        if run_command_parameters is not None:
            self._values["run_command_parameters"] = run_command_parameters
        if sqs_parameters is not None:
            self._values["sqs_parameters"] = sqs_parameters
        if target_resource is not None:
            self._values["target_resource"] = target_resource

    @builtins.property
    def arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the target.'''
        result = self._values.get("arn")
        assert result is not None, "Required property 'arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def batch_parameters(self) -> typing.Optional[CfnRule.BatchParametersProperty]:
        '''Parameters used when the rule invokes Amazon AWS Batch Job/Queue.

        :default: no parameters set
        '''
        result = self._values.get("batch_parameters")
        return typing.cast(typing.Optional[CfnRule.BatchParametersProperty], result)

    @builtins.property
    def dead_letter_config(self) -> typing.Optional[CfnRule.DeadLetterConfigProperty]:
        '''Contains information about a dead-letter queue configuration.

        :default: no dead-letter queue set
        '''
        result = self._values.get("dead_letter_config")
        return typing.cast(typing.Optional[CfnRule.DeadLetterConfigProperty], result)

    @builtins.property
    def ecs_parameters(self) -> typing.Optional[CfnRule.EcsParametersProperty]:
        '''The Amazon ECS task definition and task count to use, if the event target is an Amazon ECS task.'''
        result = self._values.get("ecs_parameters")
        return typing.cast(typing.Optional[CfnRule.EcsParametersProperty], result)

    @builtins.property
    def http_parameters(self) -> typing.Optional[CfnRule.HttpParametersProperty]:
        '''Contains the HTTP parameters to use when the target is a API Gateway REST endpoint or EventBridge API destination.

        :default: - None
        '''
        result = self._values.get("http_parameters")
        return typing.cast(typing.Optional[CfnRule.HttpParametersProperty], result)

    @builtins.property
    def input(self) -> typing.Optional["RuleTargetInput"]:
        '''What input to send to the event target.

        :default: the entire event
        '''
        result = self._values.get("input")
        return typing.cast(typing.Optional["RuleTargetInput"], result)

    @builtins.property
    def kinesis_parameters(self) -> typing.Optional[CfnRule.KinesisParametersProperty]:
        '''Settings that control shard assignment, when the target is a Kinesis stream.

        If you don't include this parameter, eventId is used as the
        partition key.
        '''
        result = self._values.get("kinesis_parameters")
        return typing.cast(typing.Optional[CfnRule.KinesisParametersProperty], result)

    @builtins.property
    def retry_policy(self) -> typing.Optional[CfnRule.RetryPolicyProperty]:
        '''A RetryPolicy object that includes information about the retry policy settings.

        :default: EventBridge default retry policy
        '''
        result = self._values.get("retry_policy")
        return typing.cast(typing.Optional[CfnRule.RetryPolicyProperty], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''Role to use to invoke this event target.'''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def run_command_parameters(
        self,
    ) -> typing.Optional[CfnRule.RunCommandParametersProperty]:
        '''Parameters used when the rule invokes Amazon EC2 Systems Manager Run Command.'''
        result = self._values.get("run_command_parameters")
        return typing.cast(typing.Optional[CfnRule.RunCommandParametersProperty], result)

    @builtins.property
    def sqs_parameters(self) -> typing.Optional[CfnRule.SqsParametersProperty]:
        '''Parameters used when the FIFO sqs queue is used an event target by the rule.'''
        result = self._values.get("sqs_parameters")
        return typing.cast(typing.Optional[CfnRule.SqsParametersProperty], result)

    @builtins.property
    def target_resource(self) -> typing.Optional[constructs.IConstruct]:
        '''The resource that is backing this target.

        This is the resource that will actually have some action performed on it when used as a target
        (for example, start a build for a CodeBuild project).
        We need it to determine whether the rule belongs to a different account than the target -
        if so, we generate a more complex setup,
        including an additional stack containing the EventBusPolicy.

        :default: the target is not backed by any resource

        :see: https://docs.aws.amazon.com/eventbridge/latest/userguide/eventbridge-cross-account-event-delivery.html
        '''
        result = self._values.get("target_resource")
        return typing.cast(typing.Optional[constructs.IConstruct], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RuleTargetConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class RuleTargetInput(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_events.RuleTargetInput",
):
    '''The input to send to the event target.

    :exampleMetadata: infused

    Example::

        import aws_cdk.aws_iam as iam
        import aws_cdk.aws_stepfunctions as sfn
        
        
        rule = events.Rule(self, "Rule",
            schedule=events.Schedule.rate(cdk.Duration.minutes(1))
        )
        
        dlq = sqs.Queue(self, "DeadLetterQueue")
        
        role = iam.Role(self, "Role",
            assumed_by=iam.ServicePrincipal("events.amazonaws.com")
        )
        state_machine = sfn.StateMachine(self, "SM",
            definition=sfn.Wait(self, "Hello", time=sfn.WaitTime.duration(cdk.Duration.seconds(10))),
            role=role
        )
        
        rule.add_target(targets.SfnStateMachine(state_machine,
            input=events.RuleTargetInput.from_object({"SomeParam": "SomeValue"}),
            dead_letter_queue=dlq
        ))
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="fromEventPath") # type: ignore[misc]
    @builtins.classmethod
    def from_event_path(cls, path: builtins.str) -> "RuleTargetInput":
        '''Take the event target input from a path in the event JSON.

        :param path: -
        '''
        return typing.cast("RuleTargetInput", jsii.sinvoke(cls, "fromEventPath", [path]))

    @jsii.member(jsii_name="fromMultilineText") # type: ignore[misc]
    @builtins.classmethod
    def from_multiline_text(cls, text: builtins.str) -> "RuleTargetInput":
        '''Pass text to the event target, splitting on newlines.

        This is only useful when passing to a target that does not
        take a single argument.

        May contain strings returned by ``EventField.from()`` to substitute in parts
        of the matched event.

        :param text: -
        '''
        return typing.cast("RuleTargetInput", jsii.sinvoke(cls, "fromMultilineText", [text]))

    @jsii.member(jsii_name="fromObject") # type: ignore[misc]
    @builtins.classmethod
    def from_object(cls, obj: typing.Any) -> "RuleTargetInput":
        '''Pass a JSON object to the event target.

        May contain strings returned by ``EventField.from()`` to substitute in parts of the
        matched event.

        :param obj: -
        '''
        return typing.cast("RuleTargetInput", jsii.sinvoke(cls, "fromObject", [obj]))

    @jsii.member(jsii_name="fromText") # type: ignore[misc]
    @builtins.classmethod
    def from_text(cls, text: builtins.str) -> "RuleTargetInput":
        '''Pass text to the event target.

        May contain strings returned by ``EventField.from()`` to substitute in parts of the
        matched event.

        The Rule Target input value will be a single string: the string you pass
        here.  Do not use this method to pass a complex value like a JSON object to
        a Rule Target.  Use ``RuleTargetInput.fromObject()`` instead.

        :param text: -
        '''
        return typing.cast("RuleTargetInput", jsii.sinvoke(cls, "fromText", [text]))

    @jsii.member(jsii_name="bind") # type: ignore[misc]
    @abc.abstractmethod
    def bind(self, rule: IRule) -> "RuleTargetInputProperties":
        '''Return the input properties for this input object.

        :param rule: -
        '''
        ...


class _RuleTargetInputProxy(RuleTargetInput):
    @jsii.member(jsii_name="bind")
    def bind(self, rule: IRule) -> "RuleTargetInputProperties":
        '''Return the input properties for this input object.

        :param rule: -
        '''
        return typing.cast("RuleTargetInputProperties", jsii.invoke(self, "bind", [rule]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, RuleTargetInput).__jsii_proxy_class__ = lambda : _RuleTargetInputProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.RuleTargetInputProperties",
    jsii_struct_bases=[],
    name_mapping={
        "input": "input",
        "input_path": "inputPath",
        "input_paths_map": "inputPathsMap",
        "input_template": "inputTemplate",
    },
)
class RuleTargetInputProperties:
    def __init__(
        self,
        *,
        input: typing.Optional[builtins.str] = None,
        input_path: typing.Optional[builtins.str] = None,
        input_paths_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        input_template: typing.Optional[builtins.str] = None,
    ) -> None:
        '''The input properties for an event target.

        :param input: Literal input to the target service (must be valid JSON). Default: - input for the event target. If the input contains a paths map values wil be extracted from event and inserted into the ``inputTemplate``.
        :param input_path: JsonPath to take input from the input event. Default: - None. The entire matched event is passed as input
        :param input_paths_map: Paths map to extract values from event and insert into ``inputTemplate``. Default: - No values extracted from event.
        :param input_template: Input template to insert paths map into. Default: - None.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_events as events
            
            rule_target_input_properties = events.RuleTargetInputProperties(
                input="input",
                input_path="inputPath",
                input_paths_map={
                    "input_paths_map_key": "inputPathsMap"
                },
                input_template="inputTemplate"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if input is not None:
            self._values["input"] = input
        if input_path is not None:
            self._values["input_path"] = input_path
        if input_paths_map is not None:
            self._values["input_paths_map"] = input_paths_map
        if input_template is not None:
            self._values["input_template"] = input_template

    @builtins.property
    def input(self) -> typing.Optional[builtins.str]:
        '''Literal input to the target service (must be valid JSON).

        :default:

        - input for the event target. If the input contains a paths map
        values wil be extracted from event and inserted into the ``inputTemplate``.
        '''
        result = self._values.get("input")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def input_path(self) -> typing.Optional[builtins.str]:
        '''JsonPath to take input from the input event.

        :default: - None. The entire matched event is passed as input
        '''
        result = self._values.get("input_path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def input_paths_map(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Paths map to extract values from event and insert into ``inputTemplate``.

        :default: - No values extracted from event.
        '''
        result = self._values.get("input_paths_map")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def input_template(self) -> typing.Optional[builtins.str]:
        '''Input template to insert paths map into.

        :default: - None.
        '''
        result = self._values.get("input_template")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RuleTargetInputProperties(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Schedule(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_events.Schedule",
):
    '''Schedule for scheduled event rules.

    :exampleMetadata: infused

    Example::

        connection = events.Connection(self, "Connection",
            authorization=events.Authorization.api_key("x-api-key", SecretValue.secrets_manager("ApiSecretName")),
            description="Connection with API Key x-api-key"
        )
        
        destination = events.ApiDestination(self, "Destination",
            connection=connection,
            endpoint="https://example.com",
            description="Calling example.com with API key x-api-key"
        )
        
        rule = events.Rule(self, "Rule",
            schedule=events.Schedule.rate(cdk.Duration.minutes(1)),
            targets=[targets.ApiDestination(destination)]
        )
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="cron") # type: ignore[misc]
    @builtins.classmethod
    def cron(
        cls,
        *,
        day: typing.Optional[builtins.str] = None,
        hour: typing.Optional[builtins.str] = None,
        minute: typing.Optional[builtins.str] = None,
        month: typing.Optional[builtins.str] = None,
        week_day: typing.Optional[builtins.str] = None,
        year: typing.Optional[builtins.str] = None,
    ) -> "Schedule":
        '''Create a schedule from a set of cron fields.

        :param day: The day of the month to run this rule at. Default: - Every day of the month
        :param hour: The hour to run this rule at. Default: - Every hour
        :param minute: The minute to run this rule at. Default: - Every minute
        :param month: The month to run this rule at. Default: - Every month
        :param week_day: The day of the week to run this rule at. Default: - Any day of the week
        :param year: The year to run this rule at. Default: - Every year
        '''
        options = CronOptions(
            day=day,
            hour=hour,
            minute=minute,
            month=month,
            week_day=week_day,
            year=year,
        )

        return typing.cast("Schedule", jsii.sinvoke(cls, "cron", [options]))

    @jsii.member(jsii_name="expression") # type: ignore[misc]
    @builtins.classmethod
    def expression(cls, expression: builtins.str) -> "Schedule":
        '''Construct a schedule from a literal schedule expression.

        :param expression: The expression to use. Must be in a format that EventBridge will recognize
        '''
        return typing.cast("Schedule", jsii.sinvoke(cls, "expression", [expression]))

    @jsii.member(jsii_name="rate") # type: ignore[misc]
    @builtins.classmethod
    def rate(cls, duration: _Duration_4839e8c3) -> "Schedule":
        '''Construct a schedule from an interval and a time unit.

        :param duration: -
        '''
        return typing.cast("Schedule", jsii.sinvoke(cls, "rate", [duration]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="expressionString")
    @abc.abstractmethod
    def expression_string(self) -> builtins.str:
        '''Retrieve the expression for this schedule.'''
        ...


class _ScheduleProxy(Schedule):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="expressionString")
    def expression_string(self) -> builtins.str:
        '''Retrieve the expression for this schedule.'''
        return typing.cast(builtins.str, jsii.get(self, "expressionString"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, Schedule).__jsii_proxy_class__ = lambda : _ScheduleProxy


@jsii.implements(IApiDestination)
class ApiDestination(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.ApiDestination",
):
    '''Define an EventBridge Api Destination.

    :exampleMetadata: infused
    :resource: AWS::Events::ApiDestination

    Example::

        connection = events.Connection(self, "Connection",
            authorization=events.Authorization.api_key("x-api-key", SecretValue.secrets_manager("ApiSecretName")),
            description="Connection with API Key x-api-key"
        )
        
        destination = events.ApiDestination(self, "Destination",
            connection=connection,
            endpoint="https://example.com",
            description="Calling example.com with API key x-api-key"
        )
        
        rule = events.Rule(self, "Rule",
            schedule=events.Schedule.rate(cdk.Duration.minutes(1)),
            targets=[targets.ApiDestination(destination)]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        connection: IConnection,
        endpoint: builtins.str,
        api_destination_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        http_method: typing.Optional[HttpMethod] = None,
        rate_limit_per_second: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param connection: The ARN of the connection to use for the API destination.
        :param endpoint: The URL to the HTTP invocation endpoint for the API destination..
        :param api_destination_name: The name for the API destination. Default: - A unique name will be generated
        :param description: A description for the API destination. Default: - none
        :param http_method: The method to use for the request to the HTTP invocation endpoint. Default: HttpMethod.POST
        :param rate_limit_per_second: The maximum number of requests per second to send to the HTTP invocation endpoint. Default: - Not rate limited
        '''
        props = ApiDestinationProps(
            connection=connection,
            endpoint=endpoint,
            api_destination_name=api_destination_name,
            description=description,
            http_method=http_method,
            rate_limit_per_second=rate_limit_per_second,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="apiDestinationArn")
    def api_destination_arn(self) -> builtins.str:
        '''The ARN of the Api Destination created.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "apiDestinationArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="apiDestinationName")
    def api_destination_name(self) -> builtins.str:
        '''The Name of the Api Destination created.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "apiDestinationName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connection")
    def connection(self) -> IConnection:
        '''The Connection to associate with Api Destination.'''
        return typing.cast(IConnection, jsii.get(self, "connection"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_events.ArchiveProps",
    jsii_struct_bases=[BaseArchiveProps],
    name_mapping={
        "event_pattern": "eventPattern",
        "archive_name": "archiveName",
        "description": "description",
        "retention": "retention",
        "source_event_bus": "sourceEventBus",
    },
)
class ArchiveProps(BaseArchiveProps):
    def __init__(
        self,
        *,
        event_pattern: EventPattern,
        archive_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        retention: typing.Optional[_Duration_4839e8c3] = None,
        source_event_bus: IEventBus,
    ) -> None:
        '''The event archive properties.

        :param event_pattern: An event pattern to use to filter events sent to the archive.
        :param archive_name: The name of the archive. Default: - Automatically generated
        :param description: A description for the archive. Default: - none
        :param retention: The number of days to retain events for. Default value is 0. If set to 0, events are retained indefinitely. Default: - Infinite
        :param source_event_bus: The event source associated with the archive.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_events as events
            
            # detail: Any
            # event_bus: events.EventBus
            
            archive_props = events.ArchiveProps(
                event_pattern=events.EventPattern(
                    account=["account"],
                    detail={
                        "detail_key": detail
                    },
                    detail_type=["detailType"],
                    id=["id"],
                    region=["region"],
                    resources=["resources"],
                    source=["source"],
                    time=["time"],
                    version=["version"]
                ),
                source_event_bus=event_bus,
            
                # the properties below are optional
                archive_name="archiveName",
                description="description",
                retention=cdk.Duration.minutes(30)
            )
        '''
        if isinstance(event_pattern, dict):
            event_pattern = EventPattern(**event_pattern)
        self._values: typing.Dict[str, typing.Any] = {
            "event_pattern": event_pattern,
            "source_event_bus": source_event_bus,
        }
        if archive_name is not None:
            self._values["archive_name"] = archive_name
        if description is not None:
            self._values["description"] = description
        if retention is not None:
            self._values["retention"] = retention

    @builtins.property
    def event_pattern(self) -> EventPattern:
        '''An event pattern to use to filter events sent to the archive.'''
        result = self._values.get("event_pattern")
        assert result is not None, "Required property 'event_pattern' is missing"
        return typing.cast(EventPattern, result)

    @builtins.property
    def archive_name(self) -> typing.Optional[builtins.str]:
        '''The name of the archive.

        :default: - Automatically generated
        '''
        result = self._values.get("archive_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def description(self) -> typing.Optional[builtins.str]:
        '''A description for the archive.

        :default: - none
        '''
        result = self._values.get("description")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def retention(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The number of days to retain events for.

        Default value is 0. If set to 0, events are retained indefinitely.

        :default: - Infinite
        '''
        result = self._values.get("retention")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def source_event_bus(self) -> IEventBus:
        '''The event source associated with the archive.'''
        result = self._values.get("source_event_bus")
        assert result is not None, "Required property 'source_event_bus' is missing"
        return typing.cast(IEventBus, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ArchiveProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IConnection)
class Connection(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.Connection",
):
    '''Define an EventBridge Connection.

    :exampleMetadata: infused
    :resource: AWS::Events::Connection

    Example::

        connection = events.Connection(self, "Connection",
            authorization=events.Authorization.api_key("x-api-key", SecretValue.secrets_manager("ApiSecretName")),
            description="Connection with API Key x-api-key"
        )
        
        destination = events.ApiDestination(self, "Destination",
            connection=connection,
            endpoint="https://example.com",
            description="Calling example.com with API key x-api-key"
        )
        
        rule = events.Rule(self, "Rule",
            schedule=events.Schedule.rate(cdk.Duration.minutes(1)),
            targets=[targets.ApiDestination(destination)]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        authorization: Authorization,
        body_parameters: typing.Optional[typing.Mapping[builtins.str, HttpParameter]] = None,
        connection_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        header_parameters: typing.Optional[typing.Mapping[builtins.str, HttpParameter]] = None,
        query_string_parameters: typing.Optional[typing.Mapping[builtins.str, HttpParameter]] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param authorization: The authorization type for the connection.
        :param body_parameters: Additional string parameters to add to the invocation bodies. Default: - No additional parameters
        :param connection_name: The name of the connection. Default: - A name is automatically generated
        :param description: The name of the connection. Default: - none
        :param header_parameters: Additional string parameters to add to the invocation headers. Default: - No additional parameters
        :param query_string_parameters: Additional string parameters to add to the invocation query strings. Default: - No additional parameters
        '''
        props = ConnectionProps(
            authorization=authorization,
            body_parameters=body_parameters,
            connection_name=connection_name,
            description=description,
            header_parameters=header_parameters,
            query_string_parameters=query_string_parameters,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromConnectionAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_connection_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        connection_arn: builtins.str,
        connection_name: builtins.str,
        connection_secret_arn: builtins.str,
    ) -> IConnection:
        '''Import an existing connection resource.

        :param scope: Parent construct.
        :param id: Construct ID.
        :param connection_arn: The ARN of the connection created.
        :param connection_name: The Name for the connection.
        :param connection_secret_arn: The ARN for the secret created for the connection.
        '''
        attrs = ConnectionAttributes(
            connection_arn=connection_arn,
            connection_name=connection_name,
            connection_secret_arn=connection_secret_arn,
        )

        return typing.cast(IConnection, jsii.sinvoke(cls, "fromConnectionAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="fromEventBusArn") # type: ignore[misc]
    @builtins.classmethod
    def from_event_bus_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        connection_arn: builtins.str,
        connection_secret_arn: builtins.str,
    ) -> IConnection:
        '''Import an existing connection resource.

        :param scope: Parent construct.
        :param id: Construct ID.
        :param connection_arn: ARN of imported connection.
        :param connection_secret_arn: -
        '''
        return typing.cast(IConnection, jsii.sinvoke(cls, "fromEventBusArn", [scope, id, connection_arn, connection_secret_arn]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionArn")
    def connection_arn(self) -> builtins.str:
        '''The ARN of the connection created.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "connectionArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionName")
    def connection_name(self) -> builtins.str:
        '''The Name for the connection.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "connectionName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connectionSecretArn")
    def connection_secret_arn(self) -> builtins.str:
        '''The ARN for the secret created for the connection.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "connectionSecretArn"))


@jsii.implements(IEventBus)
class EventBus(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_events.EventBus",
):
    '''Define an EventBridge EventBus.

    :exampleMetadata: infused
    :resource: AWS::Events::EventBus

    Example::

        bus = events.EventBus(self, "bus",
            event_bus_name="MyCustomEventBus"
        )
        
        bus.archive("MyArchive",
            archive_name="MyCustomEventBusArchive",
            description="MyCustomerEventBus Archive",
            event_pattern=events.EventPattern(
                account=[Stack.of(self).account]
            ),
            retention=Duration.days(365)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        event_bus_name: typing.Optional[builtins.str] = None,
        event_source_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param event_bus_name: The name of the event bus you are creating Note: If 'eventSourceName' is passed in, you cannot set this. Default: - automatically generated name
        :param event_source_name: The partner event source to associate with this event bus resource Note: If 'eventBusName' is passed in, you cannot set this. Default: - no partner event source
        '''
        props = EventBusProps(
            event_bus_name=event_bus_name, event_source_name=event_source_name
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromEventBusArn") # type: ignore[misc]
    @builtins.classmethod
    def from_event_bus_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        event_bus_arn: builtins.str,
    ) -> IEventBus:
        '''Import an existing event bus resource.

        :param scope: Parent construct.
        :param id: Construct ID.
        :param event_bus_arn: ARN of imported event bus.
        '''
        return typing.cast(IEventBus, jsii.sinvoke(cls, "fromEventBusArn", [scope, id, event_bus_arn]))

    @jsii.member(jsii_name="fromEventBusAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_event_bus_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        event_bus_arn: builtins.str,
        event_bus_name: builtins.str,
        event_bus_policy: builtins.str,
        event_source_name: typing.Optional[builtins.str] = None,
    ) -> IEventBus:
        '''Import an existing event bus resource.

        :param scope: Parent construct.
        :param id: Construct ID.
        :param event_bus_arn: The ARN of this event bus resource.
        :param event_bus_name: The physical ID of this event bus resource.
        :param event_bus_policy: The JSON policy of this event bus resource.
        :param event_source_name: The partner event source to associate with this event bus resource. Default: - no partner event source
        '''
        attrs = EventBusAttributes(
            event_bus_arn=event_bus_arn,
            event_bus_name=event_bus_name,
            event_bus_policy=event_bus_policy,
            event_source_name=event_source_name,
        )

        return typing.cast(IEventBus, jsii.sinvoke(cls, "fromEventBusAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="fromEventBusName") # type: ignore[misc]
    @builtins.classmethod
    def from_event_bus_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        event_bus_name: builtins.str,
    ) -> IEventBus:
        '''Import an existing event bus resource.

        :param scope: Parent construct.
        :param id: Construct ID.
        :param event_bus_name: Name of imported event bus.
        '''
        return typing.cast(IEventBus, jsii.sinvoke(cls, "fromEventBusName", [scope, id, event_bus_name]))

    @jsii.member(jsii_name="grantAllPutEvents") # type: ignore[misc]
    @builtins.classmethod
    def grant_all_put_events(cls, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Permits an IAM Principal to send custom events to EventBridge so that they can be matched to rules.

        :param grantee: The principal (no-op if undefined).
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.sinvoke(cls, "grantAllPutEvents", [grantee]))

    @jsii.member(jsii_name="archive")
    def archive(
        self,
        id: builtins.str,
        *,
        event_pattern: EventPattern,
        archive_name: typing.Optional[builtins.str] = None,
        description: typing.Optional[builtins.str] = None,
        retention: typing.Optional[_Duration_4839e8c3] = None,
    ) -> Archive:
        '''Create an EventBridge archive to send events to.

        When you create an archive, incoming events might not immediately start being sent to the archive.
        Allow a short period of time for changes to take effect.

        :param id: -
        :param event_pattern: An event pattern to use to filter events sent to the archive.
        :param archive_name: The name of the archive. Default: - Automatically generated
        :param description: A description for the archive. Default: - none
        :param retention: The number of days to retain events for. Default value is 0. If set to 0, events are retained indefinitely. Default: - Infinite
        '''
        props = BaseArchiveProps(
            event_pattern=event_pattern,
            archive_name=archive_name,
            description=description,
            retention=retention,
        )

        return typing.cast(Archive, jsii.invoke(self, "archive", [id, props]))

    @jsii.member(jsii_name="grantPutEventsTo")
    def grant_put_events_to(self, grantee: _IGrantable_71c4f5de) -> _Grant_a7ae64f8:
        '''Grants an IAM Principal to send custom events to the eventBus so that they can be matched to rules.

        :param grantee: -
        '''
        return typing.cast(_Grant_a7ae64f8, jsii.invoke(self, "grantPutEventsTo", [grantee]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBusArn")
    def event_bus_arn(self) -> builtins.str:
        '''The ARN of the event bus, such as: arn:aws:events:us-east-2:123456789012:event-bus/aws.partner/PartnerName/acct1/repo1.'''
        return typing.cast(builtins.str, jsii.get(self, "eventBusArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBusName")
    def event_bus_name(self) -> builtins.str:
        '''The physical ID of this event bus resource.'''
        return typing.cast(builtins.str, jsii.get(self, "eventBusName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventBusPolicy")
    def event_bus_policy(self) -> builtins.str:
        '''The policy for the event bus in JSON form.'''
        return typing.cast(builtins.str, jsii.get(self, "eventBusPolicy"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="eventSourceName")
    def event_source_name(self) -> typing.Optional[builtins.str]:
        '''The name of the partner event source.'''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "eventSourceName"))


__all__ = [
    "ApiDestination",
    "ApiDestinationProps",
    "Archive",
    "ArchiveProps",
    "Authorization",
    "BaseArchiveProps",
    "CfnApiDestination",
    "CfnApiDestinationProps",
    "CfnArchive",
    "CfnArchiveProps",
    "CfnConnection",
    "CfnConnectionProps",
    "CfnEventBus",
    "CfnEventBusPolicy",
    "CfnEventBusPolicyProps",
    "CfnEventBusProps",
    "CfnRule",
    "CfnRuleProps",
    "Connection",
    "ConnectionAttributes",
    "ConnectionProps",
    "CronOptions",
    "EventBus",
    "EventBusAttributes",
    "EventBusProps",
    "EventField",
    "EventPattern",
    "HttpMethod",
    "HttpParameter",
    "IApiDestination",
    "IConnection",
    "IEventBus",
    "IRule",
    "IRuleTarget",
    "OAuthAuthorizationProps",
    "OnEventOptions",
    "Rule",
    "RuleProps",
    "RuleTargetConfig",
    "RuleTargetInput",
    "RuleTargetInputProperties",
    "Schedule",
]

publication.publish()
