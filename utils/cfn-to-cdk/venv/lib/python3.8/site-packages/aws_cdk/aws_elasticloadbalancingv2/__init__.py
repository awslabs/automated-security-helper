'''
# Amazon Elastic Load Balancing V2 Construct Library

The `@aws-cdk/aws-elasticloadbalancingv2` package provides constructs for
configuring application and network load balancers.

For more information, see the AWS documentation for
[Application Load Balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html)
and [Network Load Balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/introduction.html).

## Defining an Application Load Balancer

You define an application load balancer by creating an instance of
`ApplicationLoadBalancer`, adding a Listener to the load balancer
and adding Targets to the Listener:

```python
from aws_cdk.aws_autoscaling import AutoScalingGroup
# asg: AutoScalingGroup

# vpc: ec2.Vpc


# Create the load balancer in a VPC. 'internetFacing' is 'false'
# by default, which creates an internal load balancer.
lb = elbv2.ApplicationLoadBalancer(self, "LB",
    vpc=vpc,
    internet_facing=True
)

# Add a listener and open up the load balancer's security group
# to the world.
listener = lb.add_listener("Listener",
    port=80,

    # 'open: true' is the default, you can leave it out if you want. Set it
    # to 'false' and use `listener.connections` if you want to be selective
    # about who can access the load balancer.
    open=True
)

# Create an AutoScaling group and add it as a load balancing
# target to the listener.
listener.add_targets("ApplicationFleet",
    port=8080,
    targets=[asg]
)
```

The security groups of the load balancer and the target are automatically
updated to allow the network traffic.

One (or more) security groups can be associated with the load balancer;
if a security group isn't provided, one will be automatically created.

```python
# vpc: ec2.Vpc


security_group1 = ec2.SecurityGroup(self, "SecurityGroup1", vpc=vpc)
lb = elbv2.ApplicationLoadBalancer(self, "LB",
    vpc=vpc,
    internet_facing=True,
    security_group=security_group1
)

security_group2 = ec2.SecurityGroup(self, "SecurityGroup2", vpc=vpc)
lb.add_security_group(security_group2)
```

### Conditions

It's possible to route traffic to targets based on conditions in the incoming
HTTP request. For example, the following will route requests to the indicated
AutoScalingGroup only if the requested host in the request is either for
`example.com/ok` or `example.com/path`:

```python
# listener: elbv2.ApplicationListener
# asg: autoscaling.AutoScalingGroup


listener.add_targets("Example.Com Fleet",
    priority=10,
    conditions=[
        elbv2.ListenerCondition.host_headers(["example.com"]),
        elbv2.ListenerCondition.path_patterns(["/ok", "/path"])
    ],
    port=8080,
    targets=[asg]
)
```

A target with a condition contains either `pathPatterns` or `hostHeader`, or
both. If both are specified, both conditions must be met for the requests to
be routed to the given target. `priority` is a required field when you add
targets with conditions. The lowest number wins.

Every listener must have at least one target without conditions, which is
where all requests that didn't match any of the conditions will be sent.

### Convenience methods and more complex Actions

Routing traffic from a Load Balancer to a Target involves the following steps:

* Create a Target Group, register the Target into the Target Group
* Add an Action to the Listener which forwards traffic to the Target Group.

A new listener can be added to the Load Balancer by calling `addListener()`.
Listeners that have been added to the load balancer can be listed using the
`listeners` property.  Note that the `listeners` property will throw an Error
for imported or looked up Load Balancers.

Various methods on the `Listener` take care of this work for you to a greater
or lesser extent:

* `addTargets()` performs both steps: automatically creates a Target Group and the
  required Action.
* `addTargetGroups()` gives you more control: you create the Target Group (or
  Target Groups) yourself and the method creates Action that routes traffic to
  the Target Groups.
* `addAction()` gives you full control: you supply the Action and wire it up
  to the Target Groups yourself (or access one of the other ELB routing features).

Using `addAction()` gives you access to some of the features of an Elastic Load
Balancer that the other two convenience methods don't:

* **Routing stickiness**: use `ListenerAction.forward()` and supply a
  `stickinessDuration` to make sure requests are routed to the same target group
  for a given duration.
* **Weighted Target Groups**: use `ListenerAction.weightedForward()`
  to give different weights to different target groups.
* **Fixed Responses**: use `ListenerAction.fixedResponse()` to serve
  a static response (ALB only).
* **Redirects**: use `ListenerAction.redirect()` to serve an HTTP
  redirect response (ALB only).
* **Authentication**: use `ListenerAction.authenticateOidc()` to
  perform OpenID authentication before serving a request (see the
  `@aws-cdk/aws-elasticloadbalancingv2-actions` package for direct authentication
  integration with Cognito) (ALB only).

Here's an example of serving a fixed response at the `/ok` URL:

```python
# listener: elbv2.ApplicationListener


listener.add_action("Fixed",
    priority=10,
    conditions=[
        elbv2.ListenerCondition.path_patterns(["/ok"])
    ],
    action=elbv2.ListenerAction.fixed_response(200,
        content_type=elbv2.ContentType.TEXT_PLAIN,
        message_body="OK"
    )
)
```

Here's an example of using OIDC authentication before forwarding to a TargetGroup:

```python
# listener: elbv2.ApplicationListener
# my_target_group: elbv2.ApplicationTargetGroup


listener.add_action("DefaultAction",
    action=elbv2.ListenerAction.authenticate_oidc(
        authorization_endpoint="https://example.com/openid",
        # Other OIDC properties here
        client_id="...",
        client_secret=SecretValue.secrets_manager("..."),
        issuer="...",
        token_endpoint="...",
        user_info_endpoint="...",

        # Next
        next=elbv2.ListenerAction.forward([my_target_group])
    )
)
```

If you just want to redirect all incoming traffic on one port to another port, you can use the following code:

```python
# lb: elbv2.ApplicationLoadBalancer


lb.add_redirect(
    source_protocol=elbv2.ApplicationProtocol.HTTPS,
    source_port=8443,
    target_protocol=elbv2.ApplicationProtocol.HTTP,
    target_port=8080
)
```

If you do not provide any options for this method, it redirects HTTP port 80 to HTTPS port 443.

By default all ingress traffic will be allowed on the source port. If you want to be more selective with your
ingress rules then set `open: false` and use the listener's `connections` object to selectively grant access to the listener.

## Defining a Network Load Balancer

Network Load Balancers are defined in a similar way to Application Load
Balancers:

```python
# vpc: ec2.Vpc
# asg: autoscaling.AutoScalingGroup


# Create the load balancer in a VPC. 'internetFacing' is 'false'
# by default, which creates an internal load balancer.
lb = elbv2.NetworkLoadBalancer(self, "LB",
    vpc=vpc,
    internet_facing=True
)

# Add a listener on a particular port.
listener = lb.add_listener("Listener",
    port=443
)

# Add targets on a particular port.
listener.add_targets("AppFleet",
    port=443,
    targets=[asg]
)
```

One thing to keep in mind is that network load balancers do not have security
groups, and no automatic security group configuration is done for you. You will
have to configure the security groups of the target yourself to allow traffic by
clients and/or load balancer instances, depending on your target types.  See
[Target Groups for your Network Load
Balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html)
and [Register targets with your Target
Group](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/target-group-register-targets.html)
for more information.

## Targets and Target Groups

Application and Network Load Balancers organize load balancing targets in Target
Groups. If you add your balancing targets (such as AutoScalingGroups, ECS
services or individual instances) to your listener directly, the appropriate
`TargetGroup` will be automatically created for you.

If you need more control over the Target Groups created, create an instance of
`ApplicationTargetGroup` or `NetworkTargetGroup`, add the members you desire,
and add it to the listener by calling `addTargetGroups` instead of `addTargets`.

`addTargets()` will always return the Target Group it just created for you:

```python
# listener: elbv2.NetworkListener
# asg1: autoscaling.AutoScalingGroup
# asg2: autoscaling.AutoScalingGroup


group = listener.add_targets("AppFleet",
    port=443,
    targets=[asg1]
)

group.add_target(asg2)
```

### Sticky sessions for your Application Load Balancer

By default, an Application Load Balancer routes each request independently to a registered target based on the chosen load-balancing algorithm. However, you can use the sticky session feature (also known as session affinity) to enable the load balancer to bind a user's session to a specific target. This ensures that all requests from the user during the session are sent to the same target. This feature is useful for servers that maintain state information in order to provide a continuous experience to clients. To use sticky sessions, the client must support cookies.

Application Load Balancers support both duration-based cookies (`lb_cookie`) and application-based cookies (`app_cookie`). The key to managing sticky sessions is determining how long your load balancer should consistently route the user's request to the same target. Sticky sessions are enabled at the target group level. You can use a combination of duration-based stickiness, application-based stickiness, and no stickiness across all of your target groups.

```python
# vpc: ec2.Vpc


# Target group with duration-based stickiness with load-balancer generated cookie
tg1 = elbv2.ApplicationTargetGroup(self, "TG1",
    target_type=elbv2.TargetType.INSTANCE,
    port=80,
    stickiness_cookie_duration=Duration.minutes(5),
    vpc=vpc
)

# Target group with application-based stickiness
tg2 = elbv2.ApplicationTargetGroup(self, "TG2",
    target_type=elbv2.TargetType.INSTANCE,
    port=80,
    stickiness_cookie_duration=Duration.minutes(5),
    stickiness_cookie_name="MyDeliciousCookie",
    vpc=vpc
)
```

For more information see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/sticky-sessions.html#application-based-stickiness

### Setting the target group protocol version

By default, Application Load Balancers send requests to targets using HTTP/1.1. You can use the [protocol version](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#target-group-protocol-version) to send requests to targets using HTTP/2 or gRPC.

```python
# vpc: ec2.Vpc


tg = elbv2.ApplicationTargetGroup(self, "TG",
    target_type=elbv2.TargetType.IP,
    port=50051,
    protocol=elbv2.ApplicationProtocol.HTTP,
    protocol_version=elbv2.ApplicationProtocolVersion.GRPC,
    health_check=elbv2.HealthCheck(
        enabled=True,
        healthy_grpc_codes="0-99"
    ),
    vpc=vpc
)
```

## Using Lambda Targets

To use a Lambda Function as a target, use the integration class in the
`@aws-cdk/aws-elasticloadbalancingv2-targets` package:

```python
import aws_cdk.aws_lambda as lambda_
import aws_cdk.aws_elasticloadbalancingv2_targets as targets

# lambda_function: lambda.Function
# lb: elbv2.ApplicationLoadBalancer


listener = lb.add_listener("Listener", port=80)
listener.add_targets("Targets",
    targets=[targets.LambdaTarget(lambda_function)],

    # For Lambda Targets, you need to explicitly enable health checks if you
    # want them.
    health_check=elbv2.HealthCheck(
        enabled=True
    )
)
```

Only a single Lambda function can be added to a single listener rule.

## Using Application Load Balancer Targets

To use a single application load balancer as a target for the network load balancer, use the integration class in the
`@aws-cdk/aws-elasticloadbalancingv2-targets` package:

```python
import aws_cdk.aws_elasticloadbalancingv2_targets as targets
import aws_cdk.aws_ecs as ecs
import aws_cdk.aws_ecs_patterns as patterns

# vpc: ec2.Vpc


task = ecs.FargateTaskDefinition(self, "Task", cpu=256, memory_limit_mi_b=512)
task.add_container("nginx",
    image=ecs.ContainerImage.from_registry("public.ecr.aws/nginx/nginx:latest"),
    port_mappings=[ecs.PortMapping(container_port=80)]
)

svc = patterns.ApplicationLoadBalancedFargateService(self, "Service",
    vpc=vpc,
    task_definition=task,
    public_load_balancer=False
)

nlb = elbv2.NetworkLoadBalancer(self, "Nlb",
    vpc=vpc,
    cross_zone_enabled=True,
    internet_facing=True
)

listener = nlb.add_listener("listener", port=80)

listener.add_targets("Targets",
    targets=[targets.AlbTarget(svc.load_balancer, 80)],
    port=80
)

CfnOutput(self, "NlbEndpoint", value=f"http://{nlb.loadBalancerDnsName}")
```

Only the network load balancer is allowed to add the application load balancer as the target.

## Configuring Health Checks

Health checks are configured upon creation of a target group:

```python
# listener: elbv2.ApplicationListener
# asg: autoscaling.AutoScalingGroup


listener.add_targets("AppFleet",
    port=8080,
    targets=[asg],
    health_check=elbv2.HealthCheck(
        path="/ping",
        interval=Duration.minutes(1)
    )
)
```

The health check can also be configured after creation by calling
`configureHealthCheck()` on the created object.

No attempts are made to configure security groups for the port you're
configuring a health check for, but if the health check is on the same port
you're routing traffic to, the security group already allows the traffic.
If not, you will have to configure the security groups appropriately:

```python
# lb: elbv2.ApplicationLoadBalancer
# listener: elbv2.ApplicationListener
# asg: autoscaling.AutoScalingGroup


listener.add_targets("AppFleet",
    port=8080,
    targets=[asg],
    health_check=elbv2.HealthCheck(
        port="8088"
    )
)

asg.connections.allow_from(lb, ec2.Port.tcp(8088))
```

## Using a Load Balancer from a different Stack

If you want to put your Load Balancer and the Targets it is load balancing to in
different stacks, you may not be able to use the convenience methods
`loadBalancer.addListener()` and `listener.addTargets()`.

The reason is that these methods will create resources in the same Stack as the
object they're called on, which may lead to cyclic references between stacks.
Instead, you will have to create an `ApplicationListener` in the target stack,
or an empty `TargetGroup` in the load balancer stack that you attach your
service to.

For an example of the alternatives while load balancing to an ECS service, see the
[ecs/cross-stack-load-balancer
example](https://github.com/aws-samples/aws-cdk-examples/tree/master/typescript/ecs/cross-stack-load-balancer/).

## Protocol for Load Balancer Targets

Constructs that want to be a load balancer target should implement
`IApplicationLoadBalancerTarget` and/or `INetworkLoadBalancerTarget`, and
provide an implementation for the function `attachToXxxTargetGroup()`, which can
call functions on the load balancer and should return metadata about the
load balancing target:

```python
class MyTarget(elbv2.IApplicationLoadBalancerTarget):
    def attach_to_application_target_group(self, target_group):
        # If we need to add security group rules
        # targetGroup.registerConnectable(...);
        return elbv2.LoadBalancerTargetProps(
            target_type=elbv2.TargetType.IP,
            target_json={"id": "1.2.3.4", "port": 8080}
        )
```

`targetType` should be one of `Instance` or `Ip`. If the target can be
directly added to the target group, `targetJson` should contain the `id` of
the target (either instance ID or IP address depending on the type) and
optionally a `port` or `availabilityZone` override.

Application load balancer targets can call `registerConnectable()` on the
target group to register themselves for addition to the load balancer's security
group rules.

If your load balancer target requires that the TargetGroup has been
associated with a LoadBalancer before registration can happen (such as is the
case for ECS Services for example), take a resource dependency on
`targetGroup.loadBalancerAttached` as follows:

```python
# resource: Resource
# target_group: elbv2.ApplicationTargetGroup


# Make sure that the listener has been created, and so the TargetGroup
# has been associated with the LoadBalancer, before 'resource' is created.

Node.of(resource).add_dependency(target_group.load_balancer_attached)
```

## Looking up Load Balancers and Listeners

You may look up load balancers and load balancer listeners by using one of the
following lookup methods:

* `ApplicationLoadBalancer.fromlookup(options)` - Look up an application load
  balancer.
* `ApplicationListener.fromLookup(options)` - Look up an application load
  balancer listener.
* `NetworkLoadBalancer.fromLookup(options)` - Look up a network load balancer.
* `NetworkListener.fromLookup(options)` - Look up a network load balancer
  listener.

### Load Balancer lookup options

You may look up a load balancer by ARN or by associated tags. When you look a
load balancer up by ARN, that load balancer will be returned unless CDK detects
that the load balancer is of the wrong type. When you look up a load balancer by
tags, CDK will return the load balancer matching all specified tags. If more
than one load balancer matches, CDK will throw an error requesting that you
provide more specific criteria.

**Look up a Application Load Balancer by ARN**

```python
load_balancer = elbv2.ApplicationLoadBalancer.from_lookup(self, "ALB",
    load_balancer_arn="arn:aws:elasticloadbalancing:us-east-2:123456789012:loadbalancer/app/my-load-balancer/1234567890123456"
)
```

**Look up an Application Load Balancer by tags**

```python
load_balancer = elbv2.ApplicationLoadBalancer.from_lookup(self, "ALB",
    load_balancer_tags={
        # Finds a load balancer matching all tags.
        "some": "tag",
        "someother": "tag"
    }
)
```

## Load Balancer Listener lookup options

You may look up a load balancer listener by the following criteria:

* Associated load balancer ARN
* Associated load balancer tags
* Listener ARN
* Listener port
* Listener protocol

The lookup method will return the matching listener. If more than one listener
matches, CDK will throw an error requesting that you specify additional
criteria.

**Look up a Listener by associated Load Balancer, Port, and Protocol**

```python
listener = elbv2.ApplicationListener.from_lookup(self, "ALBListener",
    load_balancer_arn="arn:aws:elasticloadbalancing:us-east-2:123456789012:loadbalancer/app/my-load-balancer/1234567890123456",
    listener_protocol=elbv2.ApplicationProtocol.HTTPS,
    listener_port=443
)
```

**Look up a Listener by associated Load Balancer Tag, Port, and Protocol**

```python
listener = elbv2.ApplicationListener.from_lookup(self, "ALBListener",
    load_balancer_tags={
        "Cluster": "MyClusterName"
    },
    listener_protocol=elbv2.ApplicationProtocol.HTTPS,
    listener_port=443
)
```

**Look up a Network Listener by associated Load Balancer Tag, Port, and Protocol**

```python
listener = elbv2.NetworkListener.from_lookup(self, "ALBListener",
    load_balancer_tags={
        "Cluster": "MyClusterName"
    },
    listener_protocol=elbv2.Protocol.TCP,
    listener_port=12345
)
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
    IResource as _IResource_c80c4260,
    Resource as _Resource_45bc6135,
    SecretValue as _SecretValue_3dd0ddae,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_certificatemanager import ICertificate as _ICertificate_c194c70b
from ..aws_cloudwatch import (
    Metric as _Metric_e396a4dc,
    MetricOptions as _MetricOptions_1788b62f,
    Unit as _Unit_61bc6f70,
)
from ..aws_ec2 import (
    Connections as _Connections_0f31fce8,
    IConnectable as _IConnectable_10015a05,
    ISecurityGroup as _ISecurityGroup_acf8a799,
    IVpc as _IVpc_f30d5663,
    IVpcEndpointServiceLoadBalancer as _IVpcEndpointServiceLoadBalancer_34cbc6e3,
    Port as _Port_85922693,
    SubnetSelection as _SubnetSelection_e57d76df,
)
from ..aws_s3 import IBucket as _IBucket_42e086fd


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.AddNetworkActionProps",
    jsii_struct_bases=[],
    name_mapping={"action": "action"},
)
class AddNetworkActionProps:
    def __init__(self, *, action: "NetworkListenerAction") -> None:
        '''Properties for adding a new action to a listener.

        :param action: Action to perform.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # network_listener_action: elbv2.NetworkListenerAction
            
            add_network_action_props = elbv2.AddNetworkActionProps(
                action=network_listener_action
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "action": action,
        }

    @builtins.property
    def action(self) -> "NetworkListenerAction":
        '''Action to perform.'''
        result = self._values.get("action")
        assert result is not None, "Required property 'action' is missing"
        return typing.cast("NetworkListenerAction", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AddNetworkActionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.AddNetworkTargetsProps",
    jsii_struct_bases=[],
    name_mapping={
        "port": "port",
        "deregistration_delay": "deregistrationDelay",
        "health_check": "healthCheck",
        "preserve_client_ip": "preserveClientIp",
        "protocol": "protocol",
        "proxy_protocol_v2": "proxyProtocolV2",
        "target_group_name": "targetGroupName",
        "targets": "targets",
    },
)
class AddNetworkTargetsProps:
    def __init__(
        self,
        *,
        port: jsii.Number,
        deregistration_delay: typing.Optional[_Duration_4839e8c3] = None,
        health_check: typing.Optional["HealthCheck"] = None,
        preserve_client_ip: typing.Optional[builtins.bool] = None,
        protocol: typing.Optional["Protocol"] = None,
        proxy_protocol_v2: typing.Optional[builtins.bool] = None,
        target_group_name: typing.Optional[builtins.str] = None,
        targets: typing.Optional[typing.Sequence["INetworkLoadBalancerTarget"]] = None,
    ) -> None:
        '''Properties for adding new network targets to a listener.

        :param port: The port on which the listener listens for requests. Default: Determined from protocol if known
        :param deregistration_delay: The amount of time for Elastic Load Balancing to wait before deregistering a target. The range is 0-3600 seconds. Default: Duration.minutes(5)
        :param health_check: Health check configuration. Default: No health check
        :param preserve_client_ip: Indicates whether client IP preservation is enabled. Default: false if the target group type is IP address and the target group protocol is TCP or TLS. Otherwise, true.
        :param protocol: Protocol for target group, expects TCP, TLS, UDP, or TCP_UDP. Default: - inherits the protocol of the listener
        :param proxy_protocol_v2: Indicates whether Proxy Protocol version 2 is enabled. Default: false
        :param target_group_name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. Default: Automatically generated
        :param targets: The targets to add to this target group. Can be ``Instance``, ``IPAddress``, or any self-registering load balancing target. If you use either ``Instance`` or ``IPAddress`` as targets, all target must be of the same type.

        :exampleMetadata: infused

        Example::

            from aws_cdk.aws_apigatewayv2_integrations_alpha import HttpNlbIntegration
            
            
            vpc = ec2.Vpc(self, "VPC")
            lb = elbv2.NetworkLoadBalancer(self, "lb", vpc=vpc)
            listener = lb.add_listener("listener", port=80)
            listener.add_targets("target",
                port=80
            )
            
            http_endpoint = apigwv2.HttpApi(self, "HttpProxyPrivateApi",
                default_integration=HttpNlbIntegration("DefaultIntegration", listener)
            )
        '''
        if isinstance(health_check, dict):
            health_check = HealthCheck(**health_check)
        self._values: typing.Dict[str, typing.Any] = {
            "port": port,
        }
        if deregistration_delay is not None:
            self._values["deregistration_delay"] = deregistration_delay
        if health_check is not None:
            self._values["health_check"] = health_check
        if preserve_client_ip is not None:
            self._values["preserve_client_ip"] = preserve_client_ip
        if protocol is not None:
            self._values["protocol"] = protocol
        if proxy_protocol_v2 is not None:
            self._values["proxy_protocol_v2"] = proxy_protocol_v2
        if target_group_name is not None:
            self._values["target_group_name"] = target_group_name
        if targets is not None:
            self._values["targets"] = targets

    @builtins.property
    def port(self) -> jsii.Number:
        '''The port on which the listener listens for requests.

        :default: Determined from protocol if known
        '''
        result = self._values.get("port")
        assert result is not None, "Required property 'port' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def deregistration_delay(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The amount of time for Elastic Load Balancing to wait before deregistering a target.

        The range is 0-3600 seconds.

        :default: Duration.minutes(5)
        '''
        result = self._values.get("deregistration_delay")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def health_check(self) -> typing.Optional["HealthCheck"]:
        '''Health check configuration.

        :default: No health check
        '''
        result = self._values.get("health_check")
        return typing.cast(typing.Optional["HealthCheck"], result)

    @builtins.property
    def preserve_client_ip(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether client IP preservation is enabled.

        :default:

        false if the target group type is IP address and the
        target group protocol is TCP or TLS. Otherwise, true.
        '''
        result = self._values.get("preserve_client_ip")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def protocol(self) -> typing.Optional["Protocol"]:
        '''Protocol for target group, expects TCP, TLS, UDP, or TCP_UDP.

        :default: - inherits the protocol of the listener
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional["Protocol"], result)

    @builtins.property
    def proxy_protocol_v2(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether Proxy Protocol version 2 is enabled.

        :default: false
        '''
        result = self._values.get("proxy_protocol_v2")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def target_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the target group.

        This name must be unique per region per account, can have a maximum of
        32 characters, must contain only alphanumeric characters or hyphens, and
        must not begin or end with a hyphen.

        :default: Automatically generated
        '''
        result = self._values.get("target_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def targets(self) -> typing.Optional[typing.List["INetworkLoadBalancerTarget"]]:
        '''The targets to add to this target group.

        Can be ``Instance``, ``IPAddress``, or any self-registering load balancing
        target. If you use either ``Instance`` or ``IPAddress`` as targets, all
        target must be of the same type.
        '''
        result = self._values.get("targets")
        return typing.cast(typing.Optional[typing.List["INetworkLoadBalancerTarget"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AddNetworkTargetsProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.AddRuleProps",
    jsii_struct_bases=[],
    name_mapping={"conditions": "conditions", "priority": "priority"},
)
class AddRuleProps:
    def __init__(
        self,
        *,
        conditions: typing.Optional[typing.Sequence["ListenerCondition"]] = None,
        priority: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Properties for adding a conditional load balancing rule.

        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param priority: Priority of this target group. The rule with the lowest priority will be used for every request. If priority is not given, these target groups will be added as defaults, and must not have conditions. Priorities must be unique. Default: Target groups are used as defaults

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # listener_condition: elbv2.ListenerCondition
            
            add_rule_props = elbv2.AddRuleProps(
                conditions=[listener_condition],
                priority=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if conditions is not None:
            self._values["conditions"] = conditions
        if priority is not None:
            self._values["priority"] = priority

    @builtins.property
    def conditions(self) -> typing.Optional[typing.List["ListenerCondition"]]:
        '''Rule applies if matches the conditions.

        :default: - No conditions.

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html
        '''
        result = self._values.get("conditions")
        return typing.cast(typing.Optional[typing.List["ListenerCondition"]], result)

    @builtins.property
    def priority(self) -> typing.Optional[jsii.Number]:
        '''Priority of this target group.

        The rule with the lowest priority will be used for every request.
        If priority is not given, these target groups will be added as
        defaults, and must not have conditions.

        Priorities must be unique.

        :default: Target groups are used as defaults
        '''
        result = self._values.get("priority")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AddRuleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.AlpnPolicy")
class AlpnPolicy(enum.Enum):
    '''Application-Layer Protocol Negotiation Policies for network load balancers.

    Which protocols should be used over a secure connection.
    '''

    HTTP1_ONLY = "HTTP1_ONLY"
    '''Negotiate only HTTP/1.*. The ALPN preference list is http/1.1, http/1.0.'''
    HTTP2_ONLY = "HTTP2_ONLY"
    '''Negotiate only HTTP/2.

    The ALPN preference list is h2
    '''
    HTTP2_OPTIONAL = "HTTP2_OPTIONAL"
    '''Prefer HTTP/1.* over HTTP/2 (which can be useful for HTTP/2 testing). The ALPN preference list is http/1.1, http/1.0, h2.'''
    HTTP2_PREFERRED = "HTTP2_PREFERRED"
    '''Prefer HTTP/2 over HTTP/1.*. The ALPN preference list is h2, http/1.1, http/1.0.'''
    NONE = "NONE"
    '''Do not negotiate ALPN.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationListenerAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "listener_arn": "listenerArn",
        "default_port": "defaultPort",
        "security_group": "securityGroup",
    },
)
class ApplicationListenerAttributes:
    def __init__(
        self,
        *,
        listener_arn: builtins.str,
        default_port: typing.Optional[jsii.Number] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
    ) -> None:
        '''Properties to reference an existing listener.

        :param listener_arn: ARN of the listener.
        :param default_port: The default port on which this listener is listening.
        :param security_group: Security group of the load balancer this listener is associated with.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # security_group: ec2.SecurityGroup
            
            application_listener_attributes = elbv2.ApplicationListenerAttributes(
                listener_arn="listenerArn",
            
                # the properties below are optional
                default_port=123,
                security_group=security_group
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "listener_arn": listener_arn,
        }
        if default_port is not None:
            self._values["default_port"] = default_port
        if security_group is not None:
            self._values["security_group"] = security_group

    @builtins.property
    def listener_arn(self) -> builtins.str:
        '''ARN of the listener.'''
        result = self._values.get("listener_arn")
        assert result is not None, "Required property 'listener_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def default_port(self) -> typing.Optional[jsii.Number]:
        '''The default port on which this listener is listening.'''
        result = self._values.get("default_port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''Security group of the load balancer this listener is associated with.'''
        result = self._values.get("security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApplicationListenerAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class ApplicationListenerCertificate(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationListenerCertificate",
):
    '''Add certificates to a listener.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticloadbalancingv2 as elbv2
        
        # application_listener: elbv2.ApplicationListener
        # listener_certificate: elbv2.ListenerCertificate
        
        application_listener_certificate = elbv2.ApplicationListenerCertificate(self, "MyApplicationListenerCertificate",
            listener=application_listener,
        
            # the properties below are optional
            certificates=[listener_certificate]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        listener: "IApplicationListener",
        certificates: typing.Optional[typing.Sequence["IListenerCertificate"]] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param listener: The listener to attach the rule to.
        :param certificates: Certificates to attach. Duplicates are not allowed. Default: - One of 'certificates' and 'certificateArns' is required.
        '''
        props = ApplicationListenerCertificateProps(
            listener=listener, certificates=certificates
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationListenerCertificateProps",
    jsii_struct_bases=[],
    name_mapping={"listener": "listener", "certificates": "certificates"},
)
class ApplicationListenerCertificateProps:
    def __init__(
        self,
        *,
        listener: "IApplicationListener",
        certificates: typing.Optional[typing.Sequence["IListenerCertificate"]] = None,
    ) -> None:
        '''Properties for adding a set of certificates to a listener.

        :param listener: The listener to attach the rule to.
        :param certificates: Certificates to attach. Duplicates are not allowed. Default: - One of 'certificates' and 'certificateArns' is required.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # application_listener: elbv2.ApplicationListener
            # listener_certificate: elbv2.ListenerCertificate
            
            application_listener_certificate_props = elbv2.ApplicationListenerCertificateProps(
                listener=application_listener,
            
                # the properties below are optional
                certificates=[listener_certificate]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "listener": listener,
        }
        if certificates is not None:
            self._values["certificates"] = certificates

    @builtins.property
    def listener(self) -> "IApplicationListener":
        '''The listener to attach the rule to.'''
        result = self._values.get("listener")
        assert result is not None, "Required property 'listener' is missing"
        return typing.cast("IApplicationListener", result)

    @builtins.property
    def certificates(self) -> typing.Optional[typing.List["IListenerCertificate"]]:
        '''Certificates to attach.

        Duplicates are not allowed.

        :default: - One of 'certificates' and 'certificateArns' is required.
        '''
        result = self._values.get("certificates")
        return typing.cast(typing.Optional[typing.List["IListenerCertificate"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApplicationListenerCertificateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class ApplicationListenerRule(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationListenerRule",
):
    '''Define a new listener rule.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticloadbalancingv2 as elbv2
        
        # application_listener: elbv2.ApplicationListener
        # application_target_group: elbv2.ApplicationTargetGroup
        # listener_action: elbv2.ListenerAction
        # listener_condition: elbv2.ListenerCondition
        
        application_listener_rule = elbv2.ApplicationListenerRule(self, "MyApplicationListenerRule",
            listener=application_listener,
            priority=123,
        
            # the properties below are optional
            action=listener_action,
            conditions=[listener_condition],
            target_groups=[application_target_group]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        listener: "IApplicationListener",
        priority: jsii.Number,
        action: typing.Optional["ListenerAction"] = None,
        conditions: typing.Optional[typing.Sequence["ListenerCondition"]] = None,
        target_groups: typing.Optional[typing.Sequence["IApplicationTargetGroup"]] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param listener: The listener to attach the rule to.
        :param priority: Priority of the rule. The rule with the lowest priority will be used for every request. Priorities must be unique.
        :param action: Action to perform when requests are received. Only one of ``action``, ``fixedResponse``, ``redirectResponse`` or ``targetGroups`` can be specified. Default: - No action
        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param target_groups: Target groups to forward requests to. Only one of ``action``, ``fixedResponse``, ``redirectResponse`` or ``targetGroups`` can be specified. Implies a ``forward`` action. Default: - No target groups.
        '''
        props = ApplicationListenerRuleProps(
            listener=listener,
            priority=priority,
            action=action,
            conditions=conditions,
            target_groups=target_groups,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="addCondition")
    def add_condition(self, condition: "ListenerCondition") -> None:
        '''Add a non-standard condition to this rule.

        :param condition: -
        '''
        return typing.cast(None, jsii.invoke(self, "addCondition", [condition]))

    @jsii.member(jsii_name="configureAction")
    def configure_action(self, action: "ListenerAction") -> None:
        '''Configure the action to perform for this rule.

        :param action: -
        '''
        return typing.cast(None, jsii.invoke(self, "configureAction", [action]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="listenerRuleArn")
    def listener_rule_arn(self) -> builtins.str:
        '''The ARN of this rule.'''
        return typing.cast(builtins.str, jsii.get(self, "listenerRuleArn"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationLoadBalancerAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "load_balancer_arn": "loadBalancerArn",
        "security_group_id": "securityGroupId",
        "load_balancer_canonical_hosted_zone_id": "loadBalancerCanonicalHostedZoneId",
        "load_balancer_dns_name": "loadBalancerDnsName",
        "security_group_allows_all_outbound": "securityGroupAllowsAllOutbound",
        "vpc": "vpc",
    },
)
class ApplicationLoadBalancerAttributes:
    def __init__(
        self,
        *,
        load_balancer_arn: builtins.str,
        security_group_id: builtins.str,
        load_balancer_canonical_hosted_zone_id: typing.Optional[builtins.str] = None,
        load_balancer_dns_name: typing.Optional[builtins.str] = None,
        security_group_allows_all_outbound: typing.Optional[builtins.bool] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> None:
        '''Properties to reference an existing load balancer.

        :param load_balancer_arn: ARN of the load balancer.
        :param security_group_id: ID of the load balancer's security group.
        :param load_balancer_canonical_hosted_zone_id: The canonical hosted zone ID of this load balancer. Default: - When not provided, LB cannot be used as Route53 Alias target.
        :param load_balancer_dns_name: The DNS name of this load balancer. Default: - When not provided, LB cannot be used as Route53 Alias target.
        :param security_group_allows_all_outbound: Whether the security group allows all outbound traffic or not. Unless set to ``false``, no egress rules will be added to the security group. Default: true
        :param vpc: The VPC this load balancer has been created in, if available. Default: - If the Load Balancer was imported and a VPC was not specified, the VPC is not available.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # vpc: ec2.Vpc
            
            application_load_balancer_attributes = elbv2.ApplicationLoadBalancerAttributes(
                load_balancer_arn="loadBalancerArn",
                security_group_id="securityGroupId",
            
                # the properties below are optional
                load_balancer_canonical_hosted_zone_id="loadBalancerCanonicalHostedZoneId",
                load_balancer_dns_name="loadBalancerDnsName",
                security_group_allows_all_outbound=False,
                vpc=vpc
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "load_balancer_arn": load_balancer_arn,
            "security_group_id": security_group_id,
        }
        if load_balancer_canonical_hosted_zone_id is not None:
            self._values["load_balancer_canonical_hosted_zone_id"] = load_balancer_canonical_hosted_zone_id
        if load_balancer_dns_name is not None:
            self._values["load_balancer_dns_name"] = load_balancer_dns_name
        if security_group_allows_all_outbound is not None:
            self._values["security_group_allows_all_outbound"] = security_group_allows_all_outbound
        if vpc is not None:
            self._values["vpc"] = vpc

    @builtins.property
    def load_balancer_arn(self) -> builtins.str:
        '''ARN of the load balancer.'''
        result = self._values.get("load_balancer_arn")
        assert result is not None, "Required property 'load_balancer_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def security_group_id(self) -> builtins.str:
        '''ID of the load balancer's security group.'''
        result = self._values.get("security_group_id")
        assert result is not None, "Required property 'security_group_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def load_balancer_canonical_hosted_zone_id(self) -> typing.Optional[builtins.str]:
        '''The canonical hosted zone ID of this load balancer.

        :default: - When not provided, LB cannot be used as Route53 Alias target.
        '''
        result = self._values.get("load_balancer_canonical_hosted_zone_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def load_balancer_dns_name(self) -> typing.Optional[builtins.str]:
        '''The DNS name of this load balancer.

        :default: - When not provided, LB cannot be used as Route53 Alias target.
        '''
        result = self._values.get("load_balancer_dns_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def security_group_allows_all_outbound(self) -> typing.Optional[builtins.bool]:
        '''Whether the security group allows all outbound traffic or not.

        Unless set to ``false``, no egress rules will be added to the security group.

        :default: true
        '''
        result = self._values.get("security_group_allows_all_outbound")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC this load balancer has been created in, if available.

        :default:

        - If the Load Balancer was imported and a VPC was not specified,
        the VPC is not available.
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApplicationLoadBalancerAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationLoadBalancerRedirectConfig",
    jsii_struct_bases=[],
    name_mapping={
        "open": "open",
        "source_port": "sourcePort",
        "source_protocol": "sourceProtocol",
        "target_port": "targetPort",
        "target_protocol": "targetProtocol",
    },
)
class ApplicationLoadBalancerRedirectConfig:
    def __init__(
        self,
        *,
        open: typing.Optional[builtins.bool] = None,
        source_port: typing.Optional[jsii.Number] = None,
        source_protocol: typing.Optional["ApplicationProtocol"] = None,
        target_port: typing.Optional[jsii.Number] = None,
        target_protocol: typing.Optional["ApplicationProtocol"] = None,
    ) -> None:
        '''Properties for a redirection config.

        :param open: Allow anyone to connect to this listener. If this is specified, the listener will be opened up to anyone who can reach it. For internal load balancers this is anyone in the same VPC. For public load balancers, this is anyone on the internet. If you want to be more selective about who can access this load balancer, set this to ``false`` and use the listener's ``connections`` object to selectively grant access to the listener. Default: true
        :param source_port: The port number to listen to. Default: 80
        :param source_protocol: The protocol of the listener being created. Default: HTTP
        :param target_port: The port number to redirect to. Default: 443
        :param target_protocol: The protocol of the redirection target. Default: HTTPS

        :exampleMetadata: infused

        Example::

            # lb: elbv2.ApplicationLoadBalancer
            
            
            lb.add_redirect(
                source_protocol=elbv2.ApplicationProtocol.HTTPS,
                source_port=8443,
                target_protocol=elbv2.ApplicationProtocol.HTTP,
                target_port=8080
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if open is not None:
            self._values["open"] = open
        if source_port is not None:
            self._values["source_port"] = source_port
        if source_protocol is not None:
            self._values["source_protocol"] = source_protocol
        if target_port is not None:
            self._values["target_port"] = target_port
        if target_protocol is not None:
            self._values["target_protocol"] = target_protocol

    @builtins.property
    def open(self) -> typing.Optional[builtins.bool]:
        '''Allow anyone to connect to this listener.

        If this is specified, the listener will be opened up to anyone who can reach it.
        For internal load balancers this is anyone in the same VPC. For public load
        balancers, this is anyone on the internet.

        If you want to be more selective about who can access this load
        balancer, set this to ``false`` and use the listener's ``connections``
        object to selectively grant access to the listener.

        :default: true
        '''
        result = self._values.get("open")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def source_port(self) -> typing.Optional[jsii.Number]:
        '''The port number to listen to.

        :default: 80
        '''
        result = self._values.get("source_port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def source_protocol(self) -> typing.Optional["ApplicationProtocol"]:
        '''The protocol of the listener being created.

        :default: HTTP
        '''
        result = self._values.get("source_protocol")
        return typing.cast(typing.Optional["ApplicationProtocol"], result)

    @builtins.property
    def target_port(self) -> typing.Optional[jsii.Number]:
        '''The port number to redirect to.

        :default: 443
        '''
        result = self._values.get("target_port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def target_protocol(self) -> typing.Optional["ApplicationProtocol"]:
        '''The protocol of the redirection target.

        :default: HTTPS
        '''
        result = self._values.get("target_protocol")
        return typing.cast(typing.Optional["ApplicationProtocol"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApplicationLoadBalancerRedirectConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationProtocol")
class ApplicationProtocol(enum.Enum):
    '''Load balancing protocol for application load balancers.

    :exampleMetadata: infused

    Example::

        # listener: elbv2.ApplicationListener
        # service: ecs.BaseService
        
        service.register_load_balancer_targets(
            container_name="web",
            container_port=80,
            new_target_group_id="ECS",
            listener=ecs.ListenerConfig.application_listener(listener,
                protocol=elbv2.ApplicationProtocol.HTTPS
            )
        )
    '''

    HTTP = "HTTP"
    '''HTTP.'''
    HTTPS = "HTTPS"
    '''HTTPS.'''


@jsii.enum(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationProtocolVersion"
)
class ApplicationProtocolVersion(enum.Enum):
    '''Load balancing protocol version for application load balancers.

    :exampleMetadata: infused

    Example::

        # vpc: ec2.Vpc
        
        
        tg = elbv2.ApplicationTargetGroup(self, "TG",
            target_type=elbv2.TargetType.IP,
            port=50051,
            protocol=elbv2.ApplicationProtocol.HTTP,
            protocol_version=elbv2.ApplicationProtocolVersion.GRPC,
            health_check=elbv2.HealthCheck(
                enabled=True,
                healthy_grpc_codes="0-99"
            ),
            vpc=vpc
        )
    '''

    GRPC = "GRPC"
    '''GRPC.'''
    HTTP1 = "HTTP1"
    '''HTTP1.'''
    HTTP2 = "HTTP2"
    '''HTTP2.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.AuthenticateOidcOptions",
    jsii_struct_bases=[],
    name_mapping={
        "authorization_endpoint": "authorizationEndpoint",
        "client_id": "clientId",
        "client_secret": "clientSecret",
        "issuer": "issuer",
        "next": "next",
        "token_endpoint": "tokenEndpoint",
        "user_info_endpoint": "userInfoEndpoint",
        "authentication_request_extra_params": "authenticationRequestExtraParams",
        "on_unauthenticated_request": "onUnauthenticatedRequest",
        "scope": "scope",
        "session_cookie_name": "sessionCookieName",
        "session_timeout": "sessionTimeout",
    },
)
class AuthenticateOidcOptions:
    def __init__(
        self,
        *,
        authorization_endpoint: builtins.str,
        client_id: builtins.str,
        client_secret: _SecretValue_3dd0ddae,
        issuer: builtins.str,
        next: "ListenerAction",
        token_endpoint: builtins.str,
        user_info_endpoint: builtins.str,
        authentication_request_extra_params: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        on_unauthenticated_request: typing.Optional["UnauthenticatedAction"] = None,
        scope: typing.Optional[builtins.str] = None,
        session_cookie_name: typing.Optional[builtins.str] = None,
        session_timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Options for ``ListenerAction.authenciateOidc()``.

        :param authorization_endpoint: The authorization endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
        :param client_id: The OAuth 2.0 client identifier.
        :param client_secret: The OAuth 2.0 client secret.
        :param issuer: The OIDC issuer identifier of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
        :param next: What action to execute next.
        :param token_endpoint: The token endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
        :param user_info_endpoint: The user info endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
        :param authentication_request_extra_params: The query parameters (up to 10) to include in the redirect request to the authorization endpoint. Default: - No extra parameters
        :param on_unauthenticated_request: The behavior if the user is not authenticated. Default: UnauthenticatedAction.AUTHENTICATE
        :param scope: The set of user claims to be requested from the IdP. To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP. Default: "openid"
        :param session_cookie_name: The name of the cookie used to maintain session information. Default: "AWSELBAuthSessionCookie"
        :param session_timeout: The maximum duration of the authentication session. Default: Duration.days(7)

        :exampleMetadata: infused

        Example::

            # listener: elbv2.ApplicationListener
            # my_target_group: elbv2.ApplicationTargetGroup
            
            
            listener.add_action("DefaultAction",
                action=elbv2.ListenerAction.authenticate_oidc(
                    authorization_endpoint="https://example.com/openid",
                    # Other OIDC properties here
                    client_id="...",
                    client_secret=SecretValue.secrets_manager("..."),
                    issuer="...",
                    token_endpoint="...",
                    user_info_endpoint="...",
            
                    # Next
                    next=elbv2.ListenerAction.forward([my_target_group])
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "authorization_endpoint": authorization_endpoint,
            "client_id": client_id,
            "client_secret": client_secret,
            "issuer": issuer,
            "next": next,
            "token_endpoint": token_endpoint,
            "user_info_endpoint": user_info_endpoint,
        }
        if authentication_request_extra_params is not None:
            self._values["authentication_request_extra_params"] = authentication_request_extra_params
        if on_unauthenticated_request is not None:
            self._values["on_unauthenticated_request"] = on_unauthenticated_request
        if scope is not None:
            self._values["scope"] = scope
        if session_cookie_name is not None:
            self._values["session_cookie_name"] = session_cookie_name
        if session_timeout is not None:
            self._values["session_timeout"] = session_timeout

    @builtins.property
    def authorization_endpoint(self) -> builtins.str:
        '''The authorization endpoint of the IdP.

        This must be a full URL, including the HTTPS protocol, the domain, and the path.
        '''
        result = self._values.get("authorization_endpoint")
        assert result is not None, "Required property 'authorization_endpoint' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def client_id(self) -> builtins.str:
        '''The OAuth 2.0 client identifier.'''
        result = self._values.get("client_id")
        assert result is not None, "Required property 'client_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def client_secret(self) -> _SecretValue_3dd0ddae:
        '''The OAuth 2.0 client secret.'''
        result = self._values.get("client_secret")
        assert result is not None, "Required property 'client_secret' is missing"
        return typing.cast(_SecretValue_3dd0ddae, result)

    @builtins.property
    def issuer(self) -> builtins.str:
        '''The OIDC issuer identifier of the IdP.

        This must be a full URL, including the HTTPS protocol, the domain, and the path.
        '''
        result = self._values.get("issuer")
        assert result is not None, "Required property 'issuer' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def next(self) -> "ListenerAction":
        '''What action to execute next.'''
        result = self._values.get("next")
        assert result is not None, "Required property 'next' is missing"
        return typing.cast("ListenerAction", result)

    @builtins.property
    def token_endpoint(self) -> builtins.str:
        '''The token endpoint of the IdP.

        This must be a full URL, including the HTTPS protocol, the domain, and the path.
        '''
        result = self._values.get("token_endpoint")
        assert result is not None, "Required property 'token_endpoint' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def user_info_endpoint(self) -> builtins.str:
        '''The user info endpoint of the IdP.

        This must be a full URL, including the HTTPS protocol, the domain, and the path.
        '''
        result = self._values.get("user_info_endpoint")
        assert result is not None, "Required property 'user_info_endpoint' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def authentication_request_extra_params(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The query parameters (up to 10) to include in the redirect request to the authorization endpoint.

        :default: - No extra parameters
        '''
        result = self._values.get("authentication_request_extra_params")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def on_unauthenticated_request(self) -> typing.Optional["UnauthenticatedAction"]:
        '''The behavior if the user is not authenticated.

        :default: UnauthenticatedAction.AUTHENTICATE
        '''
        result = self._values.get("on_unauthenticated_request")
        return typing.cast(typing.Optional["UnauthenticatedAction"], result)

    @builtins.property
    def scope(self) -> typing.Optional[builtins.str]:
        '''The set of user claims to be requested from the IdP.

        To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.

        :default: "openid"
        '''
        result = self._values.get("scope")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def session_cookie_name(self) -> typing.Optional[builtins.str]:
        '''The name of the cookie used to maintain session information.

        :default: "AWSELBAuthSessionCookie"
        '''
        result = self._values.get("session_cookie_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def session_timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The maximum duration of the authentication session.

        :default: Duration.days(7)
        '''
        result = self._values.get("session_timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AuthenticateOidcOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.BaseApplicationListenerProps",
    jsii_struct_bases=[],
    name_mapping={
        "certificates": "certificates",
        "default_action": "defaultAction",
        "default_target_groups": "defaultTargetGroups",
        "open": "open",
        "port": "port",
        "protocol": "protocol",
        "ssl_policy": "sslPolicy",
    },
)
class BaseApplicationListenerProps:
    def __init__(
        self,
        *,
        certificates: typing.Optional[typing.Sequence["IListenerCertificate"]] = None,
        default_action: typing.Optional["ListenerAction"] = None,
        default_target_groups: typing.Optional[typing.Sequence["IApplicationTargetGroup"]] = None,
        open: typing.Optional[builtins.bool] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        ssl_policy: typing.Optional["SslPolicy"] = None,
    ) -> None:
        '''Basic properties for an ApplicationListener.

        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default action of the load balancer, including Action chaining, fixed responses and redirect responses. See the ``ListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param open: Allow anyone to connect to the load balancer on the listener port. If this is specified, the load balancer will be opened up to anyone who can reach it. For internal load balancers this is anyone in the same VPC. For public load balancers, this is anyone on the internet. If you want to be more selective about who can access this load balancer, set this to ``false`` and use the listener's ``connections`` object to selectively grant access to the load balancer on the listener port. Default: true
        :param port: The port on which the listener listens for requests. Default: - Determined from protocol if known.
        :param protocol: The protocol to use. Default: - Determined from port if known.
        :param ssl_policy: The security policy that defines which ciphers and protocols are supported. Default: - The current predefined security policy.

        :exampleMetadata: infused

        Example::

            from aws_cdk.aws_apigatewayv2_integrations_alpha import HttpAlbIntegration
            
            # lb: elbv2.ApplicationLoadBalancer
            
            listener = lb.add_listener("listener", port=80)
            listener.add_targets("target",
                port=80
            )
            
            http_endpoint = apigwv2.HttpApi(self, "HttpProxyPrivateApi",
                default_integration=HttpAlbIntegration("DefaultIntegration", listener,
                    parameter_mapping=apigwv2.ParameterMapping().append_header("header2", apigwv2.MappingValue.request_header("header1")).remove_header("header1")
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if certificates is not None:
            self._values["certificates"] = certificates
        if default_action is not None:
            self._values["default_action"] = default_action
        if default_target_groups is not None:
            self._values["default_target_groups"] = default_target_groups
        if open is not None:
            self._values["open"] = open
        if port is not None:
            self._values["port"] = port
        if protocol is not None:
            self._values["protocol"] = protocol
        if ssl_policy is not None:
            self._values["ssl_policy"] = ssl_policy

    @builtins.property
    def certificates(self) -> typing.Optional[typing.List["IListenerCertificate"]]:
        '''Certificate list of ACM cert ARNs.

        You must provide exactly one certificate if the listener protocol is HTTPS or TLS.

        :default: - No certificates.
        '''
        result = self._values.get("certificates")
        return typing.cast(typing.Optional[typing.List["IListenerCertificate"]], result)

    @builtins.property
    def default_action(self) -> typing.Optional["ListenerAction"]:
        '''Default action to take for requests to this listener.

        This allows full control of the default action of the load balancer,
        including Action chaining, fixed responses and redirect responses.

        See the ``ListenerAction`` class for all options.

        Cannot be specified together with ``defaultTargetGroups``.

        :default: - None.
        '''
        result = self._values.get("default_action")
        return typing.cast(typing.Optional["ListenerAction"], result)

    @builtins.property
    def default_target_groups(
        self,
    ) -> typing.Optional[typing.List["IApplicationTargetGroup"]]:
        '''Default target groups to load balance to.

        All target groups will be load balanced to with equal weight and without
        stickiness. For a more complex configuration than that, use
        either ``defaultAction`` or ``addAction()``.

        Cannot be specified together with ``defaultAction``.

        :default: - None.
        '''
        result = self._values.get("default_target_groups")
        return typing.cast(typing.Optional[typing.List["IApplicationTargetGroup"]], result)

    @builtins.property
    def open(self) -> typing.Optional[builtins.bool]:
        '''Allow anyone to connect to the load balancer on the listener port.

        If this is specified, the load balancer will be opened up to anyone who can reach it.
        For internal load balancers this is anyone in the same VPC. For public load
        balancers, this is anyone on the internet.

        If you want to be more selective about who can access this load
        balancer, set this to ``false`` and use the listener's ``connections``
        object to selectively grant access to the load balancer on the listener port.

        :default: true
        '''
        result = self._values.get("open")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port on which the listener listens for requests.

        :default: - Determined from protocol if known.
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def protocol(self) -> typing.Optional[ApplicationProtocol]:
        '''The protocol to use.

        :default: - Determined from port if known.
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional[ApplicationProtocol], result)

    @builtins.property
    def ssl_policy(self) -> typing.Optional["SslPolicy"]:
        '''The security policy that defines which ciphers and protocols are supported.

        :default: - The current predefined security policy.
        '''
        result = self._values.get("ssl_policy")
        return typing.cast(typing.Optional["SslPolicy"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseApplicationListenerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.BaseApplicationListenerRuleProps",
    jsii_struct_bases=[],
    name_mapping={
        "priority": "priority",
        "action": "action",
        "conditions": "conditions",
        "target_groups": "targetGroups",
    },
)
class BaseApplicationListenerRuleProps:
    def __init__(
        self,
        *,
        priority: jsii.Number,
        action: typing.Optional["ListenerAction"] = None,
        conditions: typing.Optional[typing.Sequence["ListenerCondition"]] = None,
        target_groups: typing.Optional[typing.Sequence["IApplicationTargetGroup"]] = None,
    ) -> None:
        '''Basic properties for defining a rule on a listener.

        :param priority: Priority of the rule. The rule with the lowest priority will be used for every request. Priorities must be unique.
        :param action: Action to perform when requests are received. Only one of ``action``, ``fixedResponse``, ``redirectResponse`` or ``targetGroups`` can be specified. Default: - No action
        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param target_groups: Target groups to forward requests to. Only one of ``action``, ``fixedResponse``, ``redirectResponse`` or ``targetGroups`` can be specified. Implies a ``forward`` action. Default: - No target groups.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # application_target_group: elbv2.ApplicationTargetGroup
            # listener_action: elbv2.ListenerAction
            # listener_condition: elbv2.ListenerCondition
            
            base_application_listener_rule_props = elbv2.BaseApplicationListenerRuleProps(
                priority=123,
            
                # the properties below are optional
                action=listener_action,
                conditions=[listener_condition],
                target_groups=[application_target_group]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "priority": priority,
        }
        if action is not None:
            self._values["action"] = action
        if conditions is not None:
            self._values["conditions"] = conditions
        if target_groups is not None:
            self._values["target_groups"] = target_groups

    @builtins.property
    def priority(self) -> jsii.Number:
        '''Priority of the rule.

        The rule with the lowest priority will be used for every request.

        Priorities must be unique.
        '''
        result = self._values.get("priority")
        assert result is not None, "Required property 'priority' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def action(self) -> typing.Optional["ListenerAction"]:
        '''Action to perform when requests are received.

        Only one of ``action``, ``fixedResponse``, ``redirectResponse`` or ``targetGroups`` can be specified.

        :default: - No action
        '''
        result = self._values.get("action")
        return typing.cast(typing.Optional["ListenerAction"], result)

    @builtins.property
    def conditions(self) -> typing.Optional[typing.List["ListenerCondition"]]:
        '''Rule applies if matches the conditions.

        :default: - No conditions.

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html
        '''
        result = self._values.get("conditions")
        return typing.cast(typing.Optional[typing.List["ListenerCondition"]], result)

    @builtins.property
    def target_groups(self) -> typing.Optional[typing.List["IApplicationTargetGroup"]]:
        '''Target groups to forward requests to.

        Only one of ``action``, ``fixedResponse``, ``redirectResponse`` or ``targetGroups`` can be specified.

        Implies a ``forward`` action.

        :default: - No target groups.
        '''
        result = self._values.get("target_groups")
        return typing.cast(typing.Optional[typing.List["IApplicationTargetGroup"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseApplicationListenerRuleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class BaseListener(
    _Resource_45bc6135,
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.BaseListener",
):
    '''Base class for listeners.'''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        additional_props: typing.Any,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param additional_props: -
        '''
        jsii.create(self.__class__, self, [scope, id, additional_props])

    @jsii.member(jsii_name="validateListener")
    def _validate_listener(self) -> typing.List[builtins.str]:
        '''Validate this listener.'''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateListener", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="listenerArn")
    def listener_arn(self) -> builtins.str:
        '''
        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "listenerArn"))


class _BaseListenerProxy(
    BaseListener, jsii.proxy_for(_Resource_45bc6135) # type: ignore[misc]
):
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, BaseListener).__jsii_proxy_class__ = lambda : _BaseListenerProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.BaseListenerLookupOptions",
    jsii_struct_bases=[],
    name_mapping={
        "listener_port": "listenerPort",
        "load_balancer_arn": "loadBalancerArn",
        "load_balancer_tags": "loadBalancerTags",
    },
)
class BaseListenerLookupOptions:
    def __init__(
        self,
        *,
        listener_port: typing.Optional[jsii.Number] = None,
        load_balancer_arn: typing.Optional[builtins.str] = None,
        load_balancer_tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Options for listener lookup.

        :param listener_port: Filter listeners by listener port. Default: - does not filter by listener port
        :param load_balancer_arn: Filter listeners by associated load balancer arn. Default: - does not filter by load balancer arn
        :param load_balancer_tags: Filter listeners by associated load balancer tags. Default: - does not filter by load balancer tags

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            base_listener_lookup_options = elbv2.BaseListenerLookupOptions(
                listener_port=123,
                load_balancer_arn="loadBalancerArn",
                load_balancer_tags={
                    "load_balancer_tags_key": "loadBalancerTags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if listener_port is not None:
            self._values["listener_port"] = listener_port
        if load_balancer_arn is not None:
            self._values["load_balancer_arn"] = load_balancer_arn
        if load_balancer_tags is not None:
            self._values["load_balancer_tags"] = load_balancer_tags

    @builtins.property
    def listener_port(self) -> typing.Optional[jsii.Number]:
        '''Filter listeners by listener port.

        :default: - does not filter by listener port
        '''
        result = self._values.get("listener_port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def load_balancer_arn(self) -> typing.Optional[builtins.str]:
        '''Filter listeners by associated load balancer arn.

        :default: - does not filter by load balancer arn
        '''
        result = self._values.get("load_balancer_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def load_balancer_tags(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Filter listeners by associated load balancer tags.

        :default: - does not filter by load balancer tags
        '''
        result = self._values.get("load_balancer_tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseListenerLookupOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class BaseLoadBalancer(
    _Resource_45bc6135,
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.BaseLoadBalancer",
):
    '''Base class for both Application and Network Load Balancers.'''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        base_props: "BaseLoadBalancerProps",
        additional_props: typing.Any,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param base_props: -
        :param additional_props: -
        '''
        jsii.create(self.__class__, self, [scope, id, base_props, additional_props])

    @jsii.member(jsii_name="logAccessLogs")
    def log_access_logs(
        self,
        bucket: _IBucket_42e086fd,
        prefix: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Enable access logging for this load balancer.

        A region must be specified on the stack containing the load balancer; you cannot enable logging on
        environment-agnostic stacks. See https://docs.aws.amazon.com/cdk/latest/guide/environments.html

        :param bucket: -
        :param prefix: -
        '''
        return typing.cast(None, jsii.invoke(self, "logAccessLogs", [bucket, prefix]))

    @jsii.member(jsii_name="removeAttribute")
    def remove_attribute(self, key: builtins.str) -> None:
        '''Remove an attribute from the load balancer.

        :param key: -
        '''
        return typing.cast(None, jsii.invoke(self, "removeAttribute", [key]))

    @jsii.member(jsii_name="setAttribute")
    def set_attribute(
        self,
        key: builtins.str,
        value: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Set a non-standard attribute on the load balancer.

        :param key: -
        :param value: -

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#load-balancer-attributes
        '''
        return typing.cast(None, jsii.invoke(self, "setAttribute", [key, value]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerArn")
    def load_balancer_arn(self) -> builtins.str:
        '''The ARN of this load balancer.

        Example value: ``arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/my-internal-load-balancer/50dc6c495c0c9188``

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "loadBalancerArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerCanonicalHostedZoneId")
    def load_balancer_canonical_hosted_zone_id(self) -> builtins.str:
        '''The canonical hosted zone ID of this load balancer.

        Example value: ``Z2P70J7EXAMPLE``

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "loadBalancerCanonicalHostedZoneId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerDnsName")
    def load_balancer_dns_name(self) -> builtins.str:
        '''The DNS name of this load balancer.

        Example value: ``my-load-balancer-424835706.us-west-2.elb.amazonaws.com``

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "loadBalancerDnsName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerFullName")
    def load_balancer_full_name(self) -> builtins.str:
        '''The full name of this load balancer.

        Example value: ``app/my-load-balancer/50dc6c495c0c9188``

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "loadBalancerFullName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerName")
    def load_balancer_name(self) -> builtins.str:
        '''The name of this load balancer.

        Example value: ``my-load-balancer``

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "loadBalancerName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerSecurityGroups")
    def load_balancer_security_groups(self) -> typing.List[builtins.str]:
        '''
        :attribute: true
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "loadBalancerSecurityGroups"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpc")
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC this load balancer has been created in.

        This property is always defined (not ``null`` or ``undefined``) for sub-classes of ``BaseLoadBalancer``.
        '''
        return typing.cast(typing.Optional[_IVpc_f30d5663], jsii.get(self, "vpc"))


class _BaseLoadBalancerProxy(
    BaseLoadBalancer, jsii.proxy_for(_Resource_45bc6135) # type: ignore[misc]
):
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, BaseLoadBalancer).__jsii_proxy_class__ = lambda : _BaseLoadBalancerProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.BaseLoadBalancerLookupOptions",
    jsii_struct_bases=[],
    name_mapping={
        "load_balancer_arn": "loadBalancerArn",
        "load_balancer_tags": "loadBalancerTags",
    },
)
class BaseLoadBalancerLookupOptions:
    def __init__(
        self,
        *,
        load_balancer_arn: typing.Optional[builtins.str] = None,
        load_balancer_tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Options for looking up load balancers.

        :param load_balancer_arn: Find by load balancer's ARN. Default: - does not search by load balancer arn
        :param load_balancer_tags: Match load balancer tags. Default: - does not match load balancers by tags

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            base_load_balancer_lookup_options = elbv2.BaseLoadBalancerLookupOptions(
                load_balancer_arn="loadBalancerArn",
                load_balancer_tags={
                    "load_balancer_tags_key": "loadBalancerTags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if load_balancer_arn is not None:
            self._values["load_balancer_arn"] = load_balancer_arn
        if load_balancer_tags is not None:
            self._values["load_balancer_tags"] = load_balancer_tags

    @builtins.property
    def load_balancer_arn(self) -> typing.Optional[builtins.str]:
        '''Find by load balancer's ARN.

        :default: - does not search by load balancer arn
        '''
        result = self._values.get("load_balancer_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def load_balancer_tags(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Match load balancer tags.

        :default: - does not match load balancers by tags
        '''
        result = self._values.get("load_balancer_tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseLoadBalancerLookupOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.BaseLoadBalancerProps",
    jsii_struct_bases=[],
    name_mapping={
        "vpc": "vpc",
        "deletion_protection": "deletionProtection",
        "internet_facing": "internetFacing",
        "load_balancer_name": "loadBalancerName",
        "vpc_subnets": "vpcSubnets",
    },
)
class BaseLoadBalancerProps:
    def __init__(
        self,
        *,
        vpc: _IVpc_f30d5663,
        deletion_protection: typing.Optional[builtins.bool] = None,
        internet_facing: typing.Optional[builtins.bool] = None,
        load_balancer_name: typing.Optional[builtins.str] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> None:
        '''Shared properties of both Application and Network Load Balancers.

        :param vpc: The VPC network to place the load balancer in.
        :param deletion_protection: Indicates whether deletion protection is enabled. Default: false
        :param internet_facing: Whether the load balancer has an internet-routable address. Default: false
        :param load_balancer_name: Name of the load balancer. Default: - Automatically generated name.
        :param vpc_subnets: Which subnets place the load balancer in. Default: - the Vpc default strategy.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # subnet: ec2.Subnet
            # subnet_filter: ec2.SubnetFilter
            # vpc: ec2.Vpc
            
            base_load_balancer_props = elbv2.BaseLoadBalancerProps(
                vpc=vpc,
            
                # the properties below are optional
                deletion_protection=False,
                internet_facing=False,
                load_balancer_name="loadBalancerName",
                vpc_subnets=ec2.SubnetSelection(
                    availability_zones=["availabilityZones"],
                    one_per_az=False,
                    subnet_filters=[subnet_filter],
                    subnet_group_name="subnetGroupName",
                    subnets=[subnet],
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
                )
            )
        '''
        if isinstance(vpc_subnets, dict):
            vpc_subnets = _SubnetSelection_e57d76df(**vpc_subnets)
        self._values: typing.Dict[str, typing.Any] = {
            "vpc": vpc,
        }
        if deletion_protection is not None:
            self._values["deletion_protection"] = deletion_protection
        if internet_facing is not None:
            self._values["internet_facing"] = internet_facing
        if load_balancer_name is not None:
            self._values["load_balancer_name"] = load_balancer_name
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets

    @builtins.property
    def vpc(self) -> _IVpc_f30d5663:
        '''The VPC network to place the load balancer in.'''
        result = self._values.get("vpc")
        assert result is not None, "Required property 'vpc' is missing"
        return typing.cast(_IVpc_f30d5663, result)

    @builtins.property
    def deletion_protection(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether deletion protection is enabled.

        :default: false
        '''
        result = self._values.get("deletion_protection")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def internet_facing(self) -> typing.Optional[builtins.bool]:
        '''Whether the load balancer has an internet-routable address.

        :default: false
        '''
        result = self._values.get("internet_facing")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def load_balancer_name(self) -> typing.Optional[builtins.str]:
        '''Name of the load balancer.

        :default: - Automatically generated name.
        '''
        result = self._values.get("load_balancer_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''Which subnets place the load balancer in.

        :default: - the Vpc default strategy.
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseLoadBalancerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.BaseNetworkListenerProps",
    jsii_struct_bases=[],
    name_mapping={
        "port": "port",
        "alpn_policy": "alpnPolicy",
        "certificates": "certificates",
        "default_action": "defaultAction",
        "default_target_groups": "defaultTargetGroups",
        "protocol": "protocol",
        "ssl_policy": "sslPolicy",
    },
)
class BaseNetworkListenerProps:
    def __init__(
        self,
        *,
        port: jsii.Number,
        alpn_policy: typing.Optional[AlpnPolicy] = None,
        certificates: typing.Optional[typing.Sequence["IListenerCertificate"]] = None,
        default_action: typing.Optional["NetworkListenerAction"] = None,
        default_target_groups: typing.Optional[typing.Sequence["INetworkTargetGroup"]] = None,
        protocol: typing.Optional["Protocol"] = None,
        ssl_policy: typing.Optional["SslPolicy"] = None,
    ) -> None:
        '''Basic properties for a Network Listener.

        :param port: The port on which the listener listens for requests.
        :param alpn_policy: Application-Layer Protocol Negotiation (ALPN) is a TLS extension that is sent on the initial TLS handshake hello messages. ALPN enables the application layer to negotiate which protocols should be used over a secure connection, such as HTTP/1 and HTTP/2. Can only be specified together with Protocol TLS. Default: - None
        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default Action of the load balancer, including weighted forwarding. See the ``NetworkListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param protocol: Protocol for listener, expects TCP, TLS, UDP, or TCP_UDP. Default: - TLS if certificates are provided. TCP otherwise.
        :param ssl_policy: SSL Policy. Default: - Current predefined security policy.

        :exampleMetadata: infused

        Example::

            from aws_cdk.aws_apigatewayv2_integrations_alpha import HttpNlbIntegration
            
            
            vpc = ec2.Vpc(self, "VPC")
            lb = elbv2.NetworkLoadBalancer(self, "lb", vpc=vpc)
            listener = lb.add_listener("listener", port=80)
            listener.add_targets("target",
                port=80
            )
            
            http_endpoint = apigwv2.HttpApi(self, "HttpProxyPrivateApi",
                default_integration=HttpNlbIntegration("DefaultIntegration", listener)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "port": port,
        }
        if alpn_policy is not None:
            self._values["alpn_policy"] = alpn_policy
        if certificates is not None:
            self._values["certificates"] = certificates
        if default_action is not None:
            self._values["default_action"] = default_action
        if default_target_groups is not None:
            self._values["default_target_groups"] = default_target_groups
        if protocol is not None:
            self._values["protocol"] = protocol
        if ssl_policy is not None:
            self._values["ssl_policy"] = ssl_policy

    @builtins.property
    def port(self) -> jsii.Number:
        '''The port on which the listener listens for requests.'''
        result = self._values.get("port")
        assert result is not None, "Required property 'port' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def alpn_policy(self) -> typing.Optional[AlpnPolicy]:
        '''Application-Layer Protocol Negotiation (ALPN) is a TLS extension that is sent on the initial TLS handshake hello messages.

        ALPN enables the application layer to negotiate which protocols should be used over a secure connection, such as HTTP/1 and HTTP/2.

        Can only be specified together with Protocol TLS.

        :default: - None
        '''
        result = self._values.get("alpn_policy")
        return typing.cast(typing.Optional[AlpnPolicy], result)

    @builtins.property
    def certificates(self) -> typing.Optional[typing.List["IListenerCertificate"]]:
        '''Certificate list of ACM cert ARNs.

        You must provide exactly one certificate if the listener protocol is HTTPS or TLS.

        :default: - No certificates.
        '''
        result = self._values.get("certificates")
        return typing.cast(typing.Optional[typing.List["IListenerCertificate"]], result)

    @builtins.property
    def default_action(self) -> typing.Optional["NetworkListenerAction"]:
        '''Default action to take for requests to this listener.

        This allows full control of the default Action of the load balancer,
        including weighted forwarding. See the ``NetworkListenerAction`` class for
        all options.

        Cannot be specified together with ``defaultTargetGroups``.

        :default: - None.
        '''
        result = self._values.get("default_action")
        return typing.cast(typing.Optional["NetworkListenerAction"], result)

    @builtins.property
    def default_target_groups(
        self,
    ) -> typing.Optional[typing.List["INetworkTargetGroup"]]:
        '''Default target groups to load balance to.

        All target groups will be load balanced to with equal weight and without
        stickiness. For a more complex configuration than that, use
        either ``defaultAction`` or ``addAction()``.

        Cannot be specified together with ``defaultAction``.

        :default: - None.
        '''
        result = self._values.get("default_target_groups")
        return typing.cast(typing.Optional[typing.List["INetworkTargetGroup"]], result)

    @builtins.property
    def protocol(self) -> typing.Optional["Protocol"]:
        '''Protocol for listener, expects TCP, TLS, UDP, or TCP_UDP.

        :default: - TLS if certificates are provided. TCP otherwise.
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional["Protocol"], result)

    @builtins.property
    def ssl_policy(self) -> typing.Optional["SslPolicy"]:
        '''SSL Policy.

        :default: - Current predefined security policy.
        '''
        result = self._values.get("ssl_policy")
        return typing.cast(typing.Optional["SslPolicy"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseNetworkListenerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.BaseTargetGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "deregistration_delay": "deregistrationDelay",
        "health_check": "healthCheck",
        "target_group_name": "targetGroupName",
        "target_type": "targetType",
        "vpc": "vpc",
    },
)
class BaseTargetGroupProps:
    def __init__(
        self,
        *,
        deregistration_delay: typing.Optional[_Duration_4839e8c3] = None,
        health_check: typing.Optional["HealthCheck"] = None,
        target_group_name: typing.Optional[builtins.str] = None,
        target_type: typing.Optional["TargetType"] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> None:
        '''Basic properties of both Application and Network Target Groups.

        :param deregistration_delay: The amount of time for Elastic Load Balancing to wait before deregistering a target. The range is 0-3600 seconds. Default: 300
        :param health_check: Health check configuration. Default: - None.
        :param target_group_name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. Default: - Automatically generated.
        :param target_type: The type of targets registered to this TargetGroup, either IP or Instance. All targets registered into the group must be of this type. If you register targets to the TargetGroup in the CDK app, the TargetType is determined automatically. Default: - Determined automatically.
        :param vpc: The virtual private cloud (VPC). only if ``TargetType`` is ``Ip`` or ``InstanceId`` Default: - undefined

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # vpc: ec2.Vpc
            
            base_target_group_props = elbv2.BaseTargetGroupProps(
                deregistration_delay=cdk.Duration.minutes(30),
                health_check=elbv2.HealthCheck(
                    enabled=False,
                    healthy_grpc_codes="healthyGrpcCodes",
                    healthy_http_codes="healthyHttpCodes",
                    healthy_threshold_count=123,
                    interval=cdk.Duration.minutes(30),
                    path="path",
                    port="port",
                    protocol=elbv2.Protocol.HTTP,
                    timeout=cdk.Duration.minutes(30),
                    unhealthy_threshold_count=123
                ),
                target_group_name="targetGroupName",
                target_type=elbv2.TargetType.INSTANCE,
                vpc=vpc
            )
        '''
        if isinstance(health_check, dict):
            health_check = HealthCheck(**health_check)
        self._values: typing.Dict[str, typing.Any] = {}
        if deregistration_delay is not None:
            self._values["deregistration_delay"] = deregistration_delay
        if health_check is not None:
            self._values["health_check"] = health_check
        if target_group_name is not None:
            self._values["target_group_name"] = target_group_name
        if target_type is not None:
            self._values["target_type"] = target_type
        if vpc is not None:
            self._values["vpc"] = vpc

    @builtins.property
    def deregistration_delay(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The amount of time for Elastic Load Balancing to wait before deregistering a target.

        The range is 0-3600 seconds.

        :default: 300
        '''
        result = self._values.get("deregistration_delay")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def health_check(self) -> typing.Optional["HealthCheck"]:
        '''Health check configuration.

        :default: - None.
        '''
        result = self._values.get("health_check")
        return typing.cast(typing.Optional["HealthCheck"], result)

    @builtins.property
    def target_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the target group.

        This name must be unique per region per account, can have a maximum of
        32 characters, must contain only alphanumeric characters or hyphens, and
        must not begin or end with a hyphen.

        :default: - Automatically generated.
        '''
        result = self._values.get("target_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def target_type(self) -> typing.Optional["TargetType"]:
        '''The type of targets registered to this TargetGroup, either IP or Instance.

        All targets registered into the group must be of this type. If you
        register targets to the TargetGroup in the CDK app, the TargetType is
        determined automatically.

        :default: - Determined automatically.
        '''
        result = self._values.get("target_type")
        return typing.cast(typing.Optional["TargetType"], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The virtual private cloud (VPC).

        only if ``TargetType`` is ``Ip`` or ``InstanceId``

        :default: - undefined
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseTargetGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnListener(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListener",
):
    '''A CloudFormation ``AWS::ElasticLoadBalancingV2::Listener``.

    Specifies a listener for an Application Load Balancer or Network Load Balancer.

    :cloudformationResource: AWS::ElasticLoadBalancingV2::Listener
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticloadbalancingv2 as elbv2
        
        cfn_listener = elbv2.CfnListener(self, "MyCfnListener",
            default_actions=[elbv2.CfnListener.ActionProperty(
                type="type",
        
                # the properties below are optional
                authenticate_cognito_config=elbv2.CfnListener.AuthenticateCognitoConfigProperty(
                    user_pool_arn="userPoolArn",
                    user_pool_client_id="userPoolClientId",
                    user_pool_domain="userPoolDomain",
        
                    # the properties below are optional
                    authentication_request_extra_params={
                        "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                    },
                    on_unauthenticated_request="onUnauthenticatedRequest",
                    scope="scope",
                    session_cookie_name="sessionCookieName",
                    session_timeout="sessionTimeout"
                ),
                authenticate_oidc_config=elbv2.CfnListener.AuthenticateOidcConfigProperty(
                    authorization_endpoint="authorizationEndpoint",
                    client_id="clientId",
                    client_secret="clientSecret",
                    issuer="issuer",
                    token_endpoint="tokenEndpoint",
                    user_info_endpoint="userInfoEndpoint",
        
                    # the properties below are optional
                    authentication_request_extra_params={
                        "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                    },
                    on_unauthenticated_request="onUnauthenticatedRequest",
                    scope="scope",
                    session_cookie_name="sessionCookieName",
                    session_timeout="sessionTimeout"
                ),
                fixed_response_config=elbv2.CfnListener.FixedResponseConfigProperty(
                    status_code="statusCode",
        
                    # the properties below are optional
                    content_type="contentType",
                    message_body="messageBody"
                ),
                forward_config=elbv2.CfnListener.ForwardConfigProperty(
                    target_groups=[elbv2.CfnListener.TargetGroupTupleProperty(
                        target_group_arn="targetGroupArn",
                        weight=123
                    )],
                    target_group_stickiness_config=elbv2.CfnListener.TargetGroupStickinessConfigProperty(
                        duration_seconds=123,
                        enabled=False
                    )
                ),
                order=123,
                redirect_config=elbv2.CfnListener.RedirectConfigProperty(
                    status_code="statusCode",
        
                    # the properties below are optional
                    host="host",
                    path="path",
                    port="port",
                    protocol="protocol",
                    query="query"
                ),
                target_group_arn="targetGroupArn"
            )],
            load_balancer_arn="loadBalancerArn",
        
            # the properties below are optional
            alpn_policy=["alpnPolicy"],
            certificates=[elbv2.CfnListener.CertificateProperty(
                certificate_arn="certificateArn"
            )],
            port=123,
            protocol="protocol",
            ssl_policy="sslPolicy"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        default_actions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnListener.ActionProperty", _IResolvable_da3f097b]]],
        load_balancer_arn: builtins.str,
        alpn_policy: typing.Optional[typing.Sequence[builtins.str]] = None,
        certificates: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnListener.CertificateProperty", _IResolvable_da3f097b]]]] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[builtins.str] = None,
        ssl_policy: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::ElasticLoadBalancingV2::Listener``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param default_actions: The actions for the default rule. You cannot define a condition for a default rule. To create additional rules for an Application Load Balancer, use `AWS::ElasticLoadBalancingV2::ListenerRule <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html>`_ .
        :param load_balancer_arn: The Amazon Resource Name (ARN) of the load balancer.
        :param alpn_policy: [TLS listener] The name of the Application-Layer Protocol Negotiation (ALPN) policy.
        :param certificates: The default SSL server certificate for a secure listener. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. To create a certificate list for a secure listener, use `AWS::ElasticLoadBalancingV2::ListenerCertificate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html>`_ .
        :param port: The port on which the load balancer is listening. You cannot specify a port for a Gateway Load Balancer.
        :param protocol: The protocol for connections from clients to the load balancer. For Application Load Balancers, the supported protocols are HTTP and HTTPS. For Network Load Balancers, the supported protocols are TCP, TLS, UDP, and TCP_UDP. You can’t specify the UDP or TCP_UDP protocol if dual-stack mode is enabled. You cannot specify a protocol for a Gateway Load Balancer.
        :param ssl_policy: [HTTPS and TLS listeners] The security policy that defines which protocols and ciphers are supported. For more information, see `Security policies <https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies>`_ in the *Application Load Balancers Guide* and `Security policies <https://docs.aws.amazon.com/elasticloadbalancing/latest/network/create-tls-listener.html#describe-ssl-policies>`_ in the *Network Load Balancers Guide* .
        '''
        props = CfnListenerProps(
            default_actions=default_actions,
            load_balancer_arn=load_balancer_arn,
            alpn_policy=alpn_policy,
            certificates=certificates,
            port=port,
            protocol=protocol,
            ssl_policy=ssl_policy,
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
    @jsii.member(jsii_name="attrListenerArn")
    def attr_listener_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the listener.

        :cloudformationAttribute: ListenerArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrListenerArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultActions")
    def default_actions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListener.ActionProperty", _IResolvable_da3f097b]]]:
        '''The actions for the default rule. You cannot define a condition for a default rule.

        To create additional rules for an Application Load Balancer, use `AWS::ElasticLoadBalancingV2::ListenerRule <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-defaultactions
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListener.ActionProperty", _IResolvable_da3f097b]]], jsii.get(self, "defaultActions"))

    @default_actions.setter
    def default_actions(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListener.ActionProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "defaultActions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerArn")
    def load_balancer_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the load balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-loadbalancerarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "loadBalancerArn"))

    @load_balancer_arn.setter
    def load_balancer_arn(self, value: builtins.str) -> None:
        jsii.set(self, "loadBalancerArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="alpnPolicy")
    def alpn_policy(self) -> typing.Optional[typing.List[builtins.str]]:
        '''[TLS listener] The name of the Application-Layer Protocol Negotiation (ALPN) policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-alpnpolicy
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "alpnPolicy"))

    @alpn_policy.setter
    def alpn_policy(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "alpnPolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificates")
    def certificates(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListener.CertificateProperty", _IResolvable_da3f097b]]]]:
        '''The default SSL server certificate for a secure listener.

        You must provide exactly one certificate if the listener protocol is HTTPS or TLS.

        To create a certificate list for a secure listener, use `AWS::ElasticLoadBalancingV2::ListenerCertificate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-certificates
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListener.CertificateProperty", _IResolvable_da3f097b]]]], jsii.get(self, "certificates"))

    @certificates.setter
    def certificates(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListener.CertificateProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "certificates", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="port")
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port on which the load balancer is listening.

        You cannot specify a port for a Gateway Load Balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-port
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "port"))

    @port.setter
    def port(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "port", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="protocol")
    def protocol(self) -> typing.Optional[builtins.str]:
        '''The protocol for connections from clients to the load balancer.

        For Application Load Balancers, the supported protocols are HTTP and HTTPS. For Network Load Balancers, the supported protocols are TCP, TLS, UDP, and TCP_UDP. You can’t specify the UDP or TCP_UDP protocol if dual-stack mode is enabled. You cannot specify a protocol for a Gateway Load Balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-protocol
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "protocol"))

    @protocol.setter
    def protocol(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "protocol", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="sslPolicy")
    def ssl_policy(self) -> typing.Optional[builtins.str]:
        '''[HTTPS and TLS listeners] The security policy that defines which protocols and ciphers are supported.

        For more information, see `Security policies <https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies>`_ in the *Application Load Balancers Guide* and `Security policies <https://docs.aws.amazon.com/elasticloadbalancing/latest/network/create-tls-listener.html#describe-ssl-policies>`_ in the *Network Load Balancers Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-sslpolicy
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "sslPolicy"))

    @ssl_policy.setter
    def ssl_policy(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "sslPolicy", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListener.ActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "type": "type",
            "authenticate_cognito_config": "authenticateCognitoConfig",
            "authenticate_oidc_config": "authenticateOidcConfig",
            "fixed_response_config": "fixedResponseConfig",
            "forward_config": "forwardConfig",
            "order": "order",
            "redirect_config": "redirectConfig",
            "target_group_arn": "targetGroupArn",
        },
    )
    class ActionProperty:
        def __init__(
            self,
            *,
            type: builtins.str,
            authenticate_cognito_config: typing.Optional[typing.Union["CfnListener.AuthenticateCognitoConfigProperty", _IResolvable_da3f097b]] = None,
            authenticate_oidc_config: typing.Optional[typing.Union["CfnListener.AuthenticateOidcConfigProperty", _IResolvable_da3f097b]] = None,
            fixed_response_config: typing.Optional[typing.Union["CfnListener.FixedResponseConfigProperty", _IResolvable_da3f097b]] = None,
            forward_config: typing.Optional[typing.Union["CfnListener.ForwardConfigProperty", _IResolvable_da3f097b]] = None,
            order: typing.Optional[jsii.Number] = None,
            redirect_config: typing.Optional[typing.Union["CfnListener.RedirectConfigProperty", _IResolvable_da3f097b]] = None,
            target_group_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies an action for a listener rule.

            :param type: The type of action.
            :param authenticate_cognito_config: [HTTPS listeners] Information for using Amazon Cognito to authenticate users. Specify only when ``Type`` is ``authenticate-cognito`` .
            :param authenticate_oidc_config: [HTTPS listeners] Information about an identity provider that is compliant with OpenID Connect (OIDC). Specify only when ``Type`` is ``authenticate-oidc`` .
            :param fixed_response_config: [Application Load Balancer] Information for creating an action that returns a custom HTTP response. Specify only when ``Type`` is ``fixed-response`` .
            :param forward_config: Information for creating an action that distributes requests among one or more target groups. For Network Load Balancers, you can specify a single target group. Specify only when ``Type`` is ``forward`` . If you specify both ``ForwardConfig`` and ``TargetGroupArn`` , you can specify only one target group using ``ForwardConfig`` and it must be the same target group specified in ``TargetGroupArn`` .
            :param order: The order for the action. This value is required for rules with multiple actions. The action with the lowest value for order is performed first.
            :param redirect_config: [Application Load Balancer] Information for creating a redirect action. Specify only when ``Type`` is ``redirect`` .
            :param target_group_arn: The Amazon Resource Name (ARN) of the target group. Specify only when ``Type`` is ``forward`` and you want to route to a single target group. To route to one or more target groups, use ``ForwardConfig`` instead.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-action.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                action_property = elbv2.CfnListener.ActionProperty(
                    type="type",
                
                    # the properties below are optional
                    authenticate_cognito_config=elbv2.CfnListener.AuthenticateCognitoConfigProperty(
                        user_pool_arn="userPoolArn",
                        user_pool_client_id="userPoolClientId",
                        user_pool_domain="userPoolDomain",
                
                        # the properties below are optional
                        authentication_request_extra_params={
                            "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                        },
                        on_unauthenticated_request="onUnauthenticatedRequest",
                        scope="scope",
                        session_cookie_name="sessionCookieName",
                        session_timeout="sessionTimeout"
                    ),
                    authenticate_oidc_config=elbv2.CfnListener.AuthenticateOidcConfigProperty(
                        authorization_endpoint="authorizationEndpoint",
                        client_id="clientId",
                        client_secret="clientSecret",
                        issuer="issuer",
                        token_endpoint="tokenEndpoint",
                        user_info_endpoint="userInfoEndpoint",
                
                        # the properties below are optional
                        authentication_request_extra_params={
                            "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                        },
                        on_unauthenticated_request="onUnauthenticatedRequest",
                        scope="scope",
                        session_cookie_name="sessionCookieName",
                        session_timeout="sessionTimeout"
                    ),
                    fixed_response_config=elbv2.CfnListener.FixedResponseConfigProperty(
                        status_code="statusCode",
                
                        # the properties below are optional
                        content_type="contentType",
                        message_body="messageBody"
                    ),
                    forward_config=elbv2.CfnListener.ForwardConfigProperty(
                        target_groups=[elbv2.CfnListener.TargetGroupTupleProperty(
                            target_group_arn="targetGroupArn",
                            weight=123
                        )],
                        target_group_stickiness_config=elbv2.CfnListener.TargetGroupStickinessConfigProperty(
                            duration_seconds=123,
                            enabled=False
                        )
                    ),
                    order=123,
                    redirect_config=elbv2.CfnListener.RedirectConfigProperty(
                        status_code="statusCode",
                
                        # the properties below are optional
                        host="host",
                        path="path",
                        port="port",
                        protocol="protocol",
                        query="query"
                    ),
                    target_group_arn="targetGroupArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "type": type,
            }
            if authenticate_cognito_config is not None:
                self._values["authenticate_cognito_config"] = authenticate_cognito_config
            if authenticate_oidc_config is not None:
                self._values["authenticate_oidc_config"] = authenticate_oidc_config
            if fixed_response_config is not None:
                self._values["fixed_response_config"] = fixed_response_config
            if forward_config is not None:
                self._values["forward_config"] = forward_config
            if order is not None:
                self._values["order"] = order
            if redirect_config is not None:
                self._values["redirect_config"] = redirect_config
            if target_group_arn is not None:
                self._values["target_group_arn"] = target_group_arn

        @builtins.property
        def type(self) -> builtins.str:
            '''The type of action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-action.html#cfn-elasticloadbalancingv2-listener-action-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def authenticate_cognito_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListener.AuthenticateCognitoConfigProperty", _IResolvable_da3f097b]]:
            '''[HTTPS listeners] Information for using Amazon Cognito to authenticate users.

            Specify only when ``Type`` is ``authenticate-cognito`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-action.html#cfn-elasticloadbalancingv2-listener-action-authenticatecognitoconfig
            '''
            result = self._values.get("authenticate_cognito_config")
            return typing.cast(typing.Optional[typing.Union["CfnListener.AuthenticateCognitoConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def authenticate_oidc_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListener.AuthenticateOidcConfigProperty", _IResolvable_da3f097b]]:
            '''[HTTPS listeners] Information about an identity provider that is compliant with OpenID Connect (OIDC).

            Specify only when ``Type`` is ``authenticate-oidc`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-action.html#cfn-elasticloadbalancingv2-listener-action-authenticateoidcconfig
            '''
            result = self._values.get("authenticate_oidc_config")
            return typing.cast(typing.Optional[typing.Union["CfnListener.AuthenticateOidcConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def fixed_response_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListener.FixedResponseConfigProperty", _IResolvable_da3f097b]]:
            '''[Application Load Balancer] Information for creating an action that returns a custom HTTP response.

            Specify only when ``Type`` is ``fixed-response`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-action.html#cfn-elasticloadbalancingv2-listener-action-fixedresponseconfig
            '''
            result = self._values.get("fixed_response_config")
            return typing.cast(typing.Optional[typing.Union["CfnListener.FixedResponseConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def forward_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListener.ForwardConfigProperty", _IResolvable_da3f097b]]:
            '''Information for creating an action that distributes requests among one or more target groups.

            For Network Load Balancers, you can specify a single target group. Specify only when ``Type`` is ``forward`` . If you specify both ``ForwardConfig`` and ``TargetGroupArn`` , you can specify only one target group using ``ForwardConfig`` and it must be the same target group specified in ``TargetGroupArn`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-action.html#cfn-elasticloadbalancingv2-listener-action-forwardconfig
            '''
            result = self._values.get("forward_config")
            return typing.cast(typing.Optional[typing.Union["CfnListener.ForwardConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def order(self) -> typing.Optional[jsii.Number]:
            '''The order for the action.

            This value is required for rules with multiple actions. The action with the lowest value for order is performed first.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-action.html#cfn-elasticloadbalancingv2-listener-action-order
            '''
            result = self._values.get("order")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def redirect_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListener.RedirectConfigProperty", _IResolvable_da3f097b]]:
            '''[Application Load Balancer] Information for creating a redirect action.

            Specify only when ``Type`` is ``redirect`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-action.html#cfn-elasticloadbalancingv2-listener-action-redirectconfig
            '''
            result = self._values.get("redirect_config")
            return typing.cast(typing.Optional[typing.Union["CfnListener.RedirectConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def target_group_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the target group.

            Specify only when ``Type`` is ``forward`` and you want to route to a single target group. To route to one or more target groups, use ``ForwardConfig`` instead.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-action.html#cfn-elasticloadbalancingv2-listener-action-targetgrouparn
            '''
            result = self._values.get("target_group_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListener.AuthenticateCognitoConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "user_pool_arn": "userPoolArn",
            "user_pool_client_id": "userPoolClientId",
            "user_pool_domain": "userPoolDomain",
            "authentication_request_extra_params": "authenticationRequestExtraParams",
            "on_unauthenticated_request": "onUnauthenticatedRequest",
            "scope": "scope",
            "session_cookie_name": "sessionCookieName",
            "session_timeout": "sessionTimeout",
        },
    )
    class AuthenticateCognitoConfigProperty:
        def __init__(
            self,
            *,
            user_pool_arn: builtins.str,
            user_pool_client_id: builtins.str,
            user_pool_domain: builtins.str,
            authentication_request_extra_params: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            on_unauthenticated_request: typing.Optional[builtins.str] = None,
            scope: typing.Optional[builtins.str] = None,
            session_cookie_name: typing.Optional[builtins.str] = None,
            session_timeout: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies information required when integrating with Amazon Cognito to authenticate users.

            :param user_pool_arn: The Amazon Resource Name (ARN) of the Amazon Cognito user pool.
            :param user_pool_client_id: The ID of the Amazon Cognito user pool client.
            :param user_pool_domain: The domain prefix or fully-qualified domain name of the Amazon Cognito user pool.
            :param authentication_request_extra_params: The query parameters (up to 10) to include in the redirect request to the authorization endpoint.
            :param on_unauthenticated_request: The behavior if the user is not authenticated. The following are possible values:. - deny `` - Return an HTTP 401 Unauthorized error. - allow `` - Allow the request to be forwarded to the target. - authenticate `` - Redirect the request to the IdP authorization endpoint. This is the default value.
            :param scope: The set of user claims to be requested from the IdP. The default is ``openid`` . To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.
            :param session_cookie_name: The name of the cookie used to maintain session information. The default is AWSELBAuthSessionCookie.
            :param session_timeout: The maximum duration of the authentication session, in seconds. The default is 604800 seconds (7 days).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticatecognitoconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                authenticate_cognito_config_property = elbv2.CfnListener.AuthenticateCognitoConfigProperty(
                    user_pool_arn="userPoolArn",
                    user_pool_client_id="userPoolClientId",
                    user_pool_domain="userPoolDomain",
                
                    # the properties below are optional
                    authentication_request_extra_params={
                        "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                    },
                    on_unauthenticated_request="onUnauthenticatedRequest",
                    scope="scope",
                    session_cookie_name="sessionCookieName",
                    session_timeout="sessionTimeout"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "user_pool_arn": user_pool_arn,
                "user_pool_client_id": user_pool_client_id,
                "user_pool_domain": user_pool_domain,
            }
            if authentication_request_extra_params is not None:
                self._values["authentication_request_extra_params"] = authentication_request_extra_params
            if on_unauthenticated_request is not None:
                self._values["on_unauthenticated_request"] = on_unauthenticated_request
            if scope is not None:
                self._values["scope"] = scope
            if session_cookie_name is not None:
                self._values["session_cookie_name"] = session_cookie_name
            if session_timeout is not None:
                self._values["session_timeout"] = session_timeout

        @builtins.property
        def user_pool_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the Amazon Cognito user pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listener-authenticatecognitoconfig-userpoolarn
            '''
            result = self._values.get("user_pool_arn")
            assert result is not None, "Required property 'user_pool_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def user_pool_client_id(self) -> builtins.str:
            '''The ID of the Amazon Cognito user pool client.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listener-authenticatecognitoconfig-userpoolclientid
            '''
            result = self._values.get("user_pool_client_id")
            assert result is not None, "Required property 'user_pool_client_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def user_pool_domain(self) -> builtins.str:
            '''The domain prefix or fully-qualified domain name of the Amazon Cognito user pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listener-authenticatecognitoconfig-userpooldomain
            '''
            result = self._values.get("user_pool_domain")
            assert result is not None, "Required property 'user_pool_domain' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def authentication_request_extra_params(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''The query parameters (up to 10) to include in the redirect request to the authorization endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listener-authenticatecognitoconfig-authenticationrequestextraparams
            '''
            result = self._values.get("authentication_request_extra_params")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def on_unauthenticated_request(self) -> typing.Optional[builtins.str]:
            '''The behavior if the user is not authenticated. The following are possible values:.

            - deny `` - Return an HTTP 401 Unauthorized error.
            - allow `` - Allow the request to be forwarded to the target.
            - authenticate `` - Redirect the request to the IdP authorization endpoint. This is the default value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listener-authenticatecognitoconfig-onunauthenticatedrequest
            '''
            result = self._values.get("on_unauthenticated_request")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def scope(self) -> typing.Optional[builtins.str]:
            '''The set of user claims to be requested from the IdP. The default is ``openid`` .

            To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listener-authenticatecognitoconfig-scope
            '''
            result = self._values.get("scope")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def session_cookie_name(self) -> typing.Optional[builtins.str]:
            '''The name of the cookie used to maintain session information.

            The default is AWSELBAuthSessionCookie.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listener-authenticatecognitoconfig-sessioncookiename
            '''
            result = self._values.get("session_cookie_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def session_timeout(self) -> typing.Optional[builtins.str]:
            '''The maximum duration of the authentication session, in seconds.

            The default is 604800 seconds (7 days).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listener-authenticatecognitoconfig-sessiontimeout
            '''
            result = self._values.get("session_timeout")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AuthenticateCognitoConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListener.AuthenticateOidcConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "authorization_endpoint": "authorizationEndpoint",
            "client_id": "clientId",
            "client_secret": "clientSecret",
            "issuer": "issuer",
            "token_endpoint": "tokenEndpoint",
            "user_info_endpoint": "userInfoEndpoint",
            "authentication_request_extra_params": "authenticationRequestExtraParams",
            "on_unauthenticated_request": "onUnauthenticatedRequest",
            "scope": "scope",
            "session_cookie_name": "sessionCookieName",
            "session_timeout": "sessionTimeout",
        },
    )
    class AuthenticateOidcConfigProperty:
        def __init__(
            self,
            *,
            authorization_endpoint: builtins.str,
            client_id: builtins.str,
            client_secret: builtins.str,
            issuer: builtins.str,
            token_endpoint: builtins.str,
            user_info_endpoint: builtins.str,
            authentication_request_extra_params: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            on_unauthenticated_request: typing.Optional[builtins.str] = None,
            scope: typing.Optional[builtins.str] = None,
            session_cookie_name: typing.Optional[builtins.str] = None,
            session_timeout: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies information required using an identity provide (IdP) that is compliant with OpenID Connect (OIDC) to authenticate users.

            :param authorization_endpoint: The authorization endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
            :param client_id: The OAuth 2.0 client identifier.
            :param client_secret: The OAuth 2.0 client secret. This parameter is required if you are creating a rule. If you are modifying a rule, you can omit this parameter if you set ``UseExistingClientSecret`` to true.
            :param issuer: The OIDC issuer identifier of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
            :param token_endpoint: The token endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
            :param user_info_endpoint: The user info endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
            :param authentication_request_extra_params: The query parameters (up to 10) to include in the redirect request to the authorization endpoint.
            :param on_unauthenticated_request: The behavior if the user is not authenticated. The following are possible values:. - deny `` - Return an HTTP 401 Unauthorized error. - allow `` - Allow the request to be forwarded to the target. - authenticate `` - Redirect the request to the IdP authorization endpoint. This is the default value.
            :param scope: The set of user claims to be requested from the IdP. The default is ``openid`` . To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.
            :param session_cookie_name: The name of the cookie used to maintain session information. The default is AWSELBAuthSessionCookie.
            :param session_timeout: The maximum duration of the authentication session, in seconds. The default is 604800 seconds (7 days).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                authenticate_oidc_config_property = elbv2.CfnListener.AuthenticateOidcConfigProperty(
                    authorization_endpoint="authorizationEndpoint",
                    client_id="clientId",
                    client_secret="clientSecret",
                    issuer="issuer",
                    token_endpoint="tokenEndpoint",
                    user_info_endpoint="userInfoEndpoint",
                
                    # the properties below are optional
                    authentication_request_extra_params={
                        "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                    },
                    on_unauthenticated_request="onUnauthenticatedRequest",
                    scope="scope",
                    session_cookie_name="sessionCookieName",
                    session_timeout="sessionTimeout"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "authorization_endpoint": authorization_endpoint,
                "client_id": client_id,
                "client_secret": client_secret,
                "issuer": issuer,
                "token_endpoint": token_endpoint,
                "user_info_endpoint": user_info_endpoint,
            }
            if authentication_request_extra_params is not None:
                self._values["authentication_request_extra_params"] = authentication_request_extra_params
            if on_unauthenticated_request is not None:
                self._values["on_unauthenticated_request"] = on_unauthenticated_request
            if scope is not None:
                self._values["scope"] = scope
            if session_cookie_name is not None:
                self._values["session_cookie_name"] = session_cookie_name
            if session_timeout is not None:
                self._values["session_timeout"] = session_timeout

        @builtins.property
        def authorization_endpoint(self) -> builtins.str:
            '''The authorization endpoint of the IdP.

            This must be a full URL, including the HTTPS protocol, the domain, and the path.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listener-authenticateoidcconfig-authorizationendpoint
            '''
            result = self._values.get("authorization_endpoint")
            assert result is not None, "Required property 'authorization_endpoint' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def client_id(self) -> builtins.str:
            '''The OAuth 2.0 client identifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listener-authenticateoidcconfig-clientid
            '''
            result = self._values.get("client_id")
            assert result is not None, "Required property 'client_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def client_secret(self) -> builtins.str:
            '''The OAuth 2.0 client secret. This parameter is required if you are creating a rule. If you are modifying a rule, you can omit this parameter if you set ``UseExistingClientSecret`` to true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listener-authenticateoidcconfig-clientsecret
            '''
            result = self._values.get("client_secret")
            assert result is not None, "Required property 'client_secret' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def issuer(self) -> builtins.str:
            '''The OIDC issuer identifier of the IdP.

            This must be a full URL, including the HTTPS protocol, the domain, and the path.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listener-authenticateoidcconfig-issuer
            '''
            result = self._values.get("issuer")
            assert result is not None, "Required property 'issuer' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def token_endpoint(self) -> builtins.str:
            '''The token endpoint of the IdP.

            This must be a full URL, including the HTTPS protocol, the domain, and the path.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listener-authenticateoidcconfig-tokenendpoint
            '''
            result = self._values.get("token_endpoint")
            assert result is not None, "Required property 'token_endpoint' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def user_info_endpoint(self) -> builtins.str:
            '''The user info endpoint of the IdP.

            This must be a full URL, including the HTTPS protocol, the domain, and the path.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listener-authenticateoidcconfig-userinfoendpoint
            '''
            result = self._values.get("user_info_endpoint")
            assert result is not None, "Required property 'user_info_endpoint' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def authentication_request_extra_params(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''The query parameters (up to 10) to include in the redirect request to the authorization endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listener-authenticateoidcconfig-authenticationrequestextraparams
            '''
            result = self._values.get("authentication_request_extra_params")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def on_unauthenticated_request(self) -> typing.Optional[builtins.str]:
            '''The behavior if the user is not authenticated. The following are possible values:.

            - deny `` - Return an HTTP 401 Unauthorized error.
            - allow `` - Allow the request to be forwarded to the target.
            - authenticate `` - Redirect the request to the IdP authorization endpoint. This is the default value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listener-authenticateoidcconfig-onunauthenticatedrequest
            '''
            result = self._values.get("on_unauthenticated_request")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def scope(self) -> typing.Optional[builtins.str]:
            '''The set of user claims to be requested from the IdP. The default is ``openid`` .

            To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listener-authenticateoidcconfig-scope
            '''
            result = self._values.get("scope")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def session_cookie_name(self) -> typing.Optional[builtins.str]:
            '''The name of the cookie used to maintain session information.

            The default is AWSELBAuthSessionCookie.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listener-authenticateoidcconfig-sessioncookiename
            '''
            result = self._values.get("session_cookie_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def session_timeout(self) -> typing.Optional[builtins.str]:
            '''The maximum duration of the authentication session, in seconds.

            The default is 604800 seconds (7 days).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listener-authenticateoidcconfig-sessiontimeout
            '''
            result = self._values.get("session_timeout")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AuthenticateOidcConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListener.CertificateProperty",
        jsii_struct_bases=[],
        name_mapping={"certificate_arn": "certificateArn"},
    )
    class CertificateProperty:
        def __init__(
            self,
            *,
            certificate_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies an SSL server certificate to use as the default certificate for a secure listener.

            :param certificate_arn: The Amazon Resource Name (ARN) of the certificate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-certificate.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                certificate_property = elbv2.CfnListener.CertificateProperty(
                    certificate_arn="certificateArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if certificate_arn is not None:
                self._values["certificate_arn"] = certificate_arn

        @builtins.property
        def certificate_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the certificate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-certificate.html#cfn-elasticloadbalancingv2-listener-certificate-certificatearn
            '''
            result = self._values.get("certificate_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CertificateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListener.FixedResponseConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "status_code": "statusCode",
            "content_type": "contentType",
            "message_body": "messageBody",
        },
    )
    class FixedResponseConfigProperty:
        def __init__(
            self,
            *,
            status_code: builtins.str,
            content_type: typing.Optional[builtins.str] = None,
            message_body: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies information required when returning a custom HTTP response.

            :param status_code: The HTTP response code (2XX, 4XX, or 5XX).
            :param content_type: The content type. Valid Values: text/plain | text/css | text/html | application/javascript | application/json
            :param message_body: The message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-fixedresponseconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                fixed_response_config_property = elbv2.CfnListener.FixedResponseConfigProperty(
                    status_code="statusCode",
                
                    # the properties below are optional
                    content_type="contentType",
                    message_body="messageBody"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "status_code": status_code,
            }
            if content_type is not None:
                self._values["content_type"] = content_type
            if message_body is not None:
                self._values["message_body"] = message_body

        @builtins.property
        def status_code(self) -> builtins.str:
            '''The HTTP response code (2XX, 4XX, or 5XX).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-fixedresponseconfig.html#cfn-elasticloadbalancingv2-listener-fixedresponseconfig-statuscode
            '''
            result = self._values.get("status_code")
            assert result is not None, "Required property 'status_code' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def content_type(self) -> typing.Optional[builtins.str]:
            '''The content type.

            Valid Values: text/plain | text/css | text/html | application/javascript | application/json

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-fixedresponseconfig.html#cfn-elasticloadbalancingv2-listener-fixedresponseconfig-contenttype
            '''
            result = self._values.get("content_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def message_body(self) -> typing.Optional[builtins.str]:
            '''The message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-fixedresponseconfig.html#cfn-elasticloadbalancingv2-listener-fixedresponseconfig-messagebody
            '''
            result = self._values.get("message_body")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FixedResponseConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListener.ForwardConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "target_groups": "targetGroups",
            "target_group_stickiness_config": "targetGroupStickinessConfig",
        },
    )
    class ForwardConfigProperty:
        def __init__(
            self,
            *,
            target_groups: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnListener.TargetGroupTupleProperty", _IResolvable_da3f097b]]]] = None,
            target_group_stickiness_config: typing.Optional[typing.Union["CfnListener.TargetGroupStickinessConfigProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Information for creating an action that distributes requests among one or more target groups.

            For Network Load Balancers, you can specify a single target group. Specify only when ``Type`` is ``forward`` . If you specify both ``ForwardConfig`` and ``TargetGroupArn`` , you can specify only one target group using ``ForwardConfig`` and it must be the same target group specified in ``TargetGroupArn`` .

            :param target_groups: Information about how traffic will be distributed between multiple target groups in a forward rule.
            :param target_group_stickiness_config: Information about the target group stickiness for a rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-forwardconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                forward_config_property = elbv2.CfnListener.ForwardConfigProperty(
                    target_groups=[elbv2.CfnListener.TargetGroupTupleProperty(
                        target_group_arn="targetGroupArn",
                        weight=123
                    )],
                    target_group_stickiness_config=elbv2.CfnListener.TargetGroupStickinessConfigProperty(
                        duration_seconds=123,
                        enabled=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if target_groups is not None:
                self._values["target_groups"] = target_groups
            if target_group_stickiness_config is not None:
                self._values["target_group_stickiness_config"] = target_group_stickiness_config

        @builtins.property
        def target_groups(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListener.TargetGroupTupleProperty", _IResolvable_da3f097b]]]]:
            '''Information about how traffic will be distributed between multiple target groups in a forward rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-forwardconfig.html#cfn-elasticloadbalancingv2-listener-forwardconfig-targetgroups
            '''
            result = self._values.get("target_groups")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListener.TargetGroupTupleProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def target_group_stickiness_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListener.TargetGroupStickinessConfigProperty", _IResolvable_da3f097b]]:
            '''Information about the target group stickiness for a rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-forwardconfig.html#cfn-elasticloadbalancingv2-listener-forwardconfig-targetgroupstickinessconfig
            '''
            result = self._values.get("target_group_stickiness_config")
            return typing.cast(typing.Optional[typing.Union["CfnListener.TargetGroupStickinessConfigProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ForwardConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListener.RedirectConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "status_code": "statusCode",
            "host": "host",
            "path": "path",
            "port": "port",
            "protocol": "protocol",
            "query": "query",
        },
    )
    class RedirectConfigProperty:
        def __init__(
            self,
            *,
            status_code: builtins.str,
            host: typing.Optional[builtins.str] = None,
            path: typing.Optional[builtins.str] = None,
            port: typing.Optional[builtins.str] = None,
            protocol: typing.Optional[builtins.str] = None,
            query: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about a redirect action.

            A URI consists of the following components: protocol://hostname:port/path?query. You must modify at least one of the following components to avoid a redirect loop: protocol, hostname, port, or path. Any components that you do not modify retain their original values.

            You can reuse URI components using the following reserved keywords:

            - #{protocol}
            - #{host}
            - #{port}
            - #{path} (the leading "/" is removed)
            - #{query}

            For example, you can change the path to "/new/#{path}", the hostname to "example.#{host}", or the query to "#{query}&value=xyz".

            :param status_code: The HTTP redirect code. The redirect is either permanent (HTTP 301) or temporary (HTTP 302).
            :param host: The hostname. This component is not percent-encoded. The hostname can contain #{host}.
            :param path: The absolute path, starting with the leading "/". This component is not percent-encoded. The path can contain #{host}, #{path}, and #{port}.
            :param port: The port. You can specify a value from 1 to 65535 or #{port}.
            :param protocol: The protocol. You can specify HTTP, HTTPS, or #{protocol}. You can redirect HTTP to HTTP, HTTP to HTTPS, and HTTPS to HTTPS. You cannot redirect HTTPS to HTTP.
            :param query: The query parameters, URL-encoded when necessary, but not percent-encoded. Do not include the leading "?", as it is automatically added. You can specify any of the reserved keywords.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-redirectconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                redirect_config_property = elbv2.CfnListener.RedirectConfigProperty(
                    status_code="statusCode",
                
                    # the properties below are optional
                    host="host",
                    path="path",
                    port="port",
                    protocol="protocol",
                    query="query"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "status_code": status_code,
            }
            if host is not None:
                self._values["host"] = host
            if path is not None:
                self._values["path"] = path
            if port is not None:
                self._values["port"] = port
            if protocol is not None:
                self._values["protocol"] = protocol
            if query is not None:
                self._values["query"] = query

        @builtins.property
        def status_code(self) -> builtins.str:
            '''The HTTP redirect code.

            The redirect is either permanent (HTTP 301) or temporary (HTTP 302).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-redirectconfig.html#cfn-elasticloadbalancingv2-listener-redirectconfig-statuscode
            '''
            result = self._values.get("status_code")
            assert result is not None, "Required property 'status_code' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> typing.Optional[builtins.str]:
            '''The hostname.

            This component is not percent-encoded. The hostname can contain #{host}.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-redirectconfig.html#cfn-elasticloadbalancingv2-listener-redirectconfig-host
            '''
            result = self._values.get("host")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def path(self) -> typing.Optional[builtins.str]:
            '''The absolute path, starting with the leading "/".

            This component is not percent-encoded. The path can contain #{host}, #{path}, and #{port}.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-redirectconfig.html#cfn-elasticloadbalancingv2-listener-redirectconfig-path
            '''
            result = self._values.get("path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def port(self) -> typing.Optional[builtins.str]:
            '''The port.

            You can specify a value from 1 to 65535 or #{port}.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-redirectconfig.html#cfn-elasticloadbalancingv2-listener-redirectconfig-port
            '''
            result = self._values.get("port")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def protocol(self) -> typing.Optional[builtins.str]:
            '''The protocol.

            You can specify HTTP, HTTPS, or #{protocol}. You can redirect HTTP to HTTP, HTTP to HTTPS, and HTTPS to HTTPS. You cannot redirect HTTPS to HTTP.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-redirectconfig.html#cfn-elasticloadbalancingv2-listener-redirectconfig-protocol
            '''
            result = self._values.get("protocol")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def query(self) -> typing.Optional[builtins.str]:
            '''The query parameters, URL-encoded when necessary, but not percent-encoded.

            Do not include the leading "?", as it is automatically added. You can specify any of the reserved keywords.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-redirectconfig.html#cfn-elasticloadbalancingv2-listener-redirectconfig-query
            '''
            result = self._values.get("query")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RedirectConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListener.TargetGroupStickinessConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"duration_seconds": "durationSeconds", "enabled": "enabled"},
    )
    class TargetGroupStickinessConfigProperty:
        def __init__(
            self,
            *,
            duration_seconds: typing.Optional[jsii.Number] = None,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Information about the target group stickiness for a rule.

            :param duration_seconds: The time period, in seconds, during which requests from a client should be routed to the same target group. The range is 1-604800 seconds (7 days).
            :param enabled: Indicates whether target group stickiness is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-targetgroupstickinessconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                target_group_stickiness_config_property = elbv2.CfnListener.TargetGroupStickinessConfigProperty(
                    duration_seconds=123,
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if duration_seconds is not None:
                self._values["duration_seconds"] = duration_seconds
            if enabled is not None:
                self._values["enabled"] = enabled

        @builtins.property
        def duration_seconds(self) -> typing.Optional[jsii.Number]:
            '''The time period, in seconds, during which requests from a client should be routed to the same target group.

            The range is 1-604800 seconds (7 days).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-targetgroupstickinessconfig.html#cfn-elasticloadbalancingv2-listener-targetgroupstickinessconfig-durationseconds
            '''
            result = self._values.get("duration_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether target group stickiness is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-targetgroupstickinessconfig.html#cfn-elasticloadbalancingv2-listener-targetgroupstickinessconfig-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetGroupStickinessConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListener.TargetGroupTupleProperty",
        jsii_struct_bases=[],
        name_mapping={"target_group_arn": "targetGroupArn", "weight": "weight"},
    )
    class TargetGroupTupleProperty:
        def __init__(
            self,
            *,
            target_group_arn: typing.Optional[builtins.str] = None,
            weight: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Information about how traffic will be distributed between multiple target groups in a forward rule.

            :param target_group_arn: The Amazon Resource Name (ARN) of the target group.
            :param weight: The weight. The range is 0 to 999.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-targetgrouptuple.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                target_group_tuple_property = elbv2.CfnListener.TargetGroupTupleProperty(
                    target_group_arn="targetGroupArn",
                    weight=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if target_group_arn is not None:
                self._values["target_group_arn"] = target_group_arn
            if weight is not None:
                self._values["weight"] = weight

        @builtins.property
        def target_group_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the target group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-targetgrouptuple.html#cfn-elasticloadbalancingv2-listener-targetgrouptuple-targetgrouparn
            '''
            result = self._values.get("target_group_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def weight(self) -> typing.Optional[jsii.Number]:
            '''The weight.

            The range is 0 to 999.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-targetgrouptuple.html#cfn-elasticloadbalancingv2-listener-targetgrouptuple-weight
            '''
            result = self._values.get("weight")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetGroupTupleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.implements(_IInspectable_c2943556)
class CfnListenerCertificate(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerCertificate",
):
    '''A CloudFormation ``AWS::ElasticLoadBalancingV2::ListenerCertificate``.

    Specifies an SSL server certificate to add to the certificate list for an HTTPS or TLS listener.

    :cloudformationResource: AWS::ElasticLoadBalancingV2::ListenerCertificate
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticloadbalancingv2 as elbv2
        
        cfn_listener_certificate = elbv2.CfnListenerCertificate(self, "MyCfnListenerCertificate",
            certificates=[elbv2.CfnListenerCertificate.CertificateProperty(
                certificate_arn="certificateArn"
            )],
            listener_arn="listenerArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        certificates: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnListenerCertificate.CertificateProperty", _IResolvable_da3f097b]]],
        listener_arn: builtins.str,
    ) -> None:
        '''Create a new ``AWS::ElasticLoadBalancingV2::ListenerCertificate``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param certificates: The certificate. You can specify one certificate per resource.
        :param listener_arn: The Amazon Resource Name (ARN) of the listener.
        '''
        props = CfnListenerCertificateProps(
            certificates=certificates, listener_arn=listener_arn
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
    @jsii.member(jsii_name="certificates")
    def certificates(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerCertificate.CertificateProperty", _IResolvable_da3f097b]]]:
        '''The certificate.

        You can specify one certificate per resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html#cfn-elasticloadbalancingv2-listenercertificate-certificates
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerCertificate.CertificateProperty", _IResolvable_da3f097b]]], jsii.get(self, "certificates"))

    @certificates.setter
    def certificates(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerCertificate.CertificateProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "certificates", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="listenerArn")
    def listener_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the listener.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html#cfn-elasticloadbalancingv2-listenercertificate-listenerarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "listenerArn"))

    @listener_arn.setter
    def listener_arn(self, value: builtins.str) -> None:
        jsii.set(self, "listenerArn", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerCertificate.CertificateProperty",
        jsii_struct_bases=[],
        name_mapping={"certificate_arn": "certificateArn"},
    )
    class CertificateProperty:
        def __init__(
            self,
            *,
            certificate_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies an SSL server certificate for the certificate list of a secure listener.

            :param certificate_arn: The Amazon Resource Name (ARN) of the certificate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-certificates.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                certificate_property = elbv2.CfnListenerCertificate.CertificateProperty(
                    certificate_arn="certificateArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if certificate_arn is not None:
                self._values["certificate_arn"] = certificate_arn

        @builtins.property
        def certificate_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the certificate.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listener-certificates.html#cfn-elasticloadbalancingv2-listener-certificates-certificatearn
            '''
            result = self._values.get("certificate_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CertificateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerCertificateProps",
    jsii_struct_bases=[],
    name_mapping={"certificates": "certificates", "listener_arn": "listenerArn"},
)
class CfnListenerCertificateProps:
    def __init__(
        self,
        *,
        certificates: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnListenerCertificate.CertificateProperty, _IResolvable_da3f097b]]],
        listener_arn: builtins.str,
    ) -> None:
        '''Properties for defining a ``CfnListenerCertificate``.

        :param certificates: The certificate. You can specify one certificate per resource.
        :param listener_arn: The Amazon Resource Name (ARN) of the listener.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            cfn_listener_certificate_props = elbv2.CfnListenerCertificateProps(
                certificates=[elbv2.CfnListenerCertificate.CertificateProperty(
                    certificate_arn="certificateArn"
                )],
                listener_arn="listenerArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "certificates": certificates,
            "listener_arn": listener_arn,
        }

    @builtins.property
    def certificates(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnListenerCertificate.CertificateProperty, _IResolvable_da3f097b]]]:
        '''The certificate.

        You can specify one certificate per resource.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html#cfn-elasticloadbalancingv2-listenercertificate-certificates
        '''
        result = self._values.get("certificates")
        assert result is not None, "Required property 'certificates' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnListenerCertificate.CertificateProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def listener_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the listener.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html#cfn-elasticloadbalancingv2-listenercertificate-listenerarn
        '''
        result = self._values.get("listener_arn")
        assert result is not None, "Required property 'listener_arn' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnListenerCertificateProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerProps",
    jsii_struct_bases=[],
    name_mapping={
        "default_actions": "defaultActions",
        "load_balancer_arn": "loadBalancerArn",
        "alpn_policy": "alpnPolicy",
        "certificates": "certificates",
        "port": "port",
        "protocol": "protocol",
        "ssl_policy": "sslPolicy",
    },
)
class CfnListenerProps:
    def __init__(
        self,
        *,
        default_actions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnListener.ActionProperty, _IResolvable_da3f097b]]],
        load_balancer_arn: builtins.str,
        alpn_policy: typing.Optional[typing.Sequence[builtins.str]] = None,
        certificates: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnListener.CertificateProperty, _IResolvable_da3f097b]]]] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[builtins.str] = None,
        ssl_policy: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnListener``.

        :param default_actions: The actions for the default rule. You cannot define a condition for a default rule. To create additional rules for an Application Load Balancer, use `AWS::ElasticLoadBalancingV2::ListenerRule <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html>`_ .
        :param load_balancer_arn: The Amazon Resource Name (ARN) of the load balancer.
        :param alpn_policy: [TLS listener] The name of the Application-Layer Protocol Negotiation (ALPN) policy.
        :param certificates: The default SSL server certificate for a secure listener. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. To create a certificate list for a secure listener, use `AWS::ElasticLoadBalancingV2::ListenerCertificate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html>`_ .
        :param port: The port on which the load balancer is listening. You cannot specify a port for a Gateway Load Balancer.
        :param protocol: The protocol for connections from clients to the load balancer. For Application Load Balancers, the supported protocols are HTTP and HTTPS. For Network Load Balancers, the supported protocols are TCP, TLS, UDP, and TCP_UDP. You can’t specify the UDP or TCP_UDP protocol if dual-stack mode is enabled. You cannot specify a protocol for a Gateway Load Balancer.
        :param ssl_policy: [HTTPS and TLS listeners] The security policy that defines which protocols and ciphers are supported. For more information, see `Security policies <https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies>`_ in the *Application Load Balancers Guide* and `Security policies <https://docs.aws.amazon.com/elasticloadbalancing/latest/network/create-tls-listener.html#describe-ssl-policies>`_ in the *Network Load Balancers Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            cfn_listener_props = elbv2.CfnListenerProps(
                default_actions=[elbv2.CfnListener.ActionProperty(
                    type="type",
            
                    # the properties below are optional
                    authenticate_cognito_config=elbv2.CfnListener.AuthenticateCognitoConfigProperty(
                        user_pool_arn="userPoolArn",
                        user_pool_client_id="userPoolClientId",
                        user_pool_domain="userPoolDomain",
            
                        # the properties below are optional
                        authentication_request_extra_params={
                            "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                        },
                        on_unauthenticated_request="onUnauthenticatedRequest",
                        scope="scope",
                        session_cookie_name="sessionCookieName",
                        session_timeout="sessionTimeout"
                    ),
                    authenticate_oidc_config=elbv2.CfnListener.AuthenticateOidcConfigProperty(
                        authorization_endpoint="authorizationEndpoint",
                        client_id="clientId",
                        client_secret="clientSecret",
                        issuer="issuer",
                        token_endpoint="tokenEndpoint",
                        user_info_endpoint="userInfoEndpoint",
            
                        # the properties below are optional
                        authentication_request_extra_params={
                            "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                        },
                        on_unauthenticated_request="onUnauthenticatedRequest",
                        scope="scope",
                        session_cookie_name="sessionCookieName",
                        session_timeout="sessionTimeout"
                    ),
                    fixed_response_config=elbv2.CfnListener.FixedResponseConfigProperty(
                        status_code="statusCode",
            
                        # the properties below are optional
                        content_type="contentType",
                        message_body="messageBody"
                    ),
                    forward_config=elbv2.CfnListener.ForwardConfigProperty(
                        target_groups=[elbv2.CfnListener.TargetGroupTupleProperty(
                            target_group_arn="targetGroupArn",
                            weight=123
                        )],
                        target_group_stickiness_config=elbv2.CfnListener.TargetGroupStickinessConfigProperty(
                            duration_seconds=123,
                            enabled=False
                        )
                    ),
                    order=123,
                    redirect_config=elbv2.CfnListener.RedirectConfigProperty(
                        status_code="statusCode",
            
                        # the properties below are optional
                        host="host",
                        path="path",
                        port="port",
                        protocol="protocol",
                        query="query"
                    ),
                    target_group_arn="targetGroupArn"
                )],
                load_balancer_arn="loadBalancerArn",
            
                # the properties below are optional
                alpn_policy=["alpnPolicy"],
                certificates=[elbv2.CfnListener.CertificateProperty(
                    certificate_arn="certificateArn"
                )],
                port=123,
                protocol="protocol",
                ssl_policy="sslPolicy"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "default_actions": default_actions,
            "load_balancer_arn": load_balancer_arn,
        }
        if alpn_policy is not None:
            self._values["alpn_policy"] = alpn_policy
        if certificates is not None:
            self._values["certificates"] = certificates
        if port is not None:
            self._values["port"] = port
        if protocol is not None:
            self._values["protocol"] = protocol
        if ssl_policy is not None:
            self._values["ssl_policy"] = ssl_policy

    @builtins.property
    def default_actions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnListener.ActionProperty, _IResolvable_da3f097b]]]:
        '''The actions for the default rule. You cannot define a condition for a default rule.

        To create additional rules for an Application Load Balancer, use `AWS::ElasticLoadBalancingV2::ListenerRule <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-defaultactions
        '''
        result = self._values.get("default_actions")
        assert result is not None, "Required property 'default_actions' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnListener.ActionProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def load_balancer_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the load balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-loadbalancerarn
        '''
        result = self._values.get("load_balancer_arn")
        assert result is not None, "Required property 'load_balancer_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def alpn_policy(self) -> typing.Optional[typing.List[builtins.str]]:
        '''[TLS listener] The name of the Application-Layer Protocol Negotiation (ALPN) policy.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-alpnpolicy
        '''
        result = self._values.get("alpn_policy")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def certificates(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnListener.CertificateProperty, _IResolvable_da3f097b]]]]:
        '''The default SSL server certificate for a secure listener.

        You must provide exactly one certificate if the listener protocol is HTTPS or TLS.

        To create a certificate list for a secure listener, use `AWS::ElasticLoadBalancingV2::ListenerCertificate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-certificates
        '''
        result = self._values.get("certificates")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnListener.CertificateProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port on which the load balancer is listening.

        You cannot specify a port for a Gateway Load Balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-port
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def protocol(self) -> typing.Optional[builtins.str]:
        '''The protocol for connections from clients to the load balancer.

        For Application Load Balancers, the supported protocols are HTTP and HTTPS. For Network Load Balancers, the supported protocols are TCP, TLS, UDP, and TCP_UDP. You can’t specify the UDP or TCP_UDP protocol if dual-stack mode is enabled. You cannot specify a protocol for a Gateway Load Balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-protocol
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ssl_policy(self) -> typing.Optional[builtins.str]:
        '''[HTTPS and TLS listeners] The security policy that defines which protocols and ciphers are supported.

        For more information, see `Security policies <https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies>`_ in the *Application Load Balancers Guide* and `Security policies <https://docs.aws.amazon.com/elasticloadbalancing/latest/network/create-tls-listener.html#describe-ssl-policies>`_ in the *Network Load Balancers Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listener.html#cfn-elasticloadbalancingv2-listener-sslpolicy
        '''
        result = self._values.get("ssl_policy")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnListenerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnListenerRule(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule",
):
    '''A CloudFormation ``AWS::ElasticLoadBalancingV2::ListenerRule``.

    Specifies a listener rule. The listener must be associated with an Application Load Balancer. Each rule consists of a priority, one or more actions, and one or more conditions.

    :cloudformationResource: AWS::ElasticLoadBalancingV2::ListenerRule
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticloadbalancingv2 as elbv2
        
        cfn_listener_rule = elbv2.CfnListenerRule(self, "MyCfnListenerRule",
            actions=[elbv2.CfnListenerRule.ActionProperty(
                type="type",
        
                # the properties below are optional
                authenticate_cognito_config=elbv2.CfnListenerRule.AuthenticateCognitoConfigProperty(
                    user_pool_arn="userPoolArn",
                    user_pool_client_id="userPoolClientId",
                    user_pool_domain="userPoolDomain",
        
                    # the properties below are optional
                    authentication_request_extra_params={
                        "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                    },
                    on_unauthenticated_request="onUnauthenticatedRequest",
                    scope="scope",
                    session_cookie_name="sessionCookieName",
                    session_timeout=123
                ),
                authenticate_oidc_config=elbv2.CfnListenerRule.AuthenticateOidcConfigProperty(
                    authorization_endpoint="authorizationEndpoint",
                    client_id="clientId",
                    client_secret="clientSecret",
                    issuer="issuer",
                    token_endpoint="tokenEndpoint",
                    user_info_endpoint="userInfoEndpoint",
        
                    # the properties below are optional
                    authentication_request_extra_params={
                        "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                    },
                    on_unauthenticated_request="onUnauthenticatedRequest",
                    scope="scope",
                    session_cookie_name="sessionCookieName",
                    session_timeout=123,
                    use_existing_client_secret=False
                ),
                fixed_response_config=elbv2.CfnListenerRule.FixedResponseConfigProperty(
                    status_code="statusCode",
        
                    # the properties below are optional
                    content_type="contentType",
                    message_body="messageBody"
                ),
                forward_config=elbv2.CfnListenerRule.ForwardConfigProperty(
                    target_groups=[elbv2.CfnListenerRule.TargetGroupTupleProperty(
                        target_group_arn="targetGroupArn",
                        weight=123
                    )],
                    target_group_stickiness_config=elbv2.CfnListenerRule.TargetGroupStickinessConfigProperty(
                        duration_seconds=123,
                        enabled=False
                    )
                ),
                order=123,
                redirect_config=elbv2.CfnListenerRule.RedirectConfigProperty(
                    status_code="statusCode",
        
                    # the properties below are optional
                    host="host",
                    path="path",
                    port="port",
                    protocol="protocol",
                    query="query"
                ),
                target_group_arn="targetGroupArn"
            )],
            conditions=[elbv2.CfnListenerRule.RuleConditionProperty(
                field="field",
                host_header_config=elbv2.CfnListenerRule.HostHeaderConfigProperty(
                    values=["values"]
                ),
                http_header_config=elbv2.CfnListenerRule.HttpHeaderConfigProperty(
                    http_header_name="httpHeaderName",
                    values=["values"]
                ),
                http_request_method_config=elbv2.CfnListenerRule.HttpRequestMethodConfigProperty(
                    values=["values"]
                ),
                path_pattern_config=elbv2.CfnListenerRule.PathPatternConfigProperty(
                    values=["values"]
                ),
                query_string_config=elbv2.CfnListenerRule.QueryStringConfigProperty(
                    values=[elbv2.CfnListenerRule.QueryStringKeyValueProperty(
                        key="key",
                        value="value"
                    )]
                ),
                source_ip_config=elbv2.CfnListenerRule.SourceIpConfigProperty(
                    values=["values"]
                ),
                values=["values"]
            )],
            listener_arn="listenerArn",
            priority=123
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        actions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnListenerRule.ActionProperty", _IResolvable_da3f097b]]],
        conditions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnListenerRule.RuleConditionProperty", _IResolvable_da3f097b]]],
        listener_arn: builtins.str,
        priority: jsii.Number,
    ) -> None:
        '''Create a new ``AWS::ElasticLoadBalancingV2::ListenerRule``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param actions: The actions. The rule must include exactly one of the following types of actions: ``forward`` , ``fixed-response`` , or ``redirect`` , and it must be the last action to be performed. If the rule is for an HTTPS listener, it can also optionally include an authentication action.
        :param conditions: The conditions. The rule can optionally include up to one of each of the following conditions: ``http-request-method`` , ``host-header`` , ``path-pattern`` , and ``source-ip`` . A rule can also optionally include one or more of each of the following conditions: ``http-header`` and ``query-string`` .
        :param listener_arn: The Amazon Resource Name (ARN) of the listener.
        :param priority: The rule priority. A listener can't have multiple rules with the same priority. If you try to reorder rules by updating their priorities, do not specify a new priority if an existing rule already uses this priority, as this can cause an error. If you need to reuse a priority with a different rule, you must remove it as a priority first, and then specify it in a subsequent update.
        '''
        props = CfnListenerRuleProps(
            actions=actions,
            conditions=conditions,
            listener_arn=listener_arn,
            priority=priority,
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
    @jsii.member(jsii_name="attrIsDefault")
    def attr_is_default(self) -> _IResolvable_da3f097b:
        '''Indicates whether this is the default rule.

        :cloudformationAttribute: IsDefault
        '''
        return typing.cast(_IResolvable_da3f097b, jsii.get(self, "attrIsDefault"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrRuleArn")
    def attr_rule_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the rule.

        :cloudformationAttribute: RuleArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrRuleArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="actions")
    def actions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerRule.ActionProperty", _IResolvable_da3f097b]]]:
        '''The actions.

        The rule must include exactly one of the following types of actions: ``forward`` , ``fixed-response`` , or ``redirect`` , and it must be the last action to be performed. If the rule is for an HTTPS listener, it can also optionally include an authentication action.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html#cfn-elasticloadbalancingv2-listenerrule-actions
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerRule.ActionProperty", _IResolvable_da3f097b]]], jsii.get(self, "actions"))

    @actions.setter
    def actions(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerRule.ActionProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "actions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="conditions")
    def conditions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerRule.RuleConditionProperty", _IResolvable_da3f097b]]]:
        '''The conditions.

        The rule can optionally include up to one of each of the following conditions: ``http-request-method`` , ``host-header`` , ``path-pattern`` , and ``source-ip`` . A rule can also optionally include one or more of each of the following conditions: ``http-header`` and ``query-string`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html#cfn-elasticloadbalancingv2-listenerrule-conditions
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerRule.RuleConditionProperty", _IResolvable_da3f097b]]], jsii.get(self, "conditions"))

    @conditions.setter
    def conditions(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerRule.RuleConditionProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "conditions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="listenerArn")
    def listener_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the listener.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html#cfn-elasticloadbalancingv2-listenerrule-listenerarn
        '''
        return typing.cast(builtins.str, jsii.get(self, "listenerArn"))

    @listener_arn.setter
    def listener_arn(self, value: builtins.str) -> None:
        jsii.set(self, "listenerArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="priority")
    def priority(self) -> jsii.Number:
        '''The rule priority. A listener can't have multiple rules with the same priority.

        If you try to reorder rules by updating their priorities, do not specify a new priority if an existing rule already uses this priority, as this can cause an error. If you need to reuse a priority with a different rule, you must remove it as a priority first, and then specify it in a subsequent update.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html#cfn-elasticloadbalancingv2-listenerrule-priority
        '''
        return typing.cast(jsii.Number, jsii.get(self, "priority"))

    @priority.setter
    def priority(self, value: jsii.Number) -> None:
        jsii.set(self, "priority", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.ActionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "type": "type",
            "authenticate_cognito_config": "authenticateCognitoConfig",
            "authenticate_oidc_config": "authenticateOidcConfig",
            "fixed_response_config": "fixedResponseConfig",
            "forward_config": "forwardConfig",
            "order": "order",
            "redirect_config": "redirectConfig",
            "target_group_arn": "targetGroupArn",
        },
    )
    class ActionProperty:
        def __init__(
            self,
            *,
            type: builtins.str,
            authenticate_cognito_config: typing.Optional[typing.Union["CfnListenerRule.AuthenticateCognitoConfigProperty", _IResolvable_da3f097b]] = None,
            authenticate_oidc_config: typing.Optional[typing.Union["CfnListenerRule.AuthenticateOidcConfigProperty", _IResolvable_da3f097b]] = None,
            fixed_response_config: typing.Optional[typing.Union["CfnListenerRule.FixedResponseConfigProperty", _IResolvable_da3f097b]] = None,
            forward_config: typing.Optional[typing.Union["CfnListenerRule.ForwardConfigProperty", _IResolvable_da3f097b]] = None,
            order: typing.Optional[jsii.Number] = None,
            redirect_config: typing.Optional[typing.Union["CfnListenerRule.RedirectConfigProperty", _IResolvable_da3f097b]] = None,
            target_group_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies an action for a listener rule.

            :param type: The type of action.
            :param authenticate_cognito_config: [HTTPS listeners] Information for using Amazon Cognito to authenticate users. Specify only when ``Type`` is ``authenticate-cognito`` .
            :param authenticate_oidc_config: [HTTPS listeners] Information about an identity provider that is compliant with OpenID Connect (OIDC). Specify only when ``Type`` is ``authenticate-oidc`` .
            :param fixed_response_config: [Application Load Balancer] Information for creating an action that returns a custom HTTP response. Specify only when ``Type`` is ``fixed-response`` .
            :param forward_config: Information for creating an action that distributes requests among one or more target groups. For Network Load Balancers, you can specify a single target group. Specify only when ``Type`` is ``forward`` . If you specify both ``ForwardConfig`` and ``TargetGroupArn`` , you can specify only one target group using ``ForwardConfig`` and it must be the same target group specified in ``TargetGroupArn`` .
            :param order: The order for the action. This value is required for rules with multiple actions. The action with the lowest value for order is performed first.
            :param redirect_config: [Application Load Balancer] Information for creating a redirect action. Specify only when ``Type`` is ``redirect`` .
            :param target_group_arn: The Amazon Resource Name (ARN) of the target group. Specify only when ``Type`` is ``forward`` and you want to route to a single target group. To route to one or more target groups, use ``ForwardConfig`` instead.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-action.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                action_property = elbv2.CfnListenerRule.ActionProperty(
                    type="type",
                
                    # the properties below are optional
                    authenticate_cognito_config=elbv2.CfnListenerRule.AuthenticateCognitoConfigProperty(
                        user_pool_arn="userPoolArn",
                        user_pool_client_id="userPoolClientId",
                        user_pool_domain="userPoolDomain",
                
                        # the properties below are optional
                        authentication_request_extra_params={
                            "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                        },
                        on_unauthenticated_request="onUnauthenticatedRequest",
                        scope="scope",
                        session_cookie_name="sessionCookieName",
                        session_timeout=123
                    ),
                    authenticate_oidc_config=elbv2.CfnListenerRule.AuthenticateOidcConfigProperty(
                        authorization_endpoint="authorizationEndpoint",
                        client_id="clientId",
                        client_secret="clientSecret",
                        issuer="issuer",
                        token_endpoint="tokenEndpoint",
                        user_info_endpoint="userInfoEndpoint",
                
                        # the properties below are optional
                        authentication_request_extra_params={
                            "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                        },
                        on_unauthenticated_request="onUnauthenticatedRequest",
                        scope="scope",
                        session_cookie_name="sessionCookieName",
                        session_timeout=123,
                        use_existing_client_secret=False
                    ),
                    fixed_response_config=elbv2.CfnListenerRule.FixedResponseConfigProperty(
                        status_code="statusCode",
                
                        # the properties below are optional
                        content_type="contentType",
                        message_body="messageBody"
                    ),
                    forward_config=elbv2.CfnListenerRule.ForwardConfigProperty(
                        target_groups=[elbv2.CfnListenerRule.TargetGroupTupleProperty(
                            target_group_arn="targetGroupArn",
                            weight=123
                        )],
                        target_group_stickiness_config=elbv2.CfnListenerRule.TargetGroupStickinessConfigProperty(
                            duration_seconds=123,
                            enabled=False
                        )
                    ),
                    order=123,
                    redirect_config=elbv2.CfnListenerRule.RedirectConfigProperty(
                        status_code="statusCode",
                
                        # the properties below are optional
                        host="host",
                        path="path",
                        port="port",
                        protocol="protocol",
                        query="query"
                    ),
                    target_group_arn="targetGroupArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "type": type,
            }
            if authenticate_cognito_config is not None:
                self._values["authenticate_cognito_config"] = authenticate_cognito_config
            if authenticate_oidc_config is not None:
                self._values["authenticate_oidc_config"] = authenticate_oidc_config
            if fixed_response_config is not None:
                self._values["fixed_response_config"] = fixed_response_config
            if forward_config is not None:
                self._values["forward_config"] = forward_config
            if order is not None:
                self._values["order"] = order
            if redirect_config is not None:
                self._values["redirect_config"] = redirect_config
            if target_group_arn is not None:
                self._values["target_group_arn"] = target_group_arn

        @builtins.property
        def type(self) -> builtins.str:
            '''The type of action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-action.html#cfn-elasticloadbalancingv2-listenerrule-action-type
            '''
            result = self._values.get("type")
            assert result is not None, "Required property 'type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def authenticate_cognito_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.AuthenticateCognitoConfigProperty", _IResolvable_da3f097b]]:
            '''[HTTPS listeners] Information for using Amazon Cognito to authenticate users.

            Specify only when ``Type`` is ``authenticate-cognito`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-action.html#cfn-elasticloadbalancingv2-listenerrule-action-authenticatecognitoconfig
            '''
            result = self._values.get("authenticate_cognito_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.AuthenticateCognitoConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def authenticate_oidc_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.AuthenticateOidcConfigProperty", _IResolvable_da3f097b]]:
            '''[HTTPS listeners] Information about an identity provider that is compliant with OpenID Connect (OIDC).

            Specify only when ``Type`` is ``authenticate-oidc`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-action.html#cfn-elasticloadbalancingv2-listenerrule-action-authenticateoidcconfig
            '''
            result = self._values.get("authenticate_oidc_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.AuthenticateOidcConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def fixed_response_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.FixedResponseConfigProperty", _IResolvable_da3f097b]]:
            '''[Application Load Balancer] Information for creating an action that returns a custom HTTP response.

            Specify only when ``Type`` is ``fixed-response`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-action.html#cfn-elasticloadbalancingv2-listenerrule-action-fixedresponseconfig
            '''
            result = self._values.get("fixed_response_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.FixedResponseConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def forward_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.ForwardConfigProperty", _IResolvable_da3f097b]]:
            '''Information for creating an action that distributes requests among one or more target groups.

            For Network Load Balancers, you can specify a single target group. Specify only when ``Type`` is ``forward`` . If you specify both ``ForwardConfig`` and ``TargetGroupArn`` , you can specify only one target group using ``ForwardConfig`` and it must be the same target group specified in ``TargetGroupArn`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-action.html#cfn-elasticloadbalancingv2-listenerrule-action-forwardconfig
            '''
            result = self._values.get("forward_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.ForwardConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def order(self) -> typing.Optional[jsii.Number]:
            '''The order for the action.

            This value is required for rules with multiple actions. The action with the lowest value for order is performed first.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-action.html#cfn-elasticloadbalancingv2-listenerrule-action-order
            '''
            result = self._values.get("order")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def redirect_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.RedirectConfigProperty", _IResolvable_da3f097b]]:
            '''[Application Load Balancer] Information for creating a redirect action.

            Specify only when ``Type`` is ``redirect`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-action.html#cfn-elasticloadbalancingv2-listenerrule-action-redirectconfig
            '''
            result = self._values.get("redirect_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.RedirectConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def target_group_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the target group.

            Specify only when ``Type`` is ``forward`` and you want to route to a single target group. To route to one or more target groups, use ``ForwardConfig`` instead.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-action.html#cfn-elasticloadbalancingv2-listenerrule-action-targetgrouparn
            '''
            result = self._values.get("target_group_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ActionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.AuthenticateCognitoConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "user_pool_arn": "userPoolArn",
            "user_pool_client_id": "userPoolClientId",
            "user_pool_domain": "userPoolDomain",
            "authentication_request_extra_params": "authenticationRequestExtraParams",
            "on_unauthenticated_request": "onUnauthenticatedRequest",
            "scope": "scope",
            "session_cookie_name": "sessionCookieName",
            "session_timeout": "sessionTimeout",
        },
    )
    class AuthenticateCognitoConfigProperty:
        def __init__(
            self,
            *,
            user_pool_arn: builtins.str,
            user_pool_client_id: builtins.str,
            user_pool_domain: builtins.str,
            authentication_request_extra_params: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            on_unauthenticated_request: typing.Optional[builtins.str] = None,
            scope: typing.Optional[builtins.str] = None,
            session_cookie_name: typing.Optional[builtins.str] = None,
            session_timeout: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies information required when integrating with Amazon Cognito to authenticate users.

            :param user_pool_arn: The Amazon Resource Name (ARN) of the Amazon Cognito user pool.
            :param user_pool_client_id: The ID of the Amazon Cognito user pool client.
            :param user_pool_domain: The domain prefix or fully-qualified domain name of the Amazon Cognito user pool.
            :param authentication_request_extra_params: The query parameters (up to 10) to include in the redirect request to the authorization endpoint.
            :param on_unauthenticated_request: The behavior if the user is not authenticated. The following are possible values:. - deny `` - Return an HTTP 401 Unauthorized error. - allow `` - Allow the request to be forwarded to the target. - authenticate `` - Redirect the request to the IdP authorization endpoint. This is the default value.
            :param scope: The set of user claims to be requested from the IdP. The default is ``openid`` . To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.
            :param session_cookie_name: The name of the cookie used to maintain session information. The default is AWSELBAuthSessionCookie.
            :param session_timeout: The maximum duration of the authentication session, in seconds. The default is 604800 seconds (7 days).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                authenticate_cognito_config_property = elbv2.CfnListenerRule.AuthenticateCognitoConfigProperty(
                    user_pool_arn="userPoolArn",
                    user_pool_client_id="userPoolClientId",
                    user_pool_domain="userPoolDomain",
                
                    # the properties below are optional
                    authentication_request_extra_params={
                        "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                    },
                    on_unauthenticated_request="onUnauthenticatedRequest",
                    scope="scope",
                    session_cookie_name="sessionCookieName",
                    session_timeout=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "user_pool_arn": user_pool_arn,
                "user_pool_client_id": user_pool_client_id,
                "user_pool_domain": user_pool_domain,
            }
            if authentication_request_extra_params is not None:
                self._values["authentication_request_extra_params"] = authentication_request_extra_params
            if on_unauthenticated_request is not None:
                self._values["on_unauthenticated_request"] = on_unauthenticated_request
            if scope is not None:
                self._values["scope"] = scope
            if session_cookie_name is not None:
                self._values["session_cookie_name"] = session_cookie_name
            if session_timeout is not None:
                self._values["session_timeout"] = session_timeout

        @builtins.property
        def user_pool_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the Amazon Cognito user pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig-userpoolarn
            '''
            result = self._values.get("user_pool_arn")
            assert result is not None, "Required property 'user_pool_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def user_pool_client_id(self) -> builtins.str:
            '''The ID of the Amazon Cognito user pool client.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig-userpoolclientid
            '''
            result = self._values.get("user_pool_client_id")
            assert result is not None, "Required property 'user_pool_client_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def user_pool_domain(self) -> builtins.str:
            '''The domain prefix or fully-qualified domain name of the Amazon Cognito user pool.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig-userpooldomain
            '''
            result = self._values.get("user_pool_domain")
            assert result is not None, "Required property 'user_pool_domain' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def authentication_request_extra_params(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''The query parameters (up to 10) to include in the redirect request to the authorization endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig-authenticationrequestextraparams
            '''
            result = self._values.get("authentication_request_extra_params")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def on_unauthenticated_request(self) -> typing.Optional[builtins.str]:
            '''The behavior if the user is not authenticated. The following are possible values:.

            - deny `` - Return an HTTP 401 Unauthorized error.
            - allow `` - Allow the request to be forwarded to the target.
            - authenticate `` - Redirect the request to the IdP authorization endpoint. This is the default value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig-onunauthenticatedrequest
            '''
            result = self._values.get("on_unauthenticated_request")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def scope(self) -> typing.Optional[builtins.str]:
            '''The set of user claims to be requested from the IdP. The default is ``openid`` .

            To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig-scope
            '''
            result = self._values.get("scope")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def session_cookie_name(self) -> typing.Optional[builtins.str]:
            '''The name of the cookie used to maintain session information.

            The default is AWSELBAuthSessionCookie.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig-sessioncookiename
            '''
            result = self._values.get("session_cookie_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def session_timeout(self) -> typing.Optional[jsii.Number]:
            '''The maximum duration of the authentication session, in seconds.

            The default is 604800 seconds (7 days).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticatecognitoconfig-sessiontimeout
            '''
            result = self._values.get("session_timeout")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AuthenticateCognitoConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.AuthenticateOidcConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "authorization_endpoint": "authorizationEndpoint",
            "client_id": "clientId",
            "client_secret": "clientSecret",
            "issuer": "issuer",
            "token_endpoint": "tokenEndpoint",
            "user_info_endpoint": "userInfoEndpoint",
            "authentication_request_extra_params": "authenticationRequestExtraParams",
            "on_unauthenticated_request": "onUnauthenticatedRequest",
            "scope": "scope",
            "session_cookie_name": "sessionCookieName",
            "session_timeout": "sessionTimeout",
            "use_existing_client_secret": "useExistingClientSecret",
        },
    )
    class AuthenticateOidcConfigProperty:
        def __init__(
            self,
            *,
            authorization_endpoint: builtins.str,
            client_id: builtins.str,
            client_secret: builtins.str,
            issuer: builtins.str,
            token_endpoint: builtins.str,
            user_info_endpoint: builtins.str,
            authentication_request_extra_params: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]] = None,
            on_unauthenticated_request: typing.Optional[builtins.str] = None,
            scope: typing.Optional[builtins.str] = None,
            session_cookie_name: typing.Optional[builtins.str] = None,
            session_timeout: typing.Optional[jsii.Number] = None,
            use_existing_client_secret: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Specifies information required using an identity provide (IdP) that is compliant with OpenID Connect (OIDC) to authenticate users.

            :param authorization_endpoint: The authorization endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
            :param client_id: The OAuth 2.0 client identifier.
            :param client_secret: The OAuth 2.0 client secret. This parameter is required if you are creating a rule. If you are modifying a rule, you can omit this parameter if you set ``UseExistingClientSecret`` to true.
            :param issuer: The OIDC issuer identifier of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
            :param token_endpoint: The token endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
            :param user_info_endpoint: The user info endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
            :param authentication_request_extra_params: The query parameters (up to 10) to include in the redirect request to the authorization endpoint.
            :param on_unauthenticated_request: The behavior if the user is not authenticated. The following are possible values:. - deny `` - Return an HTTP 401 Unauthorized error. - allow `` - Allow the request to be forwarded to the target. - authenticate `` - Redirect the request to the IdP authorization endpoint. This is the default value.
            :param scope: The set of user claims to be requested from the IdP. The default is ``openid`` . To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.
            :param session_cookie_name: The name of the cookie used to maintain session information. The default is AWSELBAuthSessionCookie.
            :param session_timeout: The maximum duration of the authentication session, in seconds. The default is 604800 seconds (7 days).
            :param use_existing_client_secret: Indicates whether to use the existing client secret when modifying a rule. If you are creating a rule, you can omit this parameter or set it to false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                authenticate_oidc_config_property = elbv2.CfnListenerRule.AuthenticateOidcConfigProperty(
                    authorization_endpoint="authorizationEndpoint",
                    client_id="clientId",
                    client_secret="clientSecret",
                    issuer="issuer",
                    token_endpoint="tokenEndpoint",
                    user_info_endpoint="userInfoEndpoint",
                
                    # the properties below are optional
                    authentication_request_extra_params={
                        "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                    },
                    on_unauthenticated_request="onUnauthenticatedRequest",
                    scope="scope",
                    session_cookie_name="sessionCookieName",
                    session_timeout=123,
                    use_existing_client_secret=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "authorization_endpoint": authorization_endpoint,
                "client_id": client_id,
                "client_secret": client_secret,
                "issuer": issuer,
                "token_endpoint": token_endpoint,
                "user_info_endpoint": user_info_endpoint,
            }
            if authentication_request_extra_params is not None:
                self._values["authentication_request_extra_params"] = authentication_request_extra_params
            if on_unauthenticated_request is not None:
                self._values["on_unauthenticated_request"] = on_unauthenticated_request
            if scope is not None:
                self._values["scope"] = scope
            if session_cookie_name is not None:
                self._values["session_cookie_name"] = session_cookie_name
            if session_timeout is not None:
                self._values["session_timeout"] = session_timeout
            if use_existing_client_secret is not None:
                self._values["use_existing_client_secret"] = use_existing_client_secret

        @builtins.property
        def authorization_endpoint(self) -> builtins.str:
            '''The authorization endpoint of the IdP.

            This must be a full URL, including the HTTPS protocol, the domain, and the path.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-authorizationendpoint
            '''
            result = self._values.get("authorization_endpoint")
            assert result is not None, "Required property 'authorization_endpoint' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def client_id(self) -> builtins.str:
            '''The OAuth 2.0 client identifier.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-clientid
            '''
            result = self._values.get("client_id")
            assert result is not None, "Required property 'client_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def client_secret(self) -> builtins.str:
            '''The OAuth 2.0 client secret. This parameter is required if you are creating a rule. If you are modifying a rule, you can omit this parameter if you set ``UseExistingClientSecret`` to true.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-clientsecret
            '''
            result = self._values.get("client_secret")
            assert result is not None, "Required property 'client_secret' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def issuer(self) -> builtins.str:
            '''The OIDC issuer identifier of the IdP.

            This must be a full URL, including the HTTPS protocol, the domain, and the path.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-issuer
            '''
            result = self._values.get("issuer")
            assert result is not None, "Required property 'issuer' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def token_endpoint(self) -> builtins.str:
            '''The token endpoint of the IdP.

            This must be a full URL, including the HTTPS protocol, the domain, and the path.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-tokenendpoint
            '''
            result = self._values.get("token_endpoint")
            assert result is not None, "Required property 'token_endpoint' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def user_info_endpoint(self) -> builtins.str:
            '''The user info endpoint of the IdP.

            This must be a full URL, including the HTTPS protocol, the domain, and the path.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-userinfoendpoint
            '''
            result = self._values.get("user_info_endpoint")
            assert result is not None, "Required property 'user_info_endpoint' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def authentication_request_extra_params(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]]:
            '''The query parameters (up to 10) to include in the redirect request to the authorization endpoint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-authenticationrequestextraparams
            '''
            result = self._values.get("authentication_request_extra_params")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Mapping[builtins.str, builtins.str]]], result)

        @builtins.property
        def on_unauthenticated_request(self) -> typing.Optional[builtins.str]:
            '''The behavior if the user is not authenticated. The following are possible values:.

            - deny `` - Return an HTTP 401 Unauthorized error.
            - allow `` - Allow the request to be forwarded to the target.
            - authenticate `` - Redirect the request to the IdP authorization endpoint. This is the default value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-onunauthenticatedrequest
            '''
            result = self._values.get("on_unauthenticated_request")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def scope(self) -> typing.Optional[builtins.str]:
            '''The set of user claims to be requested from the IdP. The default is ``openid`` .

            To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-scope
            '''
            result = self._values.get("scope")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def session_cookie_name(self) -> typing.Optional[builtins.str]:
            '''The name of the cookie used to maintain session information.

            The default is AWSELBAuthSessionCookie.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-sessioncookiename
            '''
            result = self._values.get("session_cookie_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def session_timeout(self) -> typing.Optional[jsii.Number]:
            '''The maximum duration of the authentication session, in seconds.

            The default is 604800 seconds (7 days).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-sessiontimeout
            '''
            result = self._values.get("session_timeout")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def use_existing_client_secret(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether to use the existing client secret when modifying a rule.

            If you are creating a rule, you can omit this parameter or set it to false.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-authenticateoidcconfig.html#cfn-elasticloadbalancingv2-listenerrule-authenticateoidcconfig-useexistingclientsecret
            '''
            result = self._values.get("use_existing_client_secret")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AuthenticateOidcConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.FixedResponseConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "status_code": "statusCode",
            "content_type": "contentType",
            "message_body": "messageBody",
        },
    )
    class FixedResponseConfigProperty:
        def __init__(
            self,
            *,
            status_code: builtins.str,
            content_type: typing.Optional[builtins.str] = None,
            message_body: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies information required when returning a custom HTTP response.

            :param status_code: The HTTP response code (2XX, 4XX, or 5XX).
            :param content_type: The content type. Valid Values: text/plain | text/css | text/html | application/javascript | application/json
            :param message_body: The message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-fixedresponseconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                fixed_response_config_property = elbv2.CfnListenerRule.FixedResponseConfigProperty(
                    status_code="statusCode",
                
                    # the properties below are optional
                    content_type="contentType",
                    message_body="messageBody"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "status_code": status_code,
            }
            if content_type is not None:
                self._values["content_type"] = content_type
            if message_body is not None:
                self._values["message_body"] = message_body

        @builtins.property
        def status_code(self) -> builtins.str:
            '''The HTTP response code (2XX, 4XX, or 5XX).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-fixedresponseconfig.html#cfn-elasticloadbalancingv2-listenerrule-fixedresponseconfig-statuscode
            '''
            result = self._values.get("status_code")
            assert result is not None, "Required property 'status_code' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def content_type(self) -> typing.Optional[builtins.str]:
            '''The content type.

            Valid Values: text/plain | text/css | text/html | application/javascript | application/json

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-fixedresponseconfig.html#cfn-elasticloadbalancingv2-listenerrule-fixedresponseconfig-contenttype
            '''
            result = self._values.get("content_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def message_body(self) -> typing.Optional[builtins.str]:
            '''The message.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-fixedresponseconfig.html#cfn-elasticloadbalancingv2-listenerrule-fixedresponseconfig-messagebody
            '''
            result = self._values.get("message_body")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "FixedResponseConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.ForwardConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "target_groups": "targetGroups",
            "target_group_stickiness_config": "targetGroupStickinessConfig",
        },
    )
    class ForwardConfigProperty:
        def __init__(
            self,
            *,
            target_groups: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnListenerRule.TargetGroupTupleProperty", _IResolvable_da3f097b]]]] = None,
            target_group_stickiness_config: typing.Optional[typing.Union["CfnListenerRule.TargetGroupStickinessConfigProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Information for creating an action that distributes requests among one or more target groups.

            For Network Load Balancers, you can specify a single target group. Specify only when ``Type`` is ``forward`` . If you specify both ``ForwardConfig`` and ``TargetGroupArn`` , you can specify only one target group using ``ForwardConfig`` and it must be the same target group specified in ``TargetGroupArn`` .

            :param target_groups: Information about how traffic will be distributed between multiple target groups in a forward rule.
            :param target_group_stickiness_config: Information about the target group stickiness for a rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-forwardconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                forward_config_property = elbv2.CfnListenerRule.ForwardConfigProperty(
                    target_groups=[elbv2.CfnListenerRule.TargetGroupTupleProperty(
                        target_group_arn="targetGroupArn",
                        weight=123
                    )],
                    target_group_stickiness_config=elbv2.CfnListenerRule.TargetGroupStickinessConfigProperty(
                        duration_seconds=123,
                        enabled=False
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if target_groups is not None:
                self._values["target_groups"] = target_groups
            if target_group_stickiness_config is not None:
                self._values["target_group_stickiness_config"] = target_group_stickiness_config

        @builtins.property
        def target_groups(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerRule.TargetGroupTupleProperty", _IResolvable_da3f097b]]]]:
            '''Information about how traffic will be distributed between multiple target groups in a forward rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-forwardconfig.html#cfn-elasticloadbalancingv2-listenerrule-forwardconfig-targetgroups
            '''
            result = self._values.get("target_groups")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerRule.TargetGroupTupleProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def target_group_stickiness_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.TargetGroupStickinessConfigProperty", _IResolvable_da3f097b]]:
            '''Information about the target group stickiness for a rule.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-forwardconfig.html#cfn-elasticloadbalancingv2-listenerrule-forwardconfig-targetgroupstickinessconfig
            '''
            result = self._values.get("target_group_stickiness_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.TargetGroupStickinessConfigProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ForwardConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.HostHeaderConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"values": "values"},
    )
    class HostHeaderConfigProperty:
        def __init__(
            self,
            *,
            values: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Information about a host header condition.

            :param values: One or more host names. The maximum size of each name is 128 characters. The comparison is case insensitive. The following wildcard characters are supported: * (matches 0 or more characters) and ? (matches exactly 1 character). If you specify multiple strings, the condition is satisfied if one of the strings matches the host name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-hostheaderconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                host_header_config_property = elbv2.CfnListenerRule.HostHeaderConfigProperty(
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if values is not None:
                self._values["values"] = values

        @builtins.property
        def values(self) -> typing.Optional[typing.List[builtins.str]]:
            '''One or more host names.

            The maximum size of each name is 128 characters. The comparison is case insensitive. The following wildcard characters are supported: * (matches 0 or more characters) and ? (matches exactly 1 character).

            If you specify multiple strings, the condition is satisfied if one of the strings matches the host name.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-hostheaderconfig.html#cfn-elasticloadbalancingv2-listenerrule-hostheaderconfig-values
            '''
            result = self._values.get("values")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HostHeaderConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.HttpHeaderConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"http_header_name": "httpHeaderName", "values": "values"},
    )
    class HttpHeaderConfigProperty:
        def __init__(
            self,
            *,
            http_header_name: typing.Optional[builtins.str] = None,
            values: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Information about an HTTP header condition.

            There is a set of standard HTTP header fields. You can also define custom HTTP header fields.

            :param http_header_name: The name of the HTTP header field. The maximum size is 40 characters. The header name is case insensitive. The allowed characters are specified by RFC 7230. Wildcards are not supported.
            :param values: One or more strings to compare against the value of the HTTP header. The maximum size of each string is 128 characters. The comparison strings are case insensitive. The following wildcard characters are supported: * (matches 0 or more characters) and ? (matches exactly 1 character). If the same header appears multiple times in the request, we search them in order until a match is found. If you specify multiple strings, the condition is satisfied if one of the strings matches the value of the HTTP header. To require that all of the strings are a match, create one condition per string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-httpheaderconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                http_header_config_property = elbv2.CfnListenerRule.HttpHeaderConfigProperty(
                    http_header_name="httpHeaderName",
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if http_header_name is not None:
                self._values["http_header_name"] = http_header_name
            if values is not None:
                self._values["values"] = values

        @builtins.property
        def http_header_name(self) -> typing.Optional[builtins.str]:
            '''The name of the HTTP header field.

            The maximum size is 40 characters. The header name is case insensitive. The allowed characters are specified by RFC 7230. Wildcards are not supported.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-httpheaderconfig.html#cfn-elasticloadbalancingv2-listenerrule-httpheaderconfig-httpheadername
            '''
            result = self._values.get("http_header_name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def values(self) -> typing.Optional[typing.List[builtins.str]]:
            '''One or more strings to compare against the value of the HTTP header.

            The maximum size of each string is 128 characters. The comparison strings are case insensitive. The following wildcard characters are supported: * (matches 0 or more characters) and ? (matches exactly 1 character).

            If the same header appears multiple times in the request, we search them in order until a match is found.

            If you specify multiple strings, the condition is satisfied if one of the strings matches the value of the HTTP header. To require that all of the strings are a match, create one condition per string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-httpheaderconfig.html#cfn-elasticloadbalancingv2-listenerrule-httpheaderconfig-values
            '''
            result = self._values.get("values")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HttpHeaderConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.HttpRequestMethodConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"values": "values"},
    )
    class HttpRequestMethodConfigProperty:
        def __init__(
            self,
            *,
            values: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Information about an HTTP method condition.

            HTTP defines a set of request methods, also referred to as HTTP verbs. For more information, see the `HTTP Method Registry <https://docs.aws.amazon.com/https://www.iana.org/assignments/http-methods/http-methods.xhtml>`_ . You can also define custom HTTP methods.

            :param values: The name of the request method. The maximum size is 40 characters. The allowed characters are A-Z, hyphen (-), and underscore (_). The comparison is case sensitive. Wildcards are not supported; therefore, the method name must be an exact match. If you specify multiple strings, the condition is satisfied if one of the strings matches the HTTP request method. We recommend that you route GET and HEAD requests in the same way, because the response to a HEAD request may be cached.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-httprequestmethodconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                http_request_method_config_property = elbv2.CfnListenerRule.HttpRequestMethodConfigProperty(
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if values is not None:
                self._values["values"] = values

        @builtins.property
        def values(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The name of the request method.

            The maximum size is 40 characters. The allowed characters are A-Z, hyphen (-), and underscore (_). The comparison is case sensitive. Wildcards are not supported; therefore, the method name must be an exact match.

            If you specify multiple strings, the condition is satisfied if one of the strings matches the HTTP request method. We recommend that you route GET and HEAD requests in the same way, because the response to a HEAD request may be cached.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-httprequestmethodconfig.html#cfn-elasticloadbalancingv2-listenerrule-httprequestmethodconfig-values
            '''
            result = self._values.get("values")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "HttpRequestMethodConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.PathPatternConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"values": "values"},
    )
    class PathPatternConfigProperty:
        def __init__(
            self,
            *,
            values: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Information about a path pattern condition.

            :param values: One or more path patterns to compare against the request URL. The maximum size of each string is 128 characters. The comparison is case sensitive. The following wildcard characters are supported: * (matches 0 or more characters) and ? (matches exactly 1 character). If you specify multiple strings, the condition is satisfied if one of them matches the request URL. The path pattern is compared only to the path of the URL, not to its query string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-pathpatternconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                path_pattern_config_property = elbv2.CfnListenerRule.PathPatternConfigProperty(
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if values is not None:
                self._values["values"] = values

        @builtins.property
        def values(self) -> typing.Optional[typing.List[builtins.str]]:
            '''One or more path patterns to compare against the request URL.

            The maximum size of each string is 128 characters. The comparison is case sensitive. The following wildcard characters are supported: * (matches 0 or more characters) and ? (matches exactly 1 character).

            If you specify multiple strings, the condition is satisfied if one of them matches the request URL. The path pattern is compared only to the path of the URL, not to its query string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-pathpatternconfig.html#cfn-elasticloadbalancingv2-listenerrule-pathpatternconfig-values
            '''
            result = self._values.get("values")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PathPatternConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.QueryStringConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"values": "values"},
    )
    class QueryStringConfigProperty:
        def __init__(
            self,
            *,
            values: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnListenerRule.QueryStringKeyValueProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''Information about a query string condition.

            The query string component of a URI starts after the first '?' character and is terminated by either a '#' character or the end of the URI. A typical query string contains key/value pairs separated by '&' characters. The allowed characters are specified by RFC 3986. Any character can be percentage encoded.

            :param values: One or more key/value pairs or values to find in the query string. The maximum size of each string is 128 characters. The comparison is case insensitive. The following wildcard characters are supported: * (matches 0 or more characters) and ? (matches exactly 1 character). To search for a literal '*' or '?' character in a query string, you must escape these characters in ``Values`` using a '' character. If you specify multiple key/value pairs or values, the condition is satisfied if one of them is found in the query string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-querystringconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                query_string_config_property = elbv2.CfnListenerRule.QueryStringConfigProperty(
                    values=[elbv2.CfnListenerRule.QueryStringKeyValueProperty(
                        key="key",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if values is not None:
                self._values["values"] = values

        @builtins.property
        def values(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerRule.QueryStringKeyValueProperty", _IResolvable_da3f097b]]]]:
            '''One or more key/value pairs or values to find in the query string.

            The maximum size of each string is 128 characters. The comparison is case insensitive. The following wildcard characters are supported: * (matches 0 or more characters) and ? (matches exactly 1 character). To search for a literal '*' or '?' character in a query string, you must escape these characters in ``Values`` using a '' character.

            If you specify multiple key/value pairs or values, the condition is satisfied if one of them is found in the query string.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-querystringconfig.html#cfn-elasticloadbalancingv2-listenerrule-querystringconfig-values
            '''
            result = self._values.get("values")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnListenerRule.QueryStringKeyValueProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "QueryStringConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.QueryStringKeyValueProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class QueryStringKeyValueProperty:
        def __init__(
            self,
            *,
            key: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about a key/value pair.

            :param key: The key. You can omit the key.
            :param value: The value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-querystringkeyvalue.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                query_string_key_value_property = elbv2.CfnListenerRule.QueryStringKeyValueProperty(
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
            '''The key.

            You can omit the key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-querystringkeyvalue.html#cfn-elasticloadbalancingv2-listenerrule-querystringkeyvalue-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-querystringkeyvalue.html#cfn-elasticloadbalancingv2-listenerrule-querystringkeyvalue-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "QueryStringKeyValueProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.RedirectConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "status_code": "statusCode",
            "host": "host",
            "path": "path",
            "port": "port",
            "protocol": "protocol",
            "query": "query",
        },
    )
    class RedirectConfigProperty:
        def __init__(
            self,
            *,
            status_code: builtins.str,
            host: typing.Optional[builtins.str] = None,
            path: typing.Optional[builtins.str] = None,
            port: typing.Optional[builtins.str] = None,
            protocol: typing.Optional[builtins.str] = None,
            query: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Information about a redirect action.

            A URI consists of the following components: protocol://hostname:port/path?query. You must modify at least one of the following components to avoid a redirect loop: protocol, hostname, port, or path. Any components that you do not modify retain their original values.

            You can reuse URI components using the following reserved keywords:

            - #{protocol}
            - #{host}
            - #{port}
            - #{path} (the leading "/" is removed)
            - #{query}

            For example, you can change the path to "/new/#{path}", the hostname to "example.#{host}", or the query to "#{query}&value=xyz".

            :param status_code: The HTTP redirect code. The redirect is either permanent (HTTP 301) or temporary (HTTP 302).
            :param host: The hostname. This component is not percent-encoded. The hostname can contain #{host}.
            :param path: The absolute path, starting with the leading "/". This component is not percent-encoded. The path can contain #{host}, #{path}, and #{port}.
            :param port: The port. You can specify a value from 1 to 65535 or #{port}.
            :param protocol: The protocol. You can specify HTTP, HTTPS, or #{protocol}. You can redirect HTTP to HTTP, HTTP to HTTPS, and HTTPS to HTTPS. You cannot redirect HTTPS to HTTP.
            :param query: The query parameters, URL-encoded when necessary, but not percent-encoded. Do not include the leading "?", as it is automatically added. You can specify any of the reserved keywords.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-redirectconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                redirect_config_property = elbv2.CfnListenerRule.RedirectConfigProperty(
                    status_code="statusCode",
                
                    # the properties below are optional
                    host="host",
                    path="path",
                    port="port",
                    protocol="protocol",
                    query="query"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "status_code": status_code,
            }
            if host is not None:
                self._values["host"] = host
            if path is not None:
                self._values["path"] = path
            if port is not None:
                self._values["port"] = port
            if protocol is not None:
                self._values["protocol"] = protocol
            if query is not None:
                self._values["query"] = query

        @builtins.property
        def status_code(self) -> builtins.str:
            '''The HTTP redirect code.

            The redirect is either permanent (HTTP 301) or temporary (HTTP 302).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-redirectconfig.html#cfn-elasticloadbalancingv2-listenerrule-redirectconfig-statuscode
            '''
            result = self._values.get("status_code")
            assert result is not None, "Required property 'status_code' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def host(self) -> typing.Optional[builtins.str]:
            '''The hostname.

            This component is not percent-encoded. The hostname can contain #{host}.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-redirectconfig.html#cfn-elasticloadbalancingv2-listenerrule-redirectconfig-host
            '''
            result = self._values.get("host")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def path(self) -> typing.Optional[builtins.str]:
            '''The absolute path, starting with the leading "/".

            This component is not percent-encoded. The path can contain #{host}, #{path}, and #{port}.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-redirectconfig.html#cfn-elasticloadbalancingv2-listenerrule-redirectconfig-path
            '''
            result = self._values.get("path")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def port(self) -> typing.Optional[builtins.str]:
            '''The port.

            You can specify a value from 1 to 65535 or #{port}.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-redirectconfig.html#cfn-elasticloadbalancingv2-listenerrule-redirectconfig-port
            '''
            result = self._values.get("port")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def protocol(self) -> typing.Optional[builtins.str]:
            '''The protocol.

            You can specify HTTP, HTTPS, or #{protocol}. You can redirect HTTP to HTTP, HTTP to HTTPS, and HTTPS to HTTPS. You cannot redirect HTTPS to HTTP.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-redirectconfig.html#cfn-elasticloadbalancingv2-listenerrule-redirectconfig-protocol
            '''
            result = self._values.get("protocol")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def query(self) -> typing.Optional[builtins.str]:
            '''The query parameters, URL-encoded when necessary, but not percent-encoded.

            Do not include the leading "?", as it is automatically added. You can specify any of the reserved keywords.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-redirectconfig.html#cfn-elasticloadbalancingv2-listenerrule-redirectconfig-query
            '''
            result = self._values.get("query")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RedirectConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.RuleConditionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "field": "field",
            "host_header_config": "hostHeaderConfig",
            "http_header_config": "httpHeaderConfig",
            "http_request_method_config": "httpRequestMethodConfig",
            "path_pattern_config": "pathPatternConfig",
            "query_string_config": "queryStringConfig",
            "source_ip_config": "sourceIpConfig",
            "values": "values",
        },
    )
    class RuleConditionProperty:
        def __init__(
            self,
            *,
            field: typing.Optional[builtins.str] = None,
            host_header_config: typing.Optional[typing.Union["CfnListenerRule.HostHeaderConfigProperty", _IResolvable_da3f097b]] = None,
            http_header_config: typing.Optional[typing.Union["CfnListenerRule.HttpHeaderConfigProperty", _IResolvable_da3f097b]] = None,
            http_request_method_config: typing.Optional[typing.Union["CfnListenerRule.HttpRequestMethodConfigProperty", _IResolvable_da3f097b]] = None,
            path_pattern_config: typing.Optional[typing.Union["CfnListenerRule.PathPatternConfigProperty", _IResolvable_da3f097b]] = None,
            query_string_config: typing.Optional[typing.Union["CfnListenerRule.QueryStringConfigProperty", _IResolvable_da3f097b]] = None,
            source_ip_config: typing.Optional[typing.Union["CfnListenerRule.SourceIpConfigProperty", _IResolvable_da3f097b]] = None,
            values: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Specifies a condition for a listener rule.

            :param field: The field in the HTTP request. The following are the possible values:. - ``http-header`` - ``http-request-method`` - ``host-header`` - ``path-pattern`` - ``query-string`` - ``source-ip``
            :param host_header_config: Information for a host header condition. Specify only when ``Field`` is ``host-header`` .
            :param http_header_config: Information for an HTTP header condition. Specify only when ``Field`` is ``http-header`` .
            :param http_request_method_config: Information for an HTTP method condition. Specify only when ``Field`` is ``http-request-method`` .
            :param path_pattern_config: Information for a path pattern condition. Specify only when ``Field`` is ``path-pattern`` .
            :param query_string_config: Information for a query string condition. Specify only when ``Field`` is ``query-string`` .
            :param source_ip_config: Information for a source IP condition. Specify only when ``Field`` is ``source-ip`` .
            :param values: The condition value. Specify only when ``Field`` is ``host-header`` or ``path-pattern`` . Alternatively, to specify multiple host names or multiple path patterns, use ``HostHeaderConfig`` or ``PathPatternConfig`` . If ``Field`` is ``host-header`` and you're not using ``HostHeaderConfig`` , you can specify a single host name (for example, my.example.com). A host name is case insensitive, can be up to 128 characters in length, and can contain any of the following characters. - A-Z, a-z, 0-9 - - . - - (matches 0 or more characters) - ? (matches exactly 1 character) If ``Field`` is ``path-pattern`` and you're not using ``PathPatternConfig`` , you can specify a single path pattern (for example, /img/*). A path pattern is case-sensitive, can be up to 128 characters in length, and can contain any of the following characters. - A-Z, a-z, 0-9 - _ - . $ / ~ " ' @ : + - & (using &) - - (matches 0 or more characters) - ? (matches exactly 1 character)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-rulecondition.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                rule_condition_property = elbv2.CfnListenerRule.RuleConditionProperty(
                    field="field",
                    host_header_config=elbv2.CfnListenerRule.HostHeaderConfigProperty(
                        values=["values"]
                    ),
                    http_header_config=elbv2.CfnListenerRule.HttpHeaderConfigProperty(
                        http_header_name="httpHeaderName",
                        values=["values"]
                    ),
                    http_request_method_config=elbv2.CfnListenerRule.HttpRequestMethodConfigProperty(
                        values=["values"]
                    ),
                    path_pattern_config=elbv2.CfnListenerRule.PathPatternConfigProperty(
                        values=["values"]
                    ),
                    query_string_config=elbv2.CfnListenerRule.QueryStringConfigProperty(
                        values=[elbv2.CfnListenerRule.QueryStringKeyValueProperty(
                            key="key",
                            value="value"
                        )]
                    ),
                    source_ip_config=elbv2.CfnListenerRule.SourceIpConfigProperty(
                        values=["values"]
                    ),
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if field is not None:
                self._values["field"] = field
            if host_header_config is not None:
                self._values["host_header_config"] = host_header_config
            if http_header_config is not None:
                self._values["http_header_config"] = http_header_config
            if http_request_method_config is not None:
                self._values["http_request_method_config"] = http_request_method_config
            if path_pattern_config is not None:
                self._values["path_pattern_config"] = path_pattern_config
            if query_string_config is not None:
                self._values["query_string_config"] = query_string_config
            if source_ip_config is not None:
                self._values["source_ip_config"] = source_ip_config
            if values is not None:
                self._values["values"] = values

        @builtins.property
        def field(self) -> typing.Optional[builtins.str]:
            '''The field in the HTTP request. The following are the possible values:.

            - ``http-header``
            - ``http-request-method``
            - ``host-header``
            - ``path-pattern``
            - ``query-string``
            - ``source-ip``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-rulecondition.html#cfn-elasticloadbalancingv2-listenerrule-rulecondition-field
            '''
            result = self._values.get("field")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def host_header_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.HostHeaderConfigProperty", _IResolvable_da3f097b]]:
            '''Information for a host header condition.

            Specify only when ``Field`` is ``host-header`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-rulecondition.html#cfn-elasticloadbalancingv2-listenerrule-rulecondition-hostheaderconfig
            '''
            result = self._values.get("host_header_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.HostHeaderConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def http_header_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.HttpHeaderConfigProperty", _IResolvable_da3f097b]]:
            '''Information for an HTTP header condition.

            Specify only when ``Field`` is ``http-header`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-rulecondition.html#cfn-elasticloadbalancingv2-listenerrule-rulecondition-httpheaderconfig
            '''
            result = self._values.get("http_header_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.HttpHeaderConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def http_request_method_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.HttpRequestMethodConfigProperty", _IResolvable_da3f097b]]:
            '''Information for an HTTP method condition.

            Specify only when ``Field`` is ``http-request-method`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-rulecondition.html#cfn-elasticloadbalancingv2-listenerrule-rulecondition-httprequestmethodconfig
            '''
            result = self._values.get("http_request_method_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.HttpRequestMethodConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def path_pattern_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.PathPatternConfigProperty", _IResolvable_da3f097b]]:
            '''Information for a path pattern condition.

            Specify only when ``Field`` is ``path-pattern`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-rulecondition.html#cfn-elasticloadbalancingv2-listenerrule-rulecondition-pathpatternconfig
            '''
            result = self._values.get("path_pattern_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.PathPatternConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def query_string_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.QueryStringConfigProperty", _IResolvable_da3f097b]]:
            '''Information for a query string condition.

            Specify only when ``Field`` is ``query-string`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-rulecondition.html#cfn-elasticloadbalancingv2-listenerrule-rulecondition-querystringconfig
            '''
            result = self._values.get("query_string_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.QueryStringConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def source_ip_config(
            self,
        ) -> typing.Optional[typing.Union["CfnListenerRule.SourceIpConfigProperty", _IResolvable_da3f097b]]:
            '''Information for a source IP condition.

            Specify only when ``Field`` is ``source-ip`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-rulecondition.html#cfn-elasticloadbalancingv2-listenerrule-rulecondition-sourceipconfig
            '''
            result = self._values.get("source_ip_config")
            return typing.cast(typing.Optional[typing.Union["CfnListenerRule.SourceIpConfigProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def values(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The condition value.

            Specify only when ``Field`` is ``host-header`` or ``path-pattern`` . Alternatively, to specify multiple host names or multiple path patterns, use ``HostHeaderConfig`` or ``PathPatternConfig`` .

            If ``Field`` is ``host-header`` and you're not using ``HostHeaderConfig`` , you can specify a single host name (for example, my.example.com). A host name is case insensitive, can be up to 128 characters in length, and can contain any of the following characters.

            - A-Z, a-z, 0-9
            -
              - .

            -
              - (matches 0 or more characters)

            - ? (matches exactly 1 character)

            If ``Field`` is ``path-pattern`` and you're not using ``PathPatternConfig`` , you can specify a single path pattern (for example, /img/*). A path pattern is case-sensitive, can be up to 128 characters in length, and can contain any of the following characters.

            - A-Z, a-z, 0-9
            - _ - . $ / ~ " ' @ : +
            - & (using &)
            -
              - (matches 0 or more characters)

            - ? (matches exactly 1 character)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-rulecondition.html#cfn-elasticloadbalancingv2-listenerrule-rulecondition-values
            '''
            result = self._values.get("values")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RuleConditionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.SourceIpConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"values": "values"},
    )
    class SourceIpConfigProperty:
        def __init__(
            self,
            *,
            values: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''Information about a source IP condition.

            You can use this condition to route based on the IP address of the source that connects to the load balancer. If a client is behind a proxy, this is the IP address of the proxy not the IP address of the client.

            :param values: One or more source IP addresses, in CIDR format. You can use both IPv4 and IPv6 addresses. Wildcards are not supported. If you specify multiple addresses, the condition is satisfied if the source IP address of the request matches one of the CIDR blocks. This condition is not satisfied by the addresses in the X-Forwarded-For header.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-sourceipconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                source_ip_config_property = elbv2.CfnListenerRule.SourceIpConfigProperty(
                    values=["values"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if values is not None:
                self._values["values"] = values

        @builtins.property
        def values(self) -> typing.Optional[typing.List[builtins.str]]:
            '''One or more source IP addresses, in CIDR format.

            You can use both IPv4 and IPv6 addresses. Wildcards are not supported.

            If you specify multiple addresses, the condition is satisfied if the source IP address of the request matches one of the CIDR blocks. This condition is not satisfied by the addresses in the X-Forwarded-For header.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-sourceipconfig.html#cfn-elasticloadbalancingv2-listenerrule-sourceipconfig-values
            '''
            result = self._values.get("values")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SourceIpConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.TargetGroupStickinessConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"duration_seconds": "durationSeconds", "enabled": "enabled"},
    )
    class TargetGroupStickinessConfigProperty:
        def __init__(
            self,
            *,
            duration_seconds: typing.Optional[jsii.Number] = None,
            enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Information about the target group stickiness for a rule.

            :param duration_seconds: The time period, in seconds, during which requests from a client should be routed to the same target group. The range is 1-604800 seconds (7 days).
            :param enabled: Indicates whether target group stickiness is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-targetgroupstickinessconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                target_group_stickiness_config_property = elbv2.CfnListenerRule.TargetGroupStickinessConfigProperty(
                    duration_seconds=123,
                    enabled=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if duration_seconds is not None:
                self._values["duration_seconds"] = duration_seconds
            if enabled is not None:
                self._values["enabled"] = enabled

        @builtins.property
        def duration_seconds(self) -> typing.Optional[jsii.Number]:
            '''The time period, in seconds, during which requests from a client should be routed to the same target group.

            The range is 1-604800 seconds (7 days).

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-targetgroupstickinessconfig.html#cfn-elasticloadbalancingv2-listenerrule-targetgroupstickinessconfig-durationseconds
            '''
            result = self._values.get("duration_seconds")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def enabled(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether target group stickiness is enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-targetgroupstickinessconfig.html#cfn-elasticloadbalancingv2-listenerrule-targetgroupstickinessconfig-enabled
            '''
            result = self._values.get("enabled")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetGroupStickinessConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRule.TargetGroupTupleProperty",
        jsii_struct_bases=[],
        name_mapping={"target_group_arn": "targetGroupArn", "weight": "weight"},
    )
    class TargetGroupTupleProperty:
        def __init__(
            self,
            *,
            target_group_arn: typing.Optional[builtins.str] = None,
            weight: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Information about how traffic will be distributed between multiple target groups in a forward rule.

            :param target_group_arn: The Amazon Resource Name (ARN) of the target group.
            :param weight: The weight. The range is 0 to 999.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-targetgrouptuple.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                target_group_tuple_property = elbv2.CfnListenerRule.TargetGroupTupleProperty(
                    target_group_arn="targetGroupArn",
                    weight=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if target_group_arn is not None:
                self._values["target_group_arn"] = target_group_arn
            if weight is not None:
                self._values["weight"] = weight

        @builtins.property
        def target_group_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the target group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-targetgrouptuple.html#cfn-elasticloadbalancingv2-listenerrule-targetgrouptuple-targetgrouparn
            '''
            result = self._values.get("target_group_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def weight(self) -> typing.Optional[jsii.Number]:
            '''The weight.

            The range is 0 to 999.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-listenerrule-targetgrouptuple.html#cfn-elasticloadbalancingv2-listenerrule-targetgrouptuple-weight
            '''
            result = self._values.get("weight")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetGroupTupleProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnListenerRuleProps",
    jsii_struct_bases=[],
    name_mapping={
        "actions": "actions",
        "conditions": "conditions",
        "listener_arn": "listenerArn",
        "priority": "priority",
    },
)
class CfnListenerRuleProps:
    def __init__(
        self,
        *,
        actions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnListenerRule.ActionProperty, _IResolvable_da3f097b]]],
        conditions: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnListenerRule.RuleConditionProperty, _IResolvable_da3f097b]]],
        listener_arn: builtins.str,
        priority: jsii.Number,
    ) -> None:
        '''Properties for defining a ``CfnListenerRule``.

        :param actions: The actions. The rule must include exactly one of the following types of actions: ``forward`` , ``fixed-response`` , or ``redirect`` , and it must be the last action to be performed. If the rule is for an HTTPS listener, it can also optionally include an authentication action.
        :param conditions: The conditions. The rule can optionally include up to one of each of the following conditions: ``http-request-method`` , ``host-header`` , ``path-pattern`` , and ``source-ip`` . A rule can also optionally include one or more of each of the following conditions: ``http-header`` and ``query-string`` .
        :param listener_arn: The Amazon Resource Name (ARN) of the listener.
        :param priority: The rule priority. A listener can't have multiple rules with the same priority. If you try to reorder rules by updating their priorities, do not specify a new priority if an existing rule already uses this priority, as this can cause an error. If you need to reuse a priority with a different rule, you must remove it as a priority first, and then specify it in a subsequent update.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            cfn_listener_rule_props = elbv2.CfnListenerRuleProps(
                actions=[elbv2.CfnListenerRule.ActionProperty(
                    type="type",
            
                    # the properties below are optional
                    authenticate_cognito_config=elbv2.CfnListenerRule.AuthenticateCognitoConfigProperty(
                        user_pool_arn="userPoolArn",
                        user_pool_client_id="userPoolClientId",
                        user_pool_domain="userPoolDomain",
            
                        # the properties below are optional
                        authentication_request_extra_params={
                            "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                        },
                        on_unauthenticated_request="onUnauthenticatedRequest",
                        scope="scope",
                        session_cookie_name="sessionCookieName",
                        session_timeout=123
                    ),
                    authenticate_oidc_config=elbv2.CfnListenerRule.AuthenticateOidcConfigProperty(
                        authorization_endpoint="authorizationEndpoint",
                        client_id="clientId",
                        client_secret="clientSecret",
                        issuer="issuer",
                        token_endpoint="tokenEndpoint",
                        user_info_endpoint="userInfoEndpoint",
            
                        # the properties below are optional
                        authentication_request_extra_params={
                            "authentication_request_extra_params_key": "authenticationRequestExtraParams"
                        },
                        on_unauthenticated_request="onUnauthenticatedRequest",
                        scope="scope",
                        session_cookie_name="sessionCookieName",
                        session_timeout=123,
                        use_existing_client_secret=False
                    ),
                    fixed_response_config=elbv2.CfnListenerRule.FixedResponseConfigProperty(
                        status_code="statusCode",
            
                        # the properties below are optional
                        content_type="contentType",
                        message_body="messageBody"
                    ),
                    forward_config=elbv2.CfnListenerRule.ForwardConfigProperty(
                        target_groups=[elbv2.CfnListenerRule.TargetGroupTupleProperty(
                            target_group_arn="targetGroupArn",
                            weight=123
                        )],
                        target_group_stickiness_config=elbv2.CfnListenerRule.TargetGroupStickinessConfigProperty(
                            duration_seconds=123,
                            enabled=False
                        )
                    ),
                    order=123,
                    redirect_config=elbv2.CfnListenerRule.RedirectConfigProperty(
                        status_code="statusCode",
            
                        # the properties below are optional
                        host="host",
                        path="path",
                        port="port",
                        protocol="protocol",
                        query="query"
                    ),
                    target_group_arn="targetGroupArn"
                )],
                conditions=[elbv2.CfnListenerRule.RuleConditionProperty(
                    field="field",
                    host_header_config=elbv2.CfnListenerRule.HostHeaderConfigProperty(
                        values=["values"]
                    ),
                    http_header_config=elbv2.CfnListenerRule.HttpHeaderConfigProperty(
                        http_header_name="httpHeaderName",
                        values=["values"]
                    ),
                    http_request_method_config=elbv2.CfnListenerRule.HttpRequestMethodConfigProperty(
                        values=["values"]
                    ),
                    path_pattern_config=elbv2.CfnListenerRule.PathPatternConfigProperty(
                        values=["values"]
                    ),
                    query_string_config=elbv2.CfnListenerRule.QueryStringConfigProperty(
                        values=[elbv2.CfnListenerRule.QueryStringKeyValueProperty(
                            key="key",
                            value="value"
                        )]
                    ),
                    source_ip_config=elbv2.CfnListenerRule.SourceIpConfigProperty(
                        values=["values"]
                    ),
                    values=["values"]
                )],
                listener_arn="listenerArn",
                priority=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "actions": actions,
            "conditions": conditions,
            "listener_arn": listener_arn,
            "priority": priority,
        }

    @builtins.property
    def actions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnListenerRule.ActionProperty, _IResolvable_da3f097b]]]:
        '''The actions.

        The rule must include exactly one of the following types of actions: ``forward`` , ``fixed-response`` , or ``redirect`` , and it must be the last action to be performed. If the rule is for an HTTPS listener, it can also optionally include an authentication action.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html#cfn-elasticloadbalancingv2-listenerrule-actions
        '''
        result = self._values.get("actions")
        assert result is not None, "Required property 'actions' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnListenerRule.ActionProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def conditions(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnListenerRule.RuleConditionProperty, _IResolvable_da3f097b]]]:
        '''The conditions.

        The rule can optionally include up to one of each of the following conditions: ``http-request-method`` , ``host-header`` , ``path-pattern`` , and ``source-ip`` . A rule can also optionally include one or more of each of the following conditions: ``http-header`` and ``query-string`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html#cfn-elasticloadbalancingv2-listenerrule-conditions
        '''
        result = self._values.get("conditions")
        assert result is not None, "Required property 'conditions' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnListenerRule.RuleConditionProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def listener_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the listener.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html#cfn-elasticloadbalancingv2-listenerrule-listenerarn
        '''
        result = self._values.get("listener_arn")
        assert result is not None, "Required property 'listener_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def priority(self) -> jsii.Number:
        '''The rule priority. A listener can't have multiple rules with the same priority.

        If you try to reorder rules by updating their priorities, do not specify a new priority if an existing rule already uses this priority, as this can cause an error. If you need to reuse a priority with a different rule, you must remove it as a priority first, and then specify it in a subsequent update.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenerrule.html#cfn-elasticloadbalancingv2-listenerrule-priority
        '''
        result = self._values.get("priority")
        assert result is not None, "Required property 'priority' is missing"
        return typing.cast(jsii.Number, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnListenerRuleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnLoadBalancer(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnLoadBalancer",
):
    '''A CloudFormation ``AWS::ElasticLoadBalancingV2::LoadBalancer``.

    Specifies an Application Load Balancer, a Network Load Balancer, or a Gateway Load Balancer.

    :cloudformationResource: AWS::ElasticLoadBalancingV2::LoadBalancer
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticloadbalancingv2 as elbv2
        
        cfn_load_balancer = elbv2.CfnLoadBalancer(self, "MyCfnLoadBalancer",
            ip_address_type="ipAddressType",
            load_balancer_attributes=[elbv2.CfnLoadBalancer.LoadBalancerAttributeProperty(
                key="key",
                value="value"
            )],
            name="name",
            scheme="scheme",
            security_groups=["securityGroups"],
            subnet_mappings=[elbv2.CfnLoadBalancer.SubnetMappingProperty(
                subnet_id="subnetId",
        
                # the properties below are optional
                allocation_id="allocationId",
                i_pv6_address="iPv6Address",
                private_iPv4_address="privateIPv4Address"
            )],
            subnets=["subnets"],
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            type="type"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        ip_address_type: typing.Optional[builtins.str] = None,
        load_balancer_attributes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLoadBalancer.LoadBalancerAttributeProperty", _IResolvable_da3f097b]]]] = None,
        name: typing.Optional[builtins.str] = None,
        scheme: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        subnet_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLoadBalancer.SubnetMappingProperty", _IResolvable_da3f097b]]]] = None,
        subnets: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        type: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::ElasticLoadBalancingV2::LoadBalancer``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param ip_address_type: The IP address type. The possible values are ``ipv4`` (for IPv4 addresses) and ``dualstack`` (for IPv4 and IPv6 addresses). You can’t specify ``dualstack`` for a load balancer with a UDP or TCP_UDP listener.
        :param load_balancer_attributes: The load balancer attributes.
        :param name: The name of the load balancer. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, must not begin or end with a hyphen, and must not begin with "internal-". If you don't specify a name, AWS CloudFormation generates a unique physical ID for the load balancer. If you specify a name, you cannot perform updates that require replacement of this resource, but you can perform other updates. To replace the resource, specify a new name.
        :param scheme: The nodes of an Internet-facing load balancer have public IP addresses. The DNS name of an Internet-facing load balancer is publicly resolvable to the public IP addresses of the nodes. Therefore, Internet-facing load balancers can route requests from clients over the internet. The nodes of an internal load balancer have only private IP addresses. The DNS name of an internal load balancer is publicly resolvable to the private IP addresses of the nodes. Therefore, internal load balancers can route requests only from clients with access to the VPC for the load balancer. The default is an Internet-facing load balancer. You cannot specify a scheme for a Gateway Load Balancer.
        :param security_groups: [Application Load Balancers] The IDs of the security groups for the load balancer.
        :param subnet_mappings: The IDs of the public subnets. You can specify only one subnet per Availability Zone. You must specify either subnets or subnet mappings, but not both. [Application Load Balancers] You must specify subnets from at least two Availability Zones. You cannot specify Elastic IP addresses for your subnets. [Application Load Balancers on Outposts] You must specify one Outpost subnet. [Application Load Balancers on Local Zones] You can specify subnets from one or more Local Zones. [Network Load Balancers] You can specify subnets from one or more Availability Zones. You can specify one Elastic IP address per subnet if you need static IP addresses for your internet-facing load balancer. For internal load balancers, you can specify one private IP address per subnet from the IPv4 range of the subnet. For internet-facing load balancer, you can specify one IPv6 address per subnet. [Gateway Load Balancers] You can specify subnets from one or more Availability Zones. You cannot specify Elastic IP addresses for your subnets.
        :param subnets: The IDs of the public subnets. You can specify only one subnet per Availability Zone. You must specify either subnets or subnet mappings, but not both. To specify an Elastic IP address, specify subnet mappings instead of subnets. [Application Load Balancers] You must specify subnets from at least two Availability Zones. [Application Load Balancers on Outposts] You must specify one Outpost subnet. [Application Load Balancers on Local Zones] You can specify subnets from one or more Local Zones. [Network Load Balancers] You can specify subnets from one or more Availability Zones. [Gateway Load Balancers] You can specify subnets from one or more Availability Zones.
        :param tags: The tags to assign to the load balancer.
        :param type: The type of load balancer. The default is ``application`` .
        '''
        props = CfnLoadBalancerProps(
            ip_address_type=ip_address_type,
            load_balancer_attributes=load_balancer_attributes,
            name=name,
            scheme=scheme,
            security_groups=security_groups,
            subnet_mappings=subnet_mappings,
            subnets=subnets,
            tags=tags,
            type=type,
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
    @jsii.member(jsii_name="attrCanonicalHostedZoneId")
    def attr_canonical_hosted_zone_id(self) -> builtins.str:
        '''The ID of the Amazon Route 53 hosted zone associated with the load balancer.

        For example, ``Z2P70J7EXAMPLE`` .

        :cloudformationAttribute: CanonicalHostedZoneID
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCanonicalHostedZoneId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrDnsName")
    def attr_dns_name(self) -> builtins.str:
        '''The DNS name for the load balancer.

        For example, ``my-load-balancer-424835706.us-west-2.elb.amazonaws.com`` .

        :cloudformationAttribute: DNSName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrDnsName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoadBalancerFullName")
    def attr_load_balancer_full_name(self) -> builtins.str:
        '''The full name of the load balancer.

        For example, ``app/my-load-balancer/50dc6c495c0c9188`` .

        :cloudformationAttribute: LoadBalancerFullName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLoadBalancerFullName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrLoadBalancerName")
    def attr_load_balancer_name(self) -> builtins.str:
        '''The name of the load balancer.

        For example, ``my-load-balancer`` .

        :cloudformationAttribute: LoadBalancerName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrLoadBalancerName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrSecurityGroups")
    def attr_security_groups(self) -> typing.List[builtins.str]:
        '''The IDs of the security groups for the load balancer.

        :cloudformationAttribute: SecurityGroups
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrSecurityGroups"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags to assign to the load balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ipAddressType")
    def ip_address_type(self) -> typing.Optional[builtins.str]:
        '''The IP address type.

        The possible values are ``ipv4`` (for IPv4 addresses) and ``dualstack`` (for IPv4 and IPv6 addresses). You can’t specify ``dualstack`` for a load balancer with a UDP or TCP_UDP listener.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-ipaddresstype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "ipAddressType"))

    @ip_address_type.setter
    def ip_address_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "ipAddressType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerAttributes")
    def load_balancer_attributes(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoadBalancer.LoadBalancerAttributeProperty", _IResolvable_da3f097b]]]]:
        '''The load balancer attributes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-loadbalancerattributes
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoadBalancer.LoadBalancerAttributeProperty", _IResolvable_da3f097b]]]], jsii.get(self, "loadBalancerAttributes"))

    @load_balancer_attributes.setter
    def load_balancer_attributes(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoadBalancer.LoadBalancerAttributeProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "loadBalancerAttributes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the load balancer.

        This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, must not begin or end with a hyphen, and must not begin with "internal-".

        If you don't specify a name, AWS CloudFormation generates a unique physical ID for the load balancer. If you specify a name, you cannot perform updates that require replacement of this resource, but you can perform other updates. To replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scheme")
    def scheme(self) -> typing.Optional[builtins.str]:
        '''The nodes of an Internet-facing load balancer have public IP addresses.

        The DNS name of an Internet-facing load balancer is publicly resolvable to the public IP addresses of the nodes. Therefore, Internet-facing load balancers can route requests from clients over the internet.

        The nodes of an internal load balancer have only private IP addresses. The DNS name of an internal load balancer is publicly resolvable to the private IP addresses of the nodes. Therefore, internal load balancers can route requests only from clients with access to the VPC for the load balancer.

        The default is an Internet-facing load balancer.

        You cannot specify a scheme for a Gateway Load Balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-scheme
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "scheme"))

    @scheme.setter
    def scheme(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "scheme", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityGroups")
    def security_groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''[Application Load Balancers] The IDs of the security groups for the load balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-securitygroups
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "securityGroups"))

    @security_groups.setter
    def security_groups(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "securityGroups", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnetMappings")
    def subnet_mappings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoadBalancer.SubnetMappingProperty", _IResolvable_da3f097b]]]]:
        '''The IDs of the public subnets.

        You can specify only one subnet per Availability Zone. You must specify either subnets or subnet mappings, but not both.

        [Application Load Balancers] You must specify subnets from at least two Availability Zones. You cannot specify Elastic IP addresses for your subnets.

        [Application Load Balancers on Outposts] You must specify one Outpost subnet.

        [Application Load Balancers on Local Zones] You can specify subnets from one or more Local Zones.

        [Network Load Balancers] You can specify subnets from one or more Availability Zones. You can specify one Elastic IP address per subnet if you need static IP addresses for your internet-facing load balancer. For internal load balancers, you can specify one private IP address per subnet from the IPv4 range of the subnet. For internet-facing load balancer, you can specify one IPv6 address per subnet.

        [Gateway Load Balancers] You can specify subnets from one or more Availability Zones. You cannot specify Elastic IP addresses for your subnets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmappings
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoadBalancer.SubnetMappingProperty", _IResolvable_da3f097b]]]], jsii.get(self, "subnetMappings"))

    @subnet_mappings.setter
    def subnet_mappings(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLoadBalancer.SubnetMappingProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "subnetMappings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnets")
    def subnets(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The IDs of the public subnets.

        You can specify only one subnet per Availability Zone. You must specify either subnets or subnet mappings, but not both. To specify an Elastic IP address, specify subnet mappings instead of subnets.

        [Application Load Balancers] You must specify subnets from at least two Availability Zones.

        [Application Load Balancers on Outposts] You must specify one Outpost subnet.

        [Application Load Balancers on Local Zones] You can specify subnets from one or more Local Zones.

        [Network Load Balancers] You can specify subnets from one or more Availability Zones.

        [Gateway Load Balancers] You can specify subnets from one or more Availability Zones.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-subnets
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "subnets"))

    @subnets.setter
    def subnets(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "subnets", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> typing.Optional[builtins.str]:
        '''The type of load balancer.

        The default is ``application`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-type
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "type"))

    @type.setter
    def type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "type", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnLoadBalancer.LoadBalancerAttributeProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class LoadBalancerAttributeProperty:
        def __init__(
            self,
            *,
            key: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies an attribute for an Application Load Balancer, a Network Load Balancer, or a Gateway Load Balancer.

            :param key: The name of the attribute. The following attribute is supported by all load balancers: - ``deletion_protection.enabled`` - Indicates whether deletion protection is enabled. The value is ``true`` or ``false`` . The default is ``false`` . The following attributes are supported by both Application Load Balancers and Network Load Balancers: - ``access_logs.s3.enabled`` - Indicates whether access logs are enabled. The value is ``true`` or ``false`` . The default is ``false`` . - ``access_logs.s3.bucket`` - The name of the S3 bucket for the access logs. This attribute is required if access logs are enabled. The bucket must exist in the same region as the load balancer and have a bucket policy that grants Elastic Load Balancing permissions to write to the bucket. - ``access_logs.s3.prefix`` - The prefix for the location in the S3 bucket for the access logs. - ``ipv6.deny_all_igw_traffic`` - Blocks internet gateway (IGW) access to the load balancer. It is set to ``false`` for internet-facing load balancers and ``true`` for internal load balancers, preventing unintended access to your internal load balancer through an internet gateway. The following attributes are supported by only Application Load Balancers: - ``idle_timeout.timeout_seconds`` - The idle timeout value, in seconds. The valid range is 1-4000 seconds. The default is 60 seconds. - ``routing.http.desync_mitigation_mode`` - Determines how the load balancer handles requests that might pose a security risk to your application. The possible values are ``monitor`` , ``defensive`` , and ``strictest`` . The default is ``defensive`` . - ``routing.http.drop_invalid_header_fields.enabled`` - Indicates whether HTTP headers with invalid header fields are removed by the load balancer ( ``true`` ) or routed to targets ( ``false`` ). The default is ``false`` . - ``routing.http.x_amzn_tls_version_and_cipher_suite.enabled`` - Indicates whether the two headers ( ``x-amzn-tls-version`` and ``x-amzn-tls-cipher-suite`` ), which contain information about the negotiated TLS version and cipher suite, are added to the client request before sending it to the target. The ``x-amzn-tls-version`` header has information about the TLS protocol version negotiated with the client, and the ``x-amzn-tls-cipher-suite`` header has information about the cipher suite negotiated with the client. Both headers are in OpenSSL format. The possible values for the attribute are ``true`` and ``false`` . The default is ``false`` . - ``routing.http.xff_client_port.enabled`` - Indicates whether the ``X-Forwarded-For`` header should preserve the source port that the client used to connect to the load balancer. The possible values are ``true`` and ``false`` . The default is ``false`` . - ``routing.http2.enabled`` - Indicates whether HTTP/2 is enabled. The possible values are ``true`` and ``false`` . The default is ``true`` . Elastic Load Balancing requires that message header names contain only alphanumeric characters and hyphens. - ``waf.fail_open.enabled`` - Indicates whether to allow a WAF-enabled load balancer to route requests to targets if it is unable to forward the request to AWS WAF. The possible values are ``true`` and ``false`` . The default is ``false`` . The following attribute is supported by Network Load Balancers and Gateway Load Balancers: - ``load_balancing.cross_zone.enabled`` - Indicates whether cross-zone load balancing is enabled. The possible values are ``true`` and ``false`` . The default is ``false`` .
            :param value: The value of the attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-loadbalancerattributes.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                load_balancer_attribute_property = elbv2.CfnLoadBalancer.LoadBalancerAttributeProperty(
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
            '''The name of the attribute.

            The following attribute is supported by all load balancers:

            - ``deletion_protection.enabled`` - Indicates whether deletion protection is enabled. The value is ``true`` or ``false`` . The default is ``false`` .

            The following attributes are supported by both Application Load Balancers and Network Load Balancers:

            - ``access_logs.s3.enabled`` - Indicates whether access logs are enabled. The value is ``true`` or ``false`` . The default is ``false`` .
            - ``access_logs.s3.bucket`` - The name of the S3 bucket for the access logs. This attribute is required if access logs are enabled. The bucket must exist in the same region as the load balancer and have a bucket policy that grants Elastic Load Balancing permissions to write to the bucket.
            - ``access_logs.s3.prefix`` - The prefix for the location in the S3 bucket for the access logs.
            - ``ipv6.deny_all_igw_traffic`` - Blocks internet gateway (IGW) access to the load balancer. It is set to ``false`` for internet-facing load balancers and ``true`` for internal load balancers, preventing unintended access to your internal load balancer through an internet gateway.

            The following attributes are supported by only Application Load Balancers:

            - ``idle_timeout.timeout_seconds`` - The idle timeout value, in seconds. The valid range is 1-4000 seconds. The default is 60 seconds.
            - ``routing.http.desync_mitigation_mode`` - Determines how the load balancer handles requests that might pose a security risk to your application. The possible values are ``monitor`` , ``defensive`` , and ``strictest`` . The default is ``defensive`` .
            - ``routing.http.drop_invalid_header_fields.enabled`` - Indicates whether HTTP headers with invalid header fields are removed by the load balancer ( ``true`` ) or routed to targets ( ``false`` ). The default is ``false`` .
            - ``routing.http.x_amzn_tls_version_and_cipher_suite.enabled`` - Indicates whether the two headers ( ``x-amzn-tls-version`` and ``x-amzn-tls-cipher-suite`` ), which contain information about the negotiated TLS version and cipher suite, are added to the client request before sending it to the target. The ``x-amzn-tls-version`` header has information about the TLS protocol version negotiated with the client, and the ``x-amzn-tls-cipher-suite`` header has information about the cipher suite negotiated with the client. Both headers are in OpenSSL format. The possible values for the attribute are ``true`` and ``false`` . The default is ``false`` .
            - ``routing.http.xff_client_port.enabled`` - Indicates whether the ``X-Forwarded-For`` header should preserve the source port that the client used to connect to the load balancer. The possible values are ``true`` and ``false`` . The default is ``false`` .
            - ``routing.http2.enabled`` - Indicates whether HTTP/2 is enabled. The possible values are ``true`` and ``false`` . The default is ``true`` . Elastic Load Balancing requires that message header names contain only alphanumeric characters and hyphens.
            - ``waf.fail_open.enabled`` - Indicates whether to allow a WAF-enabled load balancer to route requests to targets if it is unable to forward the request to AWS WAF. The possible values are ``true`` and ``false`` . The default is ``false`` .

            The following attribute is supported by Network Load Balancers and Gateway Load Balancers:

            - ``load_balancing.cross_zone.enabled`` - Indicates whether cross-zone load balancing is enabled. The possible values are ``true`` and ``false`` . The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-loadbalancerattributes.html#cfn-elasticloadbalancingv2-loadbalancer-loadbalancerattributes-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The value of the attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-loadbalancerattributes.html#cfn-elasticloadbalancingv2-loadbalancer-loadbalancerattributes-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoadBalancerAttributeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnLoadBalancer.SubnetMappingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "subnet_id": "subnetId",
            "allocation_id": "allocationId",
            "i_pv6_address": "iPv6Address",
            "private_i_pv4_address": "privateIPv4Address",
        },
    )
    class SubnetMappingProperty:
        def __init__(
            self,
            *,
            subnet_id: builtins.str,
            allocation_id: typing.Optional[builtins.str] = None,
            i_pv6_address: typing.Optional[builtins.str] = None,
            private_i_pv4_address: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies a subnet for a load balancer.

            :param subnet_id: The ID of the subnet.
            :param allocation_id: [Network Load Balancers] The allocation ID of the Elastic IP address for an internet-facing load balancer.
            :param i_pv6_address: [Network Load Balancers] The IPv6 address.
            :param private_i_pv4_address: [Network Load Balancers] The private IPv4 address for an internal load balancer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                subnet_mapping_property = elbv2.CfnLoadBalancer.SubnetMappingProperty(
                    subnet_id="subnetId",
                
                    # the properties below are optional
                    allocation_id="allocationId",
                    i_pv6_address="iPv6Address",
                    private_iPv4_address="privateIPv4Address"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "subnet_id": subnet_id,
            }
            if allocation_id is not None:
                self._values["allocation_id"] = allocation_id
            if i_pv6_address is not None:
                self._values["i_pv6_address"] = i_pv6_address
            if private_i_pv4_address is not None:
                self._values["private_i_pv4_address"] = private_i_pv4_address

        @builtins.property
        def subnet_id(self) -> builtins.str:
            '''The ID of the subnet.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmapping-subnetid
            '''
            result = self._values.get("subnet_id")
            assert result is not None, "Required property 'subnet_id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def allocation_id(self) -> typing.Optional[builtins.str]:
            '''[Network Load Balancers] The allocation ID of the Elastic IP address for an internet-facing load balancer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmapping-allocationid
            '''
            result = self._values.get("allocation_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def i_pv6_address(self) -> typing.Optional[builtins.str]:
            '''[Network Load Balancers] The IPv6 address.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmapping-ipv6address
            '''
            result = self._values.get("i_pv6_address")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def private_i_pv4_address(self) -> typing.Optional[builtins.str]:
            '''[Network Load Balancers] The private IPv4 address for an internal load balancer.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-loadbalancer-subnetmapping.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmapping-privateipv4address
            '''
            result = self._values.get("private_i_pv4_address")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SubnetMappingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnLoadBalancerProps",
    jsii_struct_bases=[],
    name_mapping={
        "ip_address_type": "ipAddressType",
        "load_balancer_attributes": "loadBalancerAttributes",
        "name": "name",
        "scheme": "scheme",
        "security_groups": "securityGroups",
        "subnet_mappings": "subnetMappings",
        "subnets": "subnets",
        "tags": "tags",
        "type": "type",
    },
)
class CfnLoadBalancerProps:
    def __init__(
        self,
        *,
        ip_address_type: typing.Optional[builtins.str] = None,
        load_balancer_attributes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnLoadBalancer.LoadBalancerAttributeProperty, _IResolvable_da3f097b]]]] = None,
        name: typing.Optional[builtins.str] = None,
        scheme: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        subnet_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnLoadBalancer.SubnetMappingProperty, _IResolvable_da3f097b]]]] = None,
        subnets: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        type: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnLoadBalancer``.

        :param ip_address_type: The IP address type. The possible values are ``ipv4`` (for IPv4 addresses) and ``dualstack`` (for IPv4 and IPv6 addresses). You can’t specify ``dualstack`` for a load balancer with a UDP or TCP_UDP listener.
        :param load_balancer_attributes: The load balancer attributes.
        :param name: The name of the load balancer. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, must not begin or end with a hyphen, and must not begin with "internal-". If you don't specify a name, AWS CloudFormation generates a unique physical ID for the load balancer. If you specify a name, you cannot perform updates that require replacement of this resource, but you can perform other updates. To replace the resource, specify a new name.
        :param scheme: The nodes of an Internet-facing load balancer have public IP addresses. The DNS name of an Internet-facing load balancer is publicly resolvable to the public IP addresses of the nodes. Therefore, Internet-facing load balancers can route requests from clients over the internet. The nodes of an internal load balancer have only private IP addresses. The DNS name of an internal load balancer is publicly resolvable to the private IP addresses of the nodes. Therefore, internal load balancers can route requests only from clients with access to the VPC for the load balancer. The default is an Internet-facing load balancer. You cannot specify a scheme for a Gateway Load Balancer.
        :param security_groups: [Application Load Balancers] The IDs of the security groups for the load balancer.
        :param subnet_mappings: The IDs of the public subnets. You can specify only one subnet per Availability Zone. You must specify either subnets or subnet mappings, but not both. [Application Load Balancers] You must specify subnets from at least two Availability Zones. You cannot specify Elastic IP addresses for your subnets. [Application Load Balancers on Outposts] You must specify one Outpost subnet. [Application Load Balancers on Local Zones] You can specify subnets from one or more Local Zones. [Network Load Balancers] You can specify subnets from one or more Availability Zones. You can specify one Elastic IP address per subnet if you need static IP addresses for your internet-facing load balancer. For internal load balancers, you can specify one private IP address per subnet from the IPv4 range of the subnet. For internet-facing load balancer, you can specify one IPv6 address per subnet. [Gateway Load Balancers] You can specify subnets from one or more Availability Zones. You cannot specify Elastic IP addresses for your subnets.
        :param subnets: The IDs of the public subnets. You can specify only one subnet per Availability Zone. You must specify either subnets or subnet mappings, but not both. To specify an Elastic IP address, specify subnet mappings instead of subnets. [Application Load Balancers] You must specify subnets from at least two Availability Zones. [Application Load Balancers on Outposts] You must specify one Outpost subnet. [Application Load Balancers on Local Zones] You can specify subnets from one or more Local Zones. [Network Load Balancers] You can specify subnets from one or more Availability Zones. [Gateway Load Balancers] You can specify subnets from one or more Availability Zones.
        :param tags: The tags to assign to the load balancer.
        :param type: The type of load balancer. The default is ``application`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            cfn_load_balancer_props = elbv2.CfnLoadBalancerProps(
                ip_address_type="ipAddressType",
                load_balancer_attributes=[elbv2.CfnLoadBalancer.LoadBalancerAttributeProperty(
                    key="key",
                    value="value"
                )],
                name="name",
                scheme="scheme",
                security_groups=["securityGroups"],
                subnet_mappings=[elbv2.CfnLoadBalancer.SubnetMappingProperty(
                    subnet_id="subnetId",
            
                    # the properties below are optional
                    allocation_id="allocationId",
                    i_pv6_address="iPv6Address",
                    private_iPv4_address="privateIPv4Address"
                )],
                subnets=["subnets"],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                type="type"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if ip_address_type is not None:
            self._values["ip_address_type"] = ip_address_type
        if load_balancer_attributes is not None:
            self._values["load_balancer_attributes"] = load_balancer_attributes
        if name is not None:
            self._values["name"] = name
        if scheme is not None:
            self._values["scheme"] = scheme
        if security_groups is not None:
            self._values["security_groups"] = security_groups
        if subnet_mappings is not None:
            self._values["subnet_mappings"] = subnet_mappings
        if subnets is not None:
            self._values["subnets"] = subnets
        if tags is not None:
            self._values["tags"] = tags
        if type is not None:
            self._values["type"] = type

    @builtins.property
    def ip_address_type(self) -> typing.Optional[builtins.str]:
        '''The IP address type.

        The possible values are ``ipv4`` (for IPv4 addresses) and ``dualstack`` (for IPv4 and IPv6 addresses). You can’t specify ``dualstack`` for a load balancer with a UDP or TCP_UDP listener.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-ipaddresstype
        '''
        result = self._values.get("ip_address_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def load_balancer_attributes(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLoadBalancer.LoadBalancerAttributeProperty, _IResolvable_da3f097b]]]]:
        '''The load balancer attributes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-loadbalancerattributes
        '''
        result = self._values.get("load_balancer_attributes")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLoadBalancer.LoadBalancerAttributeProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the load balancer.

        This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, must not begin or end with a hyphen, and must not begin with "internal-".

        If you don't specify a name, AWS CloudFormation generates a unique physical ID for the load balancer. If you specify a name, you cannot perform updates that require replacement of this resource, but you can perform other updates. To replace the resource, specify a new name.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def scheme(self) -> typing.Optional[builtins.str]:
        '''The nodes of an Internet-facing load balancer have public IP addresses.

        The DNS name of an Internet-facing load balancer is publicly resolvable to the public IP addresses of the nodes. Therefore, Internet-facing load balancers can route requests from clients over the internet.

        The nodes of an internal load balancer have only private IP addresses. The DNS name of an internal load balancer is publicly resolvable to the private IP addresses of the nodes. Therefore, internal load balancers can route requests only from clients with access to the VPC for the load balancer.

        The default is an Internet-facing load balancer.

        You cannot specify a scheme for a Gateway Load Balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-scheme
        '''
        result = self._values.get("scheme")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def security_groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''[Application Load Balancers] The IDs of the security groups for the load balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-securitygroups
        '''
        result = self._values.get("security_groups")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def subnet_mappings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLoadBalancer.SubnetMappingProperty, _IResolvable_da3f097b]]]]:
        '''The IDs of the public subnets.

        You can specify only one subnet per Availability Zone. You must specify either subnets or subnet mappings, but not both.

        [Application Load Balancers] You must specify subnets from at least two Availability Zones. You cannot specify Elastic IP addresses for your subnets.

        [Application Load Balancers on Outposts] You must specify one Outpost subnet.

        [Application Load Balancers on Local Zones] You can specify subnets from one or more Local Zones.

        [Network Load Balancers] You can specify subnets from one or more Availability Zones. You can specify one Elastic IP address per subnet if you need static IP addresses for your internet-facing load balancer. For internal load balancers, you can specify one private IP address per subnet from the IPv4 range of the subnet. For internet-facing load balancer, you can specify one IPv6 address per subnet.

        [Gateway Load Balancers] You can specify subnets from one or more Availability Zones. You cannot specify Elastic IP addresses for your subnets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-subnetmappings
        '''
        result = self._values.get("subnet_mappings")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLoadBalancer.SubnetMappingProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def subnets(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The IDs of the public subnets.

        You can specify only one subnet per Availability Zone. You must specify either subnets or subnet mappings, but not both. To specify an Elastic IP address, specify subnet mappings instead of subnets.

        [Application Load Balancers] You must specify subnets from at least two Availability Zones.

        [Application Load Balancers on Outposts] You must specify one Outpost subnet.

        [Application Load Balancers on Local Zones] You can specify subnets from one or more Local Zones.

        [Network Load Balancers] You can specify subnets from one or more Availability Zones.

        [Gateway Load Balancers] You can specify subnets from one or more Availability Zones.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-subnets
        '''
        result = self._values.get("subnets")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags to assign to the load balancer.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def type(self) -> typing.Optional[builtins.str]:
        '''The type of load balancer.

        The default is ``application`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-loadbalancer.html#cfn-elasticloadbalancingv2-loadbalancer-type
        '''
        result = self._values.get("type")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLoadBalancerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnTargetGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnTargetGroup",
):
    '''A CloudFormation ``AWS::ElasticLoadBalancingV2::TargetGroup``.

    Specifies a target group for a load balancer.

    Before you register a Lambda function as a target, you must create a ``AWS::Lambda::Permission`` resource that grants the Elastic Load Balancing service principal permission to invoke the Lambda function.

    :cloudformationResource: AWS::ElasticLoadBalancingV2::TargetGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticloadbalancingv2 as elbv2
        
        cfn_target_group = elbv2.CfnTargetGroup(self, "MyCfnTargetGroup",
            health_check_enabled=False,
            health_check_interval_seconds=123,
            health_check_path="healthCheckPath",
            health_check_port="healthCheckPort",
            health_check_protocol="healthCheckProtocol",
            health_check_timeout_seconds=123,
            healthy_threshold_count=123,
            ip_address_type="ipAddressType",
            matcher=elbv2.CfnTargetGroup.MatcherProperty(
                grpc_code="grpcCode",
                http_code="httpCode"
            ),
            name="name",
            port=123,
            protocol="protocol",
            protocol_version="protocolVersion",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            target_group_attributes=[elbv2.CfnTargetGroup.TargetGroupAttributeProperty(
                key="key",
                value="value"
            )],
            targets=[elbv2.CfnTargetGroup.TargetDescriptionProperty(
                id="id",
        
                # the properties below are optional
                availability_zone="availabilityZone",
                port=123
            )],
            target_type="targetType",
            unhealthy_threshold_count=123,
            vpc_id="vpcId"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        health_check_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        health_check_interval_seconds: typing.Optional[jsii.Number] = None,
        health_check_path: typing.Optional[builtins.str] = None,
        health_check_port: typing.Optional[builtins.str] = None,
        health_check_protocol: typing.Optional[builtins.str] = None,
        health_check_timeout_seconds: typing.Optional[jsii.Number] = None,
        healthy_threshold_count: typing.Optional[jsii.Number] = None,
        ip_address_type: typing.Optional[builtins.str] = None,
        matcher: typing.Optional[typing.Union["CfnTargetGroup.MatcherProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[builtins.str] = None,
        protocol_version: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        target_group_attributes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTargetGroup.TargetGroupAttributeProperty", _IResolvable_da3f097b]]]] = None,
        targets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnTargetGroup.TargetDescriptionProperty", _IResolvable_da3f097b]]]] = None,
        target_type: typing.Optional[builtins.str] = None,
        unhealthy_threshold_count: typing.Optional[jsii.Number] = None,
        vpc_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::ElasticLoadBalancingV2::TargetGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param health_check_enabled: Indicates whether health checks are enabled. If the target type is ``lambda`` , health checks are disabled by default but can be enabled. If the target type is ``instance`` , ``ip`` , or ``alb`` , health checks are always enabled and cannot be disabled.
        :param health_check_interval_seconds: The approximate amount of time, in seconds, between health checks of an individual target. If the target group protocol is HTTP or HTTPS, the default is 30 seconds. If the target group protocol is TCP, TLS, UDP, or TCP_UDP, the supported values are 10 and 30 seconds and the default is 30 seconds. If the target group protocol is GENEVE, the default is 10 seconds. If the target type is ``lambda`` , the default is 35 seconds.
        :param health_check_path: [HTTP/HTTPS health checks] The destination for health checks on the targets. [HTTP1 or HTTP2 protocol version] The ping path. The default is /. [GRPC protocol version] The path of a custom health check method with the format /package.service/method. The default is / AWS .ALB/healthcheck.
        :param health_check_port: The port the load balancer uses when performing health checks on targets. If the protocol is HTTP, HTTPS, TCP, TLS, UDP, or TCP_UDP, the default is ``traffic-port`` , which is the port on which each target receives traffic from the load balancer. If the protocol is GENEVE, the default is port 80.
        :param health_check_protocol: The protocol the load balancer uses when performing health checks on targets. For Application Load Balancers, the default is HTTP. For Network Load Balancers and Gateway Load Balancers, the default is TCP. The TCP protocol is not supported for health checks if the protocol of the target group is HTTP or HTTPS. The GENEVE, TLS, UDP, and TCP_UDP protocols are not supported for health checks.
        :param health_check_timeout_seconds: The amount of time, in seconds, during which no response from a target means a failed health check. For target groups with a protocol of HTTP, HTTPS, or GENEVE, the default is 5 seconds. For target groups with a protocol of TCP or TLS, this value must be 6 seconds for HTTP health checks and 10 seconds for TCP and HTTPS health checks. If the target type is ``lambda`` , the default is 30 seconds.
        :param healthy_threshold_count: The number of consecutive health checks successes required before considering an unhealthy target healthy. For target groups with a protocol of HTTP or HTTPS, the default is 5. For target groups with a protocol of TCP, TLS, or GENEVE, the default is 3. If the target type is ``lambda`` , the default is 5.
        :param ip_address_type: The type of IP address used for this target group. The possible values are ``ipv4`` and ``ipv6`` . This is an optional parameter. If not specified, the IP address type defaults to ``ipv4`` .
        :param matcher: [HTTP/HTTPS health checks] The HTTP or gRPC codes to use when checking for a successful response from a target.
        :param name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen.
        :param port: The port on which the targets receive traffic. This port is used unless you specify a port override when registering the target. If the target is a Lambda function, this parameter does not apply. If the protocol is GENEVE, the supported port is 6081.
        :param protocol: The protocol to use for routing traffic to the targets. For Application Load Balancers, the supported protocols are HTTP and HTTPS. For Network Load Balancers, the supported protocols are TCP, TLS, UDP, or TCP_UDP. For Gateway Load Balancers, the supported protocol is GENEVE. A TCP_UDP listener must be associated with a TCP_UDP target group. If the target is a Lambda function, this parameter does not apply.
        :param protocol_version: [HTTP/HTTPS protocol] The protocol version. The possible values are ``GRPC`` , ``HTTP1`` , and ``HTTP2`` .
        :param tags: The tags.
        :param target_group_attributes: The attributes.
        :param targets: The targets.
        :param target_type: The type of target that you must specify when registering targets with this target group. You can't specify targets for a target group using more than one target type. - ``instance`` - Register targets by instance ID. This is the default value. - ``ip`` - Register targets by IP address. You can specify IP addresses from the subnets of the virtual private cloud (VPC) for the target group, the RFC 1918 range (10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16), and the RFC 6598 range (100.64.0.0/10). You can't specify publicly routable IP addresses. - ``lambda`` - Register a single Lambda function as a target. - ``alb`` - Register a single Application Load Balancer as a target.
        :param unhealthy_threshold_count: The number of consecutive health check failures required before considering a target unhealthy. If the target group protocol is HTTP or HTTPS, the default is 2. If the target group protocol is TCP or TLS, this value must be the same as the healthy threshold count. If the target group protocol is GENEVE, the default is 3. If the target type is ``lambda`` , the default is 2.
        :param vpc_id: The identifier of the virtual private cloud (VPC). If the target is a Lambda function, this parameter does not apply. Otherwise, this parameter is required.
        '''
        props = CfnTargetGroupProps(
            health_check_enabled=health_check_enabled,
            health_check_interval_seconds=health_check_interval_seconds,
            health_check_path=health_check_path,
            health_check_port=health_check_port,
            health_check_protocol=health_check_protocol,
            health_check_timeout_seconds=health_check_timeout_seconds,
            healthy_threshold_count=healthy_threshold_count,
            ip_address_type=ip_address_type,
            matcher=matcher,
            name=name,
            port=port,
            protocol=protocol,
            protocol_version=protocol_version,
            tags=tags,
            target_group_attributes=target_group_attributes,
            targets=targets,
            target_type=target_type,
            unhealthy_threshold_count=unhealthy_threshold_count,
            vpc_id=vpc_id,
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
    @jsii.member(jsii_name="attrLoadBalancerArns")
    def attr_load_balancer_arns(self) -> typing.List[builtins.str]:
        '''The Amazon Resource Names (ARNs) of the load balancers that route traffic to this target group.

        :cloudformationAttribute: LoadBalancerArns
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "attrLoadBalancerArns"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrTargetGroupFullName")
    def attr_target_group_full_name(self) -> builtins.str:
        '''The full name of the target group.

        For example, ``targetgroup/my-target-group/cbf133c568e0d028`` .

        :cloudformationAttribute: TargetGroupFullName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrTargetGroupFullName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrTargetGroupName")
    def attr_target_group_name(self) -> builtins.str:
        '''The name of the target group.

        For example, ``my-target-group`` .

        :cloudformationAttribute: TargetGroupName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrTargetGroupName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The tags.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckEnabled")
    def health_check_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether health checks are enabled.

        If the target type is ``lambda`` , health checks are disabled by default but can be enabled. If the target type is ``instance`` , ``ip`` , or ``alb`` , health checks are always enabled and cannot be disabled.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthcheckenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "healthCheckEnabled"))

    @health_check_enabled.setter
    def health_check_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "healthCheckEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckIntervalSeconds")
    def health_check_interval_seconds(self) -> typing.Optional[jsii.Number]:
        '''The approximate amount of time, in seconds, between health checks of an individual target.

        If the target group protocol is HTTP or HTTPS, the default is 30 seconds. If the target group protocol is TCP, TLS, UDP, or TCP_UDP, the supported values are 10 and 30 seconds and the default is 30 seconds. If the target group protocol is GENEVE, the default is 10 seconds. If the target type is ``lambda`` , the default is 35 seconds.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthcheckintervalseconds
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "healthCheckIntervalSeconds"))

    @health_check_interval_seconds.setter
    def health_check_interval_seconds(
        self,
        value: typing.Optional[jsii.Number],
    ) -> None:
        jsii.set(self, "healthCheckIntervalSeconds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckPath")
    def health_check_path(self) -> typing.Optional[builtins.str]:
        '''[HTTP/HTTPS health checks] The destination for health checks on the targets.

        [HTTP1 or HTTP2 protocol version] The ping path. The default is /.

        [GRPC protocol version] The path of a custom health check method with the format /package.service/method. The default is / AWS .ALB/healthcheck.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthcheckpath
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "healthCheckPath"))

    @health_check_path.setter
    def health_check_path(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "healthCheckPath", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckPort")
    def health_check_port(self) -> typing.Optional[builtins.str]:
        '''The port the load balancer uses when performing health checks on targets.

        If the protocol is HTTP, HTTPS, TCP, TLS, UDP, or TCP_UDP, the default is ``traffic-port`` , which is the port on which each target receives traffic from the load balancer. If the protocol is GENEVE, the default is port 80.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthcheckport
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "healthCheckPort"))

    @health_check_port.setter
    def health_check_port(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "healthCheckPort", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckProtocol")
    def health_check_protocol(self) -> typing.Optional[builtins.str]:
        '''The protocol the load balancer uses when performing health checks on targets.

        For Application Load Balancers, the default is HTTP. For Network Load Balancers and Gateway Load Balancers, the default is TCP. The TCP protocol is not supported for health checks if the protocol of the target group is HTTP or HTTPS. The GENEVE, TLS, UDP, and TCP_UDP protocols are not supported for health checks.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthcheckprotocol
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "healthCheckProtocol"))

    @health_check_protocol.setter
    def health_check_protocol(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "healthCheckProtocol", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckTimeoutSeconds")
    def health_check_timeout_seconds(self) -> typing.Optional[jsii.Number]:
        '''The amount of time, in seconds, during which no response from a target means a failed health check.

        For target groups with a protocol of HTTP, HTTPS, or GENEVE, the default is 5 seconds. For target groups with a protocol of TCP or TLS, this value must be 6 seconds for HTTP health checks and 10 seconds for TCP and HTTPS health checks. If the target type is ``lambda`` , the default is 30 seconds.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthchecktimeoutseconds
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "healthCheckTimeoutSeconds"))

    @health_check_timeout_seconds.setter
    def health_check_timeout_seconds(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "healthCheckTimeoutSeconds", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthyThresholdCount")
    def healthy_threshold_count(self) -> typing.Optional[jsii.Number]:
        '''The number of consecutive health checks successes required before considering an unhealthy target healthy.

        For target groups with a protocol of HTTP or HTTPS, the default is 5. For target groups with a protocol of TCP, TLS, or GENEVE, the default is 3. If the target type is ``lambda`` , the default is 5.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthythresholdcount
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "healthyThresholdCount"))

    @healthy_threshold_count.setter
    def healthy_threshold_count(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "healthyThresholdCount", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ipAddressType")
    def ip_address_type(self) -> typing.Optional[builtins.str]:
        '''The type of IP address used for this target group.

        The possible values are ``ipv4`` and ``ipv6`` . This is an optional parameter. If not specified, the IP address type defaults to ``ipv4`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-ipaddresstype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "ipAddressType"))

    @ip_address_type.setter
    def ip_address_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "ipAddressType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="matcher")
    def matcher(
        self,
    ) -> typing.Optional[typing.Union["CfnTargetGroup.MatcherProperty", _IResolvable_da3f097b]]:
        '''[HTTP/HTTPS health checks] The HTTP or gRPC codes to use when checking for a successful response from a target.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-matcher
        '''
        return typing.cast(typing.Optional[typing.Union["CfnTargetGroup.MatcherProperty", _IResolvable_da3f097b]], jsii.get(self, "matcher"))

    @matcher.setter
    def matcher(
        self,
        value: typing.Optional[typing.Union["CfnTargetGroup.MatcherProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "matcher", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the target group.

        This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="port")
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port on which the targets receive traffic.

        This port is used unless you specify a port override when registering the target. If the target is a Lambda function, this parameter does not apply. If the protocol is GENEVE, the supported port is 6081.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-port
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "port"))

    @port.setter
    def port(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "port", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="protocol")
    def protocol(self) -> typing.Optional[builtins.str]:
        '''The protocol to use for routing traffic to the targets.

        For Application Load Balancers, the supported protocols are HTTP and HTTPS. For Network Load Balancers, the supported protocols are TCP, TLS, UDP, or TCP_UDP. For Gateway Load Balancers, the supported protocol is GENEVE. A TCP_UDP listener must be associated with a TCP_UDP target group. If the target is a Lambda function, this parameter does not apply.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-protocol
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "protocol"))

    @protocol.setter
    def protocol(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "protocol", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="protocolVersion")
    def protocol_version(self) -> typing.Optional[builtins.str]:
        '''[HTTP/HTTPS protocol] The protocol version.

        The possible values are ``GRPC`` , ``HTTP1`` , and ``HTTP2`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-protocolversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "protocolVersion"))

    @protocol_version.setter
    def protocol_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "protocolVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetGroupAttributes")
    def target_group_attributes(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTargetGroup.TargetGroupAttributeProperty", _IResolvable_da3f097b]]]]:
        '''The attributes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-targetgroupattributes
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTargetGroup.TargetGroupAttributeProperty", _IResolvable_da3f097b]]]], jsii.get(self, "targetGroupAttributes"))

    @target_group_attributes.setter
    def target_group_attributes(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTargetGroup.TargetGroupAttributeProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "targetGroupAttributes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targets")
    def targets(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTargetGroup.TargetDescriptionProperty", _IResolvable_da3f097b]]]]:
        '''The targets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-targets
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTargetGroup.TargetDescriptionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "targets"))

    @targets.setter
    def targets(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnTargetGroup.TargetDescriptionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "targets", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetType")
    def target_type(self) -> typing.Optional[builtins.str]:
        '''The type of target that you must specify when registering targets with this target group.

        You can't specify targets for a target group using more than one target type.

        - ``instance`` - Register targets by instance ID. This is the default value.
        - ``ip`` - Register targets by IP address. You can specify IP addresses from the subnets of the virtual private cloud (VPC) for the target group, the RFC 1918 range (10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16), and the RFC 6598 range (100.64.0.0/10). You can't specify publicly routable IP addresses.
        - ``lambda`` - Register a single Lambda function as a target.
        - ``alb`` - Register a single Application Load Balancer as a target.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-targettype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "targetType"))

    @target_type.setter
    def target_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "targetType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="unhealthyThresholdCount")
    def unhealthy_threshold_count(self) -> typing.Optional[jsii.Number]:
        '''The number of consecutive health check failures required before considering a target unhealthy.

        If the target group protocol is HTTP or HTTPS, the default is 2. If the target group protocol is TCP or TLS, this value must be the same as the healthy threshold count. If the target group protocol is GENEVE, the default is 3. If the target type is ``lambda`` , the default is 2.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-unhealthythresholdcount
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "unhealthyThresholdCount"))

    @unhealthy_threshold_count.setter
    def unhealthy_threshold_count(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "unhealthyThresholdCount", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcId")
    def vpc_id(self) -> typing.Optional[builtins.str]:
        '''The identifier of the virtual private cloud (VPC).

        If the target is a Lambda function, this parameter does not apply. Otherwise, this parameter is required.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-vpcid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "vpcId"))

    @vpc_id.setter
    def vpc_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "vpcId", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnTargetGroup.MatcherProperty",
        jsii_struct_bases=[],
        name_mapping={"grpc_code": "grpcCode", "http_code": "httpCode"},
    )
    class MatcherProperty:
        def __init__(
            self,
            *,
            grpc_code: typing.Optional[builtins.str] = None,
            http_code: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies the HTTP codes that healthy targets must use when responding to an HTTP health check.

            :param grpc_code: You can specify values between 0 and 99. You can specify multiple values (for example, "0,1") or a range of values (for example, "0-5"). The default value is 12.
            :param http_code: For Application Load Balancers, you can specify values between 200 and 499, and the default value is 200. You can specify multiple values (for example, "200,202") or a range of values (for example, "200-299"). For Network Load Balancers and Gateway Load Balancers, this must be "200–399". Note that when using shorthand syntax, some values such as commas need to be escaped.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-targetgroup-matcher.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                matcher_property = elbv2.CfnTargetGroup.MatcherProperty(
                    grpc_code="grpcCode",
                    http_code="httpCode"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if grpc_code is not None:
                self._values["grpc_code"] = grpc_code
            if http_code is not None:
                self._values["http_code"] = http_code

        @builtins.property
        def grpc_code(self) -> typing.Optional[builtins.str]:
            '''You can specify values between 0 and 99.

            You can specify multiple values (for example, "0,1") or a range of values (for example, "0-5"). The default value is 12.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-targetgroup-matcher.html#cfn-elasticloadbalancingv2-targetgroup-matcher-grpccode
            '''
            result = self._values.get("grpc_code")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def http_code(self) -> typing.Optional[builtins.str]:
            '''For Application Load Balancers, you can specify values between 200 and 499, and the default value is 200.

            You can specify multiple values (for example, "200,202") or a range of values (for example, "200-299").

            For Network Load Balancers and Gateway Load Balancers, this must be "200–399".

            Note that when using shorthand syntax, some values such as commas need to be escaped.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-targetgroup-matcher.html#cfn-elasticloadbalancingv2-targetgroup-matcher-httpcode
            '''
            result = self._values.get("http_code")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MatcherProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnTargetGroup.TargetDescriptionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "id": "id",
            "availability_zone": "availabilityZone",
            "port": "port",
        },
    )
    class TargetDescriptionProperty:
        def __init__(
            self,
            *,
            id: builtins.str,
            availability_zone: typing.Optional[builtins.str] = None,
            port: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''Specifies a target to add to a target group.

            :param id: The ID of the target. If the target type of the target group is ``instance`` , specify an instance ID. If the target type is ``ip`` , specify an IP address. If the target type is ``lambda`` , specify the ARN of the Lambda function. If the target type is ``alb`` , specify the ARN of the Application Load Balancer target.
            :param availability_zone: An Availability Zone or ``all`` . This determines whether the target receives traffic from the load balancer nodes in the specified Availability Zone or from all enabled Availability Zones for the load balancer. This parameter is not supported if the target type of the target group is ``instance`` or ``alb`` . If the target type is ``ip`` and the IP address is in a subnet of the VPC for the target group, the Availability Zone is automatically detected and this parameter is optional. If the IP address is outside the VPC, this parameter is required. With an Application Load Balancer, if the target type is ``ip`` and the IP address is outside the VPC for the target group, the only supported value is ``all`` . If the target type is ``lambda`` , this parameter is optional and the only supported value is ``all`` .
            :param port: The port on which the target is listening. If the target group protocol is GENEVE, the supported port is 6081. If the target type is ``alb`` , the targeted Application Load Balancer must have at least one listener whose port matches the target group port. Not used if the target is a Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-targetgroup-targetdescription.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                target_description_property = elbv2.CfnTargetGroup.TargetDescriptionProperty(
                    id="id",
                
                    # the properties below are optional
                    availability_zone="availabilityZone",
                    port=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "id": id,
            }
            if availability_zone is not None:
                self._values["availability_zone"] = availability_zone
            if port is not None:
                self._values["port"] = port

        @builtins.property
        def id(self) -> builtins.str:
            '''The ID of the target.

            If the target type of the target group is ``instance`` , specify an instance ID. If the target type is ``ip`` , specify an IP address. If the target type is ``lambda`` , specify the ARN of the Lambda function. If the target type is ``alb`` , specify the ARN of the Application Load Balancer target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-targetgroup-targetdescription.html#cfn-elasticloadbalancingv2-targetgroup-targetdescription-id
            '''
            result = self._values.get("id")
            assert result is not None, "Required property 'id' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def availability_zone(self) -> typing.Optional[builtins.str]:
            '''An Availability Zone or ``all`` .

            This determines whether the target receives traffic from the load balancer nodes in the specified Availability Zone or from all enabled Availability Zones for the load balancer.

            This parameter is not supported if the target type of the target group is ``instance`` or ``alb`` .

            If the target type is ``ip`` and the IP address is in a subnet of the VPC for the target group, the Availability Zone is automatically detected and this parameter is optional. If the IP address is outside the VPC, this parameter is required.

            With an Application Load Balancer, if the target type is ``ip`` and the IP address is outside the VPC for the target group, the only supported value is ``all`` .

            If the target type is ``lambda`` , this parameter is optional and the only supported value is ``all`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-targetgroup-targetdescription.html#cfn-elasticloadbalancingv2-targetgroup-targetdescription-availabilityzone
            '''
            result = self._values.get("availability_zone")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def port(self) -> typing.Optional[jsii.Number]:
            '''The port on which the target is listening.

            If the target group protocol is GENEVE, the supported port is 6081. If the target type is ``alb`` , the targeted Application Load Balancer must have at least one listener whose port matches the target group port. Not used if the target is a Lambda function.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-targetgroup-targetdescription.html#cfn-elasticloadbalancingv2-targetgroup-targetdescription-port
            '''
            result = self._values.get("port")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetDescriptionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnTargetGroup.TargetGroupAttributeProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class TargetGroupAttributeProperty:
        def __init__(
            self,
            *,
            key: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Specifies a target group attribute.

            :param key: The name of the attribute. The following attribute is supported by all load balancers: - ``deregistration_delay.timeout_seconds`` - The amount of time, in seconds, for Elastic Load Balancing to wait before changing the state of a deregistering target from ``draining`` to ``unused`` . The range is 0-3600 seconds. The default value is 300 seconds. If the target is a Lambda function, this attribute is not supported. The following attributes are supported by both Application Load Balancers and Network Load Balancers: - ``stickiness.enabled`` - Indicates whether sticky sessions are enabled. The value is ``true`` or ``false`` . The default is ``false`` . - ``stickiness.type`` - The type of sticky sessions. The possible values are ``lb_cookie`` and ``app_cookie`` for Application Load Balancers or ``source_ip`` for Network Load Balancers. The following attributes are supported only if the load balancer is an Application Load Balancer and the target is an instance or an IP address: - ``load_balancing.algorithm.type`` - The load balancing algorithm determines how the load balancer selects targets when routing requests. The value is ``round_robin`` or ``least_outstanding_requests`` . The default is ``round_robin`` . - ``slow_start.duration_seconds`` - The time period, in seconds, during which a newly registered target receives an increasing share of the traffic to the target group. After this time period ends, the target receives its full share of traffic. The range is 30-900 seconds (15 minutes). The default is 0 seconds (disabled). - ``stickiness.app_cookie.cookie_name`` - Indicates the name of the application-based cookie. Names that start with the following prefixes are not allowed: ``AWSALB`` , ``AWSALBAPP`` , and ``AWSALBTG`` ; they're reserved for use by the load balancer. - ``stickiness.app_cookie.duration_seconds`` - The time period, in seconds, during which requests from a client should be routed to the same target. After this time period expires, the application-based cookie is considered stale. The range is 1 second to 1 week (604800 seconds). The default value is 1 day (86400 seconds). - ``stickiness.lb_cookie.duration_seconds`` - The time period, in seconds, during which requests from a client should be routed to the same target. After this time period expires, the load balancer-generated cookie is considered stale. The range is 1 second to 1 week (604800 seconds). The default value is 1 day (86400 seconds). The following attribute is supported only if the load balancer is an Application Load Balancer and the target is a Lambda function: - ``lambda.multi_value_headers.enabled`` - Indicates whether the request and response headers that are exchanged between the load balancer and the Lambda function include arrays of values or strings. The value is ``true`` or ``false`` . The default is ``false`` . If the value is ``false`` and the request contains a duplicate header field name or query parameter key, the load balancer uses the last value sent by the client. The following attributes are supported only by Network Load Balancers: - ``deregistration_delay.connection_termination.enabled`` - Indicates whether the load balancer terminates connections at the end of the deregistration timeout. The value is ``true`` or ``false`` . The default is ``false`` . - ``preserve_client_ip.enabled`` - Indicates whether client IP preservation is enabled. The value is ``true`` or ``false`` . The default is disabled if the target group type is IP address and the target group protocol is TCP or TLS. Otherwise, the default is enabled. Client IP preservation cannot be disabled for UDP and TCP_UDP target groups. - ``proxy_protocol_v2.enabled`` - Indicates whether Proxy Protocol version 2 is enabled. The value is ``true`` or ``false`` . The default is ``false`` .
            :param value: The value of the attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-targetgroup-targetgroupattribute.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_elasticloadbalancingv2 as elbv2
                
                target_group_attribute_property = elbv2.CfnTargetGroup.TargetGroupAttributeProperty(
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
            '''The name of the attribute.

            The following attribute is supported by all load balancers:

            - ``deregistration_delay.timeout_seconds`` - The amount of time, in seconds, for Elastic Load Balancing to wait before changing the state of a deregistering target from ``draining`` to ``unused`` . The range is 0-3600 seconds. The default value is 300 seconds. If the target is a Lambda function, this attribute is not supported.

            The following attributes are supported by both Application Load Balancers and Network Load Balancers:

            - ``stickiness.enabled`` - Indicates whether sticky sessions are enabled. The value is ``true`` or ``false`` . The default is ``false`` .
            - ``stickiness.type`` - The type of sticky sessions. The possible values are ``lb_cookie`` and ``app_cookie`` for Application Load Balancers or ``source_ip`` for Network Load Balancers.

            The following attributes are supported only if the load balancer is an Application Load Balancer and the target is an instance or an IP address:

            - ``load_balancing.algorithm.type`` - The load balancing algorithm determines how the load balancer selects targets when routing requests. The value is ``round_robin`` or ``least_outstanding_requests`` . The default is ``round_robin`` .
            - ``slow_start.duration_seconds`` - The time period, in seconds, during which a newly registered target receives an increasing share of the traffic to the target group. After this time period ends, the target receives its full share of traffic. The range is 30-900 seconds (15 minutes). The default is 0 seconds (disabled).
            - ``stickiness.app_cookie.cookie_name`` - Indicates the name of the application-based cookie. Names that start with the following prefixes are not allowed: ``AWSALB`` , ``AWSALBAPP`` , and ``AWSALBTG`` ; they're reserved for use by the load balancer.
            - ``stickiness.app_cookie.duration_seconds`` - The time period, in seconds, during which requests from a client should be routed to the same target. After this time period expires, the application-based cookie is considered stale. The range is 1 second to 1 week (604800 seconds). The default value is 1 day (86400 seconds).
            - ``stickiness.lb_cookie.duration_seconds`` - The time period, in seconds, during which requests from a client should be routed to the same target. After this time period expires, the load balancer-generated cookie is considered stale. The range is 1 second to 1 week (604800 seconds). The default value is 1 day (86400 seconds).

            The following attribute is supported only if the load balancer is an Application Load Balancer and the target is a Lambda function:

            - ``lambda.multi_value_headers.enabled`` - Indicates whether the request and response headers that are exchanged between the load balancer and the Lambda function include arrays of values or strings. The value is ``true`` or ``false`` . The default is ``false`` . If the value is ``false`` and the request contains a duplicate header field name or query parameter key, the load balancer uses the last value sent by the client.

            The following attributes are supported only by Network Load Balancers:

            - ``deregistration_delay.connection_termination.enabled`` - Indicates whether the load balancer terminates connections at the end of the deregistration timeout. The value is ``true`` or ``false`` . The default is ``false`` .
            - ``preserve_client_ip.enabled`` - Indicates whether client IP preservation is enabled. The value is ``true`` or ``false`` . The default is disabled if the target group type is IP address and the target group protocol is TCP or TLS. Otherwise, the default is enabled. Client IP preservation cannot be disabled for UDP and TCP_UDP target groups.
            - ``proxy_protocol_v2.enabled`` - Indicates whether Proxy Protocol version 2 is enabled. The value is ``true`` or ``false`` . The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-targetgroup-targetgroupattribute.html#cfn-elasticloadbalancingv2-targetgroup-targetgroupattribute-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The value of the attribute.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-elasticloadbalancingv2-targetgroup-targetgroupattribute.html#cfn-elasticloadbalancingv2-targetgroup-targetgroupattribute-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetGroupAttributeProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.CfnTargetGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "health_check_enabled": "healthCheckEnabled",
        "health_check_interval_seconds": "healthCheckIntervalSeconds",
        "health_check_path": "healthCheckPath",
        "health_check_port": "healthCheckPort",
        "health_check_protocol": "healthCheckProtocol",
        "health_check_timeout_seconds": "healthCheckTimeoutSeconds",
        "healthy_threshold_count": "healthyThresholdCount",
        "ip_address_type": "ipAddressType",
        "matcher": "matcher",
        "name": "name",
        "port": "port",
        "protocol": "protocol",
        "protocol_version": "protocolVersion",
        "tags": "tags",
        "target_group_attributes": "targetGroupAttributes",
        "targets": "targets",
        "target_type": "targetType",
        "unhealthy_threshold_count": "unhealthyThresholdCount",
        "vpc_id": "vpcId",
    },
)
class CfnTargetGroupProps:
    def __init__(
        self,
        *,
        health_check_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        health_check_interval_seconds: typing.Optional[jsii.Number] = None,
        health_check_path: typing.Optional[builtins.str] = None,
        health_check_port: typing.Optional[builtins.str] = None,
        health_check_protocol: typing.Optional[builtins.str] = None,
        health_check_timeout_seconds: typing.Optional[jsii.Number] = None,
        healthy_threshold_count: typing.Optional[jsii.Number] = None,
        ip_address_type: typing.Optional[builtins.str] = None,
        matcher: typing.Optional[typing.Union[CfnTargetGroup.MatcherProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[builtins.str] = None,
        protocol_version: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        target_group_attributes: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTargetGroup.TargetGroupAttributeProperty, _IResolvable_da3f097b]]]] = None,
        targets: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnTargetGroup.TargetDescriptionProperty, _IResolvable_da3f097b]]]] = None,
        target_type: typing.Optional[builtins.str] = None,
        unhealthy_threshold_count: typing.Optional[jsii.Number] = None,
        vpc_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnTargetGroup``.

        :param health_check_enabled: Indicates whether health checks are enabled. If the target type is ``lambda`` , health checks are disabled by default but can be enabled. If the target type is ``instance`` , ``ip`` , or ``alb`` , health checks are always enabled and cannot be disabled.
        :param health_check_interval_seconds: The approximate amount of time, in seconds, between health checks of an individual target. If the target group protocol is HTTP or HTTPS, the default is 30 seconds. If the target group protocol is TCP, TLS, UDP, or TCP_UDP, the supported values are 10 and 30 seconds and the default is 30 seconds. If the target group protocol is GENEVE, the default is 10 seconds. If the target type is ``lambda`` , the default is 35 seconds.
        :param health_check_path: [HTTP/HTTPS health checks] The destination for health checks on the targets. [HTTP1 or HTTP2 protocol version] The ping path. The default is /. [GRPC protocol version] The path of a custom health check method with the format /package.service/method. The default is / AWS .ALB/healthcheck.
        :param health_check_port: The port the load balancer uses when performing health checks on targets. If the protocol is HTTP, HTTPS, TCP, TLS, UDP, or TCP_UDP, the default is ``traffic-port`` , which is the port on which each target receives traffic from the load balancer. If the protocol is GENEVE, the default is port 80.
        :param health_check_protocol: The protocol the load balancer uses when performing health checks on targets. For Application Load Balancers, the default is HTTP. For Network Load Balancers and Gateway Load Balancers, the default is TCP. The TCP protocol is not supported for health checks if the protocol of the target group is HTTP or HTTPS. The GENEVE, TLS, UDP, and TCP_UDP protocols are not supported for health checks.
        :param health_check_timeout_seconds: The amount of time, in seconds, during which no response from a target means a failed health check. For target groups with a protocol of HTTP, HTTPS, or GENEVE, the default is 5 seconds. For target groups with a protocol of TCP or TLS, this value must be 6 seconds for HTTP health checks and 10 seconds for TCP and HTTPS health checks. If the target type is ``lambda`` , the default is 30 seconds.
        :param healthy_threshold_count: The number of consecutive health checks successes required before considering an unhealthy target healthy. For target groups with a protocol of HTTP or HTTPS, the default is 5. For target groups with a protocol of TCP, TLS, or GENEVE, the default is 3. If the target type is ``lambda`` , the default is 5.
        :param ip_address_type: The type of IP address used for this target group. The possible values are ``ipv4`` and ``ipv6`` . This is an optional parameter. If not specified, the IP address type defaults to ``ipv4`` .
        :param matcher: [HTTP/HTTPS health checks] The HTTP or gRPC codes to use when checking for a successful response from a target.
        :param name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen.
        :param port: The port on which the targets receive traffic. This port is used unless you specify a port override when registering the target. If the target is a Lambda function, this parameter does not apply. If the protocol is GENEVE, the supported port is 6081.
        :param protocol: The protocol to use for routing traffic to the targets. For Application Load Balancers, the supported protocols are HTTP and HTTPS. For Network Load Balancers, the supported protocols are TCP, TLS, UDP, or TCP_UDP. For Gateway Load Balancers, the supported protocol is GENEVE. A TCP_UDP listener must be associated with a TCP_UDP target group. If the target is a Lambda function, this parameter does not apply.
        :param protocol_version: [HTTP/HTTPS protocol] The protocol version. The possible values are ``GRPC`` , ``HTTP1`` , and ``HTTP2`` .
        :param tags: The tags.
        :param target_group_attributes: The attributes.
        :param targets: The targets.
        :param target_type: The type of target that you must specify when registering targets with this target group. You can't specify targets for a target group using more than one target type. - ``instance`` - Register targets by instance ID. This is the default value. - ``ip`` - Register targets by IP address. You can specify IP addresses from the subnets of the virtual private cloud (VPC) for the target group, the RFC 1918 range (10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16), and the RFC 6598 range (100.64.0.0/10). You can't specify publicly routable IP addresses. - ``lambda`` - Register a single Lambda function as a target. - ``alb`` - Register a single Application Load Balancer as a target.
        :param unhealthy_threshold_count: The number of consecutive health check failures required before considering a target unhealthy. If the target group protocol is HTTP or HTTPS, the default is 2. If the target group protocol is TCP or TLS, this value must be the same as the healthy threshold count. If the target group protocol is GENEVE, the default is 3. If the target type is ``lambda`` , the default is 2.
        :param vpc_id: The identifier of the virtual private cloud (VPC). If the target is a Lambda function, this parameter does not apply. Otherwise, this parameter is required.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            cfn_target_group_props = elbv2.CfnTargetGroupProps(
                health_check_enabled=False,
                health_check_interval_seconds=123,
                health_check_path="healthCheckPath",
                health_check_port="healthCheckPort",
                health_check_protocol="healthCheckProtocol",
                health_check_timeout_seconds=123,
                healthy_threshold_count=123,
                ip_address_type="ipAddressType",
                matcher=elbv2.CfnTargetGroup.MatcherProperty(
                    grpc_code="grpcCode",
                    http_code="httpCode"
                ),
                name="name",
                port=123,
                protocol="protocol",
                protocol_version="protocolVersion",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                target_group_attributes=[elbv2.CfnTargetGroup.TargetGroupAttributeProperty(
                    key="key",
                    value="value"
                )],
                targets=[elbv2.CfnTargetGroup.TargetDescriptionProperty(
                    id="id",
            
                    # the properties below are optional
                    availability_zone="availabilityZone",
                    port=123
                )],
                target_type="targetType",
                unhealthy_threshold_count=123,
                vpc_id="vpcId"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if health_check_enabled is not None:
            self._values["health_check_enabled"] = health_check_enabled
        if health_check_interval_seconds is not None:
            self._values["health_check_interval_seconds"] = health_check_interval_seconds
        if health_check_path is not None:
            self._values["health_check_path"] = health_check_path
        if health_check_port is not None:
            self._values["health_check_port"] = health_check_port
        if health_check_protocol is not None:
            self._values["health_check_protocol"] = health_check_protocol
        if health_check_timeout_seconds is not None:
            self._values["health_check_timeout_seconds"] = health_check_timeout_seconds
        if healthy_threshold_count is not None:
            self._values["healthy_threshold_count"] = healthy_threshold_count
        if ip_address_type is not None:
            self._values["ip_address_type"] = ip_address_type
        if matcher is not None:
            self._values["matcher"] = matcher
        if name is not None:
            self._values["name"] = name
        if port is not None:
            self._values["port"] = port
        if protocol is not None:
            self._values["protocol"] = protocol
        if protocol_version is not None:
            self._values["protocol_version"] = protocol_version
        if tags is not None:
            self._values["tags"] = tags
        if target_group_attributes is not None:
            self._values["target_group_attributes"] = target_group_attributes
        if targets is not None:
            self._values["targets"] = targets
        if target_type is not None:
            self._values["target_type"] = target_type
        if unhealthy_threshold_count is not None:
            self._values["unhealthy_threshold_count"] = unhealthy_threshold_count
        if vpc_id is not None:
            self._values["vpc_id"] = vpc_id

    @builtins.property
    def health_check_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether health checks are enabled.

        If the target type is ``lambda`` , health checks are disabled by default but can be enabled. If the target type is ``instance`` , ``ip`` , or ``alb`` , health checks are always enabled and cannot be disabled.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthcheckenabled
        '''
        result = self._values.get("health_check_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def health_check_interval_seconds(self) -> typing.Optional[jsii.Number]:
        '''The approximate amount of time, in seconds, between health checks of an individual target.

        If the target group protocol is HTTP or HTTPS, the default is 30 seconds. If the target group protocol is TCP, TLS, UDP, or TCP_UDP, the supported values are 10 and 30 seconds and the default is 30 seconds. If the target group protocol is GENEVE, the default is 10 seconds. If the target type is ``lambda`` , the default is 35 seconds.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthcheckintervalseconds
        '''
        result = self._values.get("health_check_interval_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def health_check_path(self) -> typing.Optional[builtins.str]:
        '''[HTTP/HTTPS health checks] The destination for health checks on the targets.

        [HTTP1 or HTTP2 protocol version] The ping path. The default is /.

        [GRPC protocol version] The path of a custom health check method with the format /package.service/method. The default is / AWS .ALB/healthcheck.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthcheckpath
        '''
        result = self._values.get("health_check_path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def health_check_port(self) -> typing.Optional[builtins.str]:
        '''The port the load balancer uses when performing health checks on targets.

        If the protocol is HTTP, HTTPS, TCP, TLS, UDP, or TCP_UDP, the default is ``traffic-port`` , which is the port on which each target receives traffic from the load balancer. If the protocol is GENEVE, the default is port 80.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthcheckport
        '''
        result = self._values.get("health_check_port")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def health_check_protocol(self) -> typing.Optional[builtins.str]:
        '''The protocol the load balancer uses when performing health checks on targets.

        For Application Load Balancers, the default is HTTP. For Network Load Balancers and Gateway Load Balancers, the default is TCP. The TCP protocol is not supported for health checks if the protocol of the target group is HTTP or HTTPS. The GENEVE, TLS, UDP, and TCP_UDP protocols are not supported for health checks.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthcheckprotocol
        '''
        result = self._values.get("health_check_protocol")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def health_check_timeout_seconds(self) -> typing.Optional[jsii.Number]:
        '''The amount of time, in seconds, during which no response from a target means a failed health check.

        For target groups with a protocol of HTTP, HTTPS, or GENEVE, the default is 5 seconds. For target groups with a protocol of TCP or TLS, this value must be 6 seconds for HTTP health checks and 10 seconds for TCP and HTTPS health checks. If the target type is ``lambda`` , the default is 30 seconds.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthchecktimeoutseconds
        '''
        result = self._values.get("health_check_timeout_seconds")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def healthy_threshold_count(self) -> typing.Optional[jsii.Number]:
        '''The number of consecutive health checks successes required before considering an unhealthy target healthy.

        For target groups with a protocol of HTTP or HTTPS, the default is 5. For target groups with a protocol of TCP, TLS, or GENEVE, the default is 3. If the target type is ``lambda`` , the default is 5.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-healthythresholdcount
        '''
        result = self._values.get("healthy_threshold_count")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def ip_address_type(self) -> typing.Optional[builtins.str]:
        '''The type of IP address used for this target group.

        The possible values are ``ipv4`` and ``ipv6`` . This is an optional parameter. If not specified, the IP address type defaults to ``ipv4`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-ipaddresstype
        '''
        result = self._values.get("ip_address_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def matcher(
        self,
    ) -> typing.Optional[typing.Union[CfnTargetGroup.MatcherProperty, _IResolvable_da3f097b]]:
        '''[HTTP/HTTPS health checks] The HTTP or gRPC codes to use when checking for a successful response from a target.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-matcher
        '''
        result = self._values.get("matcher")
        return typing.cast(typing.Optional[typing.Union[CfnTargetGroup.MatcherProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the target group.

        This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port on which the targets receive traffic.

        This port is used unless you specify a port override when registering the target. If the target is a Lambda function, this parameter does not apply. If the protocol is GENEVE, the supported port is 6081.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-port
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def protocol(self) -> typing.Optional[builtins.str]:
        '''The protocol to use for routing traffic to the targets.

        For Application Load Balancers, the supported protocols are HTTP and HTTPS. For Network Load Balancers, the supported protocols are TCP, TLS, UDP, or TCP_UDP. For Gateway Load Balancers, the supported protocol is GENEVE. A TCP_UDP listener must be associated with a TCP_UDP target group. If the target is a Lambda function, this parameter does not apply.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-protocol
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def protocol_version(self) -> typing.Optional[builtins.str]:
        '''[HTTP/HTTPS protocol] The protocol version.

        The possible values are ``GRPC`` , ``HTTP1`` , and ``HTTP2`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-protocolversion
        '''
        result = self._values.get("protocol_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The tags.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def target_group_attributes(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTargetGroup.TargetGroupAttributeProperty, _IResolvable_da3f097b]]]]:
        '''The attributes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-targetgroupattributes
        '''
        result = self._values.get("target_group_attributes")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTargetGroup.TargetGroupAttributeProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def targets(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTargetGroup.TargetDescriptionProperty, _IResolvable_da3f097b]]]]:
        '''The targets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-targets
        '''
        result = self._values.get("targets")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnTargetGroup.TargetDescriptionProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def target_type(self) -> typing.Optional[builtins.str]:
        '''The type of target that you must specify when registering targets with this target group.

        You can't specify targets for a target group using more than one target type.

        - ``instance`` - Register targets by instance ID. This is the default value.
        - ``ip`` - Register targets by IP address. You can specify IP addresses from the subnets of the virtual private cloud (VPC) for the target group, the RFC 1918 range (10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16), and the RFC 6598 range (100.64.0.0/10). You can't specify publicly routable IP addresses.
        - ``lambda`` - Register a single Lambda function as a target.
        - ``alb`` - Register a single Application Load Balancer as a target.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-targettype
        '''
        result = self._values.get("target_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def unhealthy_threshold_count(self) -> typing.Optional[jsii.Number]:
        '''The number of consecutive health check failures required before considering a target unhealthy.

        If the target group protocol is HTTP or HTTPS, the default is 2. If the target group protocol is TCP or TLS, this value must be the same as the healthy threshold count. If the target group protocol is GENEVE, the default is 3. If the target type is ``lambda`` , the default is 2.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-unhealthythresholdcount
        '''
        result = self._values.get("unhealthy_threshold_count")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def vpc_id(self) -> typing.Optional[builtins.str]:
        '''The identifier of the virtual private cloud (VPC).

        If the target is a Lambda function, this parameter does not apply. Otherwise, this parameter is required.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-targetgroup.html#cfn-elasticloadbalancingv2-targetgroup-vpcid
        '''
        result = self._values.get("vpc_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnTargetGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.FixedResponseOptions",
    jsii_struct_bases=[],
    name_mapping={"content_type": "contentType", "message_body": "messageBody"},
)
class FixedResponseOptions:
    def __init__(
        self,
        *,
        content_type: typing.Optional[builtins.str] = None,
        message_body: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Options for ``ListenerAction.fixedResponse()``.

        :param content_type: Content Type of the response. Valid Values: text/plain | text/css | text/html | application/javascript | application/json Default: - Automatically determined
        :param message_body: The response body. Default: - No body

        :exampleMetadata: infused

        Example::

            # listener: elbv2.ApplicationListener
            
            
            listener.add_action("Fixed",
                priority=10,
                conditions=[
                    elbv2.ListenerCondition.path_patterns(["/ok"])
                ],
                action=elbv2.ListenerAction.fixed_response(200,
                    content_type=elbv2.ContentType.TEXT_PLAIN,
                    message_body="OK"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if content_type is not None:
            self._values["content_type"] = content_type
        if message_body is not None:
            self._values["message_body"] = message_body

    @builtins.property
    def content_type(self) -> typing.Optional[builtins.str]:
        '''Content Type of the response.

        Valid Values: text/plain | text/css | text/html | application/javascript | application/json

        :default: - Automatically determined
        '''
        result = self._values.get("content_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def message_body(self) -> typing.Optional[builtins.str]:
        '''The response body.

        :default: - No body
        '''
        result = self._values.get("message_body")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "FixedResponseOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ForwardOptions",
    jsii_struct_bases=[],
    name_mapping={"stickiness_duration": "stickinessDuration"},
)
class ForwardOptions:
    def __init__(
        self,
        *,
        stickiness_duration: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Options for ``ListenerAction.forward()``.

        :param stickiness_duration: For how long clients should be directed to the same target group. Range between 1 second and 7 days. Default: - No stickiness

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            forward_options = elbv2.ForwardOptions(
                stickiness_duration=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if stickiness_duration is not None:
            self._values["stickiness_duration"] = stickiness_duration

    @builtins.property
    def stickiness_duration(self) -> typing.Optional[_Duration_4839e8c3]:
        '''For how long clients should be directed to the same target group.

        Range between 1 second and 7 days.

        :default: - No stickiness
        '''
        result = self._values.get("stickiness_duration")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ForwardOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.HealthCheck",
    jsii_struct_bases=[],
    name_mapping={
        "enabled": "enabled",
        "healthy_grpc_codes": "healthyGrpcCodes",
        "healthy_http_codes": "healthyHttpCodes",
        "healthy_threshold_count": "healthyThresholdCount",
        "interval": "interval",
        "path": "path",
        "port": "port",
        "protocol": "protocol",
        "timeout": "timeout",
        "unhealthy_threshold_count": "unhealthyThresholdCount",
    },
)
class HealthCheck:
    def __init__(
        self,
        *,
        enabled: typing.Optional[builtins.bool] = None,
        healthy_grpc_codes: typing.Optional[builtins.str] = None,
        healthy_http_codes: typing.Optional[builtins.str] = None,
        healthy_threshold_count: typing.Optional[jsii.Number] = None,
        interval: typing.Optional[_Duration_4839e8c3] = None,
        path: typing.Optional[builtins.str] = None,
        port: typing.Optional[builtins.str] = None,
        protocol: typing.Optional["Protocol"] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
        unhealthy_threshold_count: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Properties for configuring a health check.

        :param enabled: Indicates whether health checks are enabled. If the target type is lambda, health checks are disabled by default but can be enabled. If the target type is instance or ip, health checks are always enabled and cannot be disabled. Default: - Determined automatically.
        :param healthy_grpc_codes: GRPC code to use when checking for a successful response from a target. You can specify values between 0 and 99. You can specify multiple values (for example, "0,1") or a range of values (for example, "0-5"). Default: - 12
        :param healthy_http_codes: HTTP code to use when checking for a successful response from a target. For Application Load Balancers, you can specify values between 200 and 499, and the default value is 200. You can specify multiple values (for example, "200,202") or a range of values (for example, "200-299").
        :param healthy_threshold_count: The number of consecutive health checks successes required before considering an unhealthy target healthy. For Application Load Balancers, the default is 5. For Network Load Balancers, the default is 3. Default: 5 for ALBs, 3 for NLBs
        :param interval: The approximate number of seconds between health checks for an individual target. Default: Duration.seconds(30)
        :param path: The ping path destination where Elastic Load Balancing sends health check requests. Default: /
        :param port: The port that the load balancer uses when performing health checks on the targets. Default: 'traffic-port'
        :param protocol: The protocol the load balancer uses when performing health checks on targets. The TCP protocol is supported for health checks only if the protocol of the target group is TCP, TLS, UDP, or TCP_UDP. The TLS, UDP, and TCP_UDP protocols are not supported for health checks. Default: HTTP for ALBs, TCP for NLBs
        :param timeout: The amount of time, in seconds, during which no response from a target means a failed health check. For Application Load Balancers, the range is 2-60 seconds and the default is 5 seconds. For Network Load Balancers, this is 10 seconds for TCP and HTTPS health checks and 6 seconds for HTTP health checks. Default: Duration.seconds(5) for ALBs, Duration.seconds(10) or Duration.seconds(6) for NLBs
        :param unhealthy_threshold_count: The number of consecutive health check failures required before considering a target unhealthy. For Application Load Balancers, the default is 2. For Network Load Balancers, this value must be the same as the healthy threshold count. Default: 2

        :exampleMetadata: infused

        Example::

            # cluster: ecs.Cluster
            
            load_balanced_fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(self, "Service",
                cluster=cluster,
                memory_limit_mi_b=1024,
                cpu=512,
                task_image_options=ecsPatterns.ApplicationLoadBalancedTaskImageOptions(
                    image=ecs.ContainerImage.from_registry("amazon/amazon-ecs-sample")
                )
            )
            
            load_balanced_fargate_service.target_group.configure_health_check(
                path="/custom-health-path"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if enabled is not None:
            self._values["enabled"] = enabled
        if healthy_grpc_codes is not None:
            self._values["healthy_grpc_codes"] = healthy_grpc_codes
        if healthy_http_codes is not None:
            self._values["healthy_http_codes"] = healthy_http_codes
        if healthy_threshold_count is not None:
            self._values["healthy_threshold_count"] = healthy_threshold_count
        if interval is not None:
            self._values["interval"] = interval
        if path is not None:
            self._values["path"] = path
        if port is not None:
            self._values["port"] = port
        if protocol is not None:
            self._values["protocol"] = protocol
        if timeout is not None:
            self._values["timeout"] = timeout
        if unhealthy_threshold_count is not None:
            self._values["unhealthy_threshold_count"] = unhealthy_threshold_count

    @builtins.property
    def enabled(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether health checks are enabled.

        If the target type is lambda,
        health checks are disabled by default but can be enabled. If the target type
        is instance or ip, health checks are always enabled and cannot be disabled.

        :default: - Determined automatically.
        '''
        result = self._values.get("enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def healthy_grpc_codes(self) -> typing.Optional[builtins.str]:
        '''GRPC code to use when checking for a successful response from a target.

        You can specify values between 0 and 99. You can specify multiple values
        (for example, "0,1") or a range of values (for example, "0-5").

        :default: - 12
        '''
        result = self._values.get("healthy_grpc_codes")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def healthy_http_codes(self) -> typing.Optional[builtins.str]:
        '''HTTP code to use when checking for a successful response from a target.

        For Application Load Balancers, you can specify values between 200 and
        499, and the default value is 200. You can specify multiple values (for
        example, "200,202") or a range of values (for example, "200-299").
        '''
        result = self._values.get("healthy_http_codes")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def healthy_threshold_count(self) -> typing.Optional[jsii.Number]:
        '''The number of consecutive health checks successes required before considering an unhealthy target healthy.

        For Application Load Balancers, the default is 5. For Network Load Balancers, the default is 3.

        :default: 5 for ALBs, 3 for NLBs
        '''
        result = self._values.get("healthy_threshold_count")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def interval(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The approximate number of seconds between health checks for an individual target.

        :default: Duration.seconds(30)
        '''
        result = self._values.get("interval")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The ping path destination where Elastic Load Balancing sends health check requests.

        :default: /
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def port(self) -> typing.Optional[builtins.str]:
        '''The port that the load balancer uses when performing health checks on the targets.

        :default: 'traffic-port'
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def protocol(self) -> typing.Optional["Protocol"]:
        '''The protocol the load balancer uses when performing health checks on targets.

        The TCP protocol is supported for health checks only if the protocol of the target group is TCP, TLS, UDP, or TCP_UDP.
        The TLS, UDP, and TCP_UDP protocols are not supported for health checks.

        :default: HTTP for ALBs, TCP for NLBs
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional["Protocol"], result)

    @builtins.property
    def timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The amount of time, in seconds, during which no response from a target means a failed health check.

        For Application Load Balancers, the range is 2-60 seconds and the
        default is 5 seconds. For Network Load Balancers, this is 10 seconds for
        TCP and HTTPS health checks and 6 seconds for HTTP health checks.

        :default: Duration.seconds(5) for ALBs, Duration.seconds(10) or Duration.seconds(6) for NLBs
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def unhealthy_threshold_count(self) -> typing.Optional[jsii.Number]:
        '''The number of consecutive health check failures required before considering a target unhealthy.

        For Application Load Balancers, the default is 2. For Network Load
        Balancers, this value must be the same as the healthy threshold count.

        :default: 2
        '''
        result = self._values.get("unhealthy_threshold_count")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "HealthCheck(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.HttpCodeElb")
class HttpCodeElb(enum.Enum):
    '''Count of HTTP status originating from the load balancer.

    This count does not include any response codes generated by the targets.
    '''

    ELB_3XX_COUNT = "ELB_3XX_COUNT"
    '''The number of HTTP 3XX redirection codes that originate from the load balancer.'''
    ELB_4XX_COUNT = "ELB_4XX_COUNT"
    '''The number of HTTP 4XX client error codes that originate from the load balancer.

    Client errors are generated when requests are malformed or incomplete.
    These requests have not been received by the target. This count does not
    include any response codes generated by the targets.
    '''
    ELB_5XX_COUNT = "ELB_5XX_COUNT"
    '''The number of HTTP 5XX server error codes that originate from the load balancer.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.HttpCodeTarget")
class HttpCodeTarget(enum.Enum):
    '''Count of HTTP status originating from the targets.'''

    TARGET_2XX_COUNT = "TARGET_2XX_COUNT"
    '''The number of 2xx response codes from targets.'''
    TARGET_3XX_COUNT = "TARGET_3XX_COUNT"
    '''The number of 3xx response codes from targets.'''
    TARGET_4XX_COUNT = "TARGET_4XX_COUNT"
    '''The number of 4xx response codes from targets.'''
    TARGET_5XX_COUNT = "TARGET_5XX_COUNT"
    '''The number of 5xx response codes from targets.'''


@jsii.interface(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.IApplicationListener"
)
class IApplicationListener(
    _IResource_c80c4260,
    _IConnectable_10015a05,
    typing_extensions.Protocol,
):
    '''Properties to reference an existing listener.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="listenerArn")
    def listener_arn(self) -> builtins.str:
        '''ARN of the listener.

        :attribute: true
        '''
        ...

    @jsii.member(jsii_name="addCertificates")
    def add_certificates(
        self,
        id: builtins.str,
        certificates: typing.Sequence["IListenerCertificate"],
    ) -> None:
        '''Add one or more certificates to this listener.

        :param id: -
        :param certificates: -
        '''
        ...

    @jsii.member(jsii_name="addTargetGroups")
    def add_target_groups(
        self,
        id: builtins.str,
        *,
        target_groups: typing.Sequence["IApplicationTargetGroup"],
        conditions: typing.Optional[typing.Sequence["ListenerCondition"]] = None,
        priority: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Load balance incoming requests to the given target groups.

        It's possible to add conditions to the TargetGroups added in this way.
        At least one TargetGroup must be added without conditions.

        :param id: -
        :param target_groups: Target groups to forward requests to.
        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param priority: Priority of this target group. The rule with the lowest priority will be used for every request. If priority is not given, these target groups will be added as defaults, and must not have conditions. Priorities must be unique. Default: Target groups are used as defaults
        '''
        ...

    @jsii.member(jsii_name="addTargets")
    def add_targets(
        self,
        id: builtins.str,
        *,
        deregistration_delay: typing.Optional[_Duration_4839e8c3] = None,
        health_check: typing.Optional[HealthCheck] = None,
        load_balancing_algorithm_type: typing.Optional["TargetGroupLoadBalancingAlgorithmType"] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        protocol_version: typing.Optional[ApplicationProtocolVersion] = None,
        slow_start: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_duration: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_name: typing.Optional[builtins.str] = None,
        target_group_name: typing.Optional[builtins.str] = None,
        targets: typing.Optional[typing.Sequence["IApplicationLoadBalancerTarget"]] = None,
        conditions: typing.Optional[typing.Sequence["ListenerCondition"]] = None,
        priority: typing.Optional[jsii.Number] = None,
    ) -> "ApplicationTargetGroup":
        '''Load balance incoming requests to the given load balancing targets.

        This method implicitly creates an ApplicationTargetGroup for the targets
        involved.

        It's possible to add conditions to the targets added in this way. At least
        one set of targets must be added without conditions.

        :param id: -
        :param deregistration_delay: The amount of time for Elastic Load Balancing to wait before deregistering a target. The range is 0-3600 seconds. Default: Duration.minutes(5)
        :param health_check: Health check configuration. Default: No health check
        :param load_balancing_algorithm_type: The load balancing algorithm to select targets for routing requests. Default: round_robin.
        :param port: The port on which the listener listens for requests. Default: Determined from protocol if known
        :param protocol: The protocol to use. Default: Determined from port if known
        :param protocol_version: The protocol version to use. Default: ApplicationProtocolVersion.HTTP1
        :param slow_start: The time period during which the load balancer sends a newly registered target a linearly increasing share of the traffic to the target group. The range is 30-900 seconds (15 minutes). Default: 0
        :param stickiness_cookie_duration: The stickiness cookie expiration period. Setting this value enables load balancer stickiness. After this period, the cookie is considered stale. The minimum value is 1 second and the maximum value is 7 days (604800 seconds). Default: Stickiness disabled
        :param stickiness_cookie_name: The name of an application-based stickiness cookie. Names that start with the following prefixes are not allowed: AWSALB, AWSALBAPP, and AWSALBTG; they're reserved for use by the load balancer. Note: ``stickinessCookieName`` parameter depends on the presence of ``stickinessCookieDuration`` parameter. If ``stickinessCookieDuration`` is not set, ``stickinessCookieName`` will be omitted. Default: - If ``stickinessCookieDuration`` is set, a load-balancer generated cookie is used. Otherwise, no stickiness is defined.
        :param target_group_name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. Default: Automatically generated
        :param targets: The targets to add to this target group. Can be ``Instance``, ``IPAddress``, or any self-registering load balancing target. All target must be of the same type.
        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param priority: Priority of this target group. The rule with the lowest priority will be used for every request. If priority is not given, these target groups will be added as defaults, and must not have conditions. Priorities must be unique. Default: Target groups are used as defaults

        :return: The newly created target group
        '''
        ...

    @jsii.member(jsii_name="registerConnectable")
    def register_connectable(
        self,
        connectable: _IConnectable_10015a05,
        port_range: _Port_85922693,
    ) -> None:
        '''Register that a connectable that has been added to this load balancer.

        Don't call this directly. It is called by ApplicationTargetGroup.

        :param connectable: -
        :param port_range: -
        '''
        ...


class _IApplicationListenerProxy(
    jsii.proxy_for(_IResource_c80c4260), # type: ignore[misc]
    jsii.proxy_for(_IConnectable_10015a05), # type: ignore[misc]
):
    '''Properties to reference an existing listener.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.IApplicationListener"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="listenerArn")
    def listener_arn(self) -> builtins.str:
        '''ARN of the listener.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "listenerArn"))

    @jsii.member(jsii_name="addCertificates")
    def add_certificates(
        self,
        id: builtins.str,
        certificates: typing.Sequence["IListenerCertificate"],
    ) -> None:
        '''Add one or more certificates to this listener.

        :param id: -
        :param certificates: -
        '''
        return typing.cast(None, jsii.invoke(self, "addCertificates", [id, certificates]))

    @jsii.member(jsii_name="addTargetGroups")
    def add_target_groups(
        self,
        id: builtins.str,
        *,
        target_groups: typing.Sequence["IApplicationTargetGroup"],
        conditions: typing.Optional[typing.Sequence["ListenerCondition"]] = None,
        priority: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Load balance incoming requests to the given target groups.

        It's possible to add conditions to the TargetGroups added in this way.
        At least one TargetGroup must be added without conditions.

        :param id: -
        :param target_groups: Target groups to forward requests to.
        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param priority: Priority of this target group. The rule with the lowest priority will be used for every request. If priority is not given, these target groups will be added as defaults, and must not have conditions. Priorities must be unique. Default: Target groups are used as defaults
        '''
        props = AddApplicationTargetGroupsProps(
            target_groups=target_groups, conditions=conditions, priority=priority
        )

        return typing.cast(None, jsii.invoke(self, "addTargetGroups", [id, props]))

    @jsii.member(jsii_name="addTargets")
    def add_targets(
        self,
        id: builtins.str,
        *,
        deregistration_delay: typing.Optional[_Duration_4839e8c3] = None,
        health_check: typing.Optional[HealthCheck] = None,
        load_balancing_algorithm_type: typing.Optional["TargetGroupLoadBalancingAlgorithmType"] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        protocol_version: typing.Optional[ApplicationProtocolVersion] = None,
        slow_start: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_duration: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_name: typing.Optional[builtins.str] = None,
        target_group_name: typing.Optional[builtins.str] = None,
        targets: typing.Optional[typing.Sequence["IApplicationLoadBalancerTarget"]] = None,
        conditions: typing.Optional[typing.Sequence["ListenerCondition"]] = None,
        priority: typing.Optional[jsii.Number] = None,
    ) -> "ApplicationTargetGroup":
        '''Load balance incoming requests to the given load balancing targets.

        This method implicitly creates an ApplicationTargetGroup for the targets
        involved.

        It's possible to add conditions to the targets added in this way. At least
        one set of targets must be added without conditions.

        :param id: -
        :param deregistration_delay: The amount of time for Elastic Load Balancing to wait before deregistering a target. The range is 0-3600 seconds. Default: Duration.minutes(5)
        :param health_check: Health check configuration. Default: No health check
        :param load_balancing_algorithm_type: The load balancing algorithm to select targets for routing requests. Default: round_robin.
        :param port: The port on which the listener listens for requests. Default: Determined from protocol if known
        :param protocol: The protocol to use. Default: Determined from port if known
        :param protocol_version: The protocol version to use. Default: ApplicationProtocolVersion.HTTP1
        :param slow_start: The time period during which the load balancer sends a newly registered target a linearly increasing share of the traffic to the target group. The range is 30-900 seconds (15 minutes). Default: 0
        :param stickiness_cookie_duration: The stickiness cookie expiration period. Setting this value enables load balancer stickiness. After this period, the cookie is considered stale. The minimum value is 1 second and the maximum value is 7 days (604800 seconds). Default: Stickiness disabled
        :param stickiness_cookie_name: The name of an application-based stickiness cookie. Names that start with the following prefixes are not allowed: AWSALB, AWSALBAPP, and AWSALBTG; they're reserved for use by the load balancer. Note: ``stickinessCookieName`` parameter depends on the presence of ``stickinessCookieDuration`` parameter. If ``stickinessCookieDuration`` is not set, ``stickinessCookieName`` will be omitted. Default: - If ``stickinessCookieDuration`` is set, a load-balancer generated cookie is used. Otherwise, no stickiness is defined.
        :param target_group_name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. Default: Automatically generated
        :param targets: The targets to add to this target group. Can be ``Instance``, ``IPAddress``, or any self-registering load balancing target. All target must be of the same type.
        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param priority: Priority of this target group. The rule with the lowest priority will be used for every request. If priority is not given, these target groups will be added as defaults, and must not have conditions. Priorities must be unique. Default: Target groups are used as defaults

        :return: The newly created target group
        '''
        props = AddApplicationTargetsProps(
            deregistration_delay=deregistration_delay,
            health_check=health_check,
            load_balancing_algorithm_type=load_balancing_algorithm_type,
            port=port,
            protocol=protocol,
            protocol_version=protocol_version,
            slow_start=slow_start,
            stickiness_cookie_duration=stickiness_cookie_duration,
            stickiness_cookie_name=stickiness_cookie_name,
            target_group_name=target_group_name,
            targets=targets,
            conditions=conditions,
            priority=priority,
        )

        return typing.cast("ApplicationTargetGroup", jsii.invoke(self, "addTargets", [id, props]))

    @jsii.member(jsii_name="registerConnectable")
    def register_connectable(
        self,
        connectable: _IConnectable_10015a05,
        port_range: _Port_85922693,
    ) -> None:
        '''Register that a connectable that has been added to this load balancer.

        Don't call this directly. It is called by ApplicationTargetGroup.

        :param connectable: -
        :param port_range: -
        '''
        return typing.cast(None, jsii.invoke(self, "registerConnectable", [connectable, port_range]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IApplicationListener).__jsii_proxy_class__ = lambda : _IApplicationListenerProxy


@jsii.interface(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.IApplicationLoadBalancerTarget"
)
class IApplicationLoadBalancerTarget(typing_extensions.Protocol):
    '''Interface for constructs that can be targets of an application load balancer.'''

    @jsii.member(jsii_name="attachToApplicationTargetGroup")
    def attach_to_application_target_group(
        self,
        target_group: "IApplicationTargetGroup",
    ) -> "LoadBalancerTargetProps":
        '''Attach load-balanced target to a TargetGroup.

        May return JSON to directly add to the [Targets] list, or return undefined
        if the target will register itself with the load balancer.

        :param target_group: -
        '''
        ...


class _IApplicationLoadBalancerTargetProxy:
    '''Interface for constructs that can be targets of an application load balancer.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.IApplicationLoadBalancerTarget"

    @jsii.member(jsii_name="attachToApplicationTargetGroup")
    def attach_to_application_target_group(
        self,
        target_group: "IApplicationTargetGroup",
    ) -> "LoadBalancerTargetProps":
        '''Attach load-balanced target to a TargetGroup.

        May return JSON to directly add to the [Targets] list, or return undefined
        if the target will register itself with the load balancer.

        :param target_group: -
        '''
        return typing.cast("LoadBalancerTargetProps", jsii.invoke(self, "attachToApplicationTargetGroup", [target_group]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IApplicationLoadBalancerTarget).__jsii_proxy_class__ = lambda : _IApplicationLoadBalancerTargetProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.IListenerAction")
class IListenerAction(typing_extensions.Protocol):
    '''Interface for listener actions.'''

    @jsii.member(jsii_name="renderActions")
    def render_actions(self) -> typing.List[CfnListener.ActionProperty]:
        '''Render the actions in this chain.'''
        ...


class _IListenerActionProxy:
    '''Interface for listener actions.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.IListenerAction"

    @jsii.member(jsii_name="renderActions")
    def render_actions(self) -> typing.List[CfnListener.ActionProperty]:
        '''Render the actions in this chain.'''
        return typing.cast(typing.List[CfnListener.ActionProperty], jsii.invoke(self, "renderActions", []))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IListenerAction).__jsii_proxy_class__ = lambda : _IListenerActionProxy


@jsii.interface(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.IListenerCertificate"
)
class IListenerCertificate(typing_extensions.Protocol):
    '''A certificate source for an ELBv2 listener.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateArn")
    def certificate_arn(self) -> builtins.str:
        '''The ARN of the certificate to use.'''
        ...


class _IListenerCertificateProxy:
    '''A certificate source for an ELBv2 listener.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.IListenerCertificate"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateArn")
    def certificate_arn(self) -> builtins.str:
        '''The ARN of the certificate to use.'''
        return typing.cast(builtins.str, jsii.get(self, "certificateArn"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IListenerCertificate).__jsii_proxy_class__ = lambda : _IListenerCertificateProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ILoadBalancerV2")
class ILoadBalancerV2(_IResource_c80c4260, typing_extensions.Protocol):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerCanonicalHostedZoneId")
    def load_balancer_canonical_hosted_zone_id(self) -> builtins.str:
        '''The canonical hosted zone ID of this load balancer.

        Example value: ``Z2P70J7EXAMPLE``

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerDnsName")
    def load_balancer_dns_name(self) -> builtins.str:
        '''The DNS name of this load balancer.

        Example value: ``my-load-balancer-424835706.us-west-2.elb.amazonaws.com``

        :attribute: true
        '''
        ...


class _ILoadBalancerV2Proxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.ILoadBalancerV2"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerCanonicalHostedZoneId")
    def load_balancer_canonical_hosted_zone_id(self) -> builtins.str:
        '''The canonical hosted zone ID of this load balancer.

        Example value: ``Z2P70J7EXAMPLE``

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "loadBalancerCanonicalHostedZoneId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerDnsName")
    def load_balancer_dns_name(self) -> builtins.str:
        '''The DNS name of this load balancer.

        Example value: ``my-load-balancer-424835706.us-west-2.elb.amazonaws.com``

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "loadBalancerDnsName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ILoadBalancerV2).__jsii_proxy_class__ = lambda : _ILoadBalancerV2Proxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.INetworkListener")
class INetworkListener(_IResource_c80c4260, typing_extensions.Protocol):
    '''Properties to reference an existing listener.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="listenerArn")
    def listener_arn(self) -> builtins.str:
        '''ARN of the listener.

        :attribute: true
        '''
        ...


class _INetworkListenerProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''Properties to reference an existing listener.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.INetworkListener"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="listenerArn")
    def listener_arn(self) -> builtins.str:
        '''ARN of the listener.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "listenerArn"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, INetworkListener).__jsii_proxy_class__ = lambda : _INetworkListenerProxy


@jsii.interface(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.INetworkLoadBalancer"
)
class INetworkLoadBalancer(
    ILoadBalancerV2,
    _IVpcEndpointServiceLoadBalancer_34cbc6e3,
    typing_extensions.Protocol,
):
    '''A network load balancer.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpc")
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC this load balancer has been created in (if available).'''
        ...

    @jsii.member(jsii_name="addListener")
    def add_listener(
        self,
        id: builtins.str,
        *,
        port: jsii.Number,
        alpn_policy: typing.Optional[AlpnPolicy] = None,
        certificates: typing.Optional[typing.Sequence[IListenerCertificate]] = None,
        default_action: typing.Optional["NetworkListenerAction"] = None,
        default_target_groups: typing.Optional[typing.Sequence["INetworkTargetGroup"]] = None,
        protocol: typing.Optional["Protocol"] = None,
        ssl_policy: typing.Optional["SslPolicy"] = None,
    ) -> "NetworkListener":
        '''Add a listener to this load balancer.

        :param id: -
        :param port: The port on which the listener listens for requests.
        :param alpn_policy: Application-Layer Protocol Negotiation (ALPN) is a TLS extension that is sent on the initial TLS handshake hello messages. ALPN enables the application layer to negotiate which protocols should be used over a secure connection, such as HTTP/1 and HTTP/2. Can only be specified together with Protocol TLS. Default: - None
        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default Action of the load balancer, including weighted forwarding. See the ``NetworkListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param protocol: Protocol for listener, expects TCP, TLS, UDP, or TCP_UDP. Default: - TLS if certificates are provided. TCP otherwise.
        :param ssl_policy: SSL Policy. Default: - Current predefined security policy.

        :return: The newly created listener
        '''
        ...


class _INetworkLoadBalancerProxy(
    jsii.proxy_for(ILoadBalancerV2), # type: ignore[misc]
    jsii.proxy_for(_IVpcEndpointServiceLoadBalancer_34cbc6e3), # type: ignore[misc]
):
    '''A network load balancer.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.INetworkLoadBalancer"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpc")
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC this load balancer has been created in (if available).'''
        return typing.cast(typing.Optional[_IVpc_f30d5663], jsii.get(self, "vpc"))

    @jsii.member(jsii_name="addListener")
    def add_listener(
        self,
        id: builtins.str,
        *,
        port: jsii.Number,
        alpn_policy: typing.Optional[AlpnPolicy] = None,
        certificates: typing.Optional[typing.Sequence[IListenerCertificate]] = None,
        default_action: typing.Optional["NetworkListenerAction"] = None,
        default_target_groups: typing.Optional[typing.Sequence["INetworkTargetGroup"]] = None,
        protocol: typing.Optional["Protocol"] = None,
        ssl_policy: typing.Optional["SslPolicy"] = None,
    ) -> "NetworkListener":
        '''Add a listener to this load balancer.

        :param id: -
        :param port: The port on which the listener listens for requests.
        :param alpn_policy: Application-Layer Protocol Negotiation (ALPN) is a TLS extension that is sent on the initial TLS handshake hello messages. ALPN enables the application layer to negotiate which protocols should be used over a secure connection, such as HTTP/1 and HTTP/2. Can only be specified together with Protocol TLS. Default: - None
        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default Action of the load balancer, including weighted forwarding. See the ``NetworkListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param protocol: Protocol for listener, expects TCP, TLS, UDP, or TCP_UDP. Default: - TLS if certificates are provided. TCP otherwise.
        :param ssl_policy: SSL Policy. Default: - Current predefined security policy.

        :return: The newly created listener
        '''
        props = BaseNetworkListenerProps(
            port=port,
            alpn_policy=alpn_policy,
            certificates=certificates,
            default_action=default_action,
            default_target_groups=default_target_groups,
            protocol=protocol,
            ssl_policy=ssl_policy,
        )

        return typing.cast("NetworkListener", jsii.invoke(self, "addListener", [id, props]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, INetworkLoadBalancer).__jsii_proxy_class__ = lambda : _INetworkLoadBalancerProxy


@jsii.interface(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.INetworkLoadBalancerTarget"
)
class INetworkLoadBalancerTarget(typing_extensions.Protocol):
    '''Interface for constructs that can be targets of an network load balancer.'''

    @jsii.member(jsii_name="attachToNetworkTargetGroup")
    def attach_to_network_target_group(
        self,
        target_group: "INetworkTargetGroup",
    ) -> "LoadBalancerTargetProps":
        '''Attach load-balanced target to a TargetGroup.

        May return JSON to directly add to the [Targets] list, or return undefined
        if the target will register itself with the load balancer.

        :param target_group: -
        '''
        ...


class _INetworkLoadBalancerTargetProxy:
    '''Interface for constructs that can be targets of an network load balancer.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.INetworkLoadBalancerTarget"

    @jsii.member(jsii_name="attachToNetworkTargetGroup")
    def attach_to_network_target_group(
        self,
        target_group: "INetworkTargetGroup",
    ) -> "LoadBalancerTargetProps":
        '''Attach load-balanced target to a TargetGroup.

        May return JSON to directly add to the [Targets] list, or return undefined
        if the target will register itself with the load balancer.

        :param target_group: -
        '''
        return typing.cast("LoadBalancerTargetProps", jsii.invoke(self, "attachToNetworkTargetGroup", [target_group]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, INetworkLoadBalancerTarget).__jsii_proxy_class__ = lambda : _INetworkLoadBalancerTargetProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ITargetGroup")
class ITargetGroup(constructs.IConstruct, typing_extensions.Protocol):
    '''A target group.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerArns")
    def load_balancer_arns(self) -> builtins.str:
        '''A token representing a list of ARNs of the load balancers that route traffic to this target group.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerAttached")
    def load_balancer_attached(self) -> constructs.IDependable:
        '''Return an object to depend on the listeners added to this target group.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetGroupArn")
    def target_group_arn(self) -> builtins.str:
        '''ARN of the target group.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetGroupName")
    def target_group_name(self) -> builtins.str:
        '''The name of the target group.'''
        ...


class _ITargetGroupProxy(
    jsii.proxy_for(constructs.IConstruct) # type: ignore[misc]
):
    '''A target group.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.ITargetGroup"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerArns")
    def load_balancer_arns(self) -> builtins.str:
        '''A token representing a list of ARNs of the load balancers that route traffic to this target group.'''
        return typing.cast(builtins.str, jsii.get(self, "loadBalancerArns"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerAttached")
    def load_balancer_attached(self) -> constructs.IDependable:
        '''Return an object to depend on the listeners added to this target group.'''
        return typing.cast(constructs.IDependable, jsii.get(self, "loadBalancerAttached"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetGroupArn")
    def target_group_arn(self) -> builtins.str:
        '''ARN of the target group.'''
        return typing.cast(builtins.str, jsii.get(self, "targetGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetGroupName")
    def target_group_name(self) -> builtins.str:
        '''The name of the target group.'''
        return typing.cast(builtins.str, jsii.get(self, "targetGroupName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ITargetGroup).__jsii_proxy_class__ = lambda : _ITargetGroupProxy


@jsii.enum(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.IpAddressType")
class IpAddressType(enum.Enum):
    '''What kind of addresses to allocate to the load balancer.'''

    IPV4 = "IPV4"
    '''Allocate IPv4 addresses.'''
    DUAL_STACK = "DUAL_STACK"
    '''Allocate both IPv4 and IPv6 addresses.'''


@jsii.implements(IListenerAction)
class ListenerAction(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ListenerAction",
):
    '''What to do when a client makes a request to a listener.

    Some actions can be combined with other ones (specifically,
    you can perform authentication before serving the request).

    Multiple actions form a linked chain; the chain must always terminate in a
    *(weighted)forward*, *fixedResponse* or *redirect* action.

    If an action supports chaining, the next action can be indicated
    by passing it in the ``next`` property.

    (Called ``ListenerAction`` instead of the more strictly correct
    ``ListenerAction`` because this is the class most users interact
    with, and we want to make it not too visually overwhelming).

    :exampleMetadata: infused

    Example::

        # listener: elbv2.ApplicationListener
        # my_target_group: elbv2.ApplicationTargetGroup
        
        
        listener.add_action("DefaultAction",
            action=elbv2.ListenerAction.authenticate_oidc(
                authorization_endpoint="https://example.com/openid",
                # Other OIDC properties here
                client_id="...",
                client_secret=SecretValue.secrets_manager("..."),
                issuer="...",
                token_endpoint="...",
                user_info_endpoint="...",
        
                # Next
                next=elbv2.ListenerAction.forward([my_target_group])
            )
        )
    '''

    def __init__(
        self,
        action_json: CfnListener.ActionProperty,
        next: typing.Optional["ListenerAction"] = None,
    ) -> None:
        '''Create an instance of ListenerAction.

        The default class should be good enough for most cases and
        should be created by using one of the static factory functions,
        but allow overriding to make sure we allow flexibility for the future.

        :param action_json: -
        :param next: -
        '''
        jsii.create(self.__class__, self, [action_json, next])

    @jsii.member(jsii_name="authenticateOidc") # type: ignore[misc]
    @builtins.classmethod
    def authenticate_oidc(
        cls,
        *,
        authorization_endpoint: builtins.str,
        client_id: builtins.str,
        client_secret: _SecretValue_3dd0ddae,
        issuer: builtins.str,
        next: "ListenerAction",
        token_endpoint: builtins.str,
        user_info_endpoint: builtins.str,
        authentication_request_extra_params: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        on_unauthenticated_request: typing.Optional["UnauthenticatedAction"] = None,
        scope: typing.Optional[builtins.str] = None,
        session_cookie_name: typing.Optional[builtins.str] = None,
        session_timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "ListenerAction":
        '''Authenticate using an identity provider (IdP) that is compliant with OpenID Connect (OIDC).

        :param authorization_endpoint: The authorization endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
        :param client_id: The OAuth 2.0 client identifier.
        :param client_secret: The OAuth 2.0 client secret.
        :param issuer: The OIDC issuer identifier of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
        :param next: What action to execute next.
        :param token_endpoint: The token endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
        :param user_info_endpoint: The user info endpoint of the IdP. This must be a full URL, including the HTTPS protocol, the domain, and the path.
        :param authentication_request_extra_params: The query parameters (up to 10) to include in the redirect request to the authorization endpoint. Default: - No extra parameters
        :param on_unauthenticated_request: The behavior if the user is not authenticated. Default: UnauthenticatedAction.AUTHENTICATE
        :param scope: The set of user claims to be requested from the IdP. To verify which scope values your IdP supports and how to separate multiple values, see the documentation for your IdP. Default: "openid"
        :param session_cookie_name: The name of the cookie used to maintain session information. Default: "AWSELBAuthSessionCookie"
        :param session_timeout: The maximum duration of the authentication session. Default: Duration.days(7)

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html#oidc-requirements
        '''
        options = AuthenticateOidcOptions(
            authorization_endpoint=authorization_endpoint,
            client_id=client_id,
            client_secret=client_secret,
            issuer=issuer,
            next=next,
            token_endpoint=token_endpoint,
            user_info_endpoint=user_info_endpoint,
            authentication_request_extra_params=authentication_request_extra_params,
            on_unauthenticated_request=on_unauthenticated_request,
            scope=scope,
            session_cookie_name=session_cookie_name,
            session_timeout=session_timeout,
        )

        return typing.cast("ListenerAction", jsii.sinvoke(cls, "authenticateOidc", [options]))

    @jsii.member(jsii_name="fixedResponse") # type: ignore[misc]
    @builtins.classmethod
    def fixed_response(
        cls,
        status_code: jsii.Number,
        *,
        content_type: typing.Optional[builtins.str] = None,
        message_body: typing.Optional[builtins.str] = None,
    ) -> "ListenerAction":
        '''Return a fixed response.

        :param status_code: -
        :param content_type: Content Type of the response. Valid Values: text/plain | text/css | text/html | application/javascript | application/json Default: - Automatically determined
        :param message_body: The response body. Default: - No body

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#fixed-response-actions
        '''
        options = FixedResponseOptions(
            content_type=content_type, message_body=message_body
        )

        return typing.cast("ListenerAction", jsii.sinvoke(cls, "fixedResponse", [status_code, options]))

    @jsii.member(jsii_name="forward") # type: ignore[misc]
    @builtins.classmethod
    def forward(
        cls,
        target_groups: typing.Sequence["IApplicationTargetGroup"],
        *,
        stickiness_duration: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "ListenerAction":
        '''Forward to one or more Target Groups.

        :param target_groups: -
        :param stickiness_duration: For how long clients should be directed to the same target group. Range between 1 second and 7 days. Default: - No stickiness

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#forward-actions
        '''
        options = ForwardOptions(stickiness_duration=stickiness_duration)

        return typing.cast("ListenerAction", jsii.sinvoke(cls, "forward", [target_groups, options]))

    @jsii.member(jsii_name="redirect") # type: ignore[misc]
    @builtins.classmethod
    def redirect(
        cls,
        *,
        host: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
        permanent: typing.Optional[builtins.bool] = None,
        port: typing.Optional[builtins.str] = None,
        protocol: typing.Optional[builtins.str] = None,
        query: typing.Optional[builtins.str] = None,
    ) -> "ListenerAction":
        '''Redirect to a different URI.

        A URI consists of the following components:
        protocol://hostname:port/path?query. You must modify at least one of the
        following components to avoid a redirect loop: protocol, hostname, port, or
        path. Any components that you do not modify retain their original values.

        You can reuse URI components using the following reserved keywords:

        - ``#{protocol}``
        - ``#{host}``
        - ``#{port}``
        - ``#{path}`` (the leading "/" is removed)
        - ``#{query}``

        For example, you can change the path to "/new/#{path}", the hostname to
        "example.#{host}", or the query to "#{query}&value=xyz".

        :param host: The hostname. This component is not percent-encoded. The hostname can contain #{host}. Default: - No change
        :param path: The absolute path, starting with the leading "/". This component is not percent-encoded. The path can contain #{host}, #{path}, and #{port}. Default: - No change
        :param permanent: The HTTP redirect code. The redirect is either permanent (HTTP 301) or temporary (HTTP 302). Default: false
        :param port: The port. You can specify a value from 1 to 65535 or #{port}. Default: - No change
        :param protocol: The protocol. You can specify HTTP, HTTPS, or #{protocol}. You can redirect HTTP to HTTP, HTTP to HTTPS, and HTTPS to HTTPS. You cannot redirect HTTPS to HTTP. Default: - No change
        :param query: The query parameters, URL-encoded when necessary, but not percent-encoded. Do not include the leading "?", as it is automatically added. You can specify any of the reserved keywords. Default: - No change

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#redirect-actions
        '''
        options = RedirectOptions(
            host=host,
            path=path,
            permanent=permanent,
            port=port,
            protocol=protocol,
            query=query,
        )

        return typing.cast("ListenerAction", jsii.sinvoke(cls, "redirect", [options]))

    @jsii.member(jsii_name="weightedForward") # type: ignore[misc]
    @builtins.classmethod
    def weighted_forward(
        cls,
        target_groups: typing.Sequence["WeightedTargetGroup"],
        *,
        stickiness_duration: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "ListenerAction":
        '''Forward to one or more Target Groups which are weighted differently.

        :param target_groups: -
        :param stickiness_duration: For how long clients should be directed to the same target group. Range between 1 second and 7 days. Default: - No stickiness

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#forward-actions
        '''
        options = ForwardOptions(stickiness_duration=stickiness_duration)

        return typing.cast("ListenerAction", jsii.sinvoke(cls, "weightedForward", [target_groups, options]))

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        scope: constructs.Construct,
        listener: IApplicationListener,
        associating_construct: typing.Optional[constructs.IConstruct] = None,
    ) -> None:
        '''Called when the action is being used in a listener.

        :param scope: -
        :param listener: -
        :param associating_construct: -
        '''
        return typing.cast(None, jsii.invoke(self, "bind", [scope, listener, associating_construct]))

    @jsii.member(jsii_name="renderActions")
    def render_actions(self) -> typing.List[CfnListener.ActionProperty]:
        '''Render the actions in this chain.'''
        return typing.cast(typing.List[CfnListener.ActionProperty], jsii.invoke(self, "renderActions", []))

    @jsii.member(jsii_name="renumber")
    def _renumber(
        self,
        actions: typing.Sequence[CfnListener.ActionProperty],
    ) -> typing.List[CfnListener.ActionProperty]:
        '''Renumber the "order" fields in the actions array.

        We don't number for 0 or 1 elements, but otherwise number them 1...#actions
        so ELB knows about the right order.

        Do this in ``ListenerAction`` instead of in ``Listener`` so that we give
        users the opportunity to override by subclassing and overriding ``renderActions``.

        :param actions: -
        '''
        return typing.cast(typing.List[CfnListener.ActionProperty], jsii.invoke(self, "renumber", [actions]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="next")
    def _next(self) -> typing.Optional["ListenerAction"]:
        return typing.cast(typing.Optional["ListenerAction"], jsii.get(self, "next"))


@jsii.implements(IListenerCertificate)
class ListenerCertificate(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ListenerCertificate",
):
    '''A certificate source for an ELBv2 listener.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_elasticloadbalancingv2 as elbv2
        
        listener_certificate = elbv2.ListenerCertificate.from_arn("certificateArn")
    '''

    def __init__(self, certificate_arn: builtins.str) -> None:
        '''
        :param certificate_arn: -
        '''
        jsii.create(self.__class__, self, [certificate_arn])

    @jsii.member(jsii_name="fromArn") # type: ignore[misc]
    @builtins.classmethod
    def from_arn(cls, certificate_arn: builtins.str) -> "ListenerCertificate":
        '''Use any certificate, identified by its ARN, as a listener certificate.

        :param certificate_arn: -
        '''
        return typing.cast("ListenerCertificate", jsii.sinvoke(cls, "fromArn", [certificate_arn]))

    @jsii.member(jsii_name="fromCertificateManager") # type: ignore[misc]
    @builtins.classmethod
    def from_certificate_manager(
        cls,
        acm_certificate: _ICertificate_c194c70b,
    ) -> "ListenerCertificate":
        '''Use an ACM certificate as a listener certificate.

        :param acm_certificate: -
        '''
        return typing.cast("ListenerCertificate", jsii.sinvoke(cls, "fromCertificateManager", [acm_certificate]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="certificateArn")
    def certificate_arn(self) -> builtins.str:
        '''The ARN of the certificate to use.'''
        return typing.cast(builtins.str, jsii.get(self, "certificateArn"))


class ListenerCondition(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ListenerCondition",
):
    '''ListenerCondition providers definition.

    :exampleMetadata: infused

    Example::

        # listener: elbv2.ApplicationListener
        # asg: autoscaling.AutoScalingGroup
        
        
        listener.add_targets("Example.Com Fleet",
            priority=10,
            conditions=[
                elbv2.ListenerCondition.host_headers(["example.com"]),
                elbv2.ListenerCondition.path_patterns(["/ok", "/path"])
            ],
            port=8080,
            targets=[asg]
        )
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="hostHeaders") # type: ignore[misc]
    @builtins.classmethod
    def host_headers(cls, values: typing.Sequence[builtins.str]) -> "ListenerCondition":
        '''Create a host-header listener rule condition.

        :param values: Hosts for host headers.
        '''
        return typing.cast("ListenerCondition", jsii.sinvoke(cls, "hostHeaders", [values]))

    @jsii.member(jsii_name="httpHeader") # type: ignore[misc]
    @builtins.classmethod
    def http_header(
        cls,
        name: builtins.str,
        values: typing.Sequence[builtins.str],
    ) -> "ListenerCondition":
        '''Create a http-header listener rule condition.

        :param name: HTTP header name.
        :param values: HTTP header values.
        '''
        return typing.cast("ListenerCondition", jsii.sinvoke(cls, "httpHeader", [name, values]))

    @jsii.member(jsii_name="httpRequestMethods") # type: ignore[misc]
    @builtins.classmethod
    def http_request_methods(
        cls,
        values: typing.Sequence[builtins.str],
    ) -> "ListenerCondition":
        '''Create a http-request-method listener rule condition.

        :param values: HTTP request methods.
        '''
        return typing.cast("ListenerCondition", jsii.sinvoke(cls, "httpRequestMethods", [values]))

    @jsii.member(jsii_name="pathPatterns") # type: ignore[misc]
    @builtins.classmethod
    def path_patterns(
        cls,
        values: typing.Sequence[builtins.str],
    ) -> "ListenerCondition":
        '''Create a path-pattern listener rule condition.

        :param values: Path patterns.
        '''
        return typing.cast("ListenerCondition", jsii.sinvoke(cls, "pathPatterns", [values]))

    @jsii.member(jsii_name="queryStrings") # type: ignore[misc]
    @builtins.classmethod
    def query_strings(
        cls,
        values: typing.Sequence["QueryStringCondition"],
    ) -> "ListenerCondition":
        '''Create a query-string listener rule condition.

        :param values: Query string key/value pairs.
        '''
        return typing.cast("ListenerCondition", jsii.sinvoke(cls, "queryStrings", [values]))

    @jsii.member(jsii_name="sourceIps") # type: ignore[misc]
    @builtins.classmethod
    def source_ips(cls, values: typing.Sequence[builtins.str]) -> "ListenerCondition":
        '''Create a source-ip listener rule condition.

        :param values: Source ips.
        '''
        return typing.cast("ListenerCondition", jsii.sinvoke(cls, "sourceIps", [values]))

    @jsii.member(jsii_name="renderRawCondition") # type: ignore[misc]
    @abc.abstractmethod
    def render_raw_condition(self) -> typing.Any:
        '''Render the raw Cfn listener rule condition object.'''
        ...


class _ListenerConditionProxy(ListenerCondition):
    @jsii.member(jsii_name="renderRawCondition")
    def render_raw_condition(self) -> typing.Any:
        '''Render the raw Cfn listener rule condition object.'''
        return typing.cast(typing.Any, jsii.invoke(self, "renderRawCondition", []))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, ListenerCondition).__jsii_proxy_class__ = lambda : _ListenerConditionProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.LoadBalancerTargetProps",
    jsii_struct_bases=[],
    name_mapping={"target_type": "targetType", "target_json": "targetJson"},
)
class LoadBalancerTargetProps:
    def __init__(
        self,
        *,
        target_type: "TargetType",
        target_json: typing.Any = None,
    ) -> None:
        '''Result of attaching a target to load balancer.

        :param target_type: What kind of target this is.
        :param target_json: JSON representing the target's direct addition to the TargetGroup list. May be omitted if the target is going to register itself later.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # target_json: Any
            
            load_balancer_target_props = elbv2.LoadBalancerTargetProps(
                target_type=elbv2.TargetType.INSTANCE,
            
                # the properties below are optional
                target_json=target_json
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target_type": target_type,
        }
        if target_json is not None:
            self._values["target_json"] = target_json

    @builtins.property
    def target_type(self) -> "TargetType":
        '''What kind of target this is.'''
        result = self._values.get("target_type")
        assert result is not None, "Required property 'target_type' is missing"
        return typing.cast("TargetType", result)

    @builtins.property
    def target_json(self) -> typing.Any:
        '''JSON representing the target's direct addition to the TargetGroup list.

        May be omitted if the target is going to register itself later.
        '''
        result = self._values.get("target_json")
        return typing.cast(typing.Any, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LoadBalancerTargetProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkForwardOptions",
    jsii_struct_bases=[],
    name_mapping={"stickiness_duration": "stickinessDuration"},
)
class NetworkForwardOptions:
    def __init__(
        self,
        *,
        stickiness_duration: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Options for ``NetworkListenerAction.forward()``.

        :param stickiness_duration: For how long clients should be directed to the same target group. Range between 1 second and 7 days. Default: - No stickiness

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            network_forward_options = elbv2.NetworkForwardOptions(
                stickiness_duration=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if stickiness_duration is not None:
            self._values["stickiness_duration"] = stickiness_duration

    @builtins.property
    def stickiness_duration(self) -> typing.Optional[_Duration_4839e8c3]:
        '''For how long clients should be directed to the same target group.

        Range between 1 second and 7 days.

        :default: - No stickiness
        '''
        result = self._values.get("stickiness_duration")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NetworkForwardOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(INetworkListener)
class NetworkListener(
    BaseListener,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkListener",
):
    '''Define a Network Listener.

    :exampleMetadata: infused
    :resource: AWS::ElasticLoadBalancingV2::Listener

    Example::

        from aws_cdk.aws_apigatewayv2_integrations_alpha import HttpNlbIntegration
        
        
        vpc = ec2.Vpc(self, "VPC")
        lb = elbv2.NetworkLoadBalancer(self, "lb", vpc=vpc)
        listener = lb.add_listener("listener", port=80)
        listener.add_targets("target",
            port=80
        )
        
        http_endpoint = apigwv2.HttpApi(self, "HttpProxyPrivateApi",
            default_integration=HttpNlbIntegration("DefaultIntegration", listener)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        load_balancer: INetworkLoadBalancer,
        port: jsii.Number,
        alpn_policy: typing.Optional[AlpnPolicy] = None,
        certificates: typing.Optional[typing.Sequence[IListenerCertificate]] = None,
        default_action: typing.Optional["NetworkListenerAction"] = None,
        default_target_groups: typing.Optional[typing.Sequence["INetworkTargetGroup"]] = None,
        protocol: typing.Optional["Protocol"] = None,
        ssl_policy: typing.Optional["SslPolicy"] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param load_balancer: The load balancer to attach this listener to.
        :param port: The port on which the listener listens for requests.
        :param alpn_policy: Application-Layer Protocol Negotiation (ALPN) is a TLS extension that is sent on the initial TLS handshake hello messages. ALPN enables the application layer to negotiate which protocols should be used over a secure connection, such as HTTP/1 and HTTP/2. Can only be specified together with Protocol TLS. Default: - None
        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default Action of the load balancer, including weighted forwarding. See the ``NetworkListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param protocol: Protocol for listener, expects TCP, TLS, UDP, or TCP_UDP. Default: - TLS if certificates are provided. TCP otherwise.
        :param ssl_policy: SSL Policy. Default: - Current predefined security policy.
        '''
        props = NetworkListenerProps(
            load_balancer=load_balancer,
            port=port,
            alpn_policy=alpn_policy,
            certificates=certificates,
            default_action=default_action,
            default_target_groups=default_target_groups,
            protocol=protocol,
            ssl_policy=ssl_policy,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromLookup") # type: ignore[misc]
    @builtins.classmethod
    def from_lookup(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        listener_protocol: typing.Optional["Protocol"] = None,
        listener_port: typing.Optional[jsii.Number] = None,
        load_balancer_arn: typing.Optional[builtins.str] = None,
        load_balancer_tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> INetworkListener:
        '''Looks up a network listener.

        :param scope: -
        :param id: -
        :param listener_protocol: Protocol of the listener port. Default: - listener is not filtered by protocol
        :param listener_port: Filter listeners by listener port. Default: - does not filter by listener port
        :param load_balancer_arn: Filter listeners by associated load balancer arn. Default: - does not filter by load balancer arn
        :param load_balancer_tags: Filter listeners by associated load balancer tags. Default: - does not filter by load balancer tags
        '''
        options = NetworkListenerLookupOptions(
            listener_protocol=listener_protocol,
            listener_port=listener_port,
            load_balancer_arn=load_balancer_arn,
            load_balancer_tags=load_balancer_tags,
        )

        return typing.cast(INetworkListener, jsii.sinvoke(cls, "fromLookup", [scope, id, options]))

    @jsii.member(jsii_name="fromNetworkListenerArn") # type: ignore[misc]
    @builtins.classmethod
    def from_network_listener_arn(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        network_listener_arn: builtins.str,
    ) -> INetworkListener:
        '''Import an existing listener.

        :param scope: -
        :param id: -
        :param network_listener_arn: -
        '''
        return typing.cast(INetworkListener, jsii.sinvoke(cls, "fromNetworkListenerArn", [scope, id, network_listener_arn]))

    @jsii.member(jsii_name="addAction")
    def add_action(self, _id: builtins.str, *, action: "NetworkListenerAction") -> None:
        '''Perform the given Action on incoming requests.

        This allows full control of the default Action of the load balancer,
        including weighted forwarding. See the ``NetworkListenerAction`` class for
        all options.

        :param _id: -
        :param action: Action to perform.
        '''
        props = AddNetworkActionProps(action=action)

        return typing.cast(None, jsii.invoke(self, "addAction", [_id, props]))

    @jsii.member(jsii_name="addTargetGroups")
    def add_target_groups(
        self,
        _id: builtins.str,
        *target_groups: "INetworkTargetGroup",
    ) -> None:
        '''Load balance incoming requests to the given target groups.

        All target groups will be load balanced to with equal weight and without
        stickiness. For a more complex configuration than that, use ``addAction()``.

        :param _id: -
        :param target_groups: -
        '''
        return typing.cast(None, jsii.invoke(self, "addTargetGroups", [_id, *target_groups]))

    @jsii.member(jsii_name="addTargets")
    def add_targets(
        self,
        id: builtins.str,
        *,
        port: jsii.Number,
        deregistration_delay: typing.Optional[_Duration_4839e8c3] = None,
        health_check: typing.Optional[HealthCheck] = None,
        preserve_client_ip: typing.Optional[builtins.bool] = None,
        protocol: typing.Optional["Protocol"] = None,
        proxy_protocol_v2: typing.Optional[builtins.bool] = None,
        target_group_name: typing.Optional[builtins.str] = None,
        targets: typing.Optional[typing.Sequence[INetworkLoadBalancerTarget]] = None,
    ) -> "NetworkTargetGroup":
        '''Load balance incoming requests to the given load balancing targets.

        This method implicitly creates a NetworkTargetGroup for the targets
        involved, and a 'forward' action to route traffic to the given TargetGroup.

        If you want more control over the precise setup, create the TargetGroup
        and use ``addAction`` yourself.

        It's possible to add conditions to the targets added in this way. At least
        one set of targets must be added without conditions.

        :param id: -
        :param port: The port on which the listener listens for requests. Default: Determined from protocol if known
        :param deregistration_delay: The amount of time for Elastic Load Balancing to wait before deregistering a target. The range is 0-3600 seconds. Default: Duration.minutes(5)
        :param health_check: Health check configuration. Default: No health check
        :param preserve_client_ip: Indicates whether client IP preservation is enabled. Default: false if the target group type is IP address and the target group protocol is TCP or TLS. Otherwise, true.
        :param protocol: Protocol for target group, expects TCP, TLS, UDP, or TCP_UDP. Default: - inherits the protocol of the listener
        :param proxy_protocol_v2: Indicates whether Proxy Protocol version 2 is enabled. Default: false
        :param target_group_name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. Default: Automatically generated
        :param targets: The targets to add to this target group. Can be ``Instance``, ``IPAddress``, or any self-registering load balancing target. If you use either ``Instance`` or ``IPAddress`` as targets, all target must be of the same type.

        :return: The newly created target group
        '''
        props = AddNetworkTargetsProps(
            port=port,
            deregistration_delay=deregistration_delay,
            health_check=health_check,
            preserve_client_ip=preserve_client_ip,
            protocol=protocol,
            proxy_protocol_v2=proxy_protocol_v2,
            target_group_name=target_group_name,
            targets=targets,
        )

        return typing.cast("NetworkTargetGroup", jsii.invoke(self, "addTargets", [id, props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancer")
    def load_balancer(self) -> INetworkLoadBalancer:
        '''The load balancer this listener is attached to.'''
        return typing.cast(INetworkLoadBalancer, jsii.get(self, "loadBalancer"))


@jsii.implements(IListenerAction)
class NetworkListenerAction(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkListenerAction",
):
    '''What to do when a client makes a request to a listener.

    Some actions can be combined with other ones (specifically,
    you can perform authentication before serving the request).

    Multiple actions form a linked chain; the chain must always terminate in a
    *(weighted)forward*, *fixedResponse* or *redirect* action.

    If an action supports chaining, the next action can be indicated
    by passing it in the ``next`` property.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_elasticloadbalancingv2 as elbv2
        
        # network_target_group: elbv2.NetworkTargetGroup
        
        network_listener_action = elbv2.NetworkListenerAction.forward([network_target_group],
            stickiness_duration=cdk.Duration.minutes(30)
        )
    '''

    def __init__(
        self,
        action_json: CfnListener.ActionProperty,
        next: typing.Optional["NetworkListenerAction"] = None,
    ) -> None:
        '''Create an instance of NetworkListenerAction.

        The default class should be good enough for most cases and
        should be created by using one of the static factory functions,
        but allow overriding to make sure we allow flexibility for the future.

        :param action_json: -
        :param next: -
        '''
        jsii.create(self.__class__, self, [action_json, next])

    @jsii.member(jsii_name="forward") # type: ignore[misc]
    @builtins.classmethod
    def forward(
        cls,
        target_groups: typing.Sequence["INetworkTargetGroup"],
        *,
        stickiness_duration: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "NetworkListenerAction":
        '''Forward to one or more Target Groups.

        :param target_groups: -
        :param stickiness_duration: For how long clients should be directed to the same target group. Range between 1 second and 7 days. Default: - No stickiness
        '''
        options = NetworkForwardOptions(stickiness_duration=stickiness_duration)

        return typing.cast("NetworkListenerAction", jsii.sinvoke(cls, "forward", [target_groups, options]))

    @jsii.member(jsii_name="weightedForward") # type: ignore[misc]
    @builtins.classmethod
    def weighted_forward(
        cls,
        target_groups: typing.Sequence["NetworkWeightedTargetGroup"],
        *,
        stickiness_duration: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "NetworkListenerAction":
        '''Forward to one or more Target Groups which are weighted differently.

        :param target_groups: -
        :param stickiness_duration: For how long clients should be directed to the same target group. Range between 1 second and 7 days. Default: - No stickiness
        '''
        options = NetworkForwardOptions(stickiness_duration=stickiness_duration)

        return typing.cast("NetworkListenerAction", jsii.sinvoke(cls, "weightedForward", [target_groups, options]))

    @jsii.member(jsii_name="bind")
    def bind(self, scope: constructs.Construct, listener: INetworkListener) -> None:
        '''Called when the action is being used in a listener.

        :param scope: -
        :param listener: -
        '''
        return typing.cast(None, jsii.invoke(self, "bind", [scope, listener]))

    @jsii.member(jsii_name="renderActions")
    def render_actions(self) -> typing.List[CfnListener.ActionProperty]:
        '''Render the actions in this chain.'''
        return typing.cast(typing.List[CfnListener.ActionProperty], jsii.invoke(self, "renderActions", []))

    @jsii.member(jsii_name="renumber")
    def _renumber(
        self,
        actions: typing.Sequence[CfnListener.ActionProperty],
    ) -> typing.List[CfnListener.ActionProperty]:
        '''Renumber the "order" fields in the actions array.

        We don't number for 0 or 1 elements, but otherwise number them 1...#actions
        so ELB knows about the right order.

        Do this in ``NetworkListenerAction`` instead of in ``Listener`` so that we give
        users the opportunity to override by subclassing and overriding ``renderActions``.

        :param actions: -
        '''
        return typing.cast(typing.List[CfnListener.ActionProperty], jsii.invoke(self, "renumber", [actions]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="next")
    def _next(self) -> typing.Optional["NetworkListenerAction"]:
        return typing.cast(typing.Optional["NetworkListenerAction"], jsii.get(self, "next"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkListenerLookupOptions",
    jsii_struct_bases=[BaseListenerLookupOptions],
    name_mapping={
        "listener_port": "listenerPort",
        "load_balancer_arn": "loadBalancerArn",
        "load_balancer_tags": "loadBalancerTags",
        "listener_protocol": "listenerProtocol",
    },
)
class NetworkListenerLookupOptions(BaseListenerLookupOptions):
    def __init__(
        self,
        *,
        listener_port: typing.Optional[jsii.Number] = None,
        load_balancer_arn: typing.Optional[builtins.str] = None,
        load_balancer_tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        listener_protocol: typing.Optional["Protocol"] = None,
    ) -> None:
        '''Options for looking up a network listener.

        :param listener_port: Filter listeners by listener port. Default: - does not filter by listener port
        :param load_balancer_arn: Filter listeners by associated load balancer arn. Default: - does not filter by load balancer arn
        :param load_balancer_tags: Filter listeners by associated load balancer tags. Default: - does not filter by load balancer tags
        :param listener_protocol: Protocol of the listener port. Default: - listener is not filtered by protocol

        :exampleMetadata: infused

        Example::

            listener = elbv2.NetworkListener.from_lookup(self, "ALBListener",
                load_balancer_tags={
                    "Cluster": "MyClusterName"
                },
                listener_protocol=elbv2.Protocol.TCP,
                listener_port=12345
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if listener_port is not None:
            self._values["listener_port"] = listener_port
        if load_balancer_arn is not None:
            self._values["load_balancer_arn"] = load_balancer_arn
        if load_balancer_tags is not None:
            self._values["load_balancer_tags"] = load_balancer_tags
        if listener_protocol is not None:
            self._values["listener_protocol"] = listener_protocol

    @builtins.property
    def listener_port(self) -> typing.Optional[jsii.Number]:
        '''Filter listeners by listener port.

        :default: - does not filter by listener port
        '''
        result = self._values.get("listener_port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def load_balancer_arn(self) -> typing.Optional[builtins.str]:
        '''Filter listeners by associated load balancer arn.

        :default: - does not filter by load balancer arn
        '''
        result = self._values.get("load_balancer_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def load_balancer_tags(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Filter listeners by associated load balancer tags.

        :default: - does not filter by load balancer tags
        '''
        result = self._values.get("load_balancer_tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def listener_protocol(self) -> typing.Optional["Protocol"]:
        '''Protocol of the listener port.

        :default: - listener is not filtered by protocol
        '''
        result = self._values.get("listener_protocol")
        return typing.cast(typing.Optional["Protocol"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NetworkListenerLookupOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkListenerProps",
    jsii_struct_bases=[BaseNetworkListenerProps],
    name_mapping={
        "port": "port",
        "alpn_policy": "alpnPolicy",
        "certificates": "certificates",
        "default_action": "defaultAction",
        "default_target_groups": "defaultTargetGroups",
        "protocol": "protocol",
        "ssl_policy": "sslPolicy",
        "load_balancer": "loadBalancer",
    },
)
class NetworkListenerProps(BaseNetworkListenerProps):
    def __init__(
        self,
        *,
        port: jsii.Number,
        alpn_policy: typing.Optional[AlpnPolicy] = None,
        certificates: typing.Optional[typing.Sequence[IListenerCertificate]] = None,
        default_action: typing.Optional[NetworkListenerAction] = None,
        default_target_groups: typing.Optional[typing.Sequence["INetworkTargetGroup"]] = None,
        protocol: typing.Optional["Protocol"] = None,
        ssl_policy: typing.Optional["SslPolicy"] = None,
        load_balancer: INetworkLoadBalancer,
    ) -> None:
        '''Properties for a Network Listener attached to a Load Balancer.

        :param port: The port on which the listener listens for requests.
        :param alpn_policy: Application-Layer Protocol Negotiation (ALPN) is a TLS extension that is sent on the initial TLS handshake hello messages. ALPN enables the application layer to negotiate which protocols should be used over a secure connection, such as HTTP/1 and HTTP/2. Can only be specified together with Protocol TLS. Default: - None
        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default Action of the load balancer, including weighted forwarding. See the ``NetworkListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param protocol: Protocol for listener, expects TCP, TLS, UDP, or TCP_UDP. Default: - TLS if certificates are provided. TCP otherwise.
        :param ssl_policy: SSL Policy. Default: - Current predefined security policy.
        :param load_balancer: The load balancer to attach this listener to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # listener_certificate: elbv2.ListenerCertificate
            # network_listener_action: elbv2.NetworkListenerAction
            # network_load_balancer: elbv2.NetworkLoadBalancer
            # network_target_group: elbv2.NetworkTargetGroup
            
            network_listener_props = elbv2.NetworkListenerProps(
                load_balancer=network_load_balancer,
                port=123,
            
                # the properties below are optional
                alpn_policy=elbv2.AlpnPolicy.HTTP1_ONLY,
                certificates=[listener_certificate],
                default_action=network_listener_action,
                default_target_groups=[network_target_group],
                protocol=elbv2.Protocol.HTTP,
                ssl_policy=elbv2.SslPolicy.RECOMMENDED
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "port": port,
            "load_balancer": load_balancer,
        }
        if alpn_policy is not None:
            self._values["alpn_policy"] = alpn_policy
        if certificates is not None:
            self._values["certificates"] = certificates
        if default_action is not None:
            self._values["default_action"] = default_action
        if default_target_groups is not None:
            self._values["default_target_groups"] = default_target_groups
        if protocol is not None:
            self._values["protocol"] = protocol
        if ssl_policy is not None:
            self._values["ssl_policy"] = ssl_policy

    @builtins.property
    def port(self) -> jsii.Number:
        '''The port on which the listener listens for requests.'''
        result = self._values.get("port")
        assert result is not None, "Required property 'port' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def alpn_policy(self) -> typing.Optional[AlpnPolicy]:
        '''Application-Layer Protocol Negotiation (ALPN) is a TLS extension that is sent on the initial TLS handshake hello messages.

        ALPN enables the application layer to negotiate which protocols should be used over a secure connection, such as HTTP/1 and HTTP/2.

        Can only be specified together with Protocol TLS.

        :default: - None
        '''
        result = self._values.get("alpn_policy")
        return typing.cast(typing.Optional[AlpnPolicy], result)

    @builtins.property
    def certificates(self) -> typing.Optional[typing.List[IListenerCertificate]]:
        '''Certificate list of ACM cert ARNs.

        You must provide exactly one certificate if the listener protocol is HTTPS or TLS.

        :default: - No certificates.
        '''
        result = self._values.get("certificates")
        return typing.cast(typing.Optional[typing.List[IListenerCertificate]], result)

    @builtins.property
    def default_action(self) -> typing.Optional[NetworkListenerAction]:
        '''Default action to take for requests to this listener.

        This allows full control of the default Action of the load balancer,
        including weighted forwarding. See the ``NetworkListenerAction`` class for
        all options.

        Cannot be specified together with ``defaultTargetGroups``.

        :default: - None.
        '''
        result = self._values.get("default_action")
        return typing.cast(typing.Optional[NetworkListenerAction], result)

    @builtins.property
    def default_target_groups(
        self,
    ) -> typing.Optional[typing.List["INetworkTargetGroup"]]:
        '''Default target groups to load balance to.

        All target groups will be load balanced to with equal weight and without
        stickiness. For a more complex configuration than that, use
        either ``defaultAction`` or ``addAction()``.

        Cannot be specified together with ``defaultAction``.

        :default: - None.
        '''
        result = self._values.get("default_target_groups")
        return typing.cast(typing.Optional[typing.List["INetworkTargetGroup"]], result)

    @builtins.property
    def protocol(self) -> typing.Optional["Protocol"]:
        '''Protocol for listener, expects TCP, TLS, UDP, or TCP_UDP.

        :default: - TLS if certificates are provided. TCP otherwise.
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional["Protocol"], result)

    @builtins.property
    def ssl_policy(self) -> typing.Optional["SslPolicy"]:
        '''SSL Policy.

        :default: - Current predefined security policy.
        '''
        result = self._values.get("ssl_policy")
        return typing.cast(typing.Optional["SslPolicy"], result)

    @builtins.property
    def load_balancer(self) -> INetworkLoadBalancer:
        '''The load balancer to attach this listener to.'''
        result = self._values.get("load_balancer")
        assert result is not None, "Required property 'load_balancer' is missing"
        return typing.cast(INetworkLoadBalancer, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NetworkListenerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(INetworkLoadBalancer)
class NetworkLoadBalancer(
    BaseLoadBalancer,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkLoadBalancer",
):
    '''Define a new network load balancer.

    :exampleMetadata: infused
    :resource: AWS::ElasticLoadBalancingV2::LoadBalancer

    Example::

        from aws_cdk.aws_apigatewayv2_integrations_alpha import HttpNlbIntegration
        
        
        vpc = ec2.Vpc(self, "VPC")
        lb = elbv2.NetworkLoadBalancer(self, "lb", vpc=vpc)
        listener = lb.add_listener("listener", port=80)
        listener.add_targets("target",
            port=80
        )
        
        http_endpoint = apigwv2.HttpApi(self, "HttpProxyPrivateApi",
            default_integration=HttpNlbIntegration("DefaultIntegration", listener)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cross_zone_enabled: typing.Optional[builtins.bool] = None,
        vpc: _IVpc_f30d5663,
        deletion_protection: typing.Optional[builtins.bool] = None,
        internet_facing: typing.Optional[builtins.bool] = None,
        load_balancer_name: typing.Optional[builtins.str] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param cross_zone_enabled: Indicates whether cross-zone load balancing is enabled. Default: false
        :param vpc: The VPC network to place the load balancer in.
        :param deletion_protection: Indicates whether deletion protection is enabled. Default: false
        :param internet_facing: Whether the load balancer has an internet-routable address. Default: false
        :param load_balancer_name: Name of the load balancer. Default: - Automatically generated name.
        :param vpc_subnets: Which subnets place the load balancer in. Default: - the Vpc default strategy.
        '''
        props = NetworkLoadBalancerProps(
            cross_zone_enabled=cross_zone_enabled,
            vpc=vpc,
            deletion_protection=deletion_protection,
            internet_facing=internet_facing,
            load_balancer_name=load_balancer_name,
            vpc_subnets=vpc_subnets,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromLookup") # type: ignore[misc]
    @builtins.classmethod
    def from_lookup(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        load_balancer_arn: typing.Optional[builtins.str] = None,
        load_balancer_tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> INetworkLoadBalancer:
        '''Looks up the network load balancer.

        :param scope: -
        :param id: -
        :param load_balancer_arn: Find by load balancer's ARN. Default: - does not search by load balancer arn
        :param load_balancer_tags: Match load balancer tags. Default: - does not match load balancers by tags
        '''
        options = NetworkLoadBalancerLookupOptions(
            load_balancer_arn=load_balancer_arn, load_balancer_tags=load_balancer_tags
        )

        return typing.cast(INetworkLoadBalancer, jsii.sinvoke(cls, "fromLookup", [scope, id, options]))

    @jsii.member(jsii_name="fromNetworkLoadBalancerAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_network_load_balancer_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        load_balancer_arn: builtins.str,
        load_balancer_canonical_hosted_zone_id: typing.Optional[builtins.str] = None,
        load_balancer_dns_name: typing.Optional[builtins.str] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> INetworkLoadBalancer:
        '''
        :param scope: -
        :param id: -
        :param load_balancer_arn: ARN of the load balancer.
        :param load_balancer_canonical_hosted_zone_id: The canonical hosted zone ID of this load balancer. Default: - When not provided, LB cannot be used as Route53 Alias target.
        :param load_balancer_dns_name: The DNS name of this load balancer. Default: - When not provided, LB cannot be used as Route53 Alias target.
        :param vpc: The VPC to associate with the load balancer. Default: - When not provided, listeners cannot be created on imported load balancers.
        '''
        attrs = NetworkLoadBalancerAttributes(
            load_balancer_arn=load_balancer_arn,
            load_balancer_canonical_hosted_zone_id=load_balancer_canonical_hosted_zone_id,
            load_balancer_dns_name=load_balancer_dns_name,
            vpc=vpc,
        )

        return typing.cast(INetworkLoadBalancer, jsii.sinvoke(cls, "fromNetworkLoadBalancerAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="addListener")
    def add_listener(
        self,
        id: builtins.str,
        *,
        port: jsii.Number,
        alpn_policy: typing.Optional[AlpnPolicy] = None,
        certificates: typing.Optional[typing.Sequence[IListenerCertificate]] = None,
        default_action: typing.Optional[NetworkListenerAction] = None,
        default_target_groups: typing.Optional[typing.Sequence["INetworkTargetGroup"]] = None,
        protocol: typing.Optional["Protocol"] = None,
        ssl_policy: typing.Optional["SslPolicy"] = None,
    ) -> NetworkListener:
        '''Add a listener to this load balancer.

        :param id: -
        :param port: The port on which the listener listens for requests.
        :param alpn_policy: Application-Layer Protocol Negotiation (ALPN) is a TLS extension that is sent on the initial TLS handshake hello messages. ALPN enables the application layer to negotiate which protocols should be used over a secure connection, such as HTTP/1 and HTTP/2. Can only be specified together with Protocol TLS. Default: - None
        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default Action of the load balancer, including weighted forwarding. See the ``NetworkListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param protocol: Protocol for listener, expects TCP, TLS, UDP, or TCP_UDP. Default: - TLS if certificates are provided. TCP otherwise.
        :param ssl_policy: SSL Policy. Default: - Current predefined security policy.

        :return: The newly created listener
        '''
        props = BaseNetworkListenerProps(
            port=port,
            alpn_policy=alpn_policy,
            certificates=certificates,
            default_action=default_action,
            default_target_groups=default_target_groups,
            protocol=protocol,
            ssl_policy=ssl_policy,
        )

        return typing.cast(NetworkListener, jsii.invoke(self, "addListener", [id, props]))

    @jsii.member(jsii_name="metric")
    def metric(
        self,
        metric_name: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the given named metric for this Network Load Balancer.

        :param metric_name: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Average over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metric", [metric_name, props]))

    @jsii.member(jsii_name="metricActiveFlowCount")
    def metric_active_flow_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The total number of concurrent TCP flows (or connections) from clients to targets.

        This metric includes connections in the SYN_SENT and ESTABLISHED states.
        TCP connections are not terminated at the load balancer, so a client
        opening a TCP connection to a target counts as a single flow.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Average over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricActiveFlowCount", [props]))

    @jsii.member(jsii_name="metricConsumedLCUs")
    def metric_consumed_lc_us(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of load balancer capacity units (LCU) used by your load balancer.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricConsumedLCUs", [props]))

    @jsii.member(jsii_name="metricNewFlowCount")
    def metric_new_flow_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The total number of new TCP flows (or connections) established from clients to targets in the time period.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNewFlowCount", [props]))

    @jsii.member(jsii_name="metricProcessedBytes")
    def metric_processed_bytes(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The total number of bytes processed by the load balancer, including TCP/IP headers.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricProcessedBytes", [props]))

    @jsii.member(jsii_name="metricTcpClientResetCount")
    def metric_tcp_client_reset_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The total number of reset (RST) packets sent from a client to a target.

        These resets are generated by the client and forwarded by the load balancer.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricTcpClientResetCount", [props]))

    @jsii.member(jsii_name="metricTcpElbResetCount")
    def metric_tcp_elb_reset_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The total number of reset (RST) packets generated by the load balancer.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricTcpElbResetCount", [props]))

    @jsii.member(jsii_name="metricTcpTargetResetCount")
    def metric_tcp_target_reset_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The total number of reset (RST) packets sent from a target to a client.

        These resets are generated by the target and forwarded by the load balancer.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricTcpTargetResetCount", [props]))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkLoadBalancerAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "load_balancer_arn": "loadBalancerArn",
        "load_balancer_canonical_hosted_zone_id": "loadBalancerCanonicalHostedZoneId",
        "load_balancer_dns_name": "loadBalancerDnsName",
        "vpc": "vpc",
    },
)
class NetworkLoadBalancerAttributes:
    def __init__(
        self,
        *,
        load_balancer_arn: builtins.str,
        load_balancer_canonical_hosted_zone_id: typing.Optional[builtins.str] = None,
        load_balancer_dns_name: typing.Optional[builtins.str] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> None:
        '''Properties to reference an existing load balancer.

        :param load_balancer_arn: ARN of the load balancer.
        :param load_balancer_canonical_hosted_zone_id: The canonical hosted zone ID of this load balancer. Default: - When not provided, LB cannot be used as Route53 Alias target.
        :param load_balancer_dns_name: The DNS name of this load balancer. Default: - When not provided, LB cannot be used as Route53 Alias target.
        :param vpc: The VPC to associate with the load balancer. Default: - When not provided, listeners cannot be created on imported load balancers.

        :exampleMetadata: infused

        Example::

            # Create an Accelerator
            accelerator = globalaccelerator.Accelerator(self, "Accelerator")
            
            # Create a Listener
            listener = accelerator.add_listener("Listener",
                port_ranges=[globalaccelerator.PortRange(from_port=80), globalaccelerator.PortRange(from_port=443)
                ]
            )
            
            # Import the Load Balancers
            nlb1 = elbv2.NetworkLoadBalancer.from_network_load_balancer_attributes(self, "NLB1",
                load_balancer_arn="arn:aws:elasticloadbalancing:us-west-2:111111111111:loadbalancer/app/my-load-balancer1/e16bef66805b"
            )
            nlb2 = elbv2.NetworkLoadBalancer.from_network_load_balancer_attributes(self, "NLB2",
                load_balancer_arn="arn:aws:elasticloadbalancing:ap-south-1:111111111111:loadbalancer/app/my-load-balancer2/5513dc2ea8a1"
            )
            
            # Add one EndpointGroup for each Region we are targeting
            listener.add_endpoint_group("Group1",
                endpoints=[ga_endpoints.NetworkLoadBalancerEndpoint(nlb1)]
            )
            listener.add_endpoint_group("Group2",
                # Imported load balancers automatically calculate their Region from the ARN.
                # If you are load balancing to other resources, you must also pass a `region`
                # parameter here.
                endpoints=[ga_endpoints.NetworkLoadBalancerEndpoint(nlb2)]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "load_balancer_arn": load_balancer_arn,
        }
        if load_balancer_canonical_hosted_zone_id is not None:
            self._values["load_balancer_canonical_hosted_zone_id"] = load_balancer_canonical_hosted_zone_id
        if load_balancer_dns_name is not None:
            self._values["load_balancer_dns_name"] = load_balancer_dns_name
        if vpc is not None:
            self._values["vpc"] = vpc

    @builtins.property
    def load_balancer_arn(self) -> builtins.str:
        '''ARN of the load balancer.'''
        result = self._values.get("load_balancer_arn")
        assert result is not None, "Required property 'load_balancer_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def load_balancer_canonical_hosted_zone_id(self) -> typing.Optional[builtins.str]:
        '''The canonical hosted zone ID of this load balancer.

        :default: - When not provided, LB cannot be used as Route53 Alias target.
        '''
        result = self._values.get("load_balancer_canonical_hosted_zone_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def load_balancer_dns_name(self) -> typing.Optional[builtins.str]:
        '''The DNS name of this load balancer.

        :default: - When not provided, LB cannot be used as Route53 Alias target.
        '''
        result = self._values.get("load_balancer_dns_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC to associate with the load balancer.

        :default:

        - When not provided, listeners cannot be created on imported load
        balancers.
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NetworkLoadBalancerAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkLoadBalancerLookupOptions",
    jsii_struct_bases=[BaseLoadBalancerLookupOptions],
    name_mapping={
        "load_balancer_arn": "loadBalancerArn",
        "load_balancer_tags": "loadBalancerTags",
    },
)
class NetworkLoadBalancerLookupOptions(BaseLoadBalancerLookupOptions):
    def __init__(
        self,
        *,
        load_balancer_arn: typing.Optional[builtins.str] = None,
        load_balancer_tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Options for looking up an NetworkLoadBalancer.

        :param load_balancer_arn: Find by load balancer's ARN. Default: - does not search by load balancer arn
        :param load_balancer_tags: Match load balancer tags. Default: - does not match load balancers by tags

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            network_load_balancer_lookup_options = elbv2.NetworkLoadBalancerLookupOptions(
                load_balancer_arn="loadBalancerArn",
                load_balancer_tags={
                    "load_balancer_tags_key": "loadBalancerTags"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if load_balancer_arn is not None:
            self._values["load_balancer_arn"] = load_balancer_arn
        if load_balancer_tags is not None:
            self._values["load_balancer_tags"] = load_balancer_tags

    @builtins.property
    def load_balancer_arn(self) -> typing.Optional[builtins.str]:
        '''Find by load balancer's ARN.

        :default: - does not search by load balancer arn
        '''
        result = self._values.get("load_balancer_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def load_balancer_tags(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Match load balancer tags.

        :default: - does not match load balancers by tags
        '''
        result = self._values.get("load_balancer_tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NetworkLoadBalancerLookupOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkLoadBalancerProps",
    jsii_struct_bases=[BaseLoadBalancerProps],
    name_mapping={
        "vpc": "vpc",
        "deletion_protection": "deletionProtection",
        "internet_facing": "internetFacing",
        "load_balancer_name": "loadBalancerName",
        "vpc_subnets": "vpcSubnets",
        "cross_zone_enabled": "crossZoneEnabled",
    },
)
class NetworkLoadBalancerProps(BaseLoadBalancerProps):
    def __init__(
        self,
        *,
        vpc: _IVpc_f30d5663,
        deletion_protection: typing.Optional[builtins.bool] = None,
        internet_facing: typing.Optional[builtins.bool] = None,
        load_balancer_name: typing.Optional[builtins.str] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
        cross_zone_enabled: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Properties for a network load balancer.

        :param vpc: The VPC network to place the load balancer in.
        :param deletion_protection: Indicates whether deletion protection is enabled. Default: false
        :param internet_facing: Whether the load balancer has an internet-routable address. Default: false
        :param load_balancer_name: Name of the load balancer. Default: - Automatically generated name.
        :param vpc_subnets: Which subnets place the load balancer in. Default: - the Vpc default strategy.
        :param cross_zone_enabled: Indicates whether cross-zone load balancing is enabled. Default: false

        :exampleMetadata: infused

        Example::

            from aws_cdk.aws_apigatewayv2_integrations_alpha import HttpNlbIntegration
            
            
            vpc = ec2.Vpc(self, "VPC")
            lb = elbv2.NetworkLoadBalancer(self, "lb", vpc=vpc)
            listener = lb.add_listener("listener", port=80)
            listener.add_targets("target",
                port=80
            )
            
            http_endpoint = apigwv2.HttpApi(self, "HttpProxyPrivateApi",
                default_integration=HttpNlbIntegration("DefaultIntegration", listener)
            )
        '''
        if isinstance(vpc_subnets, dict):
            vpc_subnets = _SubnetSelection_e57d76df(**vpc_subnets)
        self._values: typing.Dict[str, typing.Any] = {
            "vpc": vpc,
        }
        if deletion_protection is not None:
            self._values["deletion_protection"] = deletion_protection
        if internet_facing is not None:
            self._values["internet_facing"] = internet_facing
        if load_balancer_name is not None:
            self._values["load_balancer_name"] = load_balancer_name
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets
        if cross_zone_enabled is not None:
            self._values["cross_zone_enabled"] = cross_zone_enabled

    @builtins.property
    def vpc(self) -> _IVpc_f30d5663:
        '''The VPC network to place the load balancer in.'''
        result = self._values.get("vpc")
        assert result is not None, "Required property 'vpc' is missing"
        return typing.cast(_IVpc_f30d5663, result)

    @builtins.property
    def deletion_protection(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether deletion protection is enabled.

        :default: false
        '''
        result = self._values.get("deletion_protection")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def internet_facing(self) -> typing.Optional[builtins.bool]:
        '''Whether the load balancer has an internet-routable address.

        :default: false
        '''
        result = self._values.get("internet_facing")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def load_balancer_name(self) -> typing.Optional[builtins.str]:
        '''Name of the load balancer.

        :default: - Automatically generated name.
        '''
        result = self._values.get("load_balancer_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''Which subnets place the load balancer in.

        :default: - the Vpc default strategy.
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    @builtins.property
    def cross_zone_enabled(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether cross-zone load balancing is enabled.

        :default: false
        '''
        result = self._values.get("cross_zone_enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NetworkLoadBalancerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkTargetGroupProps",
    jsii_struct_bases=[BaseTargetGroupProps],
    name_mapping={
        "deregistration_delay": "deregistrationDelay",
        "health_check": "healthCheck",
        "target_group_name": "targetGroupName",
        "target_type": "targetType",
        "vpc": "vpc",
        "port": "port",
        "preserve_client_ip": "preserveClientIp",
        "protocol": "protocol",
        "proxy_protocol_v2": "proxyProtocolV2",
        "targets": "targets",
    },
)
class NetworkTargetGroupProps(BaseTargetGroupProps):
    def __init__(
        self,
        *,
        deregistration_delay: typing.Optional[_Duration_4839e8c3] = None,
        health_check: typing.Optional[HealthCheck] = None,
        target_group_name: typing.Optional[builtins.str] = None,
        target_type: typing.Optional["TargetType"] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        port: jsii.Number,
        preserve_client_ip: typing.Optional[builtins.bool] = None,
        protocol: typing.Optional["Protocol"] = None,
        proxy_protocol_v2: typing.Optional[builtins.bool] = None,
        targets: typing.Optional[typing.Sequence[INetworkLoadBalancerTarget]] = None,
    ) -> None:
        '''Properties for a new Network Target Group.

        :param deregistration_delay: The amount of time for Elastic Load Balancing to wait before deregistering a target. The range is 0-3600 seconds. Default: 300
        :param health_check: Health check configuration. Default: - None.
        :param target_group_name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. Default: - Automatically generated.
        :param target_type: The type of targets registered to this TargetGroup, either IP or Instance. All targets registered into the group must be of this type. If you register targets to the TargetGroup in the CDK app, the TargetType is determined automatically. Default: - Determined automatically.
        :param vpc: The virtual private cloud (VPC). only if ``TargetType`` is ``Ip`` or ``InstanceId`` Default: - undefined
        :param port: The port on which the listener listens for requests.
        :param preserve_client_ip: Indicates whether client IP preservation is enabled. Default: false if the target group type is IP address and the target group protocol is TCP or TLS. Otherwise, true.
        :param protocol: Protocol for target group, expects TCP, TLS, UDP, or TCP_UDP. Default: - TCP
        :param proxy_protocol_v2: Indicates whether Proxy Protocol version 2 is enabled. Default: false
        :param targets: The targets to add to this target group. Can be ``Instance``, ``IPAddress``, or any self-registering load balancing target. If you use either ``Instance`` or ``IPAddress`` as targets, all target must be of the same type. Default: - No targets.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # network_load_balancer_target: elbv2.INetworkLoadBalancerTarget
            # vpc: ec2.Vpc
            
            network_target_group_props = elbv2.NetworkTargetGroupProps(
                port=123,
            
                # the properties below are optional
                deregistration_delay=cdk.Duration.minutes(30),
                health_check=elbv2.HealthCheck(
                    enabled=False,
                    healthy_grpc_codes="healthyGrpcCodes",
                    healthy_http_codes="healthyHttpCodes",
                    healthy_threshold_count=123,
                    interval=cdk.Duration.minutes(30),
                    path="path",
                    port="port",
                    protocol=elbv2.Protocol.HTTP,
                    timeout=cdk.Duration.minutes(30),
                    unhealthy_threshold_count=123
                ),
                preserve_client_ip=False,
                protocol=elbv2.Protocol.HTTP,
                proxy_protocol_v2=False,
                target_group_name="targetGroupName",
                targets=[network_load_balancer_target],
                target_type=elbv2.TargetType.INSTANCE,
                vpc=vpc
            )
        '''
        if isinstance(health_check, dict):
            health_check = HealthCheck(**health_check)
        self._values: typing.Dict[str, typing.Any] = {
            "port": port,
        }
        if deregistration_delay is not None:
            self._values["deregistration_delay"] = deregistration_delay
        if health_check is not None:
            self._values["health_check"] = health_check
        if target_group_name is not None:
            self._values["target_group_name"] = target_group_name
        if target_type is not None:
            self._values["target_type"] = target_type
        if vpc is not None:
            self._values["vpc"] = vpc
        if preserve_client_ip is not None:
            self._values["preserve_client_ip"] = preserve_client_ip
        if protocol is not None:
            self._values["protocol"] = protocol
        if proxy_protocol_v2 is not None:
            self._values["proxy_protocol_v2"] = proxy_protocol_v2
        if targets is not None:
            self._values["targets"] = targets

    @builtins.property
    def deregistration_delay(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The amount of time for Elastic Load Balancing to wait before deregistering a target.

        The range is 0-3600 seconds.

        :default: 300
        '''
        result = self._values.get("deregistration_delay")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def health_check(self) -> typing.Optional[HealthCheck]:
        '''Health check configuration.

        :default: - None.
        '''
        result = self._values.get("health_check")
        return typing.cast(typing.Optional[HealthCheck], result)

    @builtins.property
    def target_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the target group.

        This name must be unique per region per account, can have a maximum of
        32 characters, must contain only alphanumeric characters or hyphens, and
        must not begin or end with a hyphen.

        :default: - Automatically generated.
        '''
        result = self._values.get("target_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def target_type(self) -> typing.Optional["TargetType"]:
        '''The type of targets registered to this TargetGroup, either IP or Instance.

        All targets registered into the group must be of this type. If you
        register targets to the TargetGroup in the CDK app, the TargetType is
        determined automatically.

        :default: - Determined automatically.
        '''
        result = self._values.get("target_type")
        return typing.cast(typing.Optional["TargetType"], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The virtual private cloud (VPC).

        only if ``TargetType`` is ``Ip`` or ``InstanceId``

        :default: - undefined
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    @builtins.property
    def port(self) -> jsii.Number:
        '''The port on which the listener listens for requests.'''
        result = self._values.get("port")
        assert result is not None, "Required property 'port' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def preserve_client_ip(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether client IP preservation is enabled.

        :default:

        false if the target group type is IP address and the
        target group protocol is TCP or TLS. Otherwise, true.
        '''
        result = self._values.get("preserve_client_ip")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def protocol(self) -> typing.Optional["Protocol"]:
        '''Protocol for target group, expects TCP, TLS, UDP, or TCP_UDP.

        :default: - TCP
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional["Protocol"], result)

    @builtins.property
    def proxy_protocol_v2(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether Proxy Protocol version 2 is enabled.

        :default: false
        '''
        result = self._values.get("proxy_protocol_v2")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def targets(self) -> typing.Optional[typing.List[INetworkLoadBalancerTarget]]:
        '''The targets to add to this target group.

        Can be ``Instance``, ``IPAddress``, or any self-registering load balancing
        target. If you use either ``Instance`` or ``IPAddress`` as targets, all
        target must be of the same type.

        :default: - No targets.
        '''
        result = self._values.get("targets")
        return typing.cast(typing.Optional[typing.List[INetworkLoadBalancerTarget]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NetworkTargetGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkWeightedTargetGroup",
    jsii_struct_bases=[],
    name_mapping={"target_group": "targetGroup", "weight": "weight"},
)
class NetworkWeightedTargetGroup:
    def __init__(
        self,
        *,
        target_group: "INetworkTargetGroup",
        weight: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''A Target Group and weight combination.

        :param target_group: The target group.
        :param weight: The target group's weight. Range is [0..1000). Default: 1

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # network_target_group: elbv2.NetworkTargetGroup
            
            network_weighted_target_group = elbv2.NetworkWeightedTargetGroup(
                target_group=network_target_group,
            
                # the properties below are optional
                weight=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target_group": target_group,
        }
        if weight is not None:
            self._values["weight"] = weight

    @builtins.property
    def target_group(self) -> "INetworkTargetGroup":
        '''The target group.'''
        result = self._values.get("target_group")
        assert result is not None, "Required property 'target_group' is missing"
        return typing.cast("INetworkTargetGroup", result)

    @builtins.property
    def weight(self) -> typing.Optional[jsii.Number]:
        '''The target group's weight.

        Range is [0..1000).

        :default: 1
        '''
        result = self._values.get("weight")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NetworkWeightedTargetGroup(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.Protocol")
class Protocol(enum.Enum):
    '''Backend protocol for network load balancers and health checks.

    :exampleMetadata: infused

    Example::

        listener = elbv2.NetworkListener.from_lookup(self, "ALBListener",
            load_balancer_tags={
                "Cluster": "MyClusterName"
            },
            listener_protocol=elbv2.Protocol.TCP,
            listener_port=12345
        )
    '''

    HTTP = "HTTP"
    '''HTTP (ALB health checks and NLB health checks).'''
    HTTPS = "HTTPS"
    '''HTTPS (ALB health checks and NLB health checks).'''
    TCP = "TCP"
    '''TCP (NLB, NLB health checks).'''
    TLS = "TLS"
    '''TLS (NLB).'''
    UDP = "UDP"
    '''UDP (NLB).'''
    TCP_UDP = "TCP_UDP"
    '''Listen to both TCP and UDP on the same port (NLB).'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.QueryStringCondition",
    jsii_struct_bases=[],
    name_mapping={"value": "value", "key": "key"},
)
class QueryStringCondition:
    def __init__(
        self,
        *,
        value: builtins.str,
        key: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for the key/value pair of the query string.

        :param value: The query string value for the condition.
        :param key: The query string key for the condition. Default: - Any key can be matched.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            query_string_condition = elbv2.QueryStringCondition(
                value="value",
            
                # the properties below are optional
                key="key"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "value": value,
        }
        if key is not None:
            self._values["key"] = key

    @builtins.property
    def value(self) -> builtins.str:
        '''The query string value for the condition.'''
        result = self._values.get("value")
        assert result is not None, "Required property 'value' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''The query string key for the condition.

        :default: - Any key can be matched.
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "QueryStringCondition(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.RedirectOptions",
    jsii_struct_bases=[],
    name_mapping={
        "host": "host",
        "path": "path",
        "permanent": "permanent",
        "port": "port",
        "protocol": "protocol",
        "query": "query",
    },
)
class RedirectOptions:
    def __init__(
        self,
        *,
        host: typing.Optional[builtins.str] = None,
        path: typing.Optional[builtins.str] = None,
        permanent: typing.Optional[builtins.bool] = None,
        port: typing.Optional[builtins.str] = None,
        protocol: typing.Optional[builtins.str] = None,
        query: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Options for ``ListenerAction.redirect()``.

        A URI consists of the following components:
        protocol://hostname:port/path?query. You must modify at least one of the
        following components to avoid a redirect loop: protocol, hostname, port, or
        path. Any components that you do not modify retain their original values.

        You can reuse URI components using the following reserved keywords:

        - ``#{protocol}``
        - ``#{host}``
        - ``#{port}``
        - ``#{path}`` (the leading "/" is removed)
        - ``#{query}``

        For example, you can change the path to "/new/#{path}", the hostname to
        "example.#{host}", or the query to "#{query}&value=xyz".

        :param host: The hostname. This component is not percent-encoded. The hostname can contain #{host}. Default: - No change
        :param path: The absolute path, starting with the leading "/". This component is not percent-encoded. The path can contain #{host}, #{path}, and #{port}. Default: - No change
        :param permanent: The HTTP redirect code. The redirect is either permanent (HTTP 301) or temporary (HTTP 302). Default: false
        :param port: The port. You can specify a value from 1 to 65535 or #{port}. Default: - No change
        :param protocol: The protocol. You can specify HTTP, HTTPS, or #{protocol}. You can redirect HTTP to HTTP, HTTP to HTTPS, and HTTPS to HTTPS. You cannot redirect HTTPS to HTTP. Default: - No change
        :param query: The query parameters, URL-encoded when necessary, but not percent-encoded. Do not include the leading "?", as it is automatically added. You can specify any of the reserved keywords. Default: - No change

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            redirect_options = elbv2.RedirectOptions(
                host="host",
                path="path",
                permanent=False,
                port="port",
                protocol="protocol",
                query="query"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if host is not None:
            self._values["host"] = host
        if path is not None:
            self._values["path"] = path
        if permanent is not None:
            self._values["permanent"] = permanent
        if port is not None:
            self._values["port"] = port
        if protocol is not None:
            self._values["protocol"] = protocol
        if query is not None:
            self._values["query"] = query

    @builtins.property
    def host(self) -> typing.Optional[builtins.str]:
        '''The hostname.

        This component is not percent-encoded. The hostname can contain #{host}.

        :default: - No change
        '''
        result = self._values.get("host")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def path(self) -> typing.Optional[builtins.str]:
        '''The absolute path, starting with the leading "/".

        This component is not percent-encoded. The path can contain #{host}, #{path}, and #{port}.

        :default: - No change
        '''
        result = self._values.get("path")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def permanent(self) -> typing.Optional[builtins.bool]:
        '''The HTTP redirect code.

        The redirect is either permanent (HTTP 301) or temporary (HTTP 302).

        :default: false
        '''
        result = self._values.get("permanent")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def port(self) -> typing.Optional[builtins.str]:
        '''The port.

        You can specify a value from 1 to 65535 or #{port}.

        :default: - No change
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def protocol(self) -> typing.Optional[builtins.str]:
        '''The protocol.

        You can specify HTTP, HTTPS, or #{protocol}. You can redirect HTTP to HTTP, HTTP to HTTPS, and HTTPS to HTTPS. You cannot redirect HTTPS to HTTP.

        :default: - No change
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def query(self) -> typing.Optional[builtins.str]:
        '''The query parameters, URL-encoded when necessary, but not percent-encoded.

        Do not include the leading "?", as it is automatically added. You can specify any of the reserved keywords.

        :default: - No change
        '''
        result = self._values.get("query")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RedirectOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.SslPolicy")
class SslPolicy(enum.Enum):
    '''Elastic Load Balancing provides the following security policies for Application Load Balancers.

    We recommend the Recommended policy for general use. You can
    use the ForwardSecrecy policy if you require Forward Secrecy
    (FS).

    You can use one of the TLS policies to meet compliance and security
    standards that require disabling certain TLS protocol versions, or to
    support legacy clients that require deprecated ciphers.

    :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html
    :exampleMetadata: infused

    Example::

        from aws_cdk.aws_route53 import HostedZone
        from aws_cdk.aws_certificatemanager import Certificate
        from aws_cdk.aws_elasticloadbalancingv2 import SslPolicy
        
        # vpc: ec2.Vpc
        # cluster: ecs.Cluster
        
        
        domain_zone = HostedZone.from_lookup(self, "Zone", domain_name="example.com")
        certificate = Certificate.from_certificate_arn(self, "Cert", "arn:aws:acm:us-east-1:123456:certificate/abcdefg")
        load_balanced_fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(self, "Service",
            vpc=vpc,
            cluster=cluster,
            certificate=certificate,
            ssl_policy=SslPolicy.RECOMMENDED,
            domain_name="api.example.com",
            domain_zone=domain_zone,
            redirect_hTTP=True,
            task_image_options=ecsPatterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_registry("amazon/amazon-ecs-sample")
            )
        )
    '''

    RECOMMENDED = "RECOMMENDED"
    '''The recommended security policy.'''
    FORWARD_SECRECY_TLS12_RES_GCM = "FORWARD_SECRECY_TLS12_RES_GCM"
    '''Strong foward secrecy ciphers and TLV1.2 only (2020 edition). Same as FORWARD_SECRECY_TLS12_RES, but only supports GCM versions of the TLS ciphers.'''
    FORWARD_SECRECY_TLS12_RES = "FORWARD_SECRECY_TLS12_RES"
    '''Strong forward secrecy ciphers and TLS1.2 only.'''
    FORWARD_SECRECY_TLS12 = "FORWARD_SECRECY_TLS12"
    '''Forward secrecy ciphers and TLS1.2 only.'''
    FORWARD_SECRECY_TLS11 = "FORWARD_SECRECY_TLS11"
    '''Forward secrecy ciphers only with TLS1.1 and higher.'''
    FORWARD_SECRECY = "FORWARD_SECRECY"
    '''Forward secrecy ciphers only.'''
    TLS12 = "TLS12"
    '''TLS1.2 only and no SHA ciphers.'''
    TLS12_EXT = "TLS12_EXT"
    '''TLS1.2 only with all ciphers.'''
    TLS11 = "TLS11"
    '''TLS1.1 and higher with all ciphers.'''
    LEGACY = "LEGACY"
    '''Support for DES-CBC3-SHA.

    Do not use this security policy unless you must support a legacy client
    that requires the DES-CBC3-SHA cipher, which is a weak cipher.
    '''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.TargetGroupAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "target_group_arn": "targetGroupArn",
        "load_balancer_arns": "loadBalancerArns",
    },
)
class TargetGroupAttributes:
    def __init__(
        self,
        *,
        target_group_arn: builtins.str,
        load_balancer_arns: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties to reference an existing target group.

        :param target_group_arn: ARN of the target group.
        :param load_balancer_arns: A Token representing the list of ARNs for the load balancer routing to this target group.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            target_group_attributes = elbv2.TargetGroupAttributes(
                target_group_arn="targetGroupArn",
            
                # the properties below are optional
                load_balancer_arns="loadBalancerArns"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target_group_arn": target_group_arn,
        }
        if load_balancer_arns is not None:
            self._values["load_balancer_arns"] = load_balancer_arns

    @builtins.property
    def target_group_arn(self) -> builtins.str:
        '''ARN of the target group.'''
        result = self._values.get("target_group_arn")
        assert result is not None, "Required property 'target_group_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def load_balancer_arns(self) -> typing.Optional[builtins.str]:
        '''A Token representing the list of ARNs for the load balancer routing to this target group.'''
        result = self._values.get("load_balancer_arns")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "TargetGroupAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(ITargetGroup)
class TargetGroupBase(
    constructs.Construct,
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.TargetGroupBase",
):
    '''Define the target of a load balancer.'''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        base_props: BaseTargetGroupProps,
        additional_props: typing.Any,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param base_props: -
        :param additional_props: -
        '''
        jsii.create(self.__class__, self, [scope, id, base_props, additional_props])

    @jsii.member(jsii_name="addLoadBalancerTarget")
    def _add_load_balancer_target(
        self,
        *,
        target_type: "TargetType",
        target_json: typing.Any = None,
    ) -> None:
        '''Register the given load balancing target as part of this group.

        :param target_type: What kind of target this is.
        :param target_json: JSON representing the target's direct addition to the TargetGroup list. May be omitted if the target is going to register itself later.
        '''
        props = LoadBalancerTargetProps(
            target_type=target_type, target_json=target_json
        )

        return typing.cast(None, jsii.invoke(self, "addLoadBalancerTarget", [props]))

    @jsii.member(jsii_name="configureHealthCheck")
    def configure_health_check(
        self,
        *,
        enabled: typing.Optional[builtins.bool] = None,
        healthy_grpc_codes: typing.Optional[builtins.str] = None,
        healthy_http_codes: typing.Optional[builtins.str] = None,
        healthy_threshold_count: typing.Optional[jsii.Number] = None,
        interval: typing.Optional[_Duration_4839e8c3] = None,
        path: typing.Optional[builtins.str] = None,
        port: typing.Optional[builtins.str] = None,
        protocol: typing.Optional[Protocol] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
        unhealthy_threshold_count: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Set/replace the target group's health check.

        :param enabled: Indicates whether health checks are enabled. If the target type is lambda, health checks are disabled by default but can be enabled. If the target type is instance or ip, health checks are always enabled and cannot be disabled. Default: - Determined automatically.
        :param healthy_grpc_codes: GRPC code to use when checking for a successful response from a target. You can specify values between 0 and 99. You can specify multiple values (for example, "0,1") or a range of values (for example, "0-5"). Default: - 12
        :param healthy_http_codes: HTTP code to use when checking for a successful response from a target. For Application Load Balancers, you can specify values between 200 and 499, and the default value is 200. You can specify multiple values (for example, "200,202") or a range of values (for example, "200-299").
        :param healthy_threshold_count: The number of consecutive health checks successes required before considering an unhealthy target healthy. For Application Load Balancers, the default is 5. For Network Load Balancers, the default is 3. Default: 5 for ALBs, 3 for NLBs
        :param interval: The approximate number of seconds between health checks for an individual target. Default: Duration.seconds(30)
        :param path: The ping path destination where Elastic Load Balancing sends health check requests. Default: /
        :param port: The port that the load balancer uses when performing health checks on the targets. Default: 'traffic-port'
        :param protocol: The protocol the load balancer uses when performing health checks on targets. The TCP protocol is supported for health checks only if the protocol of the target group is TCP, TLS, UDP, or TCP_UDP. The TLS, UDP, and TCP_UDP protocols are not supported for health checks. Default: HTTP for ALBs, TCP for NLBs
        :param timeout: The amount of time, in seconds, during which no response from a target means a failed health check. For Application Load Balancers, the range is 2-60 seconds and the default is 5 seconds. For Network Load Balancers, this is 10 seconds for TCP and HTTPS health checks and 6 seconds for HTTP health checks. Default: Duration.seconds(5) for ALBs, Duration.seconds(10) or Duration.seconds(6) for NLBs
        :param unhealthy_threshold_count: The number of consecutive health check failures required before considering a target unhealthy. For Application Load Balancers, the default is 2. For Network Load Balancers, this value must be the same as the healthy threshold count. Default: 2
        '''
        health_check = HealthCheck(
            enabled=enabled,
            healthy_grpc_codes=healthy_grpc_codes,
            healthy_http_codes=healthy_http_codes,
            healthy_threshold_count=healthy_threshold_count,
            interval=interval,
            path=path,
            port=port,
            protocol=protocol,
            timeout=timeout,
            unhealthy_threshold_count=unhealthy_threshold_count,
        )

        return typing.cast(None, jsii.invoke(self, "configureHealthCheck", [health_check]))

    @jsii.member(jsii_name="setAttribute")
    def set_attribute(
        self,
        key: builtins.str,
        value: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Set a non-standard attribute on the target group.

        :param key: -
        :param value: -

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#target-group-attributes
        '''
        return typing.cast(None, jsii.invoke(self, "setAttribute", [key, value]))

    @jsii.member(jsii_name="validateTargetGroup")
    def _validate_target_group(self) -> typing.List[builtins.str]:
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateTargetGroup", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultPort")
    def _default_port(self) -> jsii.Number:
        '''Default port configured for members of this target group.'''
        return typing.cast(jsii.Number, jsii.get(self, "defaultPort"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="firstLoadBalancerFullName")
    @abc.abstractmethod
    def first_load_balancer_full_name(self) -> builtins.str:
        '''Full name of first load balancer.

        This identifier is emitted as a dimensions of the metrics of this target
        group.

        Example value: ``app/my-load-balancer/123456789``
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerArns")
    def load_balancer_arns(self) -> builtins.str:
        '''A token representing a list of ARNs of the load balancers that route traffic to this target group.'''
        return typing.cast(builtins.str, jsii.get(self, "loadBalancerArns"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerAttached")
    def load_balancer_attached(self) -> constructs.IDependable:
        '''List of constructs that need to be depended on to ensure the TargetGroup is associated to a load balancer.'''
        return typing.cast(constructs.IDependable, jsii.get(self, "loadBalancerAttached"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerAttachedDependencies")
    def _load_balancer_attached_dependencies(self) -> constructs.DependencyGroup:
        '''Configurable dependable with all resources that lead to load balancer attachment.'''
        return typing.cast(constructs.DependencyGroup, jsii.get(self, "loadBalancerAttachedDependencies"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetGroupArn")
    def target_group_arn(self) -> builtins.str:
        '''The ARN of the target group.'''
        return typing.cast(builtins.str, jsii.get(self, "targetGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetGroupFullName")
    def target_group_full_name(self) -> builtins.str:
        '''The full name of the target group.'''
        return typing.cast(builtins.str, jsii.get(self, "targetGroupFullName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetGroupLoadBalancerArns")
    def target_group_load_balancer_arns(self) -> typing.List[builtins.str]:
        '''ARNs of load balancers load balancing to this TargetGroup.'''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "targetGroupLoadBalancerArns"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetGroupName")
    def target_group_name(self) -> builtins.str:
        '''The name of the target group.'''
        return typing.cast(builtins.str, jsii.get(self, "targetGroupName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheck")
    def health_check(self) -> HealthCheck:
        return typing.cast(HealthCheck, jsii.get(self, "healthCheck"))

    @health_check.setter
    def health_check(self, value: HealthCheck) -> None:
        jsii.set(self, "healthCheck", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetType")
    def _target_type(self) -> typing.Optional["TargetType"]:
        '''The types of the directly registered members of this target group.'''
        return typing.cast(typing.Optional["TargetType"], jsii.get(self, "targetType"))

    @_target_type.setter
    def _target_type(self, value: typing.Optional["TargetType"]) -> None:
        jsii.set(self, "targetType", value)


class _TargetGroupBaseProxy(TargetGroupBase):
    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="firstLoadBalancerFullName")
    def first_load_balancer_full_name(self) -> builtins.str:
        '''Full name of first load balancer.

        This identifier is emitted as a dimensions of the metrics of this target
        group.

        Example value: ``app/my-load-balancer/123456789``
        '''
        return typing.cast(builtins.str, jsii.get(self, "firstLoadBalancerFullName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, TargetGroupBase).__jsii_proxy_class__ = lambda : _TargetGroupBaseProxy


@jsii.enum(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.TargetGroupLoadBalancingAlgorithmType"
)
class TargetGroupLoadBalancingAlgorithmType(enum.Enum):
    '''Load balancing algorithmm type for target groups.'''

    ROUND_ROBIN = "ROUND_ROBIN"
    '''round_robin.'''
    LEAST_OUTSTANDING_REQUESTS = "LEAST_OUTSTANDING_REQUESTS"
    '''least_outstanding_requests.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.TargetType")
class TargetType(enum.Enum):
    '''How to interpret the load balancing target identifiers.

    :exampleMetadata: infused

    Example::

        # vpc: ec2.Vpc
        
        
        tg = elbv2.ApplicationTargetGroup(self, "TG",
            target_type=elbv2.TargetType.IP,
            port=50051,
            protocol=elbv2.ApplicationProtocol.HTTP,
            protocol_version=elbv2.ApplicationProtocolVersion.GRPC,
            health_check=elbv2.HealthCheck(
                enabled=True,
                healthy_grpc_codes="0-99"
            ),
            vpc=vpc
        )
    '''

    INSTANCE = "INSTANCE"
    '''Targets identified by instance ID.'''
    IP = "IP"
    '''Targets identified by IP address.'''
    LAMBDA = "LAMBDA"
    '''Target is a single Lambda Function.'''
    ALB = "ALB"
    '''Target is a single Application Load Balancer.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.UnauthenticatedAction")
class UnauthenticatedAction(enum.Enum):
    '''What to do with unauthenticated requests.'''

    DENY = "DENY"
    '''Return an HTTP 401 Unauthorized error.'''
    ALLOW = "ALLOW"
    '''Allow the request to be forwarded to the target.'''
    AUTHENTICATE = "AUTHENTICATE"
    '''Redirect the request to the IdP authorization endpoint.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.WeightedTargetGroup",
    jsii_struct_bases=[],
    name_mapping={"target_group": "targetGroup", "weight": "weight"},
)
class WeightedTargetGroup:
    def __init__(
        self,
        *,
        target_group: "IApplicationTargetGroup",
        weight: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''A Target Group and weight combination.

        :param target_group: The target group.
        :param weight: The target group's weight. Range is [0..1000). Default: 1

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # application_target_group: elbv2.ApplicationTargetGroup
            
            weighted_target_group = elbv2.WeightedTargetGroup(
                target_group=application_target_group,
            
                # the properties below are optional
                weight=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target_group": target_group,
        }
        if weight is not None:
            self._values["weight"] = weight

    @builtins.property
    def target_group(self) -> "IApplicationTargetGroup":
        '''The target group.'''
        result = self._values.get("target_group")
        assert result is not None, "Required property 'target_group' is missing"
        return typing.cast("IApplicationTargetGroup", result)

    @builtins.property
    def weight(self) -> typing.Optional[jsii.Number]:
        '''The target group's weight.

        Range is [0..1000).

        :default: 1
        '''
        result = self._values.get("weight")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "WeightedTargetGroup(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.AddApplicationActionProps",
    jsii_struct_bases=[AddRuleProps],
    name_mapping={
        "conditions": "conditions",
        "priority": "priority",
        "action": "action",
    },
)
class AddApplicationActionProps(AddRuleProps):
    def __init__(
        self,
        *,
        conditions: typing.Optional[typing.Sequence[ListenerCondition]] = None,
        priority: typing.Optional[jsii.Number] = None,
        action: ListenerAction,
    ) -> None:
        '''Properties for adding a new action to a listener.

        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param priority: Priority of this target group. The rule with the lowest priority will be used for every request. If priority is not given, these target groups will be added as defaults, and must not have conditions. Priorities must be unique. Default: Target groups are used as defaults
        :param action: Action to perform.

        :exampleMetadata: infused

        Example::

            # listener: elbv2.ApplicationListener
            
            
            listener.add_action("Fixed",
                priority=10,
                conditions=[
                    elbv2.ListenerCondition.path_patterns(["/ok"])
                ],
                action=elbv2.ListenerAction.fixed_response(200,
                    content_type=elbv2.ContentType.TEXT_PLAIN,
                    message_body="OK"
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "action": action,
        }
        if conditions is not None:
            self._values["conditions"] = conditions
        if priority is not None:
            self._values["priority"] = priority

    @builtins.property
    def conditions(self) -> typing.Optional[typing.List[ListenerCondition]]:
        '''Rule applies if matches the conditions.

        :default: - No conditions.

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html
        '''
        result = self._values.get("conditions")
        return typing.cast(typing.Optional[typing.List[ListenerCondition]], result)

    @builtins.property
    def priority(self) -> typing.Optional[jsii.Number]:
        '''Priority of this target group.

        The rule with the lowest priority will be used for every request.
        If priority is not given, these target groups will be added as
        defaults, and must not have conditions.

        Priorities must be unique.

        :default: Target groups are used as defaults
        '''
        result = self._values.get("priority")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def action(self) -> ListenerAction:
        '''Action to perform.'''
        result = self._values.get("action")
        assert result is not None, "Required property 'action' is missing"
        return typing.cast(ListenerAction, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AddApplicationActionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.AddApplicationTargetGroupsProps",
    jsii_struct_bases=[AddRuleProps],
    name_mapping={
        "conditions": "conditions",
        "priority": "priority",
        "target_groups": "targetGroups",
    },
)
class AddApplicationTargetGroupsProps(AddRuleProps):
    def __init__(
        self,
        *,
        conditions: typing.Optional[typing.Sequence[ListenerCondition]] = None,
        priority: typing.Optional[jsii.Number] = None,
        target_groups: typing.Sequence["IApplicationTargetGroup"],
    ) -> None:
        '''Properties for adding a new target group to a listener.

        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param priority: Priority of this target group. The rule with the lowest priority will be used for every request. If priority is not given, these target groups will be added as defaults, and must not have conditions. Priorities must be unique. Default: Target groups are used as defaults
        :param target_groups: Target groups to forward requests to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # application_target_group: elbv2.ApplicationTargetGroup
            # listener_condition: elbv2.ListenerCondition
            
            add_application_target_groups_props = elbv2.AddApplicationTargetGroupsProps(
                target_groups=[application_target_group],
            
                # the properties below are optional
                conditions=[listener_condition],
                priority=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target_groups": target_groups,
        }
        if conditions is not None:
            self._values["conditions"] = conditions
        if priority is not None:
            self._values["priority"] = priority

    @builtins.property
    def conditions(self) -> typing.Optional[typing.List[ListenerCondition]]:
        '''Rule applies if matches the conditions.

        :default: - No conditions.

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html
        '''
        result = self._values.get("conditions")
        return typing.cast(typing.Optional[typing.List[ListenerCondition]], result)

    @builtins.property
    def priority(self) -> typing.Optional[jsii.Number]:
        '''Priority of this target group.

        The rule with the lowest priority will be used for every request.
        If priority is not given, these target groups will be added as
        defaults, and must not have conditions.

        Priorities must be unique.

        :default: Target groups are used as defaults
        '''
        result = self._values.get("priority")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def target_groups(self) -> typing.List["IApplicationTargetGroup"]:
        '''Target groups to forward requests to.'''
        result = self._values.get("target_groups")
        assert result is not None, "Required property 'target_groups' is missing"
        return typing.cast(typing.List["IApplicationTargetGroup"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AddApplicationTargetGroupsProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.AddApplicationTargetsProps",
    jsii_struct_bases=[AddRuleProps],
    name_mapping={
        "conditions": "conditions",
        "priority": "priority",
        "deregistration_delay": "deregistrationDelay",
        "health_check": "healthCheck",
        "load_balancing_algorithm_type": "loadBalancingAlgorithmType",
        "port": "port",
        "protocol": "protocol",
        "protocol_version": "protocolVersion",
        "slow_start": "slowStart",
        "stickiness_cookie_duration": "stickinessCookieDuration",
        "stickiness_cookie_name": "stickinessCookieName",
        "target_group_name": "targetGroupName",
        "targets": "targets",
    },
)
class AddApplicationTargetsProps(AddRuleProps):
    def __init__(
        self,
        *,
        conditions: typing.Optional[typing.Sequence[ListenerCondition]] = None,
        priority: typing.Optional[jsii.Number] = None,
        deregistration_delay: typing.Optional[_Duration_4839e8c3] = None,
        health_check: typing.Optional[HealthCheck] = None,
        load_balancing_algorithm_type: typing.Optional[TargetGroupLoadBalancingAlgorithmType] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        protocol_version: typing.Optional[ApplicationProtocolVersion] = None,
        slow_start: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_duration: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_name: typing.Optional[builtins.str] = None,
        target_group_name: typing.Optional[builtins.str] = None,
        targets: typing.Optional[typing.Sequence[IApplicationLoadBalancerTarget]] = None,
    ) -> None:
        '''Properties for adding new targets to a listener.

        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param priority: Priority of this target group. The rule with the lowest priority will be used for every request. If priority is not given, these target groups will be added as defaults, and must not have conditions. Priorities must be unique. Default: Target groups are used as defaults
        :param deregistration_delay: The amount of time for Elastic Load Balancing to wait before deregistering a target. The range is 0-3600 seconds. Default: Duration.minutes(5)
        :param health_check: Health check configuration. Default: No health check
        :param load_balancing_algorithm_type: The load balancing algorithm to select targets for routing requests. Default: round_robin.
        :param port: The port on which the listener listens for requests. Default: Determined from protocol if known
        :param protocol: The protocol to use. Default: Determined from port if known
        :param protocol_version: The protocol version to use. Default: ApplicationProtocolVersion.HTTP1
        :param slow_start: The time period during which the load balancer sends a newly registered target a linearly increasing share of the traffic to the target group. The range is 30-900 seconds (15 minutes). Default: 0
        :param stickiness_cookie_duration: The stickiness cookie expiration period. Setting this value enables load balancer stickiness. After this period, the cookie is considered stale. The minimum value is 1 second and the maximum value is 7 days (604800 seconds). Default: Stickiness disabled
        :param stickiness_cookie_name: The name of an application-based stickiness cookie. Names that start with the following prefixes are not allowed: AWSALB, AWSALBAPP, and AWSALBTG; they're reserved for use by the load balancer. Note: ``stickinessCookieName`` parameter depends on the presence of ``stickinessCookieDuration`` parameter. If ``stickinessCookieDuration`` is not set, ``stickinessCookieName`` will be omitted. Default: - If ``stickinessCookieDuration`` is set, a load-balancer generated cookie is used. Otherwise, no stickiness is defined.
        :param target_group_name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. Default: Automatically generated
        :param targets: The targets to add to this target group. Can be ``Instance``, ``IPAddress``, or any self-registering load balancing target. All target must be of the same type.

        :exampleMetadata: infused

        Example::

            from aws_cdk.aws_autoscaling import AutoScalingGroup
            # asg: AutoScalingGroup
            
            # vpc: ec2.Vpc
            
            
            # Create the load balancer in a VPC. 'internetFacing' is 'false'
            # by default, which creates an internal load balancer.
            lb = elbv2.ApplicationLoadBalancer(self, "LB",
                vpc=vpc,
                internet_facing=True
            )
            
            # Add a listener and open up the load balancer's security group
            # to the world.
            listener = lb.add_listener("Listener",
                port=80,
            
                # 'open: true' is the default, you can leave it out if you want. Set it
                # to 'false' and use `listener.connections` if you want to be selective
                # about who can access the load balancer.
                open=True
            )
            
            # Create an AutoScaling group and add it as a load balancing
            # target to the listener.
            listener.add_targets("ApplicationFleet",
                port=8080,
                targets=[asg]
            )
        '''
        if isinstance(health_check, dict):
            health_check = HealthCheck(**health_check)
        self._values: typing.Dict[str, typing.Any] = {}
        if conditions is not None:
            self._values["conditions"] = conditions
        if priority is not None:
            self._values["priority"] = priority
        if deregistration_delay is not None:
            self._values["deregistration_delay"] = deregistration_delay
        if health_check is not None:
            self._values["health_check"] = health_check
        if load_balancing_algorithm_type is not None:
            self._values["load_balancing_algorithm_type"] = load_balancing_algorithm_type
        if port is not None:
            self._values["port"] = port
        if protocol is not None:
            self._values["protocol"] = protocol
        if protocol_version is not None:
            self._values["protocol_version"] = protocol_version
        if slow_start is not None:
            self._values["slow_start"] = slow_start
        if stickiness_cookie_duration is not None:
            self._values["stickiness_cookie_duration"] = stickiness_cookie_duration
        if stickiness_cookie_name is not None:
            self._values["stickiness_cookie_name"] = stickiness_cookie_name
        if target_group_name is not None:
            self._values["target_group_name"] = target_group_name
        if targets is not None:
            self._values["targets"] = targets

    @builtins.property
    def conditions(self) -> typing.Optional[typing.List[ListenerCondition]]:
        '''Rule applies if matches the conditions.

        :default: - No conditions.

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html
        '''
        result = self._values.get("conditions")
        return typing.cast(typing.Optional[typing.List[ListenerCondition]], result)

    @builtins.property
    def priority(self) -> typing.Optional[jsii.Number]:
        '''Priority of this target group.

        The rule with the lowest priority will be used for every request.
        If priority is not given, these target groups will be added as
        defaults, and must not have conditions.

        Priorities must be unique.

        :default: Target groups are used as defaults
        '''
        result = self._values.get("priority")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def deregistration_delay(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The amount of time for Elastic Load Balancing to wait before deregistering a target.

        The range is 0-3600 seconds.

        :default: Duration.minutes(5)
        '''
        result = self._values.get("deregistration_delay")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def health_check(self) -> typing.Optional[HealthCheck]:
        '''Health check configuration.

        :default: No health check
        '''
        result = self._values.get("health_check")
        return typing.cast(typing.Optional[HealthCheck], result)

    @builtins.property
    def load_balancing_algorithm_type(
        self,
    ) -> typing.Optional[TargetGroupLoadBalancingAlgorithmType]:
        '''The load balancing algorithm to select targets for routing requests.

        :default: round_robin.
        '''
        result = self._values.get("load_balancing_algorithm_type")
        return typing.cast(typing.Optional[TargetGroupLoadBalancingAlgorithmType], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port on which the listener listens for requests.

        :default: Determined from protocol if known
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def protocol(self) -> typing.Optional[ApplicationProtocol]:
        '''The protocol to use.

        :default: Determined from port if known
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional[ApplicationProtocol], result)

    @builtins.property
    def protocol_version(self) -> typing.Optional[ApplicationProtocolVersion]:
        '''The protocol version to use.

        :default: ApplicationProtocolVersion.HTTP1
        '''
        result = self._values.get("protocol_version")
        return typing.cast(typing.Optional[ApplicationProtocolVersion], result)

    @builtins.property
    def slow_start(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The time period during which the load balancer sends a newly registered target a linearly increasing share of the traffic to the target group.

        The range is 30-900 seconds (15 minutes).

        :default: 0
        '''
        result = self._values.get("slow_start")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def stickiness_cookie_duration(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The stickiness cookie expiration period.

        Setting this value enables load balancer stickiness.

        After this period, the cookie is considered stale. The minimum value is
        1 second and the maximum value is 7 days (604800 seconds).

        :default: Stickiness disabled
        '''
        result = self._values.get("stickiness_cookie_duration")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def stickiness_cookie_name(self) -> typing.Optional[builtins.str]:
        '''The name of an application-based stickiness cookie.

        Names that start with the following prefixes are not allowed: AWSALB, AWSALBAPP,
        and AWSALBTG; they're reserved for use by the load balancer.

        Note: ``stickinessCookieName`` parameter depends on the presence of ``stickinessCookieDuration`` parameter.
        If ``stickinessCookieDuration`` is not set, ``stickinessCookieName`` will be omitted.

        :default: - If ``stickinessCookieDuration`` is set, a load-balancer generated cookie is used. Otherwise, no stickiness is defined.

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/sticky-sessions.html
        '''
        result = self._values.get("stickiness_cookie_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def target_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the target group.

        This name must be unique per region per account, can have a maximum of
        32 characters, must contain only alphanumeric characters or hyphens, and
        must not begin or end with a hyphen.

        :default: Automatically generated
        '''
        result = self._values.get("target_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def targets(self) -> typing.Optional[typing.List[IApplicationLoadBalancerTarget]]:
        '''The targets to add to this target group.

        Can be ``Instance``, ``IPAddress``, or any self-registering load balancing
        target. All target must be of the same type.
        '''
        result = self._values.get("targets")
        return typing.cast(typing.Optional[typing.List[IApplicationLoadBalancerTarget]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AddApplicationTargetsProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(IApplicationListener)
class ApplicationListener(
    BaseListener,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationListener",
):
    '''Define an ApplicationListener.

    :exampleMetadata: infused
    :resource: AWS::ElasticLoadBalancingV2::Listener

    Example::

        import aws_cdk.aws_elasticloadbalancingv2 as elbv2
        
        # alb: elbv2.ApplicationLoadBalancer
        
        listener = alb.add_listener("Listener", port=80)
        target_group = listener.add_targets("Fleet", port=80)
        
        deployment_group = codedeploy.ServerDeploymentGroup(self, "DeploymentGroup",
            load_balancer=codedeploy.LoadBalancer.application(target_group)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        load_balancer: "IApplicationLoadBalancer",
        certificates: typing.Optional[typing.Sequence[IListenerCertificate]] = None,
        default_action: typing.Optional[ListenerAction] = None,
        default_target_groups: typing.Optional[typing.Sequence["IApplicationTargetGroup"]] = None,
        open: typing.Optional[builtins.bool] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        ssl_policy: typing.Optional[SslPolicy] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param load_balancer: The load balancer to attach this listener to.
        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default action of the load balancer, including Action chaining, fixed responses and redirect responses. See the ``ListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param open: Allow anyone to connect to the load balancer on the listener port. If this is specified, the load balancer will be opened up to anyone who can reach it. For internal load balancers this is anyone in the same VPC. For public load balancers, this is anyone on the internet. If you want to be more selective about who can access this load balancer, set this to ``false`` and use the listener's ``connections`` object to selectively grant access to the load balancer on the listener port. Default: true
        :param port: The port on which the listener listens for requests. Default: - Determined from protocol if known.
        :param protocol: The protocol to use. Default: - Determined from port if known.
        :param ssl_policy: The security policy that defines which ciphers and protocols are supported. Default: - The current predefined security policy.
        '''
        props = ApplicationListenerProps(
            load_balancer=load_balancer,
            certificates=certificates,
            default_action=default_action,
            default_target_groups=default_target_groups,
            open=open,
            port=port,
            protocol=protocol,
            ssl_policy=ssl_policy,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromApplicationListenerAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_application_listener_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        listener_arn: builtins.str,
        default_port: typing.Optional[jsii.Number] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
    ) -> IApplicationListener:
        '''Import an existing listener.

        :param scope: -
        :param id: -
        :param listener_arn: ARN of the listener.
        :param default_port: The default port on which this listener is listening.
        :param security_group: Security group of the load balancer this listener is associated with.
        '''
        attrs = ApplicationListenerAttributes(
            listener_arn=listener_arn,
            default_port=default_port,
            security_group=security_group,
        )

        return typing.cast(IApplicationListener, jsii.sinvoke(cls, "fromApplicationListenerAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="fromLookup") # type: ignore[misc]
    @builtins.classmethod
    def from_lookup(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        listener_arn: typing.Optional[builtins.str] = None,
        listener_protocol: typing.Optional[ApplicationProtocol] = None,
        listener_port: typing.Optional[jsii.Number] = None,
        load_balancer_arn: typing.Optional[builtins.str] = None,
        load_balancer_tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> IApplicationListener:
        '''Look up an ApplicationListener.

        :param scope: -
        :param id: -
        :param listener_arn: ARN of the listener to look up. Default: - does not filter by listener arn
        :param listener_protocol: Filter listeners by listener protocol. Default: - does not filter by listener protocol
        :param listener_port: Filter listeners by listener port. Default: - does not filter by listener port
        :param load_balancer_arn: Filter listeners by associated load balancer arn. Default: - does not filter by load balancer arn
        :param load_balancer_tags: Filter listeners by associated load balancer tags. Default: - does not filter by load balancer tags
        '''
        options = ApplicationListenerLookupOptions(
            listener_arn=listener_arn,
            listener_protocol=listener_protocol,
            listener_port=listener_port,
            load_balancer_arn=load_balancer_arn,
            load_balancer_tags=load_balancer_tags,
        )

        return typing.cast(IApplicationListener, jsii.sinvoke(cls, "fromLookup", [scope, id, options]))

    @jsii.member(jsii_name="addAction")
    def add_action(
        self,
        id: builtins.str,
        *,
        action: ListenerAction,
        conditions: typing.Optional[typing.Sequence[ListenerCondition]] = None,
        priority: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Perform the given default action on incoming requests.

        This allows full control of the default action of the load balancer,
        including Action chaining, fixed responses and redirect responses. See
        the ``ListenerAction`` class for all options.

        It's possible to add routing conditions to the Action added in this way.
        At least one Action must be added without conditions (which becomes the
        default Action).

        :param id: -
        :param action: Action to perform.
        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param priority: Priority of this target group. The rule with the lowest priority will be used for every request. If priority is not given, these target groups will be added as defaults, and must not have conditions. Priorities must be unique. Default: Target groups are used as defaults
        '''
        props = AddApplicationActionProps(
            action=action, conditions=conditions, priority=priority
        )

        return typing.cast(None, jsii.invoke(self, "addAction", [id, props]))

    @jsii.member(jsii_name="addCertificates")
    def add_certificates(
        self,
        id: builtins.str,
        certificates: typing.Sequence[IListenerCertificate],
    ) -> None:
        '''Add one or more certificates to this listener.

        After the first certificate, this creates ApplicationListenerCertificates
        resources since cloudformation requires the certificates array on the
        listener resource to have a length of 1.

        :param id: -
        :param certificates: -
        '''
        return typing.cast(None, jsii.invoke(self, "addCertificates", [id, certificates]))

    @jsii.member(jsii_name="addTargetGroups")
    def add_target_groups(
        self,
        id: builtins.str,
        *,
        target_groups: typing.Sequence["IApplicationTargetGroup"],
        conditions: typing.Optional[typing.Sequence[ListenerCondition]] = None,
        priority: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Load balance incoming requests to the given target groups.

        All target groups will be load balanced to with equal weight and without
        stickiness. For a more complex configuration than that, use ``addAction()``.

        It's possible to add routing conditions to the TargetGroups added in this
        way. At least one TargetGroup must be added without conditions (which will
        become the default Action for this listener).

        :param id: -
        :param target_groups: Target groups to forward requests to.
        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param priority: Priority of this target group. The rule with the lowest priority will be used for every request. If priority is not given, these target groups will be added as defaults, and must not have conditions. Priorities must be unique. Default: Target groups are used as defaults
        '''
        props = AddApplicationTargetGroupsProps(
            target_groups=target_groups, conditions=conditions, priority=priority
        )

        return typing.cast(None, jsii.invoke(self, "addTargetGroups", [id, props]))

    @jsii.member(jsii_name="addTargets")
    def add_targets(
        self,
        id: builtins.str,
        *,
        deregistration_delay: typing.Optional[_Duration_4839e8c3] = None,
        health_check: typing.Optional[HealthCheck] = None,
        load_balancing_algorithm_type: typing.Optional[TargetGroupLoadBalancingAlgorithmType] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        protocol_version: typing.Optional[ApplicationProtocolVersion] = None,
        slow_start: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_duration: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_name: typing.Optional[builtins.str] = None,
        target_group_name: typing.Optional[builtins.str] = None,
        targets: typing.Optional[typing.Sequence[IApplicationLoadBalancerTarget]] = None,
        conditions: typing.Optional[typing.Sequence[ListenerCondition]] = None,
        priority: typing.Optional[jsii.Number] = None,
    ) -> "ApplicationTargetGroup":
        '''Load balance incoming requests to the given load balancing targets.

        This method implicitly creates an ApplicationTargetGroup for the targets
        involved, and a 'forward' action to route traffic to the given TargetGroup.

        If you want more control over the precise setup, create the TargetGroup
        and use ``addAction`` yourself.

        It's possible to add conditions to the targets added in this way. At least
        one set of targets must be added without conditions.

        :param id: -
        :param deregistration_delay: The amount of time for Elastic Load Balancing to wait before deregistering a target. The range is 0-3600 seconds. Default: Duration.minutes(5)
        :param health_check: Health check configuration. Default: No health check
        :param load_balancing_algorithm_type: The load balancing algorithm to select targets for routing requests. Default: round_robin.
        :param port: The port on which the listener listens for requests. Default: Determined from protocol if known
        :param protocol: The protocol to use. Default: Determined from port if known
        :param protocol_version: The protocol version to use. Default: ApplicationProtocolVersion.HTTP1
        :param slow_start: The time period during which the load balancer sends a newly registered target a linearly increasing share of the traffic to the target group. The range is 30-900 seconds (15 minutes). Default: 0
        :param stickiness_cookie_duration: The stickiness cookie expiration period. Setting this value enables load balancer stickiness. After this period, the cookie is considered stale. The minimum value is 1 second and the maximum value is 7 days (604800 seconds). Default: Stickiness disabled
        :param stickiness_cookie_name: The name of an application-based stickiness cookie. Names that start with the following prefixes are not allowed: AWSALB, AWSALBAPP, and AWSALBTG; they're reserved for use by the load balancer. Note: ``stickinessCookieName`` parameter depends on the presence of ``stickinessCookieDuration`` parameter. If ``stickinessCookieDuration`` is not set, ``stickinessCookieName`` will be omitted. Default: - If ``stickinessCookieDuration`` is set, a load-balancer generated cookie is used. Otherwise, no stickiness is defined.
        :param target_group_name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. Default: Automatically generated
        :param targets: The targets to add to this target group. Can be ``Instance``, ``IPAddress``, or any self-registering load balancing target. All target must be of the same type.
        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param priority: Priority of this target group. The rule with the lowest priority will be used for every request. If priority is not given, these target groups will be added as defaults, and must not have conditions. Priorities must be unique. Default: Target groups are used as defaults

        :return: The newly created target group
        '''
        props = AddApplicationTargetsProps(
            deregistration_delay=deregistration_delay,
            health_check=health_check,
            load_balancing_algorithm_type=load_balancing_algorithm_type,
            port=port,
            protocol=protocol,
            protocol_version=protocol_version,
            slow_start=slow_start,
            stickiness_cookie_duration=stickiness_cookie_duration,
            stickiness_cookie_name=stickiness_cookie_name,
            target_group_name=target_group_name,
            targets=targets,
            conditions=conditions,
            priority=priority,
        )

        return typing.cast("ApplicationTargetGroup", jsii.invoke(self, "addTargets", [id, props]))

    @jsii.member(jsii_name="registerConnectable")
    def register_connectable(
        self,
        connectable: _IConnectable_10015a05,
        port_range: _Port_85922693,
    ) -> None:
        '''Register that a connectable that has been added to this load balancer.

        Don't call this directly. It is called by ApplicationTargetGroup.

        :param connectable: -
        :param port_range: -
        '''
        return typing.cast(None, jsii.invoke(self, "registerConnectable", [connectable, port_range]))

    @jsii.member(jsii_name="validateListener")
    def _validate_listener(self) -> typing.List[builtins.str]:
        '''Validate this listener.'''
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateListener", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connections")
    def connections(self) -> _Connections_0f31fce8:
        '''Manage connections to this ApplicationListener.'''
        return typing.cast(_Connections_0f31fce8, jsii.get(self, "connections"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancer")
    def load_balancer(self) -> "IApplicationLoadBalancer":
        '''Load balancer this listener is associated with.'''
        return typing.cast("IApplicationLoadBalancer", jsii.get(self, "loadBalancer"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationListenerLookupOptions",
    jsii_struct_bases=[BaseListenerLookupOptions],
    name_mapping={
        "listener_port": "listenerPort",
        "load_balancer_arn": "loadBalancerArn",
        "load_balancer_tags": "loadBalancerTags",
        "listener_arn": "listenerArn",
        "listener_protocol": "listenerProtocol",
    },
)
class ApplicationListenerLookupOptions(BaseListenerLookupOptions):
    def __init__(
        self,
        *,
        listener_port: typing.Optional[jsii.Number] = None,
        load_balancer_arn: typing.Optional[builtins.str] = None,
        load_balancer_tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        listener_arn: typing.Optional[builtins.str] = None,
        listener_protocol: typing.Optional[ApplicationProtocol] = None,
    ) -> None:
        '''Options for ApplicationListener lookup.

        :param listener_port: Filter listeners by listener port. Default: - does not filter by listener port
        :param load_balancer_arn: Filter listeners by associated load balancer arn. Default: - does not filter by load balancer arn
        :param load_balancer_tags: Filter listeners by associated load balancer tags. Default: - does not filter by load balancer tags
        :param listener_arn: ARN of the listener to look up. Default: - does not filter by listener arn
        :param listener_protocol: Filter listeners by listener protocol. Default: - does not filter by listener protocol

        :exampleMetadata: infused

        Example::

            listener = elbv2.ApplicationListener.from_lookup(self, "ALBListener",
                load_balancer_arn="arn:aws:elasticloadbalancing:us-east-2:123456789012:loadbalancer/app/my-load-balancer/1234567890123456",
                listener_protocol=elbv2.ApplicationProtocol.HTTPS,
                listener_port=443
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if listener_port is not None:
            self._values["listener_port"] = listener_port
        if load_balancer_arn is not None:
            self._values["load_balancer_arn"] = load_balancer_arn
        if load_balancer_tags is not None:
            self._values["load_balancer_tags"] = load_balancer_tags
        if listener_arn is not None:
            self._values["listener_arn"] = listener_arn
        if listener_protocol is not None:
            self._values["listener_protocol"] = listener_protocol

    @builtins.property
    def listener_port(self) -> typing.Optional[jsii.Number]:
        '''Filter listeners by listener port.

        :default: - does not filter by listener port
        '''
        result = self._values.get("listener_port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def load_balancer_arn(self) -> typing.Optional[builtins.str]:
        '''Filter listeners by associated load balancer arn.

        :default: - does not filter by load balancer arn
        '''
        result = self._values.get("load_balancer_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def load_balancer_tags(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Filter listeners by associated load balancer tags.

        :default: - does not filter by load balancer tags
        '''
        result = self._values.get("load_balancer_tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def listener_arn(self) -> typing.Optional[builtins.str]:
        '''ARN of the listener to look up.

        :default: - does not filter by listener arn
        '''
        result = self._values.get("listener_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def listener_protocol(self) -> typing.Optional[ApplicationProtocol]:
        '''Filter listeners by listener protocol.

        :default: - does not filter by listener protocol
        '''
        result = self._values.get("listener_protocol")
        return typing.cast(typing.Optional[ApplicationProtocol], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApplicationListenerLookupOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationListenerProps",
    jsii_struct_bases=[BaseApplicationListenerProps],
    name_mapping={
        "certificates": "certificates",
        "default_action": "defaultAction",
        "default_target_groups": "defaultTargetGroups",
        "open": "open",
        "port": "port",
        "protocol": "protocol",
        "ssl_policy": "sslPolicy",
        "load_balancer": "loadBalancer",
    },
)
class ApplicationListenerProps(BaseApplicationListenerProps):
    def __init__(
        self,
        *,
        certificates: typing.Optional[typing.Sequence[IListenerCertificate]] = None,
        default_action: typing.Optional[ListenerAction] = None,
        default_target_groups: typing.Optional[typing.Sequence["IApplicationTargetGroup"]] = None,
        open: typing.Optional[builtins.bool] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        ssl_policy: typing.Optional[SslPolicy] = None,
        load_balancer: "IApplicationLoadBalancer",
    ) -> None:
        '''Properties for defining a standalone ApplicationListener.

        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default action of the load balancer, including Action chaining, fixed responses and redirect responses. See the ``ListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param open: Allow anyone to connect to the load balancer on the listener port. If this is specified, the load balancer will be opened up to anyone who can reach it. For internal load balancers this is anyone in the same VPC. For public load balancers, this is anyone on the internet. If you want to be more selective about who can access this load balancer, set this to ``false`` and use the listener's ``connections`` object to selectively grant access to the load balancer on the listener port. Default: true
        :param port: The port on which the listener listens for requests. Default: - Determined from protocol if known.
        :param protocol: The protocol to use. Default: - Determined from port if known.
        :param ssl_policy: The security policy that defines which ciphers and protocols are supported. Default: - The current predefined security policy.
        :param load_balancer: The load balancer to attach this listener to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # application_load_balancer: elbv2.ApplicationLoadBalancer
            # application_target_group: elbv2.ApplicationTargetGroup
            # listener_action: elbv2.ListenerAction
            # listener_certificate: elbv2.ListenerCertificate
            
            application_listener_props = elbv2.ApplicationListenerProps(
                load_balancer=application_load_balancer,
            
                # the properties below are optional
                certificates=[listener_certificate],
                default_action=listener_action,
                default_target_groups=[application_target_group],
                open=False,
                port=123,
                protocol=elbv2.ApplicationProtocol.HTTP,
                ssl_policy=elbv2.SslPolicy.RECOMMENDED
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "load_balancer": load_balancer,
        }
        if certificates is not None:
            self._values["certificates"] = certificates
        if default_action is not None:
            self._values["default_action"] = default_action
        if default_target_groups is not None:
            self._values["default_target_groups"] = default_target_groups
        if open is not None:
            self._values["open"] = open
        if port is not None:
            self._values["port"] = port
        if protocol is not None:
            self._values["protocol"] = protocol
        if ssl_policy is not None:
            self._values["ssl_policy"] = ssl_policy

    @builtins.property
    def certificates(self) -> typing.Optional[typing.List[IListenerCertificate]]:
        '''Certificate list of ACM cert ARNs.

        You must provide exactly one certificate if the listener protocol is HTTPS or TLS.

        :default: - No certificates.
        '''
        result = self._values.get("certificates")
        return typing.cast(typing.Optional[typing.List[IListenerCertificate]], result)

    @builtins.property
    def default_action(self) -> typing.Optional[ListenerAction]:
        '''Default action to take for requests to this listener.

        This allows full control of the default action of the load balancer,
        including Action chaining, fixed responses and redirect responses.

        See the ``ListenerAction`` class for all options.

        Cannot be specified together with ``defaultTargetGroups``.

        :default: - None.
        '''
        result = self._values.get("default_action")
        return typing.cast(typing.Optional[ListenerAction], result)

    @builtins.property
    def default_target_groups(
        self,
    ) -> typing.Optional[typing.List["IApplicationTargetGroup"]]:
        '''Default target groups to load balance to.

        All target groups will be load balanced to with equal weight and without
        stickiness. For a more complex configuration than that, use
        either ``defaultAction`` or ``addAction()``.

        Cannot be specified together with ``defaultAction``.

        :default: - None.
        '''
        result = self._values.get("default_target_groups")
        return typing.cast(typing.Optional[typing.List["IApplicationTargetGroup"]], result)

    @builtins.property
    def open(self) -> typing.Optional[builtins.bool]:
        '''Allow anyone to connect to the load balancer on the listener port.

        If this is specified, the load balancer will be opened up to anyone who can reach it.
        For internal load balancers this is anyone in the same VPC. For public load
        balancers, this is anyone on the internet.

        If you want to be more selective about who can access this load
        balancer, set this to ``false`` and use the listener's ``connections``
        object to selectively grant access to the load balancer on the listener port.

        :default: true
        '''
        result = self._values.get("open")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port on which the listener listens for requests.

        :default: - Determined from protocol if known.
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def protocol(self) -> typing.Optional[ApplicationProtocol]:
        '''The protocol to use.

        :default: - Determined from port if known.
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional[ApplicationProtocol], result)

    @builtins.property
    def ssl_policy(self) -> typing.Optional[SslPolicy]:
        '''The security policy that defines which ciphers and protocols are supported.

        :default: - The current predefined security policy.
        '''
        result = self._values.get("ssl_policy")
        return typing.cast(typing.Optional[SslPolicy], result)

    @builtins.property
    def load_balancer(self) -> "IApplicationLoadBalancer":
        '''The load balancer to attach this listener to.'''
        result = self._values.get("load_balancer")
        assert result is not None, "Required property 'load_balancer' is missing"
        return typing.cast("IApplicationLoadBalancer", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApplicationListenerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationListenerRuleProps",
    jsii_struct_bases=[BaseApplicationListenerRuleProps],
    name_mapping={
        "priority": "priority",
        "action": "action",
        "conditions": "conditions",
        "target_groups": "targetGroups",
        "listener": "listener",
    },
)
class ApplicationListenerRuleProps(BaseApplicationListenerRuleProps):
    def __init__(
        self,
        *,
        priority: jsii.Number,
        action: typing.Optional[ListenerAction] = None,
        conditions: typing.Optional[typing.Sequence[ListenerCondition]] = None,
        target_groups: typing.Optional[typing.Sequence["IApplicationTargetGroup"]] = None,
        listener: IApplicationListener,
    ) -> None:
        '''Properties for defining a listener rule.

        :param priority: Priority of the rule. The rule with the lowest priority will be used for every request. Priorities must be unique.
        :param action: Action to perform when requests are received. Only one of ``action``, ``fixedResponse``, ``redirectResponse`` or ``targetGroups`` can be specified. Default: - No action
        :param conditions: Rule applies if matches the conditions. Default: - No conditions.
        :param target_groups: Target groups to forward requests to. Only one of ``action``, ``fixedResponse``, ``redirectResponse`` or ``targetGroups`` can be specified. Implies a ``forward`` action. Default: - No target groups.
        :param listener: The listener to attach the rule to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_elasticloadbalancingv2 as elbv2
            
            # application_listener: elbv2.ApplicationListener
            # application_target_group: elbv2.ApplicationTargetGroup
            # listener_action: elbv2.ListenerAction
            # listener_condition: elbv2.ListenerCondition
            
            application_listener_rule_props = elbv2.ApplicationListenerRuleProps(
                listener=application_listener,
                priority=123,
            
                # the properties below are optional
                action=listener_action,
                conditions=[listener_condition],
                target_groups=[application_target_group]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "priority": priority,
            "listener": listener,
        }
        if action is not None:
            self._values["action"] = action
        if conditions is not None:
            self._values["conditions"] = conditions
        if target_groups is not None:
            self._values["target_groups"] = target_groups

    @builtins.property
    def priority(self) -> jsii.Number:
        '''Priority of the rule.

        The rule with the lowest priority will be used for every request.

        Priorities must be unique.
        '''
        result = self._values.get("priority")
        assert result is not None, "Required property 'priority' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def action(self) -> typing.Optional[ListenerAction]:
        '''Action to perform when requests are received.

        Only one of ``action``, ``fixedResponse``, ``redirectResponse`` or ``targetGroups`` can be specified.

        :default: - No action
        '''
        result = self._values.get("action")
        return typing.cast(typing.Optional[ListenerAction], result)

    @builtins.property
    def conditions(self) -> typing.Optional[typing.List[ListenerCondition]]:
        '''Rule applies if matches the conditions.

        :default: - No conditions.

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html
        '''
        result = self._values.get("conditions")
        return typing.cast(typing.Optional[typing.List[ListenerCondition]], result)

    @builtins.property
    def target_groups(self) -> typing.Optional[typing.List["IApplicationTargetGroup"]]:
        '''Target groups to forward requests to.

        Only one of ``action``, ``fixedResponse``, ``redirectResponse`` or ``targetGroups`` can be specified.

        Implies a ``forward`` action.

        :default: - No target groups.
        '''
        result = self._values.get("target_groups")
        return typing.cast(typing.Optional[typing.List["IApplicationTargetGroup"]], result)

    @builtins.property
    def listener(self) -> IApplicationListener:
        '''The listener to attach the rule to.'''
        result = self._values.get("listener")
        assert result is not None, "Required property 'listener' is missing"
        return typing.cast(IApplicationListener, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApplicationListenerRuleProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationLoadBalancerLookupOptions",
    jsii_struct_bases=[BaseLoadBalancerLookupOptions],
    name_mapping={
        "load_balancer_arn": "loadBalancerArn",
        "load_balancer_tags": "loadBalancerTags",
    },
)
class ApplicationLoadBalancerLookupOptions(BaseLoadBalancerLookupOptions):
    def __init__(
        self,
        *,
        load_balancer_arn: typing.Optional[builtins.str] = None,
        load_balancer_tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Options for looking up an ApplicationLoadBalancer.

        :param load_balancer_arn: Find by load balancer's ARN. Default: - does not search by load balancer arn
        :param load_balancer_tags: Match load balancer tags. Default: - does not match load balancers by tags

        :exampleMetadata: infused

        Example::

            load_balancer = elbv2.ApplicationLoadBalancer.from_lookup(self, "ALB",
                load_balancer_arn="arn:aws:elasticloadbalancing:us-east-2:123456789012:loadbalancer/app/my-load-balancer/1234567890123456"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if load_balancer_arn is not None:
            self._values["load_balancer_arn"] = load_balancer_arn
        if load_balancer_tags is not None:
            self._values["load_balancer_tags"] = load_balancer_tags

    @builtins.property
    def load_balancer_arn(self) -> typing.Optional[builtins.str]:
        '''Find by load balancer's ARN.

        :default: - does not search by load balancer arn
        '''
        result = self._values.get("load_balancer_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def load_balancer_tags(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Match load balancer tags.

        :default: - does not match load balancers by tags
        '''
        result = self._values.get("load_balancer_tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApplicationLoadBalancerLookupOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationLoadBalancerProps",
    jsii_struct_bases=[BaseLoadBalancerProps],
    name_mapping={
        "vpc": "vpc",
        "deletion_protection": "deletionProtection",
        "internet_facing": "internetFacing",
        "load_balancer_name": "loadBalancerName",
        "vpc_subnets": "vpcSubnets",
        "http2_enabled": "http2Enabled",
        "idle_timeout": "idleTimeout",
        "ip_address_type": "ipAddressType",
        "security_group": "securityGroup",
    },
)
class ApplicationLoadBalancerProps(BaseLoadBalancerProps):
    def __init__(
        self,
        *,
        vpc: _IVpc_f30d5663,
        deletion_protection: typing.Optional[builtins.bool] = None,
        internet_facing: typing.Optional[builtins.bool] = None,
        load_balancer_name: typing.Optional[builtins.str] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
        http2_enabled: typing.Optional[builtins.bool] = None,
        idle_timeout: typing.Optional[_Duration_4839e8c3] = None,
        ip_address_type: typing.Optional[IpAddressType] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
    ) -> None:
        '''Properties for defining an Application Load Balancer.

        :param vpc: The VPC network to place the load balancer in.
        :param deletion_protection: Indicates whether deletion protection is enabled. Default: false
        :param internet_facing: Whether the load balancer has an internet-routable address. Default: false
        :param load_balancer_name: Name of the load balancer. Default: - Automatically generated name.
        :param vpc_subnets: Which subnets place the load balancer in. Default: - the Vpc default strategy.
        :param http2_enabled: Indicates whether HTTP/2 is enabled. Default: true
        :param idle_timeout: The load balancer idle timeout, in seconds. Default: 60
        :param ip_address_type: The type of IP addresses to use. Only applies to application load balancers. Default: IpAddressType.Ipv4
        :param security_group: Security group to associate with this load balancer. Default: A security group is created

        :exampleMetadata: infused

        Example::

            # cluster: ecs.Cluster
            # task_definition: ecs.TaskDefinition
            # vpc: ec2.Vpc
            
            service = ecs.FargateService(self, "Service", cluster=cluster, task_definition=task_definition)
            
            lb = elbv2.ApplicationLoadBalancer(self, "LB", vpc=vpc, internet_facing=True)
            listener = lb.add_listener("Listener", port=80)
            service.register_load_balancer_targets(
                container_name="web",
                container_port=80,
                new_target_group_id="ECS",
                listener=ecs.ListenerConfig.application_listener(listener,
                    protocol=elbv2.ApplicationProtocol.HTTPS
                )
            )
        '''
        if isinstance(vpc_subnets, dict):
            vpc_subnets = _SubnetSelection_e57d76df(**vpc_subnets)
        self._values: typing.Dict[str, typing.Any] = {
            "vpc": vpc,
        }
        if deletion_protection is not None:
            self._values["deletion_protection"] = deletion_protection
        if internet_facing is not None:
            self._values["internet_facing"] = internet_facing
        if load_balancer_name is not None:
            self._values["load_balancer_name"] = load_balancer_name
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets
        if http2_enabled is not None:
            self._values["http2_enabled"] = http2_enabled
        if idle_timeout is not None:
            self._values["idle_timeout"] = idle_timeout
        if ip_address_type is not None:
            self._values["ip_address_type"] = ip_address_type
        if security_group is not None:
            self._values["security_group"] = security_group

    @builtins.property
    def vpc(self) -> _IVpc_f30d5663:
        '''The VPC network to place the load balancer in.'''
        result = self._values.get("vpc")
        assert result is not None, "Required property 'vpc' is missing"
        return typing.cast(_IVpc_f30d5663, result)

    @builtins.property
    def deletion_protection(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether deletion protection is enabled.

        :default: false
        '''
        result = self._values.get("deletion_protection")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def internet_facing(self) -> typing.Optional[builtins.bool]:
        '''Whether the load balancer has an internet-routable address.

        :default: false
        '''
        result = self._values.get("internet_facing")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def load_balancer_name(self) -> typing.Optional[builtins.str]:
        '''Name of the load balancer.

        :default: - Automatically generated name.
        '''
        result = self._values.get("load_balancer_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''Which subnets place the load balancer in.

        :default: - the Vpc default strategy.
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    @builtins.property
    def http2_enabled(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether HTTP/2 is enabled.

        :default: true
        '''
        result = self._values.get("http2_enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def idle_timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The load balancer idle timeout, in seconds.

        :default: 60
        '''
        result = self._values.get("idle_timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def ip_address_type(self) -> typing.Optional[IpAddressType]:
        '''The type of IP addresses to use.

        Only applies to application load balancers.

        :default: IpAddressType.Ipv4
        '''
        result = self._values.get("ip_address_type")
        return typing.cast(typing.Optional[IpAddressType], result)

    @builtins.property
    def security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''Security group to associate with this load balancer.

        :default: A security group is created
        '''
        result = self._values.get("security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApplicationLoadBalancerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationTargetGroupProps",
    jsii_struct_bases=[BaseTargetGroupProps],
    name_mapping={
        "deregistration_delay": "deregistrationDelay",
        "health_check": "healthCheck",
        "target_group_name": "targetGroupName",
        "target_type": "targetType",
        "vpc": "vpc",
        "load_balancing_algorithm_type": "loadBalancingAlgorithmType",
        "port": "port",
        "protocol": "protocol",
        "protocol_version": "protocolVersion",
        "slow_start": "slowStart",
        "stickiness_cookie_duration": "stickinessCookieDuration",
        "stickiness_cookie_name": "stickinessCookieName",
        "targets": "targets",
    },
)
class ApplicationTargetGroupProps(BaseTargetGroupProps):
    def __init__(
        self,
        *,
        deregistration_delay: typing.Optional[_Duration_4839e8c3] = None,
        health_check: typing.Optional[HealthCheck] = None,
        target_group_name: typing.Optional[builtins.str] = None,
        target_type: typing.Optional[TargetType] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        load_balancing_algorithm_type: typing.Optional[TargetGroupLoadBalancingAlgorithmType] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        protocol_version: typing.Optional[ApplicationProtocolVersion] = None,
        slow_start: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_duration: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_name: typing.Optional[builtins.str] = None,
        targets: typing.Optional[typing.Sequence[IApplicationLoadBalancerTarget]] = None,
    ) -> None:
        '''Properties for defining an Application Target Group.

        :param deregistration_delay: The amount of time for Elastic Load Balancing to wait before deregistering a target. The range is 0-3600 seconds. Default: 300
        :param health_check: Health check configuration. Default: - None.
        :param target_group_name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. Default: - Automatically generated.
        :param target_type: The type of targets registered to this TargetGroup, either IP or Instance. All targets registered into the group must be of this type. If you register targets to the TargetGroup in the CDK app, the TargetType is determined automatically. Default: - Determined automatically.
        :param vpc: The virtual private cloud (VPC). only if ``TargetType`` is ``Ip`` or ``InstanceId`` Default: - undefined
        :param load_balancing_algorithm_type: The load balancing algorithm to select targets for routing requests. Default: TargetGroupLoadBalancingAlgorithmType.ROUND_ROBIN
        :param port: The port on which the listener listens for requests. Default: - Determined from protocol if known, optional for Lambda targets.
        :param protocol: The protocol to use. Default: - Determined from port if known, optional for Lambda targets.
        :param protocol_version: The protocol version to use. Default: ApplicationProtocolVersion.HTTP1
        :param slow_start: The time period during which the load balancer sends a newly registered target a linearly increasing share of the traffic to the target group. The range is 30-900 seconds (15 minutes). Default: 0
        :param stickiness_cookie_duration: The stickiness cookie expiration period. Setting this value enables load balancer stickiness. After this period, the cookie is considered stale. The minimum value is 1 second and the maximum value is 7 days (604800 seconds). Default: Duration.days(1)
        :param stickiness_cookie_name: The name of an application-based stickiness cookie. Names that start with the following prefixes are not allowed: AWSALB, AWSALBAPP, and AWSALBTG; they're reserved for use by the load balancer. Note: ``stickinessCookieName`` parameter depends on the presence of ``stickinessCookieDuration`` parameter. If ``stickinessCookieDuration`` is not set, ``stickinessCookieName`` will be omitted. Default: - If ``stickinessCookieDuration`` is set, a load-balancer generated cookie is used. Otherwise, no stickiness is defined.
        :param targets: The targets to add to this target group. Can be ``Instance``, ``IPAddress``, or any self-registering load balancing target. If you use either ``Instance`` or ``IPAddress`` as targets, all target must be of the same type. Default: - No targets.

        :exampleMetadata: infused

        Example::

            # vpc: ec2.Vpc
            
            
            # Target group with duration-based stickiness with load-balancer generated cookie
            tg1 = elbv2.ApplicationTargetGroup(self, "TG1",
                target_type=elbv2.TargetType.INSTANCE,
                port=80,
                stickiness_cookie_duration=Duration.minutes(5),
                vpc=vpc
            )
            
            # Target group with application-based stickiness
            tg2 = elbv2.ApplicationTargetGroup(self, "TG2",
                target_type=elbv2.TargetType.INSTANCE,
                port=80,
                stickiness_cookie_duration=Duration.minutes(5),
                stickiness_cookie_name="MyDeliciousCookie",
                vpc=vpc
            )
        '''
        if isinstance(health_check, dict):
            health_check = HealthCheck(**health_check)
        self._values: typing.Dict[str, typing.Any] = {}
        if deregistration_delay is not None:
            self._values["deregistration_delay"] = deregistration_delay
        if health_check is not None:
            self._values["health_check"] = health_check
        if target_group_name is not None:
            self._values["target_group_name"] = target_group_name
        if target_type is not None:
            self._values["target_type"] = target_type
        if vpc is not None:
            self._values["vpc"] = vpc
        if load_balancing_algorithm_type is not None:
            self._values["load_balancing_algorithm_type"] = load_balancing_algorithm_type
        if port is not None:
            self._values["port"] = port
        if protocol is not None:
            self._values["protocol"] = protocol
        if protocol_version is not None:
            self._values["protocol_version"] = protocol_version
        if slow_start is not None:
            self._values["slow_start"] = slow_start
        if stickiness_cookie_duration is not None:
            self._values["stickiness_cookie_duration"] = stickiness_cookie_duration
        if stickiness_cookie_name is not None:
            self._values["stickiness_cookie_name"] = stickiness_cookie_name
        if targets is not None:
            self._values["targets"] = targets

    @builtins.property
    def deregistration_delay(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The amount of time for Elastic Load Balancing to wait before deregistering a target.

        The range is 0-3600 seconds.

        :default: 300
        '''
        result = self._values.get("deregistration_delay")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def health_check(self) -> typing.Optional[HealthCheck]:
        '''Health check configuration.

        :default: - None.
        '''
        result = self._values.get("health_check")
        return typing.cast(typing.Optional[HealthCheck], result)

    @builtins.property
    def target_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the target group.

        This name must be unique per region per account, can have a maximum of
        32 characters, must contain only alphanumeric characters or hyphens, and
        must not begin or end with a hyphen.

        :default: - Automatically generated.
        '''
        result = self._values.get("target_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def target_type(self) -> typing.Optional[TargetType]:
        '''The type of targets registered to this TargetGroup, either IP or Instance.

        All targets registered into the group must be of this type. If you
        register targets to the TargetGroup in the CDK app, the TargetType is
        determined automatically.

        :default: - Determined automatically.
        '''
        result = self._values.get("target_type")
        return typing.cast(typing.Optional[TargetType], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The virtual private cloud (VPC).

        only if ``TargetType`` is ``Ip`` or ``InstanceId``

        :default: - undefined
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    @builtins.property
    def load_balancing_algorithm_type(
        self,
    ) -> typing.Optional[TargetGroupLoadBalancingAlgorithmType]:
        '''The load balancing algorithm to select targets for routing requests.

        :default: TargetGroupLoadBalancingAlgorithmType.ROUND_ROBIN
        '''
        result = self._values.get("load_balancing_algorithm_type")
        return typing.cast(typing.Optional[TargetGroupLoadBalancingAlgorithmType], result)

    @builtins.property
    def port(self) -> typing.Optional[jsii.Number]:
        '''The port on which the listener listens for requests.

        :default: - Determined from protocol if known, optional for Lambda targets.
        '''
        result = self._values.get("port")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def protocol(self) -> typing.Optional[ApplicationProtocol]:
        '''The protocol to use.

        :default: - Determined from port if known, optional for Lambda targets.
        '''
        result = self._values.get("protocol")
        return typing.cast(typing.Optional[ApplicationProtocol], result)

    @builtins.property
    def protocol_version(self) -> typing.Optional[ApplicationProtocolVersion]:
        '''The protocol version to use.

        :default: ApplicationProtocolVersion.HTTP1
        '''
        result = self._values.get("protocol_version")
        return typing.cast(typing.Optional[ApplicationProtocolVersion], result)

    @builtins.property
    def slow_start(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The time period during which the load balancer sends a newly registered target a linearly increasing share of the traffic to the target group.

        The range is 30-900 seconds (15 minutes).

        :default: 0
        '''
        result = self._values.get("slow_start")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def stickiness_cookie_duration(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The stickiness cookie expiration period.

        Setting this value enables load balancer stickiness.

        After this period, the cookie is considered stale. The minimum value is
        1 second and the maximum value is 7 days (604800 seconds).

        :default: Duration.days(1)
        '''
        result = self._values.get("stickiness_cookie_duration")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def stickiness_cookie_name(self) -> typing.Optional[builtins.str]:
        '''The name of an application-based stickiness cookie.

        Names that start with the following prefixes are not allowed: AWSALB, AWSALBAPP,
        and AWSALBTG; they're reserved for use by the load balancer.

        Note: ``stickinessCookieName`` parameter depends on the presence of ``stickinessCookieDuration`` parameter.
        If ``stickinessCookieDuration`` is not set, ``stickinessCookieName`` will be omitted.

        :default: - If ``stickinessCookieDuration`` is set, a load-balancer generated cookie is used. Otherwise, no stickiness is defined.

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/sticky-sessions.html
        '''
        result = self._values.get("stickiness_cookie_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def targets(self) -> typing.Optional[typing.List[IApplicationLoadBalancerTarget]]:
        '''The targets to add to this target group.

        Can be ``Instance``, ``IPAddress``, or any self-registering load balancing
        target. If you use either ``Instance`` or ``IPAddress`` as targets, all
        target must be of the same type.

        :default: - No targets.
        '''
        result = self._values.get("targets")
        return typing.cast(typing.Optional[typing.List[IApplicationLoadBalancerTarget]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApplicationTargetGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.IApplicationLoadBalancer"
)
class IApplicationLoadBalancer(
    ILoadBalancerV2,
    _IConnectable_10015a05,
    typing_extensions.Protocol,
):
    '''An application load balancer.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="listeners")
    def listeners(self) -> typing.List[ApplicationListener]:
        '''A list of listeners that have been added to the load balancer.

        This list is only valid for owned constructs.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerArn")
    def load_balancer_arn(self) -> builtins.str:
        '''The ARN of this load balancer.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ipAddressType")
    def ip_address_type(self) -> typing.Optional[IpAddressType]:
        '''The IP Address Type for this load balancer.

        :default: IpAddressType.IPV4
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpc")
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC this load balancer has been created in (if available).

        If this interface is the result of an import call to fromApplicationLoadBalancerAttributes,
        the vpc attribute will be undefined unless specified in the optional properties of that method.
        '''
        ...

    @jsii.member(jsii_name="addListener")
    def add_listener(
        self,
        id: builtins.str,
        *,
        certificates: typing.Optional[typing.Sequence[IListenerCertificate]] = None,
        default_action: typing.Optional[ListenerAction] = None,
        default_target_groups: typing.Optional[typing.Sequence["IApplicationTargetGroup"]] = None,
        open: typing.Optional[builtins.bool] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        ssl_policy: typing.Optional[SslPolicy] = None,
    ) -> ApplicationListener:
        '''Add a new listener to this load balancer.

        :param id: -
        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default action of the load balancer, including Action chaining, fixed responses and redirect responses. See the ``ListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param open: Allow anyone to connect to the load balancer on the listener port. If this is specified, the load balancer will be opened up to anyone who can reach it. For internal load balancers this is anyone in the same VPC. For public load balancers, this is anyone on the internet. If you want to be more selective about who can access this load balancer, set this to ``false`` and use the listener's ``connections`` object to selectively grant access to the load balancer on the listener port. Default: true
        :param port: The port on which the listener listens for requests. Default: - Determined from protocol if known.
        :param protocol: The protocol to use. Default: - Determined from port if known.
        :param ssl_policy: The security policy that defines which ciphers and protocols are supported. Default: - The current predefined security policy.
        '''
        ...


class _IApplicationLoadBalancerProxy(
    jsii.proxy_for(ILoadBalancerV2), # type: ignore[misc]
    jsii.proxy_for(_IConnectable_10015a05), # type: ignore[misc]
):
    '''An application load balancer.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.IApplicationLoadBalancer"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="listeners")
    def listeners(self) -> typing.List[ApplicationListener]:
        '''A list of listeners that have been added to the load balancer.

        This list is only valid for owned constructs.
        '''
        return typing.cast(typing.List[ApplicationListener], jsii.get(self, "listeners"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerArn")
    def load_balancer_arn(self) -> builtins.str:
        '''The ARN of this load balancer.'''
        return typing.cast(builtins.str, jsii.get(self, "loadBalancerArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ipAddressType")
    def ip_address_type(self) -> typing.Optional[IpAddressType]:
        '''The IP Address Type for this load balancer.

        :default: IpAddressType.IPV4
        '''
        return typing.cast(typing.Optional[IpAddressType], jsii.get(self, "ipAddressType"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpc")
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC this load balancer has been created in (if available).

        If this interface is the result of an import call to fromApplicationLoadBalancerAttributes,
        the vpc attribute will be undefined unless specified in the optional properties of that method.
        '''
        return typing.cast(typing.Optional[_IVpc_f30d5663], jsii.get(self, "vpc"))

    @jsii.member(jsii_name="addListener")
    def add_listener(
        self,
        id: builtins.str,
        *,
        certificates: typing.Optional[typing.Sequence[IListenerCertificate]] = None,
        default_action: typing.Optional[ListenerAction] = None,
        default_target_groups: typing.Optional[typing.Sequence["IApplicationTargetGroup"]] = None,
        open: typing.Optional[builtins.bool] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        ssl_policy: typing.Optional[SslPolicy] = None,
    ) -> ApplicationListener:
        '''Add a new listener to this load balancer.

        :param id: -
        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default action of the load balancer, including Action chaining, fixed responses and redirect responses. See the ``ListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param open: Allow anyone to connect to the load balancer on the listener port. If this is specified, the load balancer will be opened up to anyone who can reach it. For internal load balancers this is anyone in the same VPC. For public load balancers, this is anyone on the internet. If you want to be more selective about who can access this load balancer, set this to ``false`` and use the listener's ``connections`` object to selectively grant access to the load balancer on the listener port. Default: true
        :param port: The port on which the listener listens for requests. Default: - Determined from protocol if known.
        :param protocol: The protocol to use. Default: - Determined from port if known.
        :param ssl_policy: The security policy that defines which ciphers and protocols are supported. Default: - The current predefined security policy.
        '''
        props = BaseApplicationListenerProps(
            certificates=certificates,
            default_action=default_action,
            default_target_groups=default_target_groups,
            open=open,
            port=port,
            protocol=protocol,
            ssl_policy=ssl_policy,
        )

        return typing.cast(ApplicationListener, jsii.invoke(self, "addListener", [id, props]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IApplicationLoadBalancer).__jsii_proxy_class__ = lambda : _IApplicationLoadBalancerProxy


@jsii.interface(
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.IApplicationTargetGroup"
)
class IApplicationTargetGroup(ITargetGroup, typing_extensions.Protocol):
    '''A Target Group for Application Load Balancers.'''

    @jsii.member(jsii_name="addTarget")
    def add_target(self, *targets: IApplicationLoadBalancerTarget) -> None:
        '''Add a load balancing target to this target group.

        :param targets: -
        '''
        ...

    @jsii.member(jsii_name="registerConnectable")
    def register_connectable(
        self,
        connectable: _IConnectable_10015a05,
        port_range: typing.Optional[_Port_85922693] = None,
    ) -> None:
        '''Register a connectable as a member of this target group.

        Don't call this directly. It will be called by load balancing targets.

        :param connectable: -
        :param port_range: -
        '''
        ...

    @jsii.member(jsii_name="registerListener")
    def register_listener(
        self,
        listener: IApplicationListener,
        associating_construct: typing.Optional[constructs.IConstruct] = None,
    ) -> None:
        '''Register a listener that is load balancing to this target group.

        Don't call this directly. It will be called by listeners.

        :param listener: -
        :param associating_construct: -
        '''
        ...


class _IApplicationTargetGroupProxy(
    jsii.proxy_for(ITargetGroup) # type: ignore[misc]
):
    '''A Target Group for Application Load Balancers.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.IApplicationTargetGroup"

    @jsii.member(jsii_name="addTarget")
    def add_target(self, *targets: IApplicationLoadBalancerTarget) -> None:
        '''Add a load balancing target to this target group.

        :param targets: -
        '''
        return typing.cast(None, jsii.invoke(self, "addTarget", [*targets]))

    @jsii.member(jsii_name="registerConnectable")
    def register_connectable(
        self,
        connectable: _IConnectable_10015a05,
        port_range: typing.Optional[_Port_85922693] = None,
    ) -> None:
        '''Register a connectable as a member of this target group.

        Don't call this directly. It will be called by load balancing targets.

        :param connectable: -
        :param port_range: -
        '''
        return typing.cast(None, jsii.invoke(self, "registerConnectable", [connectable, port_range]))

    @jsii.member(jsii_name="registerListener")
    def register_listener(
        self,
        listener: IApplicationListener,
        associating_construct: typing.Optional[constructs.IConstruct] = None,
    ) -> None:
        '''Register a listener that is load balancing to this target group.

        Don't call this directly. It will be called by listeners.

        :param listener: -
        :param associating_construct: -
        '''
        return typing.cast(None, jsii.invoke(self, "registerListener", [listener, associating_construct]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IApplicationTargetGroup).__jsii_proxy_class__ = lambda : _IApplicationTargetGroupProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.INetworkTargetGroup")
class INetworkTargetGroup(ITargetGroup, typing_extensions.Protocol):
    '''A network target group.'''

    @jsii.member(jsii_name="addTarget")
    def add_target(self, *targets: INetworkLoadBalancerTarget) -> None:
        '''Add a load balancing target to this target group.

        :param targets: -
        '''
        ...

    @jsii.member(jsii_name="registerListener")
    def register_listener(self, listener: INetworkListener) -> None:
        '''Register a listener that is load balancing to this target group.

        Don't call this directly. It will be called by listeners.

        :param listener: -
        '''
        ...


class _INetworkTargetGroupProxy(
    jsii.proxy_for(ITargetGroup) # type: ignore[misc]
):
    '''A network target group.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_elasticloadbalancingv2.INetworkTargetGroup"

    @jsii.member(jsii_name="addTarget")
    def add_target(self, *targets: INetworkLoadBalancerTarget) -> None:
        '''Add a load balancing target to this target group.

        :param targets: -
        '''
        return typing.cast(None, jsii.invoke(self, "addTarget", [*targets]))

    @jsii.member(jsii_name="registerListener")
    def register_listener(self, listener: INetworkListener) -> None:
        '''Register a listener that is load balancing to this target group.

        Don't call this directly. It will be called by listeners.

        :param listener: -
        '''
        return typing.cast(None, jsii.invoke(self, "registerListener", [listener]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, INetworkTargetGroup).__jsii_proxy_class__ = lambda : _INetworkTargetGroupProxy


@jsii.implements(INetworkTargetGroup)
class NetworkTargetGroup(
    TargetGroupBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.NetworkTargetGroup",
):
    '''Define a Network Target Group.

    :exampleMetadata: infused

    Example::

        # listener: elbv2.NetworkListener
        # asg1: autoscaling.AutoScalingGroup
        # asg2: autoscaling.AutoScalingGroup
        
        
        group = listener.add_targets("AppFleet",
            port=443,
            targets=[asg1]
        )
        
        group.add_target(asg2)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        port: jsii.Number,
        preserve_client_ip: typing.Optional[builtins.bool] = None,
        protocol: typing.Optional[Protocol] = None,
        proxy_protocol_v2: typing.Optional[builtins.bool] = None,
        targets: typing.Optional[typing.Sequence[INetworkLoadBalancerTarget]] = None,
        deregistration_delay: typing.Optional[_Duration_4839e8c3] = None,
        health_check: typing.Optional[HealthCheck] = None,
        target_group_name: typing.Optional[builtins.str] = None,
        target_type: typing.Optional[TargetType] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param port: The port on which the listener listens for requests.
        :param preserve_client_ip: Indicates whether client IP preservation is enabled. Default: false if the target group type is IP address and the target group protocol is TCP or TLS. Otherwise, true.
        :param protocol: Protocol for target group, expects TCP, TLS, UDP, or TCP_UDP. Default: - TCP
        :param proxy_protocol_v2: Indicates whether Proxy Protocol version 2 is enabled. Default: false
        :param targets: The targets to add to this target group. Can be ``Instance``, ``IPAddress``, or any self-registering load balancing target. If you use either ``Instance`` or ``IPAddress`` as targets, all target must be of the same type. Default: - No targets.
        :param deregistration_delay: The amount of time for Elastic Load Balancing to wait before deregistering a target. The range is 0-3600 seconds. Default: 300
        :param health_check: Health check configuration. Default: - None.
        :param target_group_name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. Default: - Automatically generated.
        :param target_type: The type of targets registered to this TargetGroup, either IP or Instance. All targets registered into the group must be of this type. If you register targets to the TargetGroup in the CDK app, the TargetType is determined automatically. Default: - Determined automatically.
        :param vpc: The virtual private cloud (VPC). only if ``TargetType`` is ``Ip`` or ``InstanceId`` Default: - undefined
        '''
        props = NetworkTargetGroupProps(
            port=port,
            preserve_client_ip=preserve_client_ip,
            protocol=protocol,
            proxy_protocol_v2=proxy_protocol_v2,
            targets=targets,
            deregistration_delay=deregistration_delay,
            health_check=health_check,
            target_group_name=target_group_name,
            target_type=target_type,
            vpc=vpc,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromTargetGroupAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_target_group_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        target_group_arn: builtins.str,
        load_balancer_arns: typing.Optional[builtins.str] = None,
    ) -> INetworkTargetGroup:
        '''Import an existing target group.

        :param scope: -
        :param id: -
        :param target_group_arn: ARN of the target group.
        :param load_balancer_arns: A Token representing the list of ARNs for the load balancer routing to this target group.
        '''
        attrs = TargetGroupAttributes(
            target_group_arn=target_group_arn, load_balancer_arns=load_balancer_arns
        )

        return typing.cast(INetworkTargetGroup, jsii.sinvoke(cls, "fromTargetGroupAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="addTarget")
    def add_target(self, *targets: INetworkLoadBalancerTarget) -> None:
        '''Add a load balancing target to this target group.

        :param targets: -
        '''
        return typing.cast(None, jsii.invoke(self, "addTarget", [*targets]))

    @jsii.member(jsii_name="metricHealthyHostCount")
    def metric_healthy_host_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of targets that are considered healthy.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Average over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricHealthyHostCount", [props]))

    @jsii.member(jsii_name="metricUnHealthyHostCount")
    def metric_un_healthy_host_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of targets that are considered unhealthy.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Average over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricUnHealthyHostCount", [props]))

    @jsii.member(jsii_name="registerListener")
    def register_listener(self, listener: INetworkListener) -> None:
        '''Register a listener that is load balancing to this target group.

        Don't call this directly. It will be called by listeners.

        :param listener: -
        '''
        return typing.cast(None, jsii.invoke(self, "registerListener", [listener]))

    @jsii.member(jsii_name="validateTargetGroup")
    def _validate_target_group(self) -> typing.List[builtins.str]:
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateTargetGroup", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="firstLoadBalancerFullName")
    def first_load_balancer_full_name(self) -> builtins.str:
        '''Full name of first load balancer.'''
        return typing.cast(builtins.str, jsii.get(self, "firstLoadBalancerFullName"))


@jsii.implements(IApplicationLoadBalancer)
class ApplicationLoadBalancer(
    BaseLoadBalancer,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationLoadBalancer",
):
    '''Define an Application Load Balancer.

    :exampleMetadata: infused
    :resource: AWS::ElasticLoadBalancingV2::LoadBalancer

    Example::

        from aws_cdk.aws_apigatewayv2_integrations_alpha import HttpAlbIntegration
        
        
        vpc = ec2.Vpc(self, "VPC")
        lb = elbv2.ApplicationLoadBalancer(self, "lb", vpc=vpc)
        listener = lb.add_listener("listener", port=80)
        listener.add_targets("target",
            port=80
        )
        
        http_endpoint = apigwv2.HttpApi(self, "HttpProxyPrivateApi",
            default_integration=HttpAlbIntegration("DefaultIntegration", listener)
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        http2_enabled: typing.Optional[builtins.bool] = None,
        idle_timeout: typing.Optional[_Duration_4839e8c3] = None,
        ip_address_type: typing.Optional[IpAddressType] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        vpc: _IVpc_f30d5663,
        deletion_protection: typing.Optional[builtins.bool] = None,
        internet_facing: typing.Optional[builtins.bool] = None,
        load_balancer_name: typing.Optional[builtins.str] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param http2_enabled: Indicates whether HTTP/2 is enabled. Default: true
        :param idle_timeout: The load balancer idle timeout, in seconds. Default: 60
        :param ip_address_type: The type of IP addresses to use. Only applies to application load balancers. Default: IpAddressType.Ipv4
        :param security_group: Security group to associate with this load balancer. Default: A security group is created
        :param vpc: The VPC network to place the load balancer in.
        :param deletion_protection: Indicates whether deletion protection is enabled. Default: false
        :param internet_facing: Whether the load balancer has an internet-routable address. Default: false
        :param load_balancer_name: Name of the load balancer. Default: - Automatically generated name.
        :param vpc_subnets: Which subnets place the load balancer in. Default: - the Vpc default strategy.
        '''
        props = ApplicationLoadBalancerProps(
            http2_enabled=http2_enabled,
            idle_timeout=idle_timeout,
            ip_address_type=ip_address_type,
            security_group=security_group,
            vpc=vpc,
            deletion_protection=deletion_protection,
            internet_facing=internet_facing,
            load_balancer_name=load_balancer_name,
            vpc_subnets=vpc_subnets,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromApplicationLoadBalancerAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_application_load_balancer_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        load_balancer_arn: builtins.str,
        security_group_id: builtins.str,
        load_balancer_canonical_hosted_zone_id: typing.Optional[builtins.str] = None,
        load_balancer_dns_name: typing.Optional[builtins.str] = None,
        security_group_allows_all_outbound: typing.Optional[builtins.bool] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> IApplicationLoadBalancer:
        '''Import an existing Application Load Balancer.

        :param scope: -
        :param id: -
        :param load_balancer_arn: ARN of the load balancer.
        :param security_group_id: ID of the load balancer's security group.
        :param load_balancer_canonical_hosted_zone_id: The canonical hosted zone ID of this load balancer. Default: - When not provided, LB cannot be used as Route53 Alias target.
        :param load_balancer_dns_name: The DNS name of this load balancer. Default: - When not provided, LB cannot be used as Route53 Alias target.
        :param security_group_allows_all_outbound: Whether the security group allows all outbound traffic or not. Unless set to ``false``, no egress rules will be added to the security group. Default: true
        :param vpc: The VPC this load balancer has been created in, if available. Default: - If the Load Balancer was imported and a VPC was not specified, the VPC is not available.
        '''
        attrs = ApplicationLoadBalancerAttributes(
            load_balancer_arn=load_balancer_arn,
            security_group_id=security_group_id,
            load_balancer_canonical_hosted_zone_id=load_balancer_canonical_hosted_zone_id,
            load_balancer_dns_name=load_balancer_dns_name,
            security_group_allows_all_outbound=security_group_allows_all_outbound,
            vpc=vpc,
        )

        return typing.cast(IApplicationLoadBalancer, jsii.sinvoke(cls, "fromApplicationLoadBalancerAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="fromLookup") # type: ignore[misc]
    @builtins.classmethod
    def from_lookup(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        load_balancer_arn: typing.Optional[builtins.str] = None,
        load_balancer_tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> IApplicationLoadBalancer:
        '''Look up an application load balancer.

        :param scope: -
        :param id: -
        :param load_balancer_arn: Find by load balancer's ARN. Default: - does not search by load balancer arn
        :param load_balancer_tags: Match load balancer tags. Default: - does not match load balancers by tags
        '''
        options = ApplicationLoadBalancerLookupOptions(
            load_balancer_arn=load_balancer_arn, load_balancer_tags=load_balancer_tags
        )

        return typing.cast(IApplicationLoadBalancer, jsii.sinvoke(cls, "fromLookup", [scope, id, options]))

    @jsii.member(jsii_name="addListener")
    def add_listener(
        self,
        id: builtins.str,
        *,
        certificates: typing.Optional[typing.Sequence[IListenerCertificate]] = None,
        default_action: typing.Optional[ListenerAction] = None,
        default_target_groups: typing.Optional[typing.Sequence[IApplicationTargetGroup]] = None,
        open: typing.Optional[builtins.bool] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        ssl_policy: typing.Optional[SslPolicy] = None,
    ) -> ApplicationListener:
        '''Add a new listener to this load balancer.

        :param id: -
        :param certificates: Certificate list of ACM cert ARNs. You must provide exactly one certificate if the listener protocol is HTTPS or TLS. Default: - No certificates.
        :param default_action: Default action to take for requests to this listener. This allows full control of the default action of the load balancer, including Action chaining, fixed responses and redirect responses. See the ``ListenerAction`` class for all options. Cannot be specified together with ``defaultTargetGroups``. Default: - None.
        :param default_target_groups: Default target groups to load balance to. All target groups will be load balanced to with equal weight and without stickiness. For a more complex configuration than that, use either ``defaultAction`` or ``addAction()``. Cannot be specified together with ``defaultAction``. Default: - None.
        :param open: Allow anyone to connect to the load balancer on the listener port. If this is specified, the load balancer will be opened up to anyone who can reach it. For internal load balancers this is anyone in the same VPC. For public load balancers, this is anyone on the internet. If you want to be more selective about who can access this load balancer, set this to ``false`` and use the listener's ``connections`` object to selectively grant access to the load balancer on the listener port. Default: true
        :param port: The port on which the listener listens for requests. Default: - Determined from protocol if known.
        :param protocol: The protocol to use. Default: - Determined from port if known.
        :param ssl_policy: The security policy that defines which ciphers and protocols are supported. Default: - The current predefined security policy.
        '''
        props = BaseApplicationListenerProps(
            certificates=certificates,
            default_action=default_action,
            default_target_groups=default_target_groups,
            open=open,
            port=port,
            protocol=protocol,
            ssl_policy=ssl_policy,
        )

        return typing.cast(ApplicationListener, jsii.invoke(self, "addListener", [id, props]))

    @jsii.member(jsii_name="addRedirect")
    def add_redirect(
        self,
        *,
        open: typing.Optional[builtins.bool] = None,
        source_port: typing.Optional[jsii.Number] = None,
        source_protocol: typing.Optional[ApplicationProtocol] = None,
        target_port: typing.Optional[jsii.Number] = None,
        target_protocol: typing.Optional[ApplicationProtocol] = None,
    ) -> ApplicationListener:
        '''Add a redirection listener to this load balancer.

        :param open: Allow anyone to connect to this listener. If this is specified, the listener will be opened up to anyone who can reach it. For internal load balancers this is anyone in the same VPC. For public load balancers, this is anyone on the internet. If you want to be more selective about who can access this load balancer, set this to ``false`` and use the listener's ``connections`` object to selectively grant access to the listener. Default: true
        :param source_port: The port number to listen to. Default: 80
        :param source_protocol: The protocol of the listener being created. Default: HTTP
        :param target_port: The port number to redirect to. Default: 443
        :param target_protocol: The protocol of the redirection target. Default: HTTPS
        '''
        props = ApplicationLoadBalancerRedirectConfig(
            open=open,
            source_port=source_port,
            source_protocol=source_protocol,
            target_port=target_port,
            target_protocol=target_protocol,
        )

        return typing.cast(ApplicationListener, jsii.invoke(self, "addRedirect", [props]))

    @jsii.member(jsii_name="addSecurityGroup")
    def add_security_group(self, security_group: _ISecurityGroup_acf8a799) -> None:
        '''Add a security group to this load balancer.

        :param security_group: -
        '''
        return typing.cast(None, jsii.invoke(self, "addSecurityGroup", [security_group]))

    @jsii.member(jsii_name="metric")
    def metric(
        self,
        metric_name: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the given named metric for this Application Load Balancer.

        :param metric_name: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Average over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metric", [metric_name, props]))

    @jsii.member(jsii_name="metricActiveConnectionCount")
    def metric_active_connection_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The total number of concurrent TCP connections active from clients to the load balancer and from the load balancer to targets.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricActiveConnectionCount", [props]))

    @jsii.member(jsii_name="metricClientTlsNegotiationErrorCount")
    def metric_client_tls_negotiation_error_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of TLS connections initiated by the client that did not establish a session with the load balancer.

        Possible causes include a
        mismatch of ciphers or protocols.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricClientTlsNegotiationErrorCount", [props]))

    @jsii.member(jsii_name="metricConsumedLCUs")
    def metric_consumed_lc_us(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of load balancer capacity units (LCU) used by your load balancer.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricConsumedLCUs", [props]))

    @jsii.member(jsii_name="metricElbAuthError")
    def metric_elb_auth_error(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of user authentications that could not be completed.

        Because an authenticate action was misconfigured, the load balancer
        couldn't establish a connection with the IdP, or the load balancer
        couldn't complete the authentication flow due to an internal error.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricElbAuthError", [props]))

    @jsii.member(jsii_name="metricElbAuthFailure")
    def metric_elb_auth_failure(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of user authentications that could not be completed because the IdP denied access to the user or an authorization code was used more than once.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricElbAuthFailure", [props]))

    @jsii.member(jsii_name="metricElbAuthLatency")
    def metric_elb_auth_latency(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The time elapsed, in milliseconds, to query the IdP for the ID token and user info.

        If one or more of these operations fail, this is the time to failure.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Average over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricElbAuthLatency", [props]))

    @jsii.member(jsii_name="metricElbAuthSuccess")
    def metric_elb_auth_success(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of authenticate actions that were successful.

        This metric is incremented at the end of the authentication workflow,
        after the load balancer has retrieved the user claims from the IdP.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricElbAuthSuccess", [props]))

    @jsii.member(jsii_name="metricHttpCodeElb")
    def metric_http_code_elb(
        self,
        code: HttpCodeElb,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of HTTP 3xx/4xx/5xx codes that originate from the load balancer.

        This does not include any response codes generated by the targets.

        :param code: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricHttpCodeElb", [code, props]))

    @jsii.member(jsii_name="metricHttpCodeTarget")
    def metric_http_code_target(
        self,
        code: HttpCodeTarget,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of HTTP 2xx/3xx/4xx/5xx response codes generated by all targets in the load balancer.

        This does not include any response codes generated by the load balancer.

        :param code: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricHttpCodeTarget", [code, props]))

    @jsii.member(jsii_name="metricHttpFixedResponseCount")
    def metric_http_fixed_response_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of fixed-response actions that were successful.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricHttpFixedResponseCount", [props]))

    @jsii.member(jsii_name="metricHttpRedirectCount")
    def metric_http_redirect_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of redirect actions that were successful.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricHttpRedirectCount", [props]))

    @jsii.member(jsii_name="metricHttpRedirectUrlLimitExceededCount")
    def metric_http_redirect_url_limit_exceeded_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of redirect actions that couldn't be completed because the URL in the response location header is larger than 8K.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricHttpRedirectUrlLimitExceededCount", [props]))

    @jsii.member(jsii_name="metricIpv6ProcessedBytes")
    def metric_ipv6_processed_bytes(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The total number of bytes processed by the load balancer over IPv6.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricIpv6ProcessedBytes", [props]))

    @jsii.member(jsii_name="metricIpv6RequestCount")
    def metric_ipv6_request_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of IPv6 requests received by the load balancer.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricIpv6RequestCount", [props]))

    @jsii.member(jsii_name="metricNewConnectionCount")
    def metric_new_connection_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The total number of new TCP connections established from clients to the load balancer and from the load balancer to targets.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricNewConnectionCount", [props]))

    @jsii.member(jsii_name="metricProcessedBytes")
    def metric_processed_bytes(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The total number of bytes processed by the load balancer over IPv4 and IPv6.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricProcessedBytes", [props]))

    @jsii.member(jsii_name="metricRejectedConnectionCount")
    def metric_rejected_connection_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of connections that were rejected because the load balancer had reached its maximum number of connections.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricRejectedConnectionCount", [props]))

    @jsii.member(jsii_name="metricRequestCount")
    def metric_request_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of requests processed over IPv4 and IPv6.

        This count includes only the requests with a response generated by a target of the load balancer.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricRequestCount", [props]))

    @jsii.member(jsii_name="metricRuleEvaluations")
    def metric_rule_evaluations(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of rules processed by the load balancer given a request rate averaged over an hour.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricRuleEvaluations", [props]))

    @jsii.member(jsii_name="metricTargetConnectionErrorCount")
    def metric_target_connection_error_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of connections that were not successfully established between the load balancer and target.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricTargetConnectionErrorCount", [props]))

    @jsii.member(jsii_name="metricTargetResponseTime")
    def metric_target_response_time(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The time elapsed, in seconds, after the request leaves the load balancer until a response from the target is received.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Average over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricTargetResponseTime", [props]))

    @jsii.member(jsii_name="metricTargetTLSNegotiationErrorCount")
    def metric_target_tls_negotiation_error_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of TLS connections initiated by the load balancer that did not establish a session with the target.

        Possible causes include a mismatch of ciphers or protocols.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricTargetTLSNegotiationErrorCount", [props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connections")
    def connections(self) -> _Connections_0f31fce8:
        '''The network connections associated with this resource.'''
        return typing.cast(_Connections_0f31fce8, jsii.get(self, "connections"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="listeners")
    def listeners(self) -> typing.List[ApplicationListener]:
        '''A list of listeners that have been added to the load balancer.

        This list is only valid for owned constructs.
        '''
        return typing.cast(typing.List[ApplicationListener], jsii.get(self, "listeners"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ipAddressType")
    def ip_address_type(self) -> typing.Optional[IpAddressType]:
        '''The IP Address Type for this load balancer.'''
        return typing.cast(typing.Optional[IpAddressType], jsii.get(self, "ipAddressType"))


@jsii.implements(IApplicationTargetGroup)
class ApplicationTargetGroup(
    TargetGroupBase,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_elasticloadbalancingv2.ApplicationTargetGroup",
):
    '''Define an Application Target Group.

    :exampleMetadata: infused

    Example::

        # vpc: ec2.Vpc
        
        
        # Target group with duration-based stickiness with load-balancer generated cookie
        tg1 = elbv2.ApplicationTargetGroup(self, "TG1",
            target_type=elbv2.TargetType.INSTANCE,
            port=80,
            stickiness_cookie_duration=Duration.minutes(5),
            vpc=vpc
        )
        
        # Target group with application-based stickiness
        tg2 = elbv2.ApplicationTargetGroup(self, "TG2",
            target_type=elbv2.TargetType.INSTANCE,
            port=80,
            stickiness_cookie_duration=Duration.minutes(5),
            stickiness_cookie_name="MyDeliciousCookie",
            vpc=vpc
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        load_balancing_algorithm_type: typing.Optional[TargetGroupLoadBalancingAlgorithmType] = None,
        port: typing.Optional[jsii.Number] = None,
        protocol: typing.Optional[ApplicationProtocol] = None,
        protocol_version: typing.Optional[ApplicationProtocolVersion] = None,
        slow_start: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_duration: typing.Optional[_Duration_4839e8c3] = None,
        stickiness_cookie_name: typing.Optional[builtins.str] = None,
        targets: typing.Optional[typing.Sequence[IApplicationLoadBalancerTarget]] = None,
        deregistration_delay: typing.Optional[_Duration_4839e8c3] = None,
        health_check: typing.Optional[HealthCheck] = None,
        target_group_name: typing.Optional[builtins.str] = None,
        target_type: typing.Optional[TargetType] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param load_balancing_algorithm_type: The load balancing algorithm to select targets for routing requests. Default: TargetGroupLoadBalancingAlgorithmType.ROUND_ROBIN
        :param port: The port on which the listener listens for requests. Default: - Determined from protocol if known, optional for Lambda targets.
        :param protocol: The protocol to use. Default: - Determined from port if known, optional for Lambda targets.
        :param protocol_version: The protocol version to use. Default: ApplicationProtocolVersion.HTTP1
        :param slow_start: The time period during which the load balancer sends a newly registered target a linearly increasing share of the traffic to the target group. The range is 30-900 seconds (15 minutes). Default: 0
        :param stickiness_cookie_duration: The stickiness cookie expiration period. Setting this value enables load balancer stickiness. After this period, the cookie is considered stale. The minimum value is 1 second and the maximum value is 7 days (604800 seconds). Default: Duration.days(1)
        :param stickiness_cookie_name: The name of an application-based stickiness cookie. Names that start with the following prefixes are not allowed: AWSALB, AWSALBAPP, and AWSALBTG; they're reserved for use by the load balancer. Note: ``stickinessCookieName`` parameter depends on the presence of ``stickinessCookieDuration`` parameter. If ``stickinessCookieDuration`` is not set, ``stickinessCookieName`` will be omitted. Default: - If ``stickinessCookieDuration`` is set, a load-balancer generated cookie is used. Otherwise, no stickiness is defined.
        :param targets: The targets to add to this target group. Can be ``Instance``, ``IPAddress``, or any self-registering load balancing target. If you use either ``Instance`` or ``IPAddress`` as targets, all target must be of the same type. Default: - No targets.
        :param deregistration_delay: The amount of time for Elastic Load Balancing to wait before deregistering a target. The range is 0-3600 seconds. Default: 300
        :param health_check: Health check configuration. Default: - None.
        :param target_group_name: The name of the target group. This name must be unique per region per account, can have a maximum of 32 characters, must contain only alphanumeric characters or hyphens, and must not begin or end with a hyphen. Default: - Automatically generated.
        :param target_type: The type of targets registered to this TargetGroup, either IP or Instance. All targets registered into the group must be of this type. If you register targets to the TargetGroup in the CDK app, the TargetType is determined automatically. Default: - Determined automatically.
        :param vpc: The virtual private cloud (VPC). only if ``TargetType`` is ``Ip`` or ``InstanceId`` Default: - undefined
        '''
        props = ApplicationTargetGroupProps(
            load_balancing_algorithm_type=load_balancing_algorithm_type,
            port=port,
            protocol=protocol,
            protocol_version=protocol_version,
            slow_start=slow_start,
            stickiness_cookie_duration=stickiness_cookie_duration,
            stickiness_cookie_name=stickiness_cookie_name,
            targets=targets,
            deregistration_delay=deregistration_delay,
            health_check=health_check,
            target_group_name=target_group_name,
            target_type=target_type,
            vpc=vpc,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromTargetGroupAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_target_group_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        target_group_arn: builtins.str,
        load_balancer_arns: typing.Optional[builtins.str] = None,
    ) -> IApplicationTargetGroup:
        '''Import an existing target group.

        :param scope: -
        :param id: -
        :param target_group_arn: ARN of the target group.
        :param load_balancer_arns: A Token representing the list of ARNs for the load balancer routing to this target group.
        '''
        attrs = TargetGroupAttributes(
            target_group_arn=target_group_arn, load_balancer_arns=load_balancer_arns
        )

        return typing.cast(IApplicationTargetGroup, jsii.sinvoke(cls, "fromTargetGroupAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="addTarget")
    def add_target(self, *targets: IApplicationLoadBalancerTarget) -> None:
        '''Add a load balancing target to this target group.

        :param targets: -
        '''
        return typing.cast(None, jsii.invoke(self, "addTarget", [*targets]))

    @jsii.member(jsii_name="enableCookieStickiness")
    def enable_cookie_stickiness(
        self,
        duration: _Duration_4839e8c3,
        cookie_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Enable sticky routing via a cookie to members of this target group.

        Note: If the ``cookieName`` parameter is set, application-based stickiness will be applied,
        otherwise it defaults to duration-based stickiness attributes (``lb_cookie``).

        :param duration: -
        :param cookie_name: -

        :see: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/sticky-sessions.html
        '''
        return typing.cast(None, jsii.invoke(self, "enableCookieStickiness", [duration, cookie_name]))

    @jsii.member(jsii_name="metric")
    def metric(
        self,
        metric_name: builtins.str,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''Return the given named metric for this Application Load Balancer Target Group.

        Returns the metric for this target group from the point of view of the first
        load balancer load balancing to it. If you have multiple load balancers load
        sending traffic to the same target group, you will have to override the dimensions
        on this metric.

        :param metric_name: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Average over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metric", [metric_name, props]))

    @jsii.member(jsii_name="metricHealthyHostCount")
    def metric_healthy_host_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of healthy hosts in the target group.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Average over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricHealthyHostCount", [props]))

    @jsii.member(jsii_name="metricHttpCodeTarget")
    def metric_http_code_target(
        self,
        code: HttpCodeTarget,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of HTTP 2xx/3xx/4xx/5xx response codes generated by all targets in this target group.

        This does not include any response codes generated by the load balancer.

        :param code: -
        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricHttpCodeTarget", [code, props]))

    @jsii.member(jsii_name="metricIpv6RequestCount")
    def metric_ipv6_request_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of IPv6 requests received by the target group.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricIpv6RequestCount", [props]))

    @jsii.member(jsii_name="metricRequestCount")
    def metric_request_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of requests processed over IPv4 and IPv6.

        This count includes only the requests with a response generated by a target of the load balancer.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricRequestCount", [props]))

    @jsii.member(jsii_name="metricRequestCountPerTarget")
    def metric_request_count_per_target(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The average number of requests received by each target in a target group.

        The only valid statistic is Sum. Note that this represents the average not the sum.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricRequestCountPerTarget", [props]))

    @jsii.member(jsii_name="metricTargetConnectionErrorCount")
    def metric_target_connection_error_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of connections that were not successfully established between the load balancer and target.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricTargetConnectionErrorCount", [props]))

    @jsii.member(jsii_name="metricTargetResponseTime")
    def metric_target_response_time(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The time elapsed, in seconds, after the request leaves the load balancer until a response from the target is received.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Average over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricTargetResponseTime", [props]))

    @jsii.member(jsii_name="metricTargetTLSNegotiationErrorCount")
    def metric_target_tls_negotiation_error_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of TLS connections initiated by the load balancer that did not establish a session with the target.

        Possible causes include a mismatch of ciphers or protocols.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Sum over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricTargetTLSNegotiationErrorCount", [props]))

    @jsii.member(jsii_name="metricUnhealthyHostCount")
    def metric_unhealthy_host_count(
        self,
        *,
        account: typing.Optional[builtins.str] = None,
        color: typing.Optional[builtins.str] = None,
        dimensions_map: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        label: typing.Optional[builtins.str] = None,
        period: typing.Optional[_Duration_4839e8c3] = None,
        region: typing.Optional[builtins.str] = None,
        statistic: typing.Optional[builtins.str] = None,
        unit: typing.Optional[_Unit_61bc6f70] = None,
    ) -> _Metric_e396a4dc:
        '''The number of unhealthy hosts in the target group.

        :param account: Account which this metric comes from. Default: - Deployment account.
        :param color: The hex color code, prefixed with '#' (e.g. '#00ff00'), to use when this metric is rendered on a graph. The ``Color`` class has a set of standard colors that can be used here. Default: - Automatic color
        :param dimensions_map: Dimensions of the metric. Default: - No dimensions.
        :param label: Label for this metric when added to a Graph in a Dashboard. Default: - No label
        :param period: The period over which the specified statistic is applied. Default: Duration.minutes(5)
        :param region: Region which this metric comes from. Default: - Deployment region.
        :param statistic: What function to use for aggregating. Can be one of the following: - "Minimum" | "min" - "Maximum" | "max" - "Average" | "avg" - "Sum" | "sum" - "SampleCount | "n" - "pNN.NN" Default: Average
        :param unit: Unit used to filter the metric stream. Only refer to datums emitted to the metric stream with the given unit and ignore all others. Only useful when datums are being emitted to the same metric stream under different units. The default is to use all matric datums in the stream, regardless of unit, which is recommended in nearly all cases. CloudWatch does not honor this property for graphs. Default: - All metric datums in the given metric stream

        :default: Average over 5 minutes
        '''
        props = _MetricOptions_1788b62f(
            account=account,
            color=color,
            dimensions_map=dimensions_map,
            label=label,
            period=period,
            region=region,
            statistic=statistic,
            unit=unit,
        )

        return typing.cast(_Metric_e396a4dc, jsii.invoke(self, "metricUnhealthyHostCount", [props]))

    @jsii.member(jsii_name="registerConnectable")
    def register_connectable(
        self,
        connectable: _IConnectable_10015a05,
        port_range: typing.Optional[_Port_85922693] = None,
    ) -> None:
        '''Register a connectable as a member of this target group.

        Don't call this directly. It will be called by load balancing targets.

        :param connectable: -
        :param port_range: -
        '''
        return typing.cast(None, jsii.invoke(self, "registerConnectable", [connectable, port_range]))

    @jsii.member(jsii_name="registerListener")
    def register_listener(
        self,
        listener: IApplicationListener,
        associating_construct: typing.Optional[constructs.IConstruct] = None,
    ) -> None:
        '''Register a listener that is load balancing to this target group.

        Don't call this directly. It will be called by listeners.

        :param listener: -
        :param associating_construct: -
        '''
        return typing.cast(None, jsii.invoke(self, "registerListener", [listener, associating_construct]))

    @jsii.member(jsii_name="validateTargetGroup")
    def _validate_target_group(self) -> typing.List[builtins.str]:
        return typing.cast(typing.List[builtins.str], jsii.invoke(self, "validateTargetGroup", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="firstLoadBalancerFullName")
    def first_load_balancer_full_name(self) -> builtins.str:
        '''Full name of first load balancer.'''
        return typing.cast(builtins.str, jsii.get(self, "firstLoadBalancerFullName"))


__all__ = [
    "AddApplicationActionProps",
    "AddApplicationTargetGroupsProps",
    "AddApplicationTargetsProps",
    "AddNetworkActionProps",
    "AddNetworkTargetsProps",
    "AddRuleProps",
    "AlpnPolicy",
    "ApplicationListener",
    "ApplicationListenerAttributes",
    "ApplicationListenerCertificate",
    "ApplicationListenerCertificateProps",
    "ApplicationListenerLookupOptions",
    "ApplicationListenerProps",
    "ApplicationListenerRule",
    "ApplicationListenerRuleProps",
    "ApplicationLoadBalancer",
    "ApplicationLoadBalancerAttributes",
    "ApplicationLoadBalancerLookupOptions",
    "ApplicationLoadBalancerProps",
    "ApplicationLoadBalancerRedirectConfig",
    "ApplicationProtocol",
    "ApplicationProtocolVersion",
    "ApplicationTargetGroup",
    "ApplicationTargetGroupProps",
    "AuthenticateOidcOptions",
    "BaseApplicationListenerProps",
    "BaseApplicationListenerRuleProps",
    "BaseListener",
    "BaseListenerLookupOptions",
    "BaseLoadBalancer",
    "BaseLoadBalancerLookupOptions",
    "BaseLoadBalancerProps",
    "BaseNetworkListenerProps",
    "BaseTargetGroupProps",
    "CfnListener",
    "CfnListenerCertificate",
    "CfnListenerCertificateProps",
    "CfnListenerProps",
    "CfnListenerRule",
    "CfnListenerRuleProps",
    "CfnLoadBalancer",
    "CfnLoadBalancerProps",
    "CfnTargetGroup",
    "CfnTargetGroupProps",
    "FixedResponseOptions",
    "ForwardOptions",
    "HealthCheck",
    "HttpCodeElb",
    "HttpCodeTarget",
    "IApplicationListener",
    "IApplicationLoadBalancer",
    "IApplicationLoadBalancerTarget",
    "IApplicationTargetGroup",
    "IListenerAction",
    "IListenerCertificate",
    "ILoadBalancerV2",
    "INetworkListener",
    "INetworkLoadBalancer",
    "INetworkLoadBalancerTarget",
    "INetworkTargetGroup",
    "ITargetGroup",
    "IpAddressType",
    "ListenerAction",
    "ListenerCertificate",
    "ListenerCondition",
    "LoadBalancerTargetProps",
    "NetworkForwardOptions",
    "NetworkListener",
    "NetworkListenerAction",
    "NetworkListenerLookupOptions",
    "NetworkListenerProps",
    "NetworkLoadBalancer",
    "NetworkLoadBalancerAttributes",
    "NetworkLoadBalancerLookupOptions",
    "NetworkLoadBalancerProps",
    "NetworkTargetGroup",
    "NetworkTargetGroupProps",
    "NetworkWeightedTargetGroup",
    "Protocol",
    "QueryStringCondition",
    "RedirectOptions",
    "SslPolicy",
    "TargetGroupAttributes",
    "TargetGroupBase",
    "TargetGroupLoadBalancingAlgorithmType",
    "TargetType",
    "UnauthenticatedAction",
    "WeightedTargetGroup",
]

publication.publish()
