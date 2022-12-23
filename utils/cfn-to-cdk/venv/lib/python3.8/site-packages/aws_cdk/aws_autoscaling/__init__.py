'''
# Amazon EC2 Auto Scaling Construct Library

This module is part of the [AWS Cloud Development Kit](https://github.com/aws/aws-cdk) project.

## Auto Scaling Group

An `AutoScalingGroup` represents a number of instances on which you run your code. You
pick the size of the fleet, the instance type and the OS image:

```python
# vpc: ec2.Vpc


autoscaling.AutoScalingGroup(self, "ASG",
    vpc=vpc,
    instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
    machine_image=ec2.AmazonLinuxImage()
)
```

NOTE: AutoScalingGroup has an property called `allowAllOutbound` (allowing the instances to contact the
internet) which is set to `true` by default. Be sure to set this to `false`  if you don't want
your instances to be able to start arbitrary connections. Alternatively, you can specify an existing security
group to attach to the instances that are launched, rather than have the group create a new one.

```python
# vpc: ec2.Vpc


my_security_group = ec2.SecurityGroup(self, "SecurityGroup", vpc=vpc)
autoscaling.AutoScalingGroup(self, "ASG",
    vpc=vpc,
    instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
    machine_image=ec2.AmazonLinuxImage(),
    security_group=my_security_group
)
```

## Machine Images (AMIs)

AMIs control the OS that gets launched when you start your EC2 instance. The EC2
library contains constructs to select the AMI you want to use.

Depending on the type of AMI, you select it a different way.

The latest version of Amazon Linux and Microsoft Windows images are
selectable by instantiating one of these classes:

```python
# Pick a Windows edition to use
windows = ec2.WindowsImage(ec2.WindowsVersion.WINDOWS_SERVER_2019_ENGLISH_FULL_BASE)

# Pick the right Amazon Linux edition. All arguments shown are optional
# and will default to these values when omitted.
amzn_linux = ec2.AmazonLinuxImage(
    generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX,
    edition=ec2.AmazonLinuxEdition.STANDARD,
    virtualization=ec2.AmazonLinuxVirt.HVM,
    storage=ec2.AmazonLinuxStorage.GENERAL_PURPOSE
)

# For other custom (Linux) images, instantiate a `GenericLinuxImage` with
# a map giving the AMI to in for each region:

linux = ec2.GenericLinuxImage({
    "us-east-1": "ami-97785bed",
    "eu-west-1": "ami-12345678"
})
```

> NOTE: The Amazon Linux images selected will be cached in your `cdk.json`, so that your
> AutoScalingGroups don't automatically change out from under you when you're making unrelated
> changes. To update to the latest version of Amazon Linux, remove the cache entry from the `context`
> section of your `cdk.json`.
>
> We will add command-line options to make this step easier in the future.

## AutoScaling Instance Counts

AutoScalingGroups make it possible to raise and lower the number of instances in the group,
in response to (or in advance of) changes in workload.

When you create your AutoScalingGroup, you specify a `minCapacity` and a
`maxCapacity`. AutoScaling policies that respond to metrics will never go higher
or lower than the indicated capacity (but scheduled scaling actions might, see
below).

There are three ways to scale your capacity:

* **In response to a metric** (also known as step scaling); for example, you
  might want to scale out if the CPU usage across your cluster starts to rise,
  and scale in when it drops again.
* **By trying to keep a certain metric around a given value** (also known as
  target tracking scaling); you might want to automatically scale out and in to
  keep your CPU usage around 50%.
* **On a schedule**; you might want to organize your scaling around traffic
  flows you expect, by scaling out in the morning and scaling in in the
  evening.

The general pattern of autoscaling will look like this:

```python
# vpc: ec2.Vpc
# instance_type: ec2.InstanceType
# machine_image: ec2.IMachineImage


auto_scaling_group = autoscaling.AutoScalingGroup(self, "ASG",
    vpc=vpc,
    instance_type=instance_type,
    machine_image=machine_image,

    min_capacity=5,
    max_capacity=100
)
```

### Step Scaling

This type of scaling scales in and out in deterministics steps that you
configure, in response to metric values. For example, your scaling strategy to
scale in response to a metric that represents your average worker pool usage
might look like this:

```plaintext
 Scaling        -1          (no change)          +1       +3
            │        │                       │        │        │
            ├────────┼───────────────────────┼────────┼────────┤
            │        │                       │        │        │
Worker use  0%      10%                     50%       70%     100%
```

(Note that this is not necessarily a recommended scaling strategy, but it's
a possible one. You will have to determine what thresholds are right for you).

Note that in order to set up this scaling strategy, you will have to emit a
metric representing your worker utilization from your instances. After that,
you would configure the scaling something like this:

```python
# auto_scaling_group: autoscaling.AutoScalingGroup


worker_utilization_metric = cloudwatch.Metric(
    namespace="MyService",
    metric_name="WorkerUtilization"
)

auto_scaling_group.scale_on_metric("ScaleToCPU",
    metric=worker_utilization_metric,
    scaling_steps=[autoscaling.ScalingInterval(upper=10, change=-1), autoscaling.ScalingInterval(lower=50, change=+1), autoscaling.ScalingInterval(lower=70, change=+3)
    ],

    # Change this to AdjustmentType.PERCENT_CHANGE_IN_CAPACITY to interpret the
    # 'change' numbers before as percentages instead of capacity counts.
    adjustment_type=autoscaling.AdjustmentType.CHANGE_IN_CAPACITY
)
```

The AutoScaling construct library will create the required CloudWatch alarms and
AutoScaling policies for you.

### Target Tracking Scaling

This type of scaling scales in and out in order to keep a metric around a value
you prefer. There are four types of predefined metrics you can track, or you can
choose to track a custom metric. If you do choose to track a custom metric,
be aware that the metric has to represent instance utilization in some way
(AutoScaling will scale out if the metric is higher than the target, and scale
in if the metric is lower than the target).

If you configure multiple target tracking policies, AutoScaling will use the
one that yields the highest capacity.

The following example scales to keep the CPU usage of your instances around
50% utilization:

```python
# auto_scaling_group: autoscaling.AutoScalingGroup


auto_scaling_group.scale_on_cpu_utilization("KeepSpareCPU",
    target_utilization_percent=50
)
```

To scale on average network traffic in and out of your instances:

```python
# auto_scaling_group: autoscaling.AutoScalingGroup


auto_scaling_group.scale_on_incoming_bytes("LimitIngressPerInstance",
    target_bytes_per_second=10 * 1024 * 1024
)
auto_scaling_group.scale_on_outgoing_bytes("LimitEgressPerInstance",
    target_bytes_per_second=10 * 1024 * 1024
)
```

To scale on the average request count per instance (only works for
AutoScalingGroups that have been attached to Application Load
Balancers):

```python
# auto_scaling_group: autoscaling.AutoScalingGroup


auto_scaling_group.scale_on_request_count("LimitRPS",
    target_requests_per_second=1000
)
```

### Scheduled Scaling

This type of scaling is used to change capacities based on time. It works by
changing `minCapacity`, `maxCapacity` and `desiredCapacity` of the
AutoScalingGroup, and so can be used for two purposes:

* Scale in and out on a schedule by setting the `minCapacity` high or
  the `maxCapacity` low.
* Still allow the regular scaling actions to do their job, but restrict
  the range they can scale over (by setting both `minCapacity` and
  `maxCapacity` but changing their range over time).

A schedule is expressed as a cron expression. The `Schedule` class has a `cron` method to help build cron expressions.

The following example scales the fleet out in the morning, going back to natural
scaling (all the way down to 1 instance if necessary) at night:

```python
# auto_scaling_group: autoscaling.AutoScalingGroup


auto_scaling_group.scale_on_schedule("PrescaleInTheMorning",
    schedule=autoscaling.Schedule.cron(hour="8", minute="0"),
    min_capacity=20
)

auto_scaling_group.scale_on_schedule("AllowDownscalingAtNight",
    schedule=autoscaling.Schedule.cron(hour="20", minute="0"),
    min_capacity=1
)
```

## Configuring Instances using CloudFormation Init

It is possible to use the CloudFormation Init mechanism to configure the
instances in the AutoScalingGroup. You can write files to it, run commands,
start services, etc. See the documentation of
[AWS::CloudFormation::Init](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-init.html)
and the documentation of CDK's `aws-ec2` library for more information.

When you specify a CloudFormation Init configuration for an AutoScalingGroup:

* you *must* also specify `signals` to configure how long CloudFormation
  should wait for the instances to successfully configure themselves.
* you *should* also specify an `updatePolicy` to configure how instances
  should be updated when the AutoScalingGroup is updated (for example,
  when the AMI is updated). If you don't specify an update policy, a *rolling
  update* is chosen by default.

Here's an example of using CloudFormation Init to write a file to the
instance hosts on startup:

```python
# vpc: ec2.Vpc
# instance_type: ec2.InstanceType
# machine_image: ec2.IMachineImage


autoscaling.AutoScalingGroup(self, "ASG",
    vpc=vpc,
    instance_type=instance_type,
    machine_image=machine_image,

    # ...

    init=ec2.CloudFormationInit.from_elements(
        ec2.InitFile.from_string("/etc/my_instance", "This got written during instance startup")),
    signals=autoscaling.Signals.wait_for_all(
        timeout=Duration.minutes(10)
    )
)
```

## Signals

In normal operation, CloudFormation will send a Create or Update command to
an AutoScalingGroup and proceed with the rest of the deployment without waiting
for the *instances in the AutoScalingGroup*.

Configure `signals` to tell CloudFormation to wait for a specific number of
instances in the AutoScalingGroup to have been started (or failed to start)
before moving on. An instance is supposed to execute the
[`cfn-signal`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-signal.html)
program as part of its startup to indicate whether it was started
successfully or not.

If you use CloudFormation Init support (described in the previous section),
the appropriate call to `cfn-signal` is automatically added to the
AutoScalingGroup's UserData. If you don't use the `signals` directly, you are
responsible for adding such a call yourself.

The following type of `Signals` are available:

* `Signals.waitForAll([options])`: wait for all of `desiredCapacity` amount of instances
  to have started (recommended).
* `Signals.waitForMinCapacity([options])`: wait for a `minCapacity` amount of instances
  to have started (use this if waiting for all instances takes too long and you are happy
  with a minimum count of healthy hosts).
* `Signals.waitForCount(count, [options])`: wait for a specific amount of instances to have
  started.

There are two `options` you can configure:

* `timeout`: maximum time a host startup is allowed to take. If a host does not report
  success within this time, it is considered a failure. Default is 5 minutes.
* `minSuccessPercentage`: percentage of hosts that needs to be healthy in order for the
  update to succeed. If you set this value lower than 100, some percentage of hosts may
  report failure, while still considering the deployment a success. Default is 100%.

## Update Policy

The *update policy* describes what should happen to running instances when the definition
of the AutoScalingGroup is changed. For example, if you add a command to the UserData
of an AutoScalingGroup, do the existing instances get replaced with new instances that
have executed the new UserData? Or do the "old" instances just keep on running?

It is recommended to always use an update policy, otherwise the current state of your
instances also depends the previous state of your instances, rather than just on your
source code. This degrades the reproducibility of your deployments.

The following update policies are available:

* `UpdatePolicy.none()`: leave existing instances alone (not recommended).
* `UpdatePolicy.rollingUpdate([options])`: progressively replace the existing
  instances with new instances, in small batches. At any point in time,
  roughly the same amount of total instances will be running. If the deployment
  needs to be rolled back, the fresh instances will be replaced with the "old"
  configuration again.
* `UpdatePolicy.replacingUpdate([options])`: build a completely fresh copy
  of the new AutoScalingGroup next to the old one. Once the AutoScalingGroup
  has been successfully created (and the instances started, if `signals` is
  configured on the AutoScalingGroup), the old AutoScalingGroup is deleted.
  If the deployment needs to be rolled back, the new AutoScalingGroup is
  deleted and the old one is left unchanged.

## Allowing Connections

See the documentation of the `@aws-cdk/aws-ec2` package for more information
about allowing connections between resources backed by instances.

## Max Instance Lifetime

To enable the max instance lifetime support, specify `maxInstanceLifetime` property
for the `AutoscalingGroup` resource. The value must be between 7 and 365 days(inclusive).
To clear a previously set value, leave this property undefined.

## Instance Monitoring

To disable detailed instance monitoring, specify `instanceMonitoring` property
for the `AutoscalingGroup` resource as `Monitoring.BASIC`. Otherwise detailed monitoring
will be enabled.

## Monitoring Group Metrics

Group metrics are used to monitor group level properties; they describe the group rather than any of its instances (e.g GroupMaxSize, the group maximum size). To enable group metrics monitoring, use the `groupMetrics` property.
All group metrics are reported in a granularity of 1 minute at no additional charge.

See [EC2 docs](https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-monitoring.html#as-group-metrics) for a list of all available group metrics.

To enable group metrics monitoring using the `groupMetrics` property:

```python
# vpc: ec2.Vpc
# instance_type: ec2.InstanceType
# machine_image: ec2.IMachineImage


# Enable monitoring of all group metrics
autoscaling.AutoScalingGroup(self, "ASG",
    vpc=vpc,
    instance_type=instance_type,
    machine_image=machine_image,

    # ...

    group_metrics=[autoscaling.GroupMetrics.all()]
)

# Enable monitoring for a subset of group metrics
autoscaling.AutoScalingGroup(self, "ASG",
    vpc=vpc,
    instance_type=instance_type,
    machine_image=machine_image,

    # ...

    group_metrics=[autoscaling.GroupMetrics(autoscaling.GroupMetric.MIN_SIZE, autoscaling.GroupMetric.MAX_SIZE)]
)
```

## Termination policies

Auto Scaling uses [termination policies](https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html)
to determine which instances it terminates first during scale-in events. You
can specify one or more termination policies with the `terminationPolicies`
property:

```python
# vpc: ec2.Vpc
# instance_type: ec2.InstanceType
# machine_image: ec2.IMachineImage


autoscaling.AutoScalingGroup(self, "ASG",
    vpc=vpc,
    instance_type=instance_type,
    machine_image=machine_image,

    # ...

    termination_policies=[autoscaling.TerminationPolicy.OLDEST_INSTANCE, autoscaling.TerminationPolicy.DEFAULT
    ]
)
```

## Protecting new instances from being terminated on scale-in

By default, Auto Scaling can terminate an instance at any time after launch when
scaling in an Auto Scaling Group, subject to the group's [termination
policy](https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html).

However, you may wish to protect newly-launched instances from being scaled in
if they are going to run critical applications that should not be prematurely
terminated. EC2 Capacity Providers for Amazon ECS requires this attribute be
set to `true`.

```python
# vpc: ec2.Vpc
# instance_type: ec2.InstanceType
# machine_image: ec2.IMachineImage


autoscaling.AutoScalingGroup(self, "ASG",
    vpc=vpc,
    instance_type=instance_type,
    machine_image=machine_image,

    # ...

    new_instances_protected_from_scale_in=True
)
```

## Configuring Instance Metadata Service (IMDS)

### Toggling IMDSv1

You can configure [EC2 Instance Metadata Service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html) options to either
allow both IMDSv1 and IMDSv2 or enforce IMDSv2 when interacting with the IMDS.

To do this for a single `AutoScalingGroup`, you can use set the `requireImdsv2` property.
The example below demonstrates IMDSv2 being required on a single `AutoScalingGroup`:

```python
# vpc: ec2.Vpc
# instance_type: ec2.InstanceType
# machine_image: ec2.IMachineImage


autoscaling.AutoScalingGroup(self, "ASG",
    vpc=vpc,
    instance_type=instance_type,
    machine_image=machine_image,

    # ...

    require_imdsv2=True
)
```

You can also use `AutoScalingGroupRequireImdsv2Aspect` to apply the operation to multiple AutoScalingGroups.
The example below demonstrates the `AutoScalingGroupRequireImdsv2Aspect` being used to require IMDSv2 for all AutoScalingGroups in a stack:

```python
aspect = autoscaling.AutoScalingGroupRequireImdsv2Aspect()

Aspects.of(self).add(aspect)
```

## Future work

* [ ] CloudWatch Events (impossible to add currently as the AutoScalingGroup ARN is
  necessary to make this rule and this cannot be accessed from CloudFormation).
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
    CfnCreationPolicy as _CfnCreationPolicy_d904f690,
    CfnResource as _CfnResource_9df397a6,
    Duration as _Duration_4839e8c3,
    IAspect as _IAspect_118c810a,
    IInspectable as _IInspectable_c2943556,
    IResolvable as _IResolvable_da3f097b,
    IResource as _IResource_c80c4260,
    Resource as _Resource_45bc6135,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_cloudwatch import Alarm as _Alarm_9fbab1f1, IMetric as _IMetric_c7fd29de
from ..aws_ec2 import (
    CloudFormationInit as _CloudFormationInit_2bb1d1b2,
    Connections as _Connections_0f31fce8,
    IConnectable as _IConnectable_10015a05,
    IMachineImage as _IMachineImage_0e8bd50b,
    ISecurityGroup as _ISecurityGroup_acf8a799,
    IVpc as _IVpc_f30d5663,
    InstanceType as _InstanceType_f64915b9,
    OperatingSystemType as _OperatingSystemType_9224a1fe,
    SubnetSelection as _SubnetSelection_e57d76df,
    UserData as _UserData_b8b32b5e,
)
from ..aws_elasticloadbalancing import (
    ILoadBalancerTarget as _ILoadBalancerTarget_2e052b5c,
    LoadBalancer as _LoadBalancer_a894d40e,
)
from ..aws_elasticloadbalancingv2 import (
    ApplicationTargetGroup as _ApplicationTargetGroup_906fe365,
    IApplicationLoadBalancerTarget as _IApplicationLoadBalancerTarget_fabf9003,
    IApplicationTargetGroup as _IApplicationTargetGroup_57799827,
    INetworkLoadBalancerTarget as _INetworkLoadBalancerTarget_688b169f,
    INetworkTargetGroup as _INetworkTargetGroup_abca2df7,
    LoadBalancerTargetProps as _LoadBalancerTargetProps_4c30a73c,
)
from ..aws_iam import (
    IGrantable as _IGrantable_71c4f5de,
    IPrincipal as _IPrincipal_539bb2fd,
    IRole as _IRole_235f5d8e,
    PolicyStatement as _PolicyStatement_0fe33853,
)
from ..aws_sns import ITopic as _ITopic_9eca4852


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.AdjustmentTier",
    jsii_struct_bases=[],
    name_mapping={
        "adjustment": "adjustment",
        "lower_bound": "lowerBound",
        "upper_bound": "upperBound",
    },
)
class AdjustmentTier:
    def __init__(
        self,
        *,
        adjustment: jsii.Number,
        lower_bound: typing.Optional[jsii.Number] = None,
        upper_bound: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''An adjustment.

        :param adjustment: What number to adjust the capacity with. The number is interpeted as an added capacity, a new fixed capacity or an added percentage depending on the AdjustmentType value of the StepScalingPolicy. Can be positive or negative.
        :param lower_bound: Lower bound where this scaling tier applies. The scaling tier applies if the difference between the metric value and its alarm threshold is higher than this value. Default: -Infinity if this is the first tier, otherwise the upperBound of the previous tier
        :param upper_bound: Upper bound where this scaling tier applies. The scaling tier applies if the difference between the metric value and its alarm threshold is lower than this value. Default: +Infinity

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            adjustment_tier = autoscaling.AdjustmentTier(
                adjustment=123,
            
                # the properties below are optional
                lower_bound=123,
                upper_bound=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "adjustment": adjustment,
        }
        if lower_bound is not None:
            self._values["lower_bound"] = lower_bound
        if upper_bound is not None:
            self._values["upper_bound"] = upper_bound

    @builtins.property
    def adjustment(self) -> jsii.Number:
        '''What number to adjust the capacity with.

        The number is interpeted as an added capacity, a new fixed capacity or an
        added percentage depending on the AdjustmentType value of the
        StepScalingPolicy.

        Can be positive or negative.
        '''
        result = self._values.get("adjustment")
        assert result is not None, "Required property 'adjustment' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def lower_bound(self) -> typing.Optional[jsii.Number]:
        '''Lower bound where this scaling tier applies.

        The scaling tier applies if the difference between the metric
        value and its alarm threshold is higher than this value.

        :default: -Infinity if this is the first tier, otherwise the upperBound of the previous tier
        '''
        result = self._values.get("lower_bound")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def upper_bound(self) -> typing.Optional[jsii.Number]:
        '''Upper bound where this scaling tier applies.

        The scaling tier applies if the difference between the metric
        value and its alarm threshold is lower than this value.

        :default: +Infinity
        '''
        result = self._values.get("upper_bound")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AdjustmentTier(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_autoscaling.AdjustmentType")
class AdjustmentType(enum.Enum):
    '''How adjustment numbers are interpreted.

    :exampleMetadata: infused

    Example::

        # auto_scaling_group: autoscaling.AutoScalingGroup
        
        
        worker_utilization_metric = cloudwatch.Metric(
            namespace="MyService",
            metric_name="WorkerUtilization"
        )
        
        auto_scaling_group.scale_on_metric("ScaleToCPU",
            metric=worker_utilization_metric,
            scaling_steps=[autoscaling.ScalingInterval(upper=10, change=-1), autoscaling.ScalingInterval(lower=50, change=+1), autoscaling.ScalingInterval(lower=70, change=+3)
            ],
        
            # Change this to AdjustmentType.PERCENT_CHANGE_IN_CAPACITY to interpret the
            # 'change' numbers before as percentages instead of capacity counts.
            adjustment_type=autoscaling.AdjustmentType.CHANGE_IN_CAPACITY
        )
    '''

    CHANGE_IN_CAPACITY = "CHANGE_IN_CAPACITY"
    '''Add the adjustment number to the current capacity.

    A positive number increases capacity, a negative number decreases capacity.
    '''
    PERCENT_CHANGE_IN_CAPACITY = "PERCENT_CHANGE_IN_CAPACITY"
    '''Add this percentage of the current capacity to itself.

    The number must be between -100 and 100; a positive number increases
    capacity and a negative number decreases it.
    '''
    EXACT_CAPACITY = "EXACT_CAPACITY"
    '''Make the capacity equal to the exact number given.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.ApplyCloudFormationInitOptions",
    jsii_struct_bases=[],
    name_mapping={
        "config_sets": "configSets",
        "embed_fingerprint": "embedFingerprint",
        "ignore_failures": "ignoreFailures",
        "include_role": "includeRole",
        "include_url": "includeUrl",
        "print_log": "printLog",
    },
)
class ApplyCloudFormationInitOptions:
    def __init__(
        self,
        *,
        config_sets: typing.Optional[typing.Sequence[builtins.str]] = None,
        embed_fingerprint: typing.Optional[builtins.bool] = None,
        ignore_failures: typing.Optional[builtins.bool] = None,
        include_role: typing.Optional[builtins.bool] = None,
        include_url: typing.Optional[builtins.bool] = None,
        print_log: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Options for applying CloudFormation init to an instance or instance group.

        :param config_sets: ConfigSet to activate. Default: ['default']
        :param embed_fingerprint: Force instance replacement by embedding a config fingerprint. If ``true`` (the default), a hash of the config will be embedded into the UserData, so that if the config changes, the UserData changes and instances will be replaced (given an UpdatePolicy has been configured on the AutoScalingGroup). If ``false``, no such hash will be embedded, and if the CloudFormation Init config changes nothing will happen to the running instances. If a config update introduces errors, you will not notice until after the CloudFormation deployment successfully finishes and the next instance fails to launch. Default: true
        :param ignore_failures: Don't fail the instance creation when cfn-init fails. You can use this to prevent CloudFormation from rolling back when instances fail to start up, to help in debugging. Default: false
        :param include_role: Include --role argument when running cfn-init and cfn-signal commands. This will be the IAM instance profile attached to the EC2 instance Default: false
        :param include_url: Include --url argument when running cfn-init and cfn-signal commands. This will be the cloudformation endpoint in the deployed region e.g. https://cloudformation.us-east-1.amazonaws.com Default: false
        :param print_log: Print the results of running cfn-init to the Instance System Log. By default, the output of running cfn-init is written to a log file on the instance. Set this to ``true`` to print it to the System Log (visible from the EC2 Console), ``false`` to not print it. (Be aware that the system log is refreshed at certain points in time of the instance life cycle, and successful execution may not always show up). Default: true

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            apply_cloud_formation_init_options = autoscaling.ApplyCloudFormationInitOptions(
                config_sets=["configSets"],
                embed_fingerprint=False,
                ignore_failures=False,
                include_role=False,
                include_url=False,
                print_log=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if config_sets is not None:
            self._values["config_sets"] = config_sets
        if embed_fingerprint is not None:
            self._values["embed_fingerprint"] = embed_fingerprint
        if ignore_failures is not None:
            self._values["ignore_failures"] = ignore_failures
        if include_role is not None:
            self._values["include_role"] = include_role
        if include_url is not None:
            self._values["include_url"] = include_url
        if print_log is not None:
            self._values["print_log"] = print_log

    @builtins.property
    def config_sets(self) -> typing.Optional[typing.List[builtins.str]]:
        '''ConfigSet to activate.

        :default: ['default']
        '''
        result = self._values.get("config_sets")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def embed_fingerprint(self) -> typing.Optional[builtins.bool]:
        '''Force instance replacement by embedding a config fingerprint.

        If ``true`` (the default), a hash of the config will be embedded into the
        UserData, so that if the config changes, the UserData changes and
        instances will be replaced (given an UpdatePolicy has been configured on
        the AutoScalingGroup).

        If ``false``, no such hash will be embedded, and if the CloudFormation Init
        config changes nothing will happen to the running instances. If a
        config update introduces errors, you will not notice until after the
        CloudFormation deployment successfully finishes and the next instance
        fails to launch.

        :default: true
        '''
        result = self._values.get("embed_fingerprint")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def ignore_failures(self) -> typing.Optional[builtins.bool]:
        '''Don't fail the instance creation when cfn-init fails.

        You can use this to prevent CloudFormation from rolling back when
        instances fail to start up, to help in debugging.

        :default: false
        '''
        result = self._values.get("ignore_failures")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def include_role(self) -> typing.Optional[builtins.bool]:
        '''Include --role argument when running cfn-init and cfn-signal commands.

        This will be the IAM instance profile attached to the EC2 instance

        :default: false
        '''
        result = self._values.get("include_role")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def include_url(self) -> typing.Optional[builtins.bool]:
        '''Include --url argument when running cfn-init and cfn-signal commands.

        This will be the cloudformation endpoint in the deployed region
        e.g. https://cloudformation.us-east-1.amazonaws.com

        :default: false
        '''
        result = self._values.get("include_url")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def print_log(self) -> typing.Optional[builtins.bool]:
        '''Print the results of running cfn-init to the Instance System Log.

        By default, the output of running cfn-init is written to a log file
        on the instance. Set this to ``true`` to print it to the System Log
        (visible from the EC2 Console), ``false`` to not print it.

        (Be aware that the system log is refreshed at certain points in
        time of the instance life cycle, and successful execution may
        not always show up).

        :default: true
        '''
        result = self._values.get("print_log")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ApplyCloudFormationInitOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IAspect_118c810a)
class AutoScalingGroupRequireImdsv2Aspect(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.AutoScalingGroupRequireImdsv2Aspect",
):
    '''Aspect that makes IMDSv2 required on instances deployed by AutoScalingGroups.

    :exampleMetadata: infused

    Example::

        aspect = autoscaling.AutoScalingGroupRequireImdsv2Aspect()
        
        Aspects.of(self).add(aspect)
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="visit")
    def visit(self, node: constructs.IConstruct) -> None:
        '''All aspects can visit an IConstruct.

        :param node: -
        '''
        return typing.cast(None, jsii.invoke(self, "visit", [node]))

    @jsii.member(jsii_name="warn")
    def _warn(self, node: constructs.IConstruct, message: builtins.str) -> None:
        '''Adds a warning annotation to a node.

        :param node: The scope to add the warning to.
        :param message: The warning message.
        '''
        return typing.cast(None, jsii.invoke(self, "warn", [node, message]))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.BaseTargetTrackingProps",
    jsii_struct_bases=[],
    name_mapping={
        "cooldown": "cooldown",
        "disable_scale_in": "disableScaleIn",
        "estimated_instance_warmup": "estimatedInstanceWarmup",
    },
)
class BaseTargetTrackingProps:
    def __init__(
        self,
        *,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Base interface for target tracking props.

        Contains the attributes that are common to target tracking policies,
        except the ones relating to the metric and to the scalable target.

        This interface is reused by more specific target tracking props objects.

        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            
            base_target_tracking_props = autoscaling.BaseTargetTrackingProps(
                cooldown=cdk.Duration.minutes(30),
                disable_scale_in=False,
                estimated_instance_warmup=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if disable_scale_in is not None:
            self._values["disable_scale_in"] = disable_scale_in
        if estimated_instance_warmup is not None:
            self._values["estimated_instance_warmup"] = estimated_instance_warmup

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Period after a scaling completes before another scaling activity can start.

        :default: - The default cooldown configured on the AutoScalingGroup.
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def disable_scale_in(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether scale in by the target tracking policy is disabled.

        If the value is true, scale in is disabled and the target tracking policy
        won't remove capacity from the autoscaling group. Otherwise, scale in is
        enabled and the target tracking policy can remove capacity from the
        group.

        :default: false
        '''
        result = self._values.get("disable_scale_in")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def estimated_instance_warmup(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Estimated time until a newly launched instance can send metrics to CloudWatch.

        :default: - Same as the cooldown.
        '''
        result = self._values.get("estimated_instance_warmup")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BaseTargetTrackingProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.BasicLifecycleHookProps",
    jsii_struct_bases=[],
    name_mapping={
        "lifecycle_transition": "lifecycleTransition",
        "default_result": "defaultResult",
        "heartbeat_timeout": "heartbeatTimeout",
        "lifecycle_hook_name": "lifecycleHookName",
        "notification_metadata": "notificationMetadata",
        "notification_target": "notificationTarget",
        "role": "role",
    },
)
class BasicLifecycleHookProps:
    def __init__(
        self,
        *,
        lifecycle_transition: "LifecycleTransition",
        default_result: typing.Optional["DefaultResult"] = None,
        heartbeat_timeout: typing.Optional[_Duration_4839e8c3] = None,
        lifecycle_hook_name: typing.Optional[builtins.str] = None,
        notification_metadata: typing.Optional[builtins.str] = None,
        notification_target: typing.Optional["ILifecycleHookTarget"] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> None:
        '''Basic properties for a lifecycle hook.

        :param lifecycle_transition: The state of the Amazon EC2 instance to which you want to attach the lifecycle hook.
        :param default_result: The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs. Default: Continue
        :param heartbeat_timeout: Maximum time between calls to RecordLifecycleActionHeartbeat for the hook. If the lifecycle hook times out, perform the action in DefaultResult. Default: - No heartbeat timeout.
        :param lifecycle_hook_name: Name of the lifecycle hook. Default: - Automatically generated name.
        :param notification_metadata: Additional data to pass to the lifecycle hook target. Default: - No metadata.
        :param notification_target: The target of the lifecycle hook. Default: - No target.
        :param role: The role that allows publishing to the notification target. Default: - A role will be created if a target is provided. Otherwise, no role is created.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            from aws_cdk import aws_iam as iam
            
            # lifecycle_hook_target: autoscaling.ILifecycleHookTarget
            # role: iam.Role
            
            basic_lifecycle_hook_props = autoscaling.BasicLifecycleHookProps(
                lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_LAUNCHING,
            
                # the properties below are optional
                default_result=autoscaling.DefaultResult.CONTINUE,
                heartbeat_timeout=cdk.Duration.minutes(30),
                lifecycle_hook_name="lifecycleHookName",
                notification_metadata="notificationMetadata",
                notification_target=lifecycle_hook_target,
                role=role
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "lifecycle_transition": lifecycle_transition,
        }
        if default_result is not None:
            self._values["default_result"] = default_result
        if heartbeat_timeout is not None:
            self._values["heartbeat_timeout"] = heartbeat_timeout
        if lifecycle_hook_name is not None:
            self._values["lifecycle_hook_name"] = lifecycle_hook_name
        if notification_metadata is not None:
            self._values["notification_metadata"] = notification_metadata
        if notification_target is not None:
            self._values["notification_target"] = notification_target
        if role is not None:
            self._values["role"] = role

    @builtins.property
    def lifecycle_transition(self) -> "LifecycleTransition":
        '''The state of the Amazon EC2 instance to which you want to attach the lifecycle hook.'''
        result = self._values.get("lifecycle_transition")
        assert result is not None, "Required property 'lifecycle_transition' is missing"
        return typing.cast("LifecycleTransition", result)

    @builtins.property
    def default_result(self) -> typing.Optional["DefaultResult"]:
        '''The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs.

        :default: Continue
        '''
        result = self._values.get("default_result")
        return typing.cast(typing.Optional["DefaultResult"], result)

    @builtins.property
    def heartbeat_timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Maximum time between calls to RecordLifecycleActionHeartbeat for the hook.

        If the lifecycle hook times out, perform the action in DefaultResult.

        :default: - No heartbeat timeout.
        '''
        result = self._values.get("heartbeat_timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def lifecycle_hook_name(self) -> typing.Optional[builtins.str]:
        '''Name of the lifecycle hook.

        :default: - Automatically generated name.
        '''
        result = self._values.get("lifecycle_hook_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def notification_metadata(self) -> typing.Optional[builtins.str]:
        '''Additional data to pass to the lifecycle hook target.

        :default: - No metadata.
        '''
        result = self._values.get("notification_metadata")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def notification_target(self) -> typing.Optional["ILifecycleHookTarget"]:
        '''The target of the lifecycle hook.

        :default: - No target.
        '''
        result = self._values.get("notification_target")
        return typing.cast(typing.Optional["ILifecycleHookTarget"], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The role that allows publishing to the notification target.

        :default: - A role will be created if a target is provided. Otherwise, no role is created.
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BasicLifecycleHookProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.BasicScheduledActionProps",
    jsii_struct_bases=[],
    name_mapping={
        "schedule": "schedule",
        "desired_capacity": "desiredCapacity",
        "end_time": "endTime",
        "max_capacity": "maxCapacity",
        "min_capacity": "minCapacity",
        "start_time": "startTime",
        "time_zone": "timeZone",
    },
)
class BasicScheduledActionProps:
    def __init__(
        self,
        *,
        schedule: "Schedule",
        desired_capacity: typing.Optional[jsii.Number] = None,
        end_time: typing.Optional[datetime.datetime] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
        start_time: typing.Optional[datetime.datetime] = None,
        time_zone: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for a scheduled scaling action.

        :param schedule: When to perform this action. Supports cron expressions. For more information about cron expressions, see https://en.wikipedia.org/wiki/Cron.
        :param desired_capacity: The new desired capacity. At the scheduled time, set the desired capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new desired capacity.
        :param end_time: When this scheduled action expires. Default: - The rule never expires.
        :param max_capacity: The new maximum capacity. At the scheduled time, set the maximum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new maximum capacity.
        :param min_capacity: The new minimum capacity. At the scheduled time, set the minimum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new minimum capacity.
        :param start_time: When this scheduled action becomes active. Default: - The rule is activate immediately.
        :param time_zone: Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default. Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as Etc/GMT+9 or Pacific/Tahiti). For more information, see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones. Default: - UTC

        :exampleMetadata: infused

        Example::

            # auto_scaling_group: autoscaling.AutoScalingGroup
            
            
            auto_scaling_group.scale_on_schedule("PrescaleInTheMorning",
                schedule=autoscaling.Schedule.cron(hour="8", minute="0"),
                min_capacity=20
            )
            
            auto_scaling_group.scale_on_schedule("AllowDownscalingAtNight",
                schedule=autoscaling.Schedule.cron(hour="20", minute="0"),
                min_capacity=1
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "schedule": schedule,
        }
        if desired_capacity is not None:
            self._values["desired_capacity"] = desired_capacity
        if end_time is not None:
            self._values["end_time"] = end_time
        if max_capacity is not None:
            self._values["max_capacity"] = max_capacity
        if min_capacity is not None:
            self._values["min_capacity"] = min_capacity
        if start_time is not None:
            self._values["start_time"] = start_time
        if time_zone is not None:
            self._values["time_zone"] = time_zone

    @builtins.property
    def schedule(self) -> "Schedule":
        '''When to perform this action.

        Supports cron expressions.

        For more information about cron expressions, see https://en.wikipedia.org/wiki/Cron.
        '''
        result = self._values.get("schedule")
        assert result is not None, "Required property 'schedule' is missing"
        return typing.cast("Schedule", result)

    @builtins.property
    def desired_capacity(self) -> typing.Optional[jsii.Number]:
        '''The new desired capacity.

        At the scheduled time, set the desired capacity to the given capacity.

        At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied.

        :default: - No new desired capacity.
        '''
        result = self._values.get("desired_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def end_time(self) -> typing.Optional[datetime.datetime]:
        '''When this scheduled action expires.

        :default: - The rule never expires.
        '''
        result = self._values.get("end_time")
        return typing.cast(typing.Optional[datetime.datetime], result)

    @builtins.property
    def max_capacity(self) -> typing.Optional[jsii.Number]:
        '''The new maximum capacity.

        At the scheduled time, set the maximum capacity to the given capacity.

        At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied.

        :default: - No new maximum capacity.
        '''
        result = self._values.get("max_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_capacity(self) -> typing.Optional[jsii.Number]:
        '''The new minimum capacity.

        At the scheduled time, set the minimum capacity to the given capacity.

        At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied.

        :default: - No new minimum capacity.
        '''
        result = self._values.get("min_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def start_time(self) -> typing.Optional[datetime.datetime]:
        '''When this scheduled action becomes active.

        :default: - The rule is activate immediately.
        '''
        result = self._values.get("start_time")
        return typing.cast(typing.Optional[datetime.datetime], result)

    @builtins.property
    def time_zone(self) -> typing.Optional[builtins.str]:
        '''Specifies the time zone for a cron expression.

        If a time zone is not provided, UTC is used by default.

        Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as Etc/GMT+9 or Pacific/Tahiti).

        For more information, see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones.

        :default: - UTC
        '''
        result = self._values.get("time_zone")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BasicScheduledActionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.BasicStepScalingPolicyProps",
    jsii_struct_bases=[],
    name_mapping={
        "metric": "metric",
        "scaling_steps": "scalingSteps",
        "adjustment_type": "adjustmentType",
        "cooldown": "cooldown",
        "estimated_instance_warmup": "estimatedInstanceWarmup",
        "evaluation_periods": "evaluationPeriods",
        "metric_aggregation_type": "metricAggregationType",
        "min_adjustment_magnitude": "minAdjustmentMagnitude",
    },
)
class BasicStepScalingPolicyProps:
    def __init__(
        self,
        *,
        metric: _IMetric_c7fd29de,
        scaling_steps: typing.Sequence["ScalingInterval"],
        adjustment_type: typing.Optional[AdjustmentType] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        evaluation_periods: typing.Optional[jsii.Number] = None,
        metric_aggregation_type: typing.Optional["MetricAggregationType"] = None,
        min_adjustment_magnitude: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''
        :param metric: Metric to scale on.
        :param scaling_steps: The intervals for scaling. Maps a range of metric values to a particular scaling behavior.
        :param adjustment_type: How the adjustment numbers inside 'intervals' are interpreted. Default: ChangeInCapacity
        :param cooldown: Grace period after scaling activity. Default: Default cooldown period on your AutoScalingGroup
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: Same as the cooldown
        :param evaluation_periods: How many evaluation periods of the metric to wait before triggering a scaling action. Raising this value can be used to smooth out the metric, at the expense of slower response times. Default: 1
        :param metric_aggregation_type: Aggregation to apply to all data points over the evaluation periods. Only has meaning if ``evaluationPeriods != 1``. Default: - The statistic from the metric if applicable (MIN, MAX, AVERAGE), otherwise AVERAGE.
        :param min_adjustment_magnitude: Minimum absolute number to adjust capacity with as result of percentage scaling. Only when using AdjustmentType = PercentChangeInCapacity, this number controls the minimum absolute effect size. Default: No minimum scaling effect

        :exampleMetadata: infused

        Example::

            # auto_scaling_group: autoscaling.AutoScalingGroup
            
            
            worker_utilization_metric = cloudwatch.Metric(
                namespace="MyService",
                metric_name="WorkerUtilization"
            )
            
            auto_scaling_group.scale_on_metric("ScaleToCPU",
                metric=worker_utilization_metric,
                scaling_steps=[autoscaling.ScalingInterval(upper=10, change=-1), autoscaling.ScalingInterval(lower=50, change=+1), autoscaling.ScalingInterval(lower=70, change=+3)
                ],
            
                # Change this to AdjustmentType.PERCENT_CHANGE_IN_CAPACITY to interpret the
                # 'change' numbers before as percentages instead of capacity counts.
                adjustment_type=autoscaling.AdjustmentType.CHANGE_IN_CAPACITY
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "metric": metric,
            "scaling_steps": scaling_steps,
        }
        if adjustment_type is not None:
            self._values["adjustment_type"] = adjustment_type
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if estimated_instance_warmup is not None:
            self._values["estimated_instance_warmup"] = estimated_instance_warmup
        if evaluation_periods is not None:
            self._values["evaluation_periods"] = evaluation_periods
        if metric_aggregation_type is not None:
            self._values["metric_aggregation_type"] = metric_aggregation_type
        if min_adjustment_magnitude is not None:
            self._values["min_adjustment_magnitude"] = min_adjustment_magnitude

    @builtins.property
    def metric(self) -> _IMetric_c7fd29de:
        '''Metric to scale on.'''
        result = self._values.get("metric")
        assert result is not None, "Required property 'metric' is missing"
        return typing.cast(_IMetric_c7fd29de, result)

    @builtins.property
    def scaling_steps(self) -> typing.List["ScalingInterval"]:
        '''The intervals for scaling.

        Maps a range of metric values to a particular scaling behavior.
        '''
        result = self._values.get("scaling_steps")
        assert result is not None, "Required property 'scaling_steps' is missing"
        return typing.cast(typing.List["ScalingInterval"], result)

    @builtins.property
    def adjustment_type(self) -> typing.Optional[AdjustmentType]:
        '''How the adjustment numbers inside 'intervals' are interpreted.

        :default: ChangeInCapacity
        '''
        result = self._values.get("adjustment_type")
        return typing.cast(typing.Optional[AdjustmentType], result)

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Grace period after scaling activity.

        :default: Default cooldown period on your AutoScalingGroup
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def estimated_instance_warmup(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Estimated time until a newly launched instance can send metrics to CloudWatch.

        :default: Same as the cooldown
        '''
        result = self._values.get("estimated_instance_warmup")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def evaluation_periods(self) -> typing.Optional[jsii.Number]:
        '''How many evaluation periods of the metric to wait before triggering a scaling action.

        Raising this value can be used to smooth out the metric, at the expense
        of slower response times.

        :default: 1
        '''
        result = self._values.get("evaluation_periods")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def metric_aggregation_type(self) -> typing.Optional["MetricAggregationType"]:
        '''Aggregation to apply to all data points over the evaluation periods.

        Only has meaning if ``evaluationPeriods != 1``.

        :default: - The statistic from the metric if applicable (MIN, MAX, AVERAGE), otherwise AVERAGE.
        '''
        result = self._values.get("metric_aggregation_type")
        return typing.cast(typing.Optional["MetricAggregationType"], result)

    @builtins.property
    def min_adjustment_magnitude(self) -> typing.Optional[jsii.Number]:
        '''Minimum absolute number to adjust capacity with as result of percentage scaling.

        Only when using AdjustmentType = PercentChangeInCapacity, this number controls
        the minimum absolute effect size.

        :default: No minimum scaling effect
        '''
        result = self._values.get("min_adjustment_magnitude")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BasicStepScalingPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.BasicTargetTrackingScalingPolicyProps",
    jsii_struct_bases=[BaseTargetTrackingProps],
    name_mapping={
        "cooldown": "cooldown",
        "disable_scale_in": "disableScaleIn",
        "estimated_instance_warmup": "estimatedInstanceWarmup",
        "target_value": "targetValue",
        "custom_metric": "customMetric",
        "predefined_metric": "predefinedMetric",
        "resource_label": "resourceLabel",
    },
)
class BasicTargetTrackingScalingPolicyProps(BaseTargetTrackingProps):
    def __init__(
        self,
        *,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        target_value: jsii.Number,
        custom_metric: typing.Optional[_IMetric_c7fd29de] = None,
        predefined_metric: typing.Optional["PredefinedMetric"] = None,
        resource_label: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for a Target Tracking policy that include the metric but exclude the target.

        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        :param target_value: The target value for the metric.
        :param custom_metric: A custom metric for application autoscaling. The metric must track utilization. Scaling out will happen if the metric is higher than the target value, scaling in will happen in the metric is lower than the target value. Exactly one of customMetric or predefinedMetric must be specified. Default: - No custom metric.
        :param predefined_metric: A predefined metric for application autoscaling. The metric must track utilization. Scaling out will happen if the metric is higher than the target value, scaling in will happen in the metric is lower than the target value. Exactly one of customMetric or predefinedMetric must be specified. Default: - No predefined metric.
        :param resource_label: The resource label associated with the predefined metric. Should be supplied if the predefined metric is ALBRequestCountPerTarget, and the format should be: app///targetgroup// Default: - No resource label.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            from aws_cdk import aws_cloudwatch as cloudwatch
            
            # metric: cloudwatch.Metric
            
            basic_target_tracking_scaling_policy_props = autoscaling.BasicTargetTrackingScalingPolicyProps(
                target_value=123,
            
                # the properties below are optional
                cooldown=cdk.Duration.minutes(30),
                custom_metric=metric,
                disable_scale_in=False,
                estimated_instance_warmup=cdk.Duration.minutes(30),
                predefined_metric=autoscaling.PredefinedMetric.ASG_AVERAGE_CPU_UTILIZATION,
                resource_label="resourceLabel"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target_value": target_value,
        }
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if disable_scale_in is not None:
            self._values["disable_scale_in"] = disable_scale_in
        if estimated_instance_warmup is not None:
            self._values["estimated_instance_warmup"] = estimated_instance_warmup
        if custom_metric is not None:
            self._values["custom_metric"] = custom_metric
        if predefined_metric is not None:
            self._values["predefined_metric"] = predefined_metric
        if resource_label is not None:
            self._values["resource_label"] = resource_label

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Period after a scaling completes before another scaling activity can start.

        :default: - The default cooldown configured on the AutoScalingGroup.
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def disable_scale_in(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether scale in by the target tracking policy is disabled.

        If the value is true, scale in is disabled and the target tracking policy
        won't remove capacity from the autoscaling group. Otherwise, scale in is
        enabled and the target tracking policy can remove capacity from the
        group.

        :default: false
        '''
        result = self._values.get("disable_scale_in")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def estimated_instance_warmup(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Estimated time until a newly launched instance can send metrics to CloudWatch.

        :default: - Same as the cooldown.
        '''
        result = self._values.get("estimated_instance_warmup")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def target_value(self) -> jsii.Number:
        '''The target value for the metric.'''
        result = self._values.get("target_value")
        assert result is not None, "Required property 'target_value' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def custom_metric(self) -> typing.Optional[_IMetric_c7fd29de]:
        '''A custom metric for application autoscaling.

        The metric must track utilization. Scaling out will happen if the metric is higher than
        the target value, scaling in will happen in the metric is lower than the target value.

        Exactly one of customMetric or predefinedMetric must be specified.

        :default: - No custom metric.
        '''
        result = self._values.get("custom_metric")
        return typing.cast(typing.Optional[_IMetric_c7fd29de], result)

    @builtins.property
    def predefined_metric(self) -> typing.Optional["PredefinedMetric"]:
        '''A predefined metric for application autoscaling.

        The metric must track utilization. Scaling out will happen if the metric is higher than
        the target value, scaling in will happen in the metric is lower than the target value.

        Exactly one of customMetric or predefinedMetric must be specified.

        :default: - No predefined metric.
        '''
        result = self._values.get("predefined_metric")
        return typing.cast(typing.Optional["PredefinedMetric"], result)

    @builtins.property
    def resource_label(self) -> typing.Optional[builtins.str]:
        '''The resource label associated with the predefined metric.

        Should be supplied if the predefined metric is ALBRequestCountPerTarget, and the
        format should be:

        app///targetgroup//

        :default: - No resource label.
        '''
        result = self._values.get("resource_label")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BasicTargetTrackingScalingPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.BindHookTargetOptions",
    jsii_struct_bases=[],
    name_mapping={"lifecycle_hook": "lifecycleHook", "role": "role"},
)
class BindHookTargetOptions:
    def __init__(
        self,
        *,
        lifecycle_hook: "LifecycleHook",
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> None:
        '''Options needed to bind a target to a lifecycle hook.

        [disable-awslint:ref-via-interface] The lifecycle hook to attach to and an IRole to use

        :param lifecycle_hook: The lifecycle hook to attach to. [disable-awslint:ref-via-interface]
        :param role: The role to use when attaching to the lifecycle hook. [disable-awslint:ref-via-interface] Default: : a role is not created unless the target arn is specified

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            from aws_cdk import aws_iam as iam
            
            # lifecycle_hook: autoscaling.LifecycleHook
            # role: iam.Role
            
            bind_hook_target_options = autoscaling.BindHookTargetOptions(
                lifecycle_hook=lifecycle_hook,
            
                # the properties below are optional
                role=role
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "lifecycle_hook": lifecycle_hook,
        }
        if role is not None:
            self._values["role"] = role

    @builtins.property
    def lifecycle_hook(self) -> "LifecycleHook":
        '''The lifecycle hook to attach to.

        [disable-awslint:ref-via-interface]
        '''
        result = self._values.get("lifecycle_hook")
        assert result is not None, "Required property 'lifecycle_hook' is missing"
        return typing.cast("LifecycleHook", result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The role to use when attaching to the lifecycle hook.

        [disable-awslint:ref-via-interface]

        :default: : a role is not created unless the target arn is specified
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BindHookTargetOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.BlockDevice",
    jsii_struct_bases=[],
    name_mapping={"device_name": "deviceName", "volume": "volume"},
)
class BlockDevice:
    def __init__(
        self,
        *,
        device_name: builtins.str,
        volume: "BlockDeviceVolume",
    ) -> None:
        '''Block device.

        :param device_name: The device name exposed to the EC2 instance. Supply a value like ``/dev/sdh``, ``xvdh``.
        :param volume: Defines the block device volume, to be either an Amazon EBS volume or an ephemeral instance store volume. Supply a value like ``BlockDeviceVolume.ebs(15)``, ``BlockDeviceVolume.ephemeral(0)``.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            # block_device_volume: autoscaling.BlockDeviceVolume
            
            block_device = autoscaling.BlockDevice(
                device_name="deviceName",
                volume=block_device_volume
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "device_name": device_name,
            "volume": volume,
        }

    @builtins.property
    def device_name(self) -> builtins.str:
        '''The device name exposed to the EC2 instance.

        Supply a value like ``/dev/sdh``, ``xvdh``.

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html
        '''
        result = self._values.get("device_name")
        assert result is not None, "Required property 'device_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def volume(self) -> "BlockDeviceVolume":
        '''Defines the block device volume, to be either an Amazon EBS volume or an ephemeral instance store volume.

        Supply a value like ``BlockDeviceVolume.ebs(15)``, ``BlockDeviceVolume.ephemeral(0)``.
        '''
        result = self._values.get("volume")
        assert result is not None, "Required property 'volume' is missing"
        return typing.cast("BlockDeviceVolume", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BlockDevice(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class BlockDeviceVolume(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.BlockDeviceVolume",
):
    '''Describes a block device mapping for an EC2 instance or Auto Scaling group.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_autoscaling as autoscaling
        
        block_device_volume = autoscaling.BlockDeviceVolume.ebs(123,
            delete_on_termination=False,
            encrypted=False,
            iops=123,
            volume_type=autoscaling.EbsDeviceVolumeType.STANDARD
        )
    '''

    def __init__(
        self,
        ebs_device: typing.Optional["EbsDeviceProps"] = None,
        virtual_name: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param ebs_device: EBS device info.
        :param virtual_name: Virtual device name.
        '''
        jsii.create(self.__class__, self, [ebs_device, virtual_name])

    @jsii.member(jsii_name="ebs") # type: ignore[misc]
    @builtins.classmethod
    def ebs(
        cls,
        volume_size: jsii.Number,
        *,
        encrypted: typing.Optional[builtins.bool] = None,
        delete_on_termination: typing.Optional[builtins.bool] = None,
        iops: typing.Optional[jsii.Number] = None,
        volume_type: typing.Optional["EbsDeviceVolumeType"] = None,
    ) -> "BlockDeviceVolume":
        '''Creates a new Elastic Block Storage device.

        :param volume_size: The volume size, in Gibibytes (GiB).
        :param encrypted: Specifies whether the EBS volume is encrypted. Encrypted EBS volumes can only be attached to instances that support Amazon EBS encryption Default: false
        :param delete_on_termination: Indicates whether to delete the volume when the instance is terminated. Default: - true for Amazon EC2 Auto Scaling, false otherwise (e.g. EBS)
        :param iops: The number of I/O operations per second (IOPS) to provision for the volume. Must only be set for {@link volumeType}: {@link EbsDeviceVolumeType.IO1} The maximum ratio of IOPS to volume size (in GiB) is 50:1, so for 5,000 provisioned IOPS, you need at least 100 GiB storage on the volume. Default: - none, required for {@link EbsDeviceVolumeType.IO1}
        :param volume_type: The EBS volume type. Default: {@link EbsDeviceVolumeType.GP2}
        '''
        options = EbsDeviceOptions(
            encrypted=encrypted,
            delete_on_termination=delete_on_termination,
            iops=iops,
            volume_type=volume_type,
        )

        return typing.cast("BlockDeviceVolume", jsii.sinvoke(cls, "ebs", [volume_size, options]))

    @jsii.member(jsii_name="ebsFromSnapshot") # type: ignore[misc]
    @builtins.classmethod
    def ebs_from_snapshot(
        cls,
        snapshot_id: builtins.str,
        *,
        volume_size: typing.Optional[jsii.Number] = None,
        delete_on_termination: typing.Optional[builtins.bool] = None,
        iops: typing.Optional[jsii.Number] = None,
        volume_type: typing.Optional["EbsDeviceVolumeType"] = None,
    ) -> "BlockDeviceVolume":
        '''Creates a new Elastic Block Storage device from an existing snapshot.

        :param snapshot_id: The snapshot ID of the volume to use.
        :param volume_size: The volume size, in Gibibytes (GiB). If you specify volumeSize, it must be equal or greater than the size of the snapshot. Default: - The snapshot size
        :param delete_on_termination: Indicates whether to delete the volume when the instance is terminated. Default: - true for Amazon EC2 Auto Scaling, false otherwise (e.g. EBS)
        :param iops: The number of I/O operations per second (IOPS) to provision for the volume. Must only be set for {@link volumeType}: {@link EbsDeviceVolumeType.IO1} The maximum ratio of IOPS to volume size (in GiB) is 50:1, so for 5,000 provisioned IOPS, you need at least 100 GiB storage on the volume. Default: - none, required for {@link EbsDeviceVolumeType.IO1}
        :param volume_type: The EBS volume type. Default: {@link EbsDeviceVolumeType.GP2}
        '''
        options = EbsDeviceSnapshotOptions(
            volume_size=volume_size,
            delete_on_termination=delete_on_termination,
            iops=iops,
            volume_type=volume_type,
        )

        return typing.cast("BlockDeviceVolume", jsii.sinvoke(cls, "ebsFromSnapshot", [snapshot_id, options]))

    @jsii.member(jsii_name="ephemeral") # type: ignore[misc]
    @builtins.classmethod
    def ephemeral(cls, volume_index: jsii.Number) -> "BlockDeviceVolume":
        '''Creates a virtual, ephemeral device.

        The name will be in the form ephemeral{volumeIndex}.

        :param volume_index: the volume index. Must be equal or greater than 0
        '''
        return typing.cast("BlockDeviceVolume", jsii.sinvoke(cls, "ephemeral", [volume_index]))

    @jsii.member(jsii_name="noDevice") # type: ignore[misc]
    @builtins.classmethod
    def no_device(cls) -> "BlockDeviceVolume":
        '''Supresses a volume mapping.'''
        return typing.cast("BlockDeviceVolume", jsii.sinvoke(cls, "noDevice", []))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ebsDevice")
    def ebs_device(self) -> typing.Optional["EbsDeviceProps"]:
        '''EBS device info.'''
        return typing.cast(typing.Optional["EbsDeviceProps"], jsii.get(self, "ebsDevice"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="virtualName")
    def virtual_name(self) -> typing.Optional[builtins.str]:
        '''Virtual device name.'''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "virtualName"))


@jsii.implements(_IInspectable_c2943556)
class CfnAutoScalingGroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup",
):
    '''A CloudFormation ``AWS::AutoScaling::AutoScalingGroup``.

    The ``AWS::AutoScaling::AutoScalingGroup`` resource defines an Amazon EC2 Auto Scaling group, which is a collection of Amazon EC2 instances that are treated as a logical grouping for the purposes of automatic scaling and management.
    .. epigraph::

       Amazon EC2 Auto Scaling configures instances launched as part of an Auto Scaling group using either a launch template or a launch configuration. We recommend that you use a launch template to make sure that you can use the latest features of Amazon EC2, such as Dedicated Hosts and T2 Unlimited instances. For more information, see `Creating a launch template for an Auto Scaling group <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-template.html>`_ . You can find sample launch templates in `AWS::EC2::LaunchTemplate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-launchtemplate.html>`_ .

    For more information, see `CreateAutoScalingGroup <https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html>`_ and `UpdateAutoScalingGroup <https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_UpdateAutoScalingGroup.html>`_ in the *Amazon EC2 Auto Scaling API Reference* . For more information about Amazon EC2 Auto Scaling, see the `Amazon EC2 Auto Scaling User Guide <https://docs.aws.amazon.com/autoscaling/ec2/userguide/what-is-amazon-ec2-auto-scaling.html>`_ .

    :cloudformationResource: AWS::AutoScaling::AutoScalingGroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_autoscaling as autoscaling
        
        cfn_auto_scaling_group = autoscaling.CfnAutoScalingGroup(self, "MyCfnAutoScalingGroup",
            max_size="maxSize",
            min_size="minSize",
        
            # the properties below are optional
            auto_scaling_group_name="autoScalingGroupName",
            availability_zones=["availabilityZones"],
            capacity_rebalance=False,
            context="context",
            cooldown="cooldown",
            desired_capacity="desiredCapacity",
            desired_capacity_type="desiredCapacityType",
            health_check_grace_period=123,
            health_check_type="healthCheckType",
            instance_id="instanceId",
            launch_configuration_name="launchConfigurationName",
            launch_template=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                version="version",
        
                # the properties below are optional
                launch_template_id="launchTemplateId",
                launch_template_name="launchTemplateName"
            ),
            lifecycle_hook_specification_list=[autoscaling.CfnAutoScalingGroup.LifecycleHookSpecificationProperty(
                lifecycle_hook_name="lifecycleHookName",
                lifecycle_transition="lifecycleTransition",
        
                # the properties below are optional
                default_result="defaultResult",
                heartbeat_timeout=123,
                notification_metadata="notificationMetadata",
                notification_target_arn="notificationTargetArn",
                role_arn="roleArn"
            )],
            load_balancer_names=["loadBalancerNames"],
            max_instance_lifetime=123,
            metrics_collection=[autoscaling.CfnAutoScalingGroup.MetricsCollectionProperty(
                granularity="granularity",
        
                # the properties below are optional
                metrics=["metrics"]
            )],
            mixed_instances_policy=autoscaling.CfnAutoScalingGroup.MixedInstancesPolicyProperty(
                launch_template=autoscaling.CfnAutoScalingGroup.LaunchTemplateProperty(
                    launch_template_specification=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                        version="version",
        
                        # the properties below are optional
                        launch_template_id="launchTemplateId",
                        launch_template_name="launchTemplateName"
                    ),
        
                    # the properties below are optional
                    overrides=[autoscaling.CfnAutoScalingGroup.LaunchTemplateOverridesProperty(
                        instance_requirements=autoscaling.CfnAutoScalingGroup.InstanceRequirementsProperty(
                            accelerator_count=autoscaling.CfnAutoScalingGroup.AcceleratorCountRequestProperty(
                                max=123,
                                min=123
                            ),
                            accelerator_manufacturers=["acceleratorManufacturers"],
                            accelerator_names=["acceleratorNames"],
                            accelerator_total_memory_mi_b=autoscaling.CfnAutoScalingGroup.AcceleratorTotalMemoryMiBRequestProperty(
                                max=123,
                                min=123
                            ),
                            accelerator_types=["acceleratorTypes"],
                            bare_metal="bareMetal",
                            baseline_ebs_bandwidth_mbps=autoscaling.CfnAutoScalingGroup.BaselineEbsBandwidthMbpsRequestProperty(
                                max=123,
                                min=123
                            ),
                            burstable_performance="burstablePerformance",
                            cpu_manufacturers=["cpuManufacturers"],
                            excluded_instance_types=["excludedInstanceTypes"],
                            instance_generations=["instanceGenerations"],
                            local_storage="localStorage",
                            local_storage_types=["localStorageTypes"],
                            memory_gi_bPer_vCpu=autoscaling.CfnAutoScalingGroup.MemoryGiBPerVCpuRequestProperty(
                                max=123,
                                min=123
                            ),
                            memory_mi_b=autoscaling.CfnAutoScalingGroup.MemoryMiBRequestProperty(
                                max=123,
                                min=123
                            ),
                            network_interface_count=autoscaling.CfnAutoScalingGroup.NetworkInterfaceCountRequestProperty(
                                max=123,
                                min=123
                            ),
                            on_demand_max_price_percentage_over_lowest_price=123,
                            require_hibernate_support=False,
                            spot_max_price_percentage_over_lowest_price=123,
                            total_local_storage_gb=autoscaling.CfnAutoScalingGroup.TotalLocalStorageGBRequestProperty(
                                max=123,
                                min=123
                            ),
                            v_cpu_count=autoscaling.CfnAutoScalingGroup.VCpuCountRequestProperty(
                                max=123,
                                min=123
                            )
                        ),
                        instance_type="instanceType",
                        launch_template_specification=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                            version="version",
        
                            # the properties below are optional
                            launch_template_id="launchTemplateId",
                            launch_template_name="launchTemplateName"
                        ),
                        weighted_capacity="weightedCapacity"
                    )]
                ),
        
                # the properties below are optional
                instances_distribution=autoscaling.CfnAutoScalingGroup.InstancesDistributionProperty(
                    on_demand_allocation_strategy="onDemandAllocationStrategy",
                    on_demand_base_capacity=123,
                    on_demand_percentage_above_base_capacity=123,
                    spot_allocation_strategy="spotAllocationStrategy",
                    spot_instance_pools=123,
                    spot_max_price="spotMaxPrice"
                )
            ),
            new_instances_protected_from_scale_in=False,
            notification_configurations=[autoscaling.CfnAutoScalingGroup.NotificationConfigurationProperty(
                topic_arn="topicArn",
        
                # the properties below are optional
                notification_types=["notificationTypes"]
            )],
            placement_group="placementGroup",
            service_linked_role_arn="serviceLinkedRoleArn",
            tags=[autoscaling.CfnAutoScalingGroup.TagPropertyProperty(
                key="key",
                propagate_at_launch=False,
                value="value"
            )],
            target_group_arns=["targetGroupArns"],
            termination_policies=["terminationPolicies"],
            vpc_zone_identifier=["vpcZoneIdentifier"]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        max_size: builtins.str,
        min_size: builtins.str,
        auto_scaling_group_name: typing.Optional[builtins.str] = None,
        availability_zones: typing.Optional[typing.Sequence[builtins.str]] = None,
        capacity_rebalance: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        context: typing.Optional[builtins.str] = None,
        cooldown: typing.Optional[builtins.str] = None,
        desired_capacity: typing.Optional[builtins.str] = None,
        desired_capacity_type: typing.Optional[builtins.str] = None,
        health_check_grace_period: typing.Optional[jsii.Number] = None,
        health_check_type: typing.Optional[builtins.str] = None,
        instance_id: typing.Optional[builtins.str] = None,
        launch_configuration_name: typing.Optional[builtins.str] = None,
        launch_template: typing.Optional[typing.Union["CfnAutoScalingGroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]] = None,
        lifecycle_hook_specification_list: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAutoScalingGroup.LifecycleHookSpecificationProperty", _IResolvable_da3f097b]]]] = None,
        load_balancer_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        max_instance_lifetime: typing.Optional[jsii.Number] = None,
        metrics_collection: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAutoScalingGroup.MetricsCollectionProperty", _IResolvable_da3f097b]]]] = None,
        mixed_instances_policy: typing.Optional[typing.Union["CfnAutoScalingGroup.MixedInstancesPolicyProperty", _IResolvable_da3f097b]] = None,
        new_instances_protected_from_scale_in: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        notification_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAutoScalingGroup.NotificationConfigurationProperty", _IResolvable_da3f097b]]]] = None,
        placement_group: typing.Optional[builtins.str] = None,
        service_linked_role_arn: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence["CfnAutoScalingGroup.TagPropertyProperty"]] = None,
        target_group_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        termination_policies: typing.Optional[typing.Sequence[builtins.str]] = None,
        vpc_zone_identifier: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Create a new ``AWS::AutoScaling::AutoScalingGroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param max_size: The maximum size of the group. .. epigraph:: With a mixed instances policy that uses instance weighting, Amazon EC2 Auto Scaling may need to go above ``MaxSize`` to meet your capacity requirements. In this event, Amazon EC2 Auto Scaling will never go above ``MaxSize`` by more than your largest instance weight (weights that define how many units each instance contributes to the desired capacity of the group).
        :param min_size: The minimum size of the group.
        :param auto_scaling_group_name: The name of the Auto Scaling group. This name must be unique per Region per account.
        :param availability_zones: A list of Availability Zones where instances in the Auto Scaling group can be created. You must specify one of the following properties: ``VPCZoneIdentifier`` or ``AvailabilityZones`` . If your account supports EC2-Classic and VPC, this property is required to create an Auto Scaling group that launches instances into EC2-Classic.
        :param capacity_rebalance: Indicates whether Capacity Rebalancing is enabled. For more information, see `Amazon EC2 Auto Scaling Capacity Rebalancing <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-capacity-rebalancing.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param context: Reserved.
        :param cooldown: The amount of time, in seconds, after a scaling activity completes before another scaling activity can start. The default value is ``300`` . This setting applies when using simple scaling policies, but not when using other scaling policies or scheduled scaling. For more information, see `Scaling cooldowns for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param desired_capacity: The desired capacity is the initial capacity of the Auto Scaling group at the time of its creation and the capacity it attempts to maintain. It can scale beyond this capacity if you configure automatic scaling. The number must be greater than or equal to the minimum size of the group and less than or equal to the maximum size of the group. If you do not specify a desired capacity when creating the stack, the default is the minimum size of the group. CloudFormation marks the Auto Scaling group as successful (by setting its status to CREATE_COMPLETE) when the desired capacity is reached. However, if a maximum Spot price is set in the launch template or launch configuration that you specified, then desired capacity is not used as a criteria for success. Whether your request is fulfilled depends on Spot Instance capacity and your maximum price.
        :param desired_capacity_type: The unit of measurement for the value specified for desired capacity. Amazon EC2 Auto Scaling supports ``DesiredCapacityType`` for attribute-based instance type selection only. For more information, see `Creating an Auto Scaling group using attribute-based instance type selection <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-instance-type-requirements.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . By default, Amazon EC2 Auto Scaling specifies ``units`` , which translates into number of instances. Valid values: ``units`` | ``vcpu`` | ``memory-mib``
        :param health_check_grace_period: The amount of time, in seconds, that Amazon EC2 Auto Scaling waits before checking the health status of an EC2 instance that has come into service and marking it unhealthy due to a failed health check. The default value is ``0`` . For more information, see `Health checks for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/healthcheck.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . If you are adding an ``ELB`` health check, you must specify this property.
        :param health_check_type: The service to use for the health checks. The valid values are ``EC2`` (default) and ``ELB`` . If you configure an Auto Scaling group to use load balancer (ELB) health checks, it considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks. For more information, see `Health checks for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/healthcheck.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param instance_id: The ID of the instance used to base the launch configuration on. If specified, Amazon EC2 Auto Scaling uses the configuration values from the specified instance to create a new launch configuration. For more information, see `Creating an Auto Scaling group using an EC2 instance <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-from-instance.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . To get the instance ID, use the EC2 `DescribeInstances <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html>`_ API operation. If you specify ``LaunchTemplate`` , ``MixedInstancesPolicy`` , or ``LaunchConfigurationName`` , don't specify ``InstanceId`` .
        :param launch_configuration_name: The name of the `launch configuration <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig.html>`_ to use to launch instances. If you specify ``LaunchTemplate`` , ``MixedInstancesPolicy`` , or ``InstanceId`` , don't specify ``LaunchConfigurationName`` .
        :param launch_template: Properties used to specify the `launch template <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-launchtemplate.html>`_ and version to use to launch instances. You can alternatively associate a launch template to the Auto Scaling group by specifying a ``MixedInstancesPolicy`` . If you omit this property, you must specify ``MixedInstancesPolicy`` , ``LaunchConfigurationName`` , or ``InstanceId`` .
        :param lifecycle_hook_specification_list: One or more lifecycle hooks for the group, which specify actions to perform when Amazon EC2 Auto Scaling launches or terminates instances.
        :param load_balancer_names: A list of Classic Load Balancers associated with this Auto Scaling group. For Application Load Balancers, Network Load Balancers, and Gateway Load Balancers, specify the ``TargetGroupARNs`` property instead.
        :param max_instance_lifetime: The maximum amount of time, in seconds, that an instance can be in service. The default is null. If specified, the value must be either 0 or a number equal to or greater than 86,400 seconds (1 day). For more information, see `Replacing Auto Scaling instances based on maximum instance lifetime <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-max-instance-lifetime.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param metrics_collection: Enables the monitoring of group metrics of an Auto Scaling group. By default, these metrics are disabled.
        :param mixed_instances_policy: An embedded object that specifies a mixed instances policy. The policy includes properties that not only define the distribution of On-Demand Instances and Spot Instances, the maximum price to pay for Spot Instances (optional), and how the Auto Scaling group allocates instance types to fulfill On-Demand and Spot capacities, but also the properties that specify the instance configuration information—the launch template and instance types. The policy can also include a weight for each instance type and different launch templates for individual instance types. For more information, see `Auto Scaling groups with multiple instance types and purchase options <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . If you specify ``LaunchTemplate`` , ``InstanceId`` , or ``LaunchConfigurationName`` , don't specify ``MixedInstancesPolicy`` .
        :param new_instances_protected_from_scale_in: Indicates whether newly launched instances are protected from termination by Amazon EC2 Auto Scaling when scaling in. For more information about preventing instances from terminating on scale in, see `Instance Protection <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html#instance-protection>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param notification_configurations: Configures an Auto Scaling group to send notifications when specified events take place.
        :param placement_group: The name of the placement group into which you want to launch your instances. A placement group is a logical grouping of instances within a single Availability Zone. For more information, see `Placement Groups <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param service_linked_role_arn: The Amazon Resource Name (ARN) of the service-linked role that the Auto Scaling group uses to call other AWS services on your behalf. By default, Amazon EC2 Auto Scaling uses a service-linked role named ``AWSServiceRoleForAutoScaling`` , which it creates if it does not exist. For more information, see `Service-linked roles for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-service-linked-role.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param tags: One or more tags. You can tag your Auto Scaling group and propagate the tags to the Amazon EC2 instances it launches. For more information, see `Tagging Auto Scaling groups and instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-tagging.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param target_group_arns: One or more Amazon Resource Names (ARN) of load balancer target groups to associate with the Auto Scaling group. Instances are registered as targets in a target group, and traffic is routed to the target group. For more information, see `Elastic Load Balancing and Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-load-balancer.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param termination_policies: A policy or a list of policies that are used to select the instances to terminate. The policies are executed in the order that you list them. The termination policies supported by Amazon EC2 Auto Scaling: ``OldestInstance`` , ``OldestLaunchConfiguration`` , ``NewestInstance`` , ``ClosestToNextInstanceHour`` , ``Default`` , ``OldestLaunchTemplate`` , and ``AllocationStrategy`` . For more information, see `Controlling which Auto Scaling instances terminate during scale in <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param vpc_zone_identifier: A list of subnet IDs for a virtual private cloud (VPC) where instances in the Auto Scaling group can be created. If you specify ``VPCZoneIdentifier`` with ``AvailabilityZones`` , the subnets that you specify for this property must reside in those Availability Zones. If this resource specifies public subnets and is also in a VPC that is defined in the same stack template, you must use the `DependsOn attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ to declare a dependency on the `VPC-gateway attachment <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc-gateway-attachment.html>`_ . .. epigraph:: When you update ``VPCZoneIdentifier`` , this retains the same Auto Scaling group and replaces old instances with new ones, according to the specified subnets. You can optionally specify how CloudFormation handles these updates by using an `UpdatePolicy attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html>`_ .
        '''
        props = CfnAutoScalingGroupProps(
            max_size=max_size,
            min_size=min_size,
            auto_scaling_group_name=auto_scaling_group_name,
            availability_zones=availability_zones,
            capacity_rebalance=capacity_rebalance,
            context=context,
            cooldown=cooldown,
            desired_capacity=desired_capacity,
            desired_capacity_type=desired_capacity_type,
            health_check_grace_period=health_check_grace_period,
            health_check_type=health_check_type,
            instance_id=instance_id,
            launch_configuration_name=launch_configuration_name,
            launch_template=launch_template,
            lifecycle_hook_specification_list=lifecycle_hook_specification_list,
            load_balancer_names=load_balancer_names,
            max_instance_lifetime=max_instance_lifetime,
            metrics_collection=metrics_collection,
            mixed_instances_policy=mixed_instances_policy,
            new_instances_protected_from_scale_in=new_instances_protected_from_scale_in,
            notification_configurations=notification_configurations,
            placement_group=placement_group,
            service_linked_role_arn=service_linked_role_arn,
            tags=tags,
            target_group_arns=target_group_arns,
            termination_policies=termination_policies,
            vpc_zone_identifier=vpc_zone_identifier,
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
        '''One or more tags.

        You can tag your Auto Scaling group and propagate the tags to the Amazon EC2 instances it launches. For more information, see `Tagging Auto Scaling groups and instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-tagging.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxSize")
    def max_size(self) -> builtins.str:
        '''The maximum size of the group.

        .. epigraph::

           With a mixed instances policy that uses instance weighting, Amazon EC2 Auto Scaling may need to go above ``MaxSize`` to meet your capacity requirements. In this event, Amazon EC2 Auto Scaling will never go above ``MaxSize`` by more than your largest instance weight (weights that define how many units each instance contributes to the desired capacity of the group).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-maxsize
        '''
        return typing.cast(builtins.str, jsii.get(self, "maxSize"))

    @max_size.setter
    def max_size(self, value: builtins.str) -> None:
        jsii.set(self, "maxSize", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="minSize")
    def min_size(self) -> builtins.str:
        '''The minimum size of the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-minsize
        '''
        return typing.cast(builtins.str, jsii.get(self, "minSize"))

    @min_size.setter
    def min_size(self, value: builtins.str) -> None:
        jsii.set(self, "minSize", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoScalingGroupName")
    def auto_scaling_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Auto Scaling group.

        This name must be unique per Region per account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-autoscaling-autoscalinggroup-autoscalinggroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "autoScalingGroupName"))

    @auto_scaling_group_name.setter
    def auto_scaling_group_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "autoScalingGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="availabilityZones")
    def availability_zones(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Availability Zones where instances in the Auto Scaling group can be created.

        You must specify one of the following properties: ``VPCZoneIdentifier`` or ``AvailabilityZones`` . If your account supports EC2-Classic and VPC, this property is required to create an Auto Scaling group that launches instances into EC2-Classic.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-availabilityzones
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "availabilityZones"))

    @availability_zones.setter
    def availability_zones(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "availabilityZones", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="capacityRebalance")
    def capacity_rebalance(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether Capacity Rebalancing is enabled.

        For more information, see `Amazon EC2 Auto Scaling Capacity Rebalancing <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-capacity-rebalancing.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-capacityrebalance
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "capacityRebalance"))

    @capacity_rebalance.setter
    def capacity_rebalance(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "capacityRebalance", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="context")
    def context(self) -> typing.Optional[builtins.str]:
        '''Reserved.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-context
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "context"))

    @context.setter
    def context(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "context", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cooldown")
    def cooldown(self) -> typing.Optional[builtins.str]:
        '''The amount of time, in seconds, after a scaling activity completes before another scaling activity can start.

        The default value is ``300`` . This setting applies when using simple scaling policies, but not when using other scaling policies or scheduled scaling. For more information, see `Scaling cooldowns for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-cooldown
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cooldown"))

    @cooldown.setter
    def cooldown(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cooldown", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="desiredCapacity")
    def desired_capacity(self) -> typing.Optional[builtins.str]:
        '''The desired capacity is the initial capacity of the Auto Scaling group at the time of its creation and the capacity it attempts to maintain.

        It can scale beyond this capacity if you configure automatic scaling.

        The number must be greater than or equal to the minimum size of the group and less than or equal to the maximum size of the group. If you do not specify a desired capacity when creating the stack, the default is the minimum size of the group.

        CloudFormation marks the Auto Scaling group as successful (by setting its status to CREATE_COMPLETE) when the desired capacity is reached. However, if a maximum Spot price is set in the launch template or launch configuration that you specified, then desired capacity is not used as a criteria for success. Whether your request is fulfilled depends on Spot Instance capacity and your maximum price.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-desiredcapacity
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "desiredCapacity"))

    @desired_capacity.setter
    def desired_capacity(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "desiredCapacity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="desiredCapacityType")
    def desired_capacity_type(self) -> typing.Optional[builtins.str]:
        '''The unit of measurement for the value specified for desired capacity.

        Amazon EC2 Auto Scaling supports ``DesiredCapacityType`` for attribute-based instance type selection only. For more information, see `Creating an Auto Scaling group using attribute-based instance type selection <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-instance-type-requirements.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        By default, Amazon EC2 Auto Scaling specifies ``units`` , which translates into number of instances.

        Valid values: ``units`` | ``vcpu`` | ``memory-mib``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-desiredcapacitytype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "desiredCapacityType"))

    @desired_capacity_type.setter
    def desired_capacity_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "desiredCapacityType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckGracePeriod")
    def health_check_grace_period(self) -> typing.Optional[jsii.Number]:
        '''The amount of time, in seconds, that Amazon EC2 Auto Scaling waits before checking the health status of an EC2 instance that has come into service and marking it unhealthy due to a failed health check.

        The default value is ``0`` . For more information, see `Health checks for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/healthcheck.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        If you are adding an ``ELB`` health check, you must specify this property.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-healthcheckgraceperiod
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "healthCheckGracePeriod"))

    @health_check_grace_period.setter
    def health_check_grace_period(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "healthCheckGracePeriod", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="healthCheckType")
    def health_check_type(self) -> typing.Optional[builtins.str]:
        '''The service to use for the health checks.

        The valid values are ``EC2`` (default) and ``ELB`` . If you configure an Auto Scaling group to use load balancer (ELB) health checks, it considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks. For more information, see `Health checks for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/healthcheck.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-healthchecktype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "healthCheckType"))

    @health_check_type.setter
    def health_check_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "healthCheckType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceId")
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the instance used to base the launch configuration on.

        If specified, Amazon EC2 Auto Scaling uses the configuration values from the specified instance to create a new launch configuration. For more information, see `Creating an Auto Scaling group using an EC2 instance <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-from-instance.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        To get the instance ID, use the EC2 `DescribeInstances <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html>`_ API operation.

        If you specify ``LaunchTemplate`` , ``MixedInstancesPolicy`` , or ``LaunchConfigurationName`` , don't specify ``InstanceId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-instanceid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "instanceId"))

    @instance_id.setter
    def instance_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "instanceId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="launchConfigurationName")
    def launch_configuration_name(self) -> typing.Optional[builtins.str]:
        '''The name of the `launch configuration <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig.html>`_ to use to launch instances.

        If you specify ``LaunchTemplate`` , ``MixedInstancesPolicy`` , or ``InstanceId`` , don't specify ``LaunchConfigurationName`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-launchconfigurationname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "launchConfigurationName"))

    @launch_configuration_name.setter
    def launch_configuration_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "launchConfigurationName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="launchTemplate")
    def launch_template(
        self,
    ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]]:
        '''Properties used to specify the `launch template <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-launchtemplate.html>`_ and version to use to launch instances. You can alternatively associate a launch template to the Auto Scaling group by specifying a ``MixedInstancesPolicy`` .

        If you omit this property, you must specify ``MixedInstancesPolicy`` , ``LaunchConfigurationName`` , or ``InstanceId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-launchtemplate
        '''
        return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]], jsii.get(self, "launchTemplate"))

    @launch_template.setter
    def launch_template(
        self,
        value: typing.Optional[typing.Union["CfnAutoScalingGroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "launchTemplate", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lifecycleHookSpecificationList")
    def lifecycle_hook_specification_list(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAutoScalingGroup.LifecycleHookSpecificationProperty", _IResolvable_da3f097b]]]]:
        '''One or more lifecycle hooks for the group, which specify actions to perform when Amazon EC2 Auto Scaling launches or terminates instances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-autoscaling-autoscalinggroup-lifecyclehookspecificationlist
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAutoScalingGroup.LifecycleHookSpecificationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "lifecycleHookSpecificationList"))

    @lifecycle_hook_specification_list.setter
    def lifecycle_hook_specification_list(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAutoScalingGroup.LifecycleHookSpecificationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "lifecycleHookSpecificationList", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="loadBalancerNames")
    def load_balancer_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Classic Load Balancers associated with this Auto Scaling group.

        For Application Load Balancers, Network Load Balancers, and Gateway Load Balancers, specify the ``TargetGroupARNs`` property instead.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-loadbalancernames
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "loadBalancerNames"))

    @load_balancer_names.setter
    def load_balancer_names(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "loadBalancerNames", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxInstanceLifetime")
    def max_instance_lifetime(self) -> typing.Optional[jsii.Number]:
        '''The maximum amount of time, in seconds, that an instance can be in service.

        The default is null. If specified, the value must be either 0 or a number equal to or greater than 86,400 seconds (1 day). For more information, see `Replacing Auto Scaling instances based on maximum instance lifetime <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-max-instance-lifetime.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-maxinstancelifetime
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maxInstanceLifetime"))

    @max_instance_lifetime.setter
    def max_instance_lifetime(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maxInstanceLifetime", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="metricsCollection")
    def metrics_collection(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAutoScalingGroup.MetricsCollectionProperty", _IResolvable_da3f097b]]]]:
        '''Enables the monitoring of group metrics of an Auto Scaling group.

        By default, these metrics are disabled.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-metricscollection
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAutoScalingGroup.MetricsCollectionProperty", _IResolvable_da3f097b]]]], jsii.get(self, "metricsCollection"))

    @metrics_collection.setter
    def metrics_collection(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAutoScalingGroup.MetricsCollectionProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "metricsCollection", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="mixedInstancesPolicy")
    def mixed_instances_policy(
        self,
    ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.MixedInstancesPolicyProperty", _IResolvable_da3f097b]]:
        '''An embedded object that specifies a mixed instances policy.

        The policy includes properties that not only define the distribution of On-Demand Instances and Spot Instances, the maximum price to pay for Spot Instances (optional), and how the Auto Scaling group allocates instance types to fulfill On-Demand and Spot capacities, but also the properties that specify the instance configuration information—the launch template and instance types. The policy can also include a weight for each instance type and different launch templates for individual instance types.

        For more information, see `Auto Scaling groups with multiple instance types and purchase options <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        If you specify ``LaunchTemplate`` , ``InstanceId`` , or ``LaunchConfigurationName`` , don't specify ``MixedInstancesPolicy`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-mixedinstancespolicy
        '''
        return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.MixedInstancesPolicyProperty", _IResolvable_da3f097b]], jsii.get(self, "mixedInstancesPolicy"))

    @mixed_instances_policy.setter
    def mixed_instances_policy(
        self,
        value: typing.Optional[typing.Union["CfnAutoScalingGroup.MixedInstancesPolicyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "mixedInstancesPolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="newInstancesProtectedFromScaleIn")
    def new_instances_protected_from_scale_in(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether newly launched instances are protected from termination by Amazon EC2 Auto Scaling when scaling in.

        For more information about preventing instances from terminating on scale in, see `Instance Protection <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html#instance-protection>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-newinstancesprotectedfromscalein
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "newInstancesProtectedFromScaleIn"))

    @new_instances_protected_from_scale_in.setter
    def new_instances_protected_from_scale_in(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "newInstancesProtectedFromScaleIn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationConfigurations")
    def notification_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAutoScalingGroup.NotificationConfigurationProperty", _IResolvable_da3f097b]]]]:
        '''Configures an Auto Scaling group to send notifications when specified events take place.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-notificationconfigurations
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAutoScalingGroup.NotificationConfigurationProperty", _IResolvable_da3f097b]]]], jsii.get(self, "notificationConfigurations"))

    @notification_configurations.setter
    def notification_configurations(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAutoScalingGroup.NotificationConfigurationProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "notificationConfigurations", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="placementGroup")
    def placement_group(self) -> typing.Optional[builtins.str]:
        '''The name of the placement group into which you want to launch your instances.

        A placement group is a logical grouping of instances within a single Availability Zone. For more information, see `Placement Groups <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-placementgroup
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "placementGroup"))

    @placement_group.setter
    def placement_group(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "placementGroup", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceLinkedRoleArn")
    def service_linked_role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the service-linked role that the Auto Scaling group uses to call other AWS services on your behalf.

        By default, Amazon EC2 Auto Scaling uses a service-linked role named ``AWSServiceRoleForAutoScaling`` , which it creates if it does not exist. For more information, see `Service-linked roles for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-service-linked-role.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-autoscaling-autoscalinggroup-servicelinkedrolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "serviceLinkedRoleArn"))

    @service_linked_role_arn.setter
    def service_linked_role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "serviceLinkedRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetGroupArns")
    def target_group_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''One or more Amazon Resource Names (ARN) of load balancer target groups to associate with the Auto Scaling group.

        Instances are registered as targets in a target group, and traffic is routed to the target group. For more information, see `Elastic Load Balancing and Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-load-balancer.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-targetgrouparns
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "targetGroupArns"))

    @target_group_arns.setter
    def target_group_arns(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "targetGroupArns", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="terminationPolicies")
    def termination_policies(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A policy or a list of policies that are used to select the instances to terminate.

        The policies are executed in the order that you list them. The termination policies supported by Amazon EC2 Auto Scaling: ``OldestInstance`` , ``OldestLaunchConfiguration`` , ``NewestInstance`` , ``ClosestToNextInstanceHour`` , ``Default`` , ``OldestLaunchTemplate`` , and ``AllocationStrategy`` . For more information, see `Controlling which Auto Scaling instances terminate during scale in <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-termpolicy
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "terminationPolicies"))

    @termination_policies.setter
    def termination_policies(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "terminationPolicies", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpcZoneIdentifier")
    def vpc_zone_identifier(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of subnet IDs for a virtual private cloud (VPC) where instances in the Auto Scaling group can be created.

        If you specify ``VPCZoneIdentifier`` with ``AvailabilityZones`` , the subnets that you specify for this property must reside in those Availability Zones.

        If this resource specifies public subnets and is also in a VPC that is defined in the same stack template, you must use the `DependsOn attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ to declare a dependency on the `VPC-gateway attachment <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc-gateway-attachment.html>`_ .
        .. epigraph::

           When you update ``VPCZoneIdentifier`` , this retains the same Auto Scaling group and replaces old instances with new ones, according to the specified subnets. You can optionally specify how CloudFormation handles these updates by using an `UpdatePolicy attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-vpczoneidentifier
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "vpcZoneIdentifier"))

    @vpc_zone_identifier.setter
    def vpc_zone_identifier(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "vpcZoneIdentifier", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.AcceleratorCountRequestProperty",
        jsii_struct_bases=[],
        name_mapping={"max": "max", "min": "min"},
    )
    class AcceleratorCountRequestProperty:
        def __init__(
            self,
            *,
            max: typing.Optional[jsii.Number] = None,
            min: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``AcceleratorCountRequest`` is a property of the ``InstanceRequirements`` property of the `AWS::AutoScaling::AutoScalingGroup LaunchTemplateOverrides <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html>`_ property type that describes the minimum and maximum number of accelerators for an instance type.

            :param max: The maximum value.
            :param min: The minimum value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-acceleratorcountrequest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                accelerator_count_request_property = autoscaling.CfnAutoScalingGroup.AcceleratorCountRequestProperty(
                    max=123,
                    min=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max is not None:
                self._values["max"] = max
            if min is not None:
                self._values["min"] = min

        @builtins.property
        def max(self) -> typing.Optional[jsii.Number]:
            '''The maximum value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-acceleratorcountrequest.html#cfn-autoscaling-autoscalinggroup-acceleratorcountrequest-max
            '''
            result = self._values.get("max")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min(self) -> typing.Optional[jsii.Number]:
            '''The minimum value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-acceleratorcountrequest.html#cfn-autoscaling-autoscalinggroup-acceleratorcountrequest-min
            '''
            result = self._values.get("min")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AcceleratorCountRequestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.AcceleratorTotalMemoryMiBRequestProperty",
        jsii_struct_bases=[],
        name_mapping={"max": "max", "min": "min"},
    )
    class AcceleratorTotalMemoryMiBRequestProperty:
        def __init__(
            self,
            *,
            max: typing.Optional[jsii.Number] = None,
            min: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``AcceleratorTotalMemoryMiBRequest`` is a property of the ``InstanceRequirements`` property of the `AWS::AutoScaling::AutoScalingGroup LaunchTemplateOverrides <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html>`_ property type that describes the minimum and maximum total memory size for the accelerators for an instance type, in MiB.

            :param max: The memory maximum in MiB.
            :param min: The memory minimum in MiB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-acceleratortotalmemorymibrequest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                accelerator_total_memory_mi_bRequest_property = autoscaling.CfnAutoScalingGroup.AcceleratorTotalMemoryMiBRequestProperty(
                    max=123,
                    min=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max is not None:
                self._values["max"] = max
            if min is not None:
                self._values["min"] = min

        @builtins.property
        def max(self) -> typing.Optional[jsii.Number]:
            '''The memory maximum in MiB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-acceleratortotalmemorymibrequest.html#cfn-autoscaling-autoscalinggroup-acceleratortotalmemorymibrequest-max
            '''
            result = self._values.get("max")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min(self) -> typing.Optional[jsii.Number]:
            '''The memory minimum in MiB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-acceleratortotalmemorymibrequest.html#cfn-autoscaling-autoscalinggroup-acceleratortotalmemorymibrequest-min
            '''
            result = self._values.get("min")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "AcceleratorTotalMemoryMiBRequestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.BaselineEbsBandwidthMbpsRequestProperty",
        jsii_struct_bases=[],
        name_mapping={"max": "max", "min": "min"},
    )
    class BaselineEbsBandwidthMbpsRequestProperty:
        def __init__(
            self,
            *,
            max: typing.Optional[jsii.Number] = None,
            min: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``BaselineEbsBandwidthMbpsRequest`` is a property of the ``InstanceRequirements`` property of the `AWS::AutoScaling::AutoScalingGroup LaunchTemplateOverrides <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html>`_ property type that describes the minimum and maximum baseline bandwidth performance for an instance type, in Mbps.

            :param max: The maximum value in Mbps.
            :param min: The minimum value in Mbps.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-baselineebsbandwidthmbpsrequest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                baseline_ebs_bandwidth_mbps_request_property = autoscaling.CfnAutoScalingGroup.BaselineEbsBandwidthMbpsRequestProperty(
                    max=123,
                    min=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max is not None:
                self._values["max"] = max
            if min is not None:
                self._values["min"] = min

        @builtins.property
        def max(self) -> typing.Optional[jsii.Number]:
            '''The maximum value in Mbps.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-baselineebsbandwidthmbpsrequest.html#cfn-autoscaling-autoscalinggroup-baselineebsbandwidthmbpsrequest-max
            '''
            result = self._values.get("max")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min(self) -> typing.Optional[jsii.Number]:
            '''The minimum value in Mbps.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-baselineebsbandwidthmbpsrequest.html#cfn-autoscaling-autoscalinggroup-baselineebsbandwidthmbpsrequest-min
            '''
            result = self._values.get("min")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BaselineEbsBandwidthMbpsRequestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.InstanceRequirementsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "accelerator_count": "acceleratorCount",
            "accelerator_manufacturers": "acceleratorManufacturers",
            "accelerator_names": "acceleratorNames",
            "accelerator_total_memory_mib": "acceleratorTotalMemoryMiB",
            "accelerator_types": "acceleratorTypes",
            "bare_metal": "bareMetal",
            "baseline_ebs_bandwidth_mbps": "baselineEbsBandwidthMbps",
            "burstable_performance": "burstablePerformance",
            "cpu_manufacturers": "cpuManufacturers",
            "excluded_instance_types": "excludedInstanceTypes",
            "instance_generations": "instanceGenerations",
            "local_storage": "localStorage",
            "local_storage_types": "localStorageTypes",
            "memory_gib_per_v_cpu": "memoryGiBPerVCpu",
            "memory_mib": "memoryMiB",
            "network_interface_count": "networkInterfaceCount",
            "on_demand_max_price_percentage_over_lowest_price": "onDemandMaxPricePercentageOverLowestPrice",
            "require_hibernate_support": "requireHibernateSupport",
            "spot_max_price_percentage_over_lowest_price": "spotMaxPricePercentageOverLowestPrice",
            "total_local_storage_gb": "totalLocalStorageGb",
            "v_cpu_count": "vCpuCount",
        },
    )
    class InstanceRequirementsProperty:
        def __init__(
            self,
            *,
            accelerator_count: typing.Optional[typing.Union["CfnAutoScalingGroup.AcceleratorCountRequestProperty", _IResolvable_da3f097b]] = None,
            accelerator_manufacturers: typing.Optional[typing.Sequence[builtins.str]] = None,
            accelerator_names: typing.Optional[typing.Sequence[builtins.str]] = None,
            accelerator_total_memory_mib: typing.Optional[typing.Union["CfnAutoScalingGroup.AcceleratorTotalMemoryMiBRequestProperty", _IResolvable_da3f097b]] = None,
            accelerator_types: typing.Optional[typing.Sequence[builtins.str]] = None,
            bare_metal: typing.Optional[builtins.str] = None,
            baseline_ebs_bandwidth_mbps: typing.Optional[typing.Union["CfnAutoScalingGroup.BaselineEbsBandwidthMbpsRequestProperty", _IResolvable_da3f097b]] = None,
            burstable_performance: typing.Optional[builtins.str] = None,
            cpu_manufacturers: typing.Optional[typing.Sequence[builtins.str]] = None,
            excluded_instance_types: typing.Optional[typing.Sequence[builtins.str]] = None,
            instance_generations: typing.Optional[typing.Sequence[builtins.str]] = None,
            local_storage: typing.Optional[builtins.str] = None,
            local_storage_types: typing.Optional[typing.Sequence[builtins.str]] = None,
            memory_gib_per_v_cpu: typing.Optional[typing.Union["CfnAutoScalingGroup.MemoryGiBPerVCpuRequestProperty", _IResolvable_da3f097b]] = None,
            memory_mib: typing.Optional[typing.Union["CfnAutoScalingGroup.MemoryMiBRequestProperty", _IResolvable_da3f097b]] = None,
            network_interface_count: typing.Optional[typing.Union["CfnAutoScalingGroup.NetworkInterfaceCountRequestProperty", _IResolvable_da3f097b]] = None,
            on_demand_max_price_percentage_over_lowest_price: typing.Optional[jsii.Number] = None,
            require_hibernate_support: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            spot_max_price_percentage_over_lowest_price: typing.Optional[jsii.Number] = None,
            total_local_storage_gb: typing.Optional[typing.Union["CfnAutoScalingGroup.TotalLocalStorageGBRequestProperty", _IResolvable_da3f097b]] = None,
            v_cpu_count: typing.Optional[typing.Union["CfnAutoScalingGroup.VCpuCountRequestProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''``InstanceRequirements`` specifies a set of requirements for the types of instances that can be launched by an ``AWS::AutoScaling::AutoScalingGroup`` resource.

            ``InstanceRequirements`` is a property of the ``LaunchTemplateOverrides`` property of the `AWS::AutoScaling::AutoScalingGroup LaunchTemplate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplate.html>`_ property type.

            You must specify ``VCpuCount`` and ``MemoryMiB`` , but all other properties are optional. Any unspecified optional property is set to its default.

            When you specify multiple properties, you get instance types that satisfy all of the specified properties. If you specify multiple values for a property, you get instance types that satisfy any of the specified values.

            For more information, see `Creating an Auto Scaling group using attribute-based instance type selection <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-instance-type-requirements.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :param accelerator_count: The minimum and maximum number of accelerators (GPUs, FPGAs, or AWS Inferentia chips) for an instance type. To exclude accelerator-enabled instance types, set ``Max`` to ``0`` . Default: No minimum or maximum
            :param accelerator_manufacturers: Indicates whether instance types must have accelerators by specific manufacturers. - For instance types with NVIDIA devices, specify ``nvidia`` . - For instance types with AMD devices, specify ``amd`` . - For instance types with AWS devices, specify ``amazon-web-services`` . - For instance types with Xilinx devices, specify ``xilinx`` . Default: Any manufacturer
            :param accelerator_names: Lists the accelerators that must be on an instance type. - For instance types with NVIDIA A100 GPUs, specify ``a100`` . - For instance types with NVIDIA V100 GPUs, specify ``v100`` . - For instance types with NVIDIA K80 GPUs, specify ``k80`` . - For instance types with NVIDIA T4 GPUs, specify ``t4`` . - For instance types with NVIDIA M60 GPUs, specify ``m60`` . - For instance types with AMD Radeon Pro V520 GPUs, specify ``radeon-pro-v520`` . - For instance types with Xilinx VU9P FPGAs, specify ``vu9p`` . Default: Any accelerator
            :param accelerator_total_memory_mib: The minimum and maximum total memory size for the accelerators on an instance type, in MiB. Default: No minimum or maximum
            :param accelerator_types: Lists the accelerator types that must be on an instance type. - For instance types with GPU accelerators, specify ``gpu`` . - For instance types with FPGA accelerators, specify ``fpga`` . - For instance types with inference accelerators, specify ``inference`` . Default: Any accelerator type
            :param bare_metal: Indicates whether bare metal instance types are included, excluded, or required. Default: ``excluded``
            :param baseline_ebs_bandwidth_mbps: The minimum and maximum baseline bandwidth performance for an instance type, in Mbps. For more information, see `Amazon EBS–optimized instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html>`_ in the *Amazon EC2 User Guide for Linux Instances* . Default: No minimum or maximum
            :param burstable_performance: Indicates whether burstable performance instance types are included, excluded, or required. For more information, see `Burstable performance instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/burstable-performance-instances.html>`_ in the *Amazon EC2 User Guide for Linux Instances* . Default: ``excluded``
            :param cpu_manufacturers: Lists which specific CPU manufacturers to include. - For instance types with Intel CPUs, specify ``intel`` . - For instance types with AMD CPUs, specify ``amd`` . - For instance types with AWS CPUs, specify ``amazon-web-services`` . .. epigraph:: Don't confuse the CPU hardware manufacturer with the CPU hardware architecture. Instances will be launched with a compatible CPU architecture based on the Amazon Machine Image (AMI) that you specify in your launch template. Default: Any manufacturer
            :param excluded_instance_types: Lists which instance types to exclude. You can use strings with one or more wild cards, represented by an asterisk ( ``*`` ). The following are examples: ``c5*`` , ``m5a.*`` , ``r*`` , ``*3*`` . For example, if you specify ``c5*`` , you are excluding the entire C5 instance family, which includes all C5a and C5n instance types. If you specify ``m5a.*`` , you are excluding all the M5a instance types, but not the M5n instance types. Default: No excluded instance types
            :param instance_generations: Indicates whether current or previous generation instance types are included. - For current generation instance types, specify ``current`` . The current generation includes EC2 instance types currently recommended for use. This typically includes the latest two to three generations in each instance family. For more information, see `Instance types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html>`_ in the *Amazon EC2 User Guide for Linux Instances* . - For previous generation instance types, specify ``previous`` . Default: Any current or previous generation
            :param local_storage: Indicates whether instance types with instance store volumes are included, excluded, or required. For more information, see `Amazon EC2 instance store <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/InstanceStorage.html>`_ in the *Amazon EC2 User Guide for Linux Instances* . Default: ``included``
            :param local_storage_types: Indicates the type of local storage that is required. - For instance types with hard disk drive (HDD) storage, specify ``hdd`` . - For instance types with solid state drive (SSD) storage, specify ``sdd`` . Default: Any local storage type
            :param memory_gib_per_v_cpu: The minimum and maximum amount of memory per vCPU for an instance type, in GiB. Default: No minimum or maximum
            :param memory_mib: The minimum and maximum instance memory size for an instance type, in MiB.
            :param network_interface_count: The minimum and maximum number of network interfaces for an instance type. Default: No minimum or maximum
            :param on_demand_max_price_percentage_over_lowest_price: The price protection threshold for On-Demand Instances. This is the maximum you’ll pay for an On-Demand Instance, expressed as a percentage higher than the cheapest M, C, or R instance type with your specified attributes. When Amazon EC2 Auto Scaling selects instance types with your attributes, we will exclude instance types whose price is higher than your threshold. The parameter accepts an integer, which Amazon EC2 Auto Scaling interprets as a percentage. To turn off price protection, specify a high value, such as ``999999`` . If you set ``DesiredCapacityType`` to ``vcpu`` or ``memory-mib`` , the price protection threshold is applied based on the per vCPU or per memory price instead of the per instance price. Default: ``20``
            :param require_hibernate_support: Indicates whether instance types must provide On-Demand Instance hibernation support. Default: ``false``
            :param spot_max_price_percentage_over_lowest_price: The price protection threshold for Spot Instances. This is the maximum you’ll pay for a Spot Instance, expressed as a percentage higher than the cheapest M, C, or R instance type with your specified attributes. When Amazon EC2 Auto Scaling selects instance types with your attributes, we will exclude instance types whose price is higher than your threshold. The parameter accepts an integer, which Amazon EC2 Auto Scaling interprets as a percentage. To turn off price protection, specify a high value, such as ``999999`` . If you set ``DesiredCapacityType`` to ``vcpu`` or ``memory-mib`` , the price protection threshold is applied based on the per vCPU or per memory price instead of the per instance price. Default: ``100``
            :param total_local_storage_gb: The minimum and maximum total local storage size for an instance type, in GB. Default: No minimum or maximum
            :param v_cpu_count: The minimum and maximum number of vCPUs for an instance type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                instance_requirements_property = autoscaling.CfnAutoScalingGroup.InstanceRequirementsProperty(
                    accelerator_count=autoscaling.CfnAutoScalingGroup.AcceleratorCountRequestProperty(
                        max=123,
                        min=123
                    ),
                    accelerator_manufacturers=["acceleratorManufacturers"],
                    accelerator_names=["acceleratorNames"],
                    accelerator_total_memory_mi_b=autoscaling.CfnAutoScalingGroup.AcceleratorTotalMemoryMiBRequestProperty(
                        max=123,
                        min=123
                    ),
                    accelerator_types=["acceleratorTypes"],
                    bare_metal="bareMetal",
                    baseline_ebs_bandwidth_mbps=autoscaling.CfnAutoScalingGroup.BaselineEbsBandwidthMbpsRequestProperty(
                        max=123,
                        min=123
                    ),
                    burstable_performance="burstablePerformance",
                    cpu_manufacturers=["cpuManufacturers"],
                    excluded_instance_types=["excludedInstanceTypes"],
                    instance_generations=["instanceGenerations"],
                    local_storage="localStorage",
                    local_storage_types=["localStorageTypes"],
                    memory_gi_bPer_vCpu=autoscaling.CfnAutoScalingGroup.MemoryGiBPerVCpuRequestProperty(
                        max=123,
                        min=123
                    ),
                    memory_mi_b=autoscaling.CfnAutoScalingGroup.MemoryMiBRequestProperty(
                        max=123,
                        min=123
                    ),
                    network_interface_count=autoscaling.CfnAutoScalingGroup.NetworkInterfaceCountRequestProperty(
                        max=123,
                        min=123
                    ),
                    on_demand_max_price_percentage_over_lowest_price=123,
                    require_hibernate_support=False,
                    spot_max_price_percentage_over_lowest_price=123,
                    total_local_storage_gb=autoscaling.CfnAutoScalingGroup.TotalLocalStorageGBRequestProperty(
                        max=123,
                        min=123
                    ),
                    v_cpu_count=autoscaling.CfnAutoScalingGroup.VCpuCountRequestProperty(
                        max=123,
                        min=123
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if accelerator_count is not None:
                self._values["accelerator_count"] = accelerator_count
            if accelerator_manufacturers is not None:
                self._values["accelerator_manufacturers"] = accelerator_manufacturers
            if accelerator_names is not None:
                self._values["accelerator_names"] = accelerator_names
            if accelerator_total_memory_mib is not None:
                self._values["accelerator_total_memory_mib"] = accelerator_total_memory_mib
            if accelerator_types is not None:
                self._values["accelerator_types"] = accelerator_types
            if bare_metal is not None:
                self._values["bare_metal"] = bare_metal
            if baseline_ebs_bandwidth_mbps is not None:
                self._values["baseline_ebs_bandwidth_mbps"] = baseline_ebs_bandwidth_mbps
            if burstable_performance is not None:
                self._values["burstable_performance"] = burstable_performance
            if cpu_manufacturers is not None:
                self._values["cpu_manufacturers"] = cpu_manufacturers
            if excluded_instance_types is not None:
                self._values["excluded_instance_types"] = excluded_instance_types
            if instance_generations is not None:
                self._values["instance_generations"] = instance_generations
            if local_storage is not None:
                self._values["local_storage"] = local_storage
            if local_storage_types is not None:
                self._values["local_storage_types"] = local_storage_types
            if memory_gib_per_v_cpu is not None:
                self._values["memory_gib_per_v_cpu"] = memory_gib_per_v_cpu
            if memory_mib is not None:
                self._values["memory_mib"] = memory_mib
            if network_interface_count is not None:
                self._values["network_interface_count"] = network_interface_count
            if on_demand_max_price_percentage_over_lowest_price is not None:
                self._values["on_demand_max_price_percentage_over_lowest_price"] = on_demand_max_price_percentage_over_lowest_price
            if require_hibernate_support is not None:
                self._values["require_hibernate_support"] = require_hibernate_support
            if spot_max_price_percentage_over_lowest_price is not None:
                self._values["spot_max_price_percentage_over_lowest_price"] = spot_max_price_percentage_over_lowest_price
            if total_local_storage_gb is not None:
                self._values["total_local_storage_gb"] = total_local_storage_gb
            if v_cpu_count is not None:
                self._values["v_cpu_count"] = v_cpu_count

        @builtins.property
        def accelerator_count(
            self,
        ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.AcceleratorCountRequestProperty", _IResolvable_da3f097b]]:
            '''The minimum and maximum number of accelerators (GPUs, FPGAs, or AWS Inferentia chips) for an instance type.

            To exclude accelerator-enabled instance types, set ``Max`` to ``0`` .

            Default: No minimum or maximum

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-acceleratorcount
            '''
            result = self._values.get("accelerator_count")
            return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.AcceleratorCountRequestProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def accelerator_manufacturers(
            self,
        ) -> typing.Optional[typing.List[builtins.str]]:
            '''Indicates whether instance types must have accelerators by specific manufacturers.

            - For instance types with NVIDIA devices, specify ``nvidia`` .
            - For instance types with AMD devices, specify ``amd`` .
            - For instance types with AWS devices, specify ``amazon-web-services`` .
            - For instance types with Xilinx devices, specify ``xilinx`` .

            Default: Any manufacturer

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-acceleratormanufacturers
            '''
            result = self._values.get("accelerator_manufacturers")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def accelerator_names(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Lists the accelerators that must be on an instance type.

            - For instance types with NVIDIA A100 GPUs, specify ``a100`` .
            - For instance types with NVIDIA V100 GPUs, specify ``v100`` .
            - For instance types with NVIDIA K80 GPUs, specify ``k80`` .
            - For instance types with NVIDIA T4 GPUs, specify ``t4`` .
            - For instance types with NVIDIA M60 GPUs, specify ``m60`` .
            - For instance types with AMD Radeon Pro V520 GPUs, specify ``radeon-pro-v520`` .
            - For instance types with Xilinx VU9P FPGAs, specify ``vu9p`` .

            Default: Any accelerator

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-acceleratornames
            '''
            result = self._values.get("accelerator_names")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def accelerator_total_memory_mib(
            self,
        ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.AcceleratorTotalMemoryMiBRequestProperty", _IResolvable_da3f097b]]:
            '''The minimum and maximum total memory size for the accelerators on an instance type, in MiB.

            Default: No minimum or maximum

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-acceleratortotalmemorymib
            '''
            result = self._values.get("accelerator_total_memory_mib")
            return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.AcceleratorTotalMemoryMiBRequestProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def accelerator_types(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Lists the accelerator types that must be on an instance type.

            - For instance types with GPU accelerators, specify ``gpu`` .
            - For instance types with FPGA accelerators, specify ``fpga`` .
            - For instance types with inference accelerators, specify ``inference`` .

            Default: Any accelerator type

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-acceleratortypes
            '''
            result = self._values.get("accelerator_types")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def bare_metal(self) -> typing.Optional[builtins.str]:
            '''Indicates whether bare metal instance types are included, excluded, or required.

            Default: ``excluded``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-baremetal
            '''
            result = self._values.get("bare_metal")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def baseline_ebs_bandwidth_mbps(
            self,
        ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.BaselineEbsBandwidthMbpsRequestProperty", _IResolvable_da3f097b]]:
            '''The minimum and maximum baseline bandwidth performance for an instance type, in Mbps.

            For more information, see `Amazon EBS–optimized instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

            Default: No minimum or maximum

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-baselineebsbandwidthmbps
            '''
            result = self._values.get("baseline_ebs_bandwidth_mbps")
            return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.BaselineEbsBandwidthMbpsRequestProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def burstable_performance(self) -> typing.Optional[builtins.str]:
            '''Indicates whether burstable performance instance types are included, excluded, or required.

            For more information, see `Burstable performance instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/burstable-performance-instances.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

            Default: ``excluded``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-burstableperformance
            '''
            result = self._values.get("burstable_performance")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def cpu_manufacturers(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Lists which specific CPU manufacturers to include.

            - For instance types with Intel CPUs, specify ``intel`` .
            - For instance types with AMD CPUs, specify ``amd`` .
            - For instance types with AWS CPUs, specify ``amazon-web-services`` .

            .. epigraph::

               Don't confuse the CPU hardware manufacturer with the CPU hardware architecture. Instances will be launched with a compatible CPU architecture based on the Amazon Machine Image (AMI) that you specify in your launch template.

            Default: Any manufacturer

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-cpumanufacturers
            '''
            result = self._values.get("cpu_manufacturers")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def excluded_instance_types(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Lists which instance types to exclude.

            You can use strings with one or more wild cards, represented by an asterisk ( ``*`` ). The following are examples: ``c5*`` , ``m5a.*`` , ``r*`` , ``*3*`` .

            For example, if you specify ``c5*`` , you are excluding the entire C5 instance family, which includes all C5a and C5n instance types. If you specify ``m5a.*`` , you are excluding all the M5a instance types, but not the M5n instance types.

            Default: No excluded instance types

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-excludedinstancetypes
            '''
            result = self._values.get("excluded_instance_types")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def instance_generations(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Indicates whether current or previous generation instance types are included.

            - For current generation instance types, specify ``current`` . The current generation includes EC2 instance types currently recommended for use. This typically includes the latest two to three generations in each instance family. For more information, see `Instance types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
            - For previous generation instance types, specify ``previous`` .

            Default: Any current or previous generation

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-instancegenerations
            '''
            result = self._values.get("instance_generations")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def local_storage(self) -> typing.Optional[builtins.str]:
            '''Indicates whether instance types with instance store volumes are included, excluded, or required.

            For more information, see `Amazon EC2 instance store <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/InstanceStorage.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

            Default: ``included``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-localstorage
            '''
            result = self._values.get("local_storage")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def local_storage_types(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Indicates the type of local storage that is required.

            - For instance types with hard disk drive (HDD) storage, specify ``hdd`` .
            - For instance types with solid state drive (SSD) storage, specify ``sdd`` .

            Default: Any local storage type

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-localstoragetypes
            '''
            result = self._values.get("local_storage_types")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def memory_gib_per_v_cpu(
            self,
        ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.MemoryGiBPerVCpuRequestProperty", _IResolvable_da3f097b]]:
            '''The minimum and maximum amount of memory per vCPU for an instance type, in GiB.

            Default: No minimum or maximum

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-memorygibpervcpu
            '''
            result = self._values.get("memory_gib_per_v_cpu")
            return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.MemoryGiBPerVCpuRequestProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def memory_mib(
            self,
        ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.MemoryMiBRequestProperty", _IResolvable_da3f097b]]:
            '''The minimum and maximum instance memory size for an instance type, in MiB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-memorymib
            '''
            result = self._values.get("memory_mib")
            return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.MemoryMiBRequestProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def network_interface_count(
            self,
        ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.NetworkInterfaceCountRequestProperty", _IResolvable_da3f097b]]:
            '''The minimum and maximum number of network interfaces for an instance type.

            Default: No minimum or maximum

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-networkinterfacecount
            '''
            result = self._values.get("network_interface_count")
            return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.NetworkInterfaceCountRequestProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def on_demand_max_price_percentage_over_lowest_price(
            self,
        ) -> typing.Optional[jsii.Number]:
            '''The price protection threshold for On-Demand Instances.

            This is the maximum you’ll pay for an On-Demand Instance, expressed as a percentage higher than the cheapest M, C, or R instance type with your specified attributes. When Amazon EC2 Auto Scaling selects instance types with your attributes, we will exclude instance types whose price is higher than your threshold. The parameter accepts an integer, which Amazon EC2 Auto Scaling interprets as a percentage. To turn off price protection, specify a high value, such as ``999999`` .

            If you set ``DesiredCapacityType`` to ``vcpu`` or ``memory-mib`` , the price protection threshold is applied based on the per vCPU or per memory price instead of the per instance price.

            Default: ``20``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-ondemandmaxpricepercentageoverlowestprice
            '''
            result = self._values.get("on_demand_max_price_percentage_over_lowest_price")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def require_hibernate_support(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether instance types must provide On-Demand Instance hibernation support.

            Default: ``false``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-requirehibernatesupport
            '''
            result = self._values.get("require_hibernate_support")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def spot_max_price_percentage_over_lowest_price(
            self,
        ) -> typing.Optional[jsii.Number]:
            '''The price protection threshold for Spot Instances.

            This is the maximum you’ll pay for a Spot Instance, expressed as a percentage higher than the cheapest M, C, or R instance type with your specified attributes. When Amazon EC2 Auto Scaling selects instance types with your attributes, we will exclude instance types whose price is higher than your threshold. The parameter accepts an integer, which Amazon EC2 Auto Scaling interprets as a percentage. To turn off price protection, specify a high value, such as ``999999`` .

            If you set ``DesiredCapacityType`` to ``vcpu`` or ``memory-mib`` , the price protection threshold is applied based on the per vCPU or per memory price instead of the per instance price.

            Default: ``100``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-spotmaxpricepercentageoverlowestprice
            '''
            result = self._values.get("spot_max_price_percentage_over_lowest_price")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def total_local_storage_gb(
            self,
        ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.TotalLocalStorageGBRequestProperty", _IResolvable_da3f097b]]:
            '''The minimum and maximum total local storage size for an instance type, in GB.

            Default: No minimum or maximum

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-totallocalstoragegb
            '''
            result = self._values.get("total_local_storage_gb")
            return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.TotalLocalStorageGBRequestProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def v_cpu_count(
            self,
        ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.VCpuCountRequestProperty", _IResolvable_da3f097b]]:
            '''The minimum and maximum number of vCPUs for an instance type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancerequirements.html#cfn-autoscaling-autoscalinggroup-instancerequirements-vcpucount
            '''
            result = self._values.get("v_cpu_count")
            return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.VCpuCountRequestProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceRequirementsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.InstancesDistributionProperty",
        jsii_struct_bases=[],
        name_mapping={
            "on_demand_allocation_strategy": "onDemandAllocationStrategy",
            "on_demand_base_capacity": "onDemandBaseCapacity",
            "on_demand_percentage_above_base_capacity": "onDemandPercentageAboveBaseCapacity",
            "spot_allocation_strategy": "spotAllocationStrategy",
            "spot_instance_pools": "spotInstancePools",
            "spot_max_price": "spotMaxPrice",
        },
    )
    class InstancesDistributionProperty:
        def __init__(
            self,
            *,
            on_demand_allocation_strategy: typing.Optional[builtins.str] = None,
            on_demand_base_capacity: typing.Optional[jsii.Number] = None,
            on_demand_percentage_above_base_capacity: typing.Optional[jsii.Number] = None,
            spot_allocation_strategy: typing.Optional[builtins.str] = None,
            spot_instance_pools: typing.Optional[jsii.Number] = None,
            spot_max_price: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``InstancesDistribution`` is a property of the `AWS::AutoScaling::AutoScalingGroup MixedInstancesPolicy <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-mixedinstancespolicy.html>`_ property type that describes an instances distribution for an Auto Scaling group. All properties have a default value, which is the value that is used or assumed when the property is not specified.

            The instances distribution specifies the distribution of On-Demand Instances and Spot Instances, the maximum price to pay for Spot Instances, and how the Auto Scaling group allocates instance types to fulfill On-Demand and Spot capacities.

            For more information and example configurations, see `Auto Scaling groups with multiple instance types and purchase options <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :param on_demand_allocation_strategy: The order of the launch template overrides to use in fulfilling On-Demand capacity. If you specify ``lowest-price`` , Amazon EC2 Auto Scaling uses price to determine the order, launching the lowest price first. If you specify ``prioritized`` , Amazon EC2 Auto Scaling uses the priority that you assigned to each launch template override, launching the highest priority first. If all your On-Demand capacity cannot be fulfilled using your highest priority instance, then Amazon EC2 Auto Scaling launches the remaining capacity using the second priority instance type, and so on. Default: ``lowest-price`` for Auto Scaling groups that specify the ``InstanceRequirements`` property in the overrides and ``prioritized`` for Auto Scaling groups that don't.
            :param on_demand_base_capacity: The minimum amount of the Auto Scaling group's capacity that must be fulfilled by On-Demand Instances. This base portion is launched first as your group scales. If you specify weights for the instance types in the overrides, the base capacity is measured in the same unit of measurement as the instance types. If you specify the ``InstanceRequirements`` property in the overrides, the base capacity is measured in the same unit of measurement as your group's desired capacity. Default: ``0`` .. epigraph:: An update to this setting means a gradual replacement of instances to adjust the current On-Demand Instance levels. When replacing instances, Amazon EC2 Auto Scaling launches new instances before terminating the previous ones.
            :param on_demand_percentage_above_base_capacity: Controls the percentages of On-Demand Instances and Spot Instances for your additional capacity beyond ``OnDemandBaseCapacity`` . Expressed as a number (for example, 20 specifies 20% On-Demand Instances, 80% Spot Instances). If set to 100, only On-Demand Instances are used. Default: ``100`` .. epigraph:: An update to this setting means a gradual replacement of instances to adjust the current On-Demand and Spot Instance levels for your additional capacity higher than the base capacity. When replacing instances, Amazon EC2 Auto Scaling launches new instances before terminating the previous ones.
            :param spot_allocation_strategy: If the allocation strategy is ``lowest-price`` , the Auto Scaling group launches instances using the Spot pools with the lowest price, and evenly allocates your instances across the number of Spot pools that you specify. If the allocation strategy is ``capacity-optimized`` (recommended), the Auto Scaling group launches instances using Spot pools that are optimally chosen based on the available Spot capacity. Alternatively, you can use ``capacity-optimized-prioritized`` and set the order of instance types in the list of launch template overrides from highest to lowest priority (from first to last in the list). Amazon EC2 Auto Scaling honors the instance type priorities on a best-effort basis but optimizes for capacity first. Default: ``lowest-price`` Valid values: ``lowest-price`` | ``capacity-optimized`` | ``capacity-optimized-prioritized``
            :param spot_instance_pools: The number of Spot Instance pools to use to allocate your Spot capacity. The Spot pools are determined from the different instance types in the overrides. Valid only when the Spot allocation strategy is ``lowest-price`` . Value must be in the range of 1–20. Default: ``2``
            :param spot_max_price: The maximum price per unit hour that you are willing to pay for a Spot Instance. If you leave the value at its default (empty), Amazon EC2 Auto Scaling uses the On-Demand price as the maximum Spot price. To remove a value that you previously set, include the property but specify an empty string ("") for the value. .. epigraph:: If your maximum price is lower than the Spot price for the instance types that you selected, your Spot Instances are not launched. Valid Range: Minimum value of 0.001

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancesdistribution.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                instances_distribution_property = autoscaling.CfnAutoScalingGroup.InstancesDistributionProperty(
                    on_demand_allocation_strategy="onDemandAllocationStrategy",
                    on_demand_base_capacity=123,
                    on_demand_percentage_above_base_capacity=123,
                    spot_allocation_strategy="spotAllocationStrategy",
                    spot_instance_pools=123,
                    spot_max_price="spotMaxPrice"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if on_demand_allocation_strategy is not None:
                self._values["on_demand_allocation_strategy"] = on_demand_allocation_strategy
            if on_demand_base_capacity is not None:
                self._values["on_demand_base_capacity"] = on_demand_base_capacity
            if on_demand_percentage_above_base_capacity is not None:
                self._values["on_demand_percentage_above_base_capacity"] = on_demand_percentage_above_base_capacity
            if spot_allocation_strategy is not None:
                self._values["spot_allocation_strategy"] = spot_allocation_strategy
            if spot_instance_pools is not None:
                self._values["spot_instance_pools"] = spot_instance_pools
            if spot_max_price is not None:
                self._values["spot_max_price"] = spot_max_price

        @builtins.property
        def on_demand_allocation_strategy(self) -> typing.Optional[builtins.str]:
            '''The order of the launch template overrides to use in fulfilling On-Demand capacity.

            If you specify ``lowest-price`` , Amazon EC2 Auto Scaling uses price to determine the order, launching the lowest price first.

            If you specify ``prioritized`` , Amazon EC2 Auto Scaling uses the priority that you assigned to each launch template override, launching the highest priority first. If all your On-Demand capacity cannot be fulfilled using your highest priority instance, then Amazon EC2 Auto Scaling launches the remaining capacity using the second priority instance type, and so on.

            Default: ``lowest-price`` for Auto Scaling groups that specify the ``InstanceRequirements`` property in the overrides and ``prioritized`` for Auto Scaling groups that don't.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancesdistribution.html#cfn-autoscaling-autoscalinggroup-instancesdistribution-ondemandallocationstrategy
            '''
            result = self._values.get("on_demand_allocation_strategy")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def on_demand_base_capacity(self) -> typing.Optional[jsii.Number]:
            '''The minimum amount of the Auto Scaling group's capacity that must be fulfilled by On-Demand Instances.

            This base portion is launched first as your group scales.

            If you specify weights for the instance types in the overrides, the base capacity is measured in the same unit of measurement as the instance types. If you specify the ``InstanceRequirements`` property in the overrides, the base capacity is measured in the same unit of measurement as your group's desired capacity.

            Default: ``0``
            .. epigraph::

               An update to this setting means a gradual replacement of instances to adjust the current On-Demand Instance levels. When replacing instances, Amazon EC2 Auto Scaling launches new instances before terminating the previous ones.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancesdistribution.html#cfn-autoscaling-autoscalinggroup-instancesdistribution-ondemandbasecapacity
            '''
            result = self._values.get("on_demand_base_capacity")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def on_demand_percentage_above_base_capacity(
            self,
        ) -> typing.Optional[jsii.Number]:
            '''Controls the percentages of On-Demand Instances and Spot Instances for your additional capacity beyond ``OnDemandBaseCapacity`` .

            Expressed as a number (for example, 20 specifies 20% On-Demand Instances, 80% Spot Instances). If set to 100, only On-Demand Instances are used.

            Default: ``100``
            .. epigraph::

               An update to this setting means a gradual replacement of instances to adjust the current On-Demand and Spot Instance levels for your additional capacity higher than the base capacity. When replacing instances, Amazon EC2 Auto Scaling launches new instances before terminating the previous ones.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancesdistribution.html#cfn-autoscaling-autoscalinggroup-instancesdistribution-ondemandpercentageabovebasecapacity
            '''
            result = self._values.get("on_demand_percentage_above_base_capacity")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def spot_allocation_strategy(self) -> typing.Optional[builtins.str]:
            '''If the allocation strategy is ``lowest-price`` , the Auto Scaling group launches instances using the Spot pools with the lowest price, and evenly allocates your instances across the number of Spot pools that you specify.

            If the allocation strategy is ``capacity-optimized`` (recommended), the Auto Scaling group launches instances using Spot pools that are optimally chosen based on the available Spot capacity. Alternatively, you can use ``capacity-optimized-prioritized`` and set the order of instance types in the list of launch template overrides from highest to lowest priority (from first to last in the list). Amazon EC2 Auto Scaling honors the instance type priorities on a best-effort basis but optimizes for capacity first.

            Default: ``lowest-price``

            Valid values: ``lowest-price`` | ``capacity-optimized`` | ``capacity-optimized-prioritized``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancesdistribution.html#cfn-autoscaling-autoscalinggroup-instancesdistribution-spotallocationstrategy
            '''
            result = self._values.get("spot_allocation_strategy")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def spot_instance_pools(self) -> typing.Optional[jsii.Number]:
            '''The number of Spot Instance pools to use to allocate your Spot capacity.

            The Spot pools are determined from the different instance types in the overrides. Valid only when the Spot allocation strategy is ``lowest-price`` . Value must be in the range of 1–20.

            Default: ``2``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancesdistribution.html#cfn-autoscaling-autoscalinggroup-instancesdistribution-spotinstancepools
            '''
            result = self._values.get("spot_instance_pools")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def spot_max_price(self) -> typing.Optional[builtins.str]:
            '''The maximum price per unit hour that you are willing to pay for a Spot Instance.

            If you leave the value at its default (empty), Amazon EC2 Auto Scaling uses the On-Demand price as the maximum Spot price. To remove a value that you previously set, include the property but specify an empty string ("") for the value.
            .. epigraph::

               If your maximum price is lower than the Spot price for the instance types that you selected, your Spot Instances are not launched.

            Valid Range: Minimum value of 0.001

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-instancesdistribution.html#cfn-autoscaling-autoscalinggroup-instancesdistribution-spotmaxprice
            '''
            result = self._values.get("spot_max_price")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstancesDistributionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.LaunchTemplateOverridesProperty",
        jsii_struct_bases=[],
        name_mapping={
            "instance_requirements": "instanceRequirements",
            "instance_type": "instanceType",
            "launch_template_specification": "launchTemplateSpecification",
            "weighted_capacity": "weightedCapacity",
        },
    )
    class LaunchTemplateOverridesProperty:
        def __init__(
            self,
            *,
            instance_requirements: typing.Optional[typing.Union["CfnAutoScalingGroup.InstanceRequirementsProperty", _IResolvable_da3f097b]] = None,
            instance_type: typing.Optional[builtins.str] = None,
            launch_template_specification: typing.Optional[typing.Union["CfnAutoScalingGroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]] = None,
            weighted_capacity: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``LaunchTemplateOverrides`` is a property of the `AWS::AutoScaling::AutoScalingGroup LaunchTemplate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplate.html>`_ property type that describes an override for a launch template.

            If you supply your own instance types, the maximum number of instance types that can be associated with an Auto Scaling group is 40. The maximum number of distinct launch templates you can define for an Auto Scaling group is 20.

            :param instance_requirements: The instance requirements. When you specify instance requirements, Amazon EC2 Auto Scaling finds instance types that satisfy your requirements, and then uses your On-Demand and Spot allocation strategies to launch instances from these instance types, in the same way as when you specify a list of specific instance types. .. epigraph:: ``InstanceRequirements`` are incompatible with the ``InstanceType`` property. If you specify both of these properties, Amazon EC2 Auto Scaling will return a ``ValidationException`` exception.
            :param instance_type: The instance type, such as ``m3.xlarge`` . You must use an instance type that is supported in your requested Region and Availability Zones. For more information, see `Available instance types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#AvailableInstanceTypes>`_ in the *Amazon EC2 User Guide for Linux Instances.*.
            :param launch_template_specification: Provides a launch template for the specified instance type or instance requirements. For example, some instance types might require a launch template with a different AMI. If not provided, Amazon EC2 Auto Scaling uses the launch template that's defined for your mixed instances policy. For more information, see `Specifying a different launch template for an instance type <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups-launch-template-overrides.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
            :param weighted_capacity: The number of capacity units provided by the instance type specified in ``InstanceType`` in terms of virtual CPUs, memory, storage, throughput, or other relative performance characteristic. When a Spot or On-Demand Instance is provisioned, the capacity units count toward the desired capacity. Amazon EC2 Auto Scaling provisions instances until the desired capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EC2 Auto Scaling can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the desired capacity is exceeded by 3 units. For more information, see `Instance weighting for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups-instance-weighting.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . Value must be in the range of 1-999. .. epigraph:: Every Auto Scaling group has three size parameters ( ``DesiredCapacity`` , ``MaxSize`` , and ``MinSize`` ). Usually, you set these sizes based on a specific number of instances. However, if you configure a mixed instances policy that defines weights for the instance types, you must specify these sizes with the same units that you use for weighting instances.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-launchtemplateoverrides.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                launch_template_overrides_property = autoscaling.CfnAutoScalingGroup.LaunchTemplateOverridesProperty(
                    instance_requirements=autoscaling.CfnAutoScalingGroup.InstanceRequirementsProperty(
                        accelerator_count=autoscaling.CfnAutoScalingGroup.AcceleratorCountRequestProperty(
                            max=123,
                            min=123
                        ),
                        accelerator_manufacturers=["acceleratorManufacturers"],
                        accelerator_names=["acceleratorNames"],
                        accelerator_total_memory_mi_b=autoscaling.CfnAutoScalingGroup.AcceleratorTotalMemoryMiBRequestProperty(
                            max=123,
                            min=123
                        ),
                        accelerator_types=["acceleratorTypes"],
                        bare_metal="bareMetal",
                        baseline_ebs_bandwidth_mbps=autoscaling.CfnAutoScalingGroup.BaselineEbsBandwidthMbpsRequestProperty(
                            max=123,
                            min=123
                        ),
                        burstable_performance="burstablePerformance",
                        cpu_manufacturers=["cpuManufacturers"],
                        excluded_instance_types=["excludedInstanceTypes"],
                        instance_generations=["instanceGenerations"],
                        local_storage="localStorage",
                        local_storage_types=["localStorageTypes"],
                        memory_gi_bPer_vCpu=autoscaling.CfnAutoScalingGroup.MemoryGiBPerVCpuRequestProperty(
                            max=123,
                            min=123
                        ),
                        memory_mi_b=autoscaling.CfnAutoScalingGroup.MemoryMiBRequestProperty(
                            max=123,
                            min=123
                        ),
                        network_interface_count=autoscaling.CfnAutoScalingGroup.NetworkInterfaceCountRequestProperty(
                            max=123,
                            min=123
                        ),
                        on_demand_max_price_percentage_over_lowest_price=123,
                        require_hibernate_support=False,
                        spot_max_price_percentage_over_lowest_price=123,
                        total_local_storage_gb=autoscaling.CfnAutoScalingGroup.TotalLocalStorageGBRequestProperty(
                            max=123,
                            min=123
                        ),
                        v_cpu_count=autoscaling.CfnAutoScalingGroup.VCpuCountRequestProperty(
                            max=123,
                            min=123
                        )
                    ),
                    instance_type="instanceType",
                    launch_template_specification=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                        version="version",
                
                        # the properties below are optional
                        launch_template_id="launchTemplateId",
                        launch_template_name="launchTemplateName"
                    ),
                    weighted_capacity="weightedCapacity"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if instance_requirements is not None:
                self._values["instance_requirements"] = instance_requirements
            if instance_type is not None:
                self._values["instance_type"] = instance_type
            if launch_template_specification is not None:
                self._values["launch_template_specification"] = launch_template_specification
            if weighted_capacity is not None:
                self._values["weighted_capacity"] = weighted_capacity

        @builtins.property
        def instance_requirements(
            self,
        ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.InstanceRequirementsProperty", _IResolvable_da3f097b]]:
            '''The instance requirements.

            When you specify instance requirements, Amazon EC2 Auto Scaling finds instance types that satisfy your requirements, and then uses your On-Demand and Spot allocation strategies to launch instances from these instance types, in the same way as when you specify a list of specific instance types.
            .. epigraph::

               ``InstanceRequirements`` are incompatible with the ``InstanceType`` property. If you specify both of these properties, Amazon EC2 Auto Scaling will return a ``ValidationException`` exception.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-launchtemplateoverrides.html#cfn-as-mixedinstancespolicy-instancerequirements
            '''
            result = self._values.get("instance_requirements")
            return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.InstanceRequirementsProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def instance_type(self) -> typing.Optional[builtins.str]:
            '''The instance type, such as ``m3.xlarge`` . You must use an instance type that is supported in your requested Region and Availability Zones. For more information, see `Available instance types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#AvailableInstanceTypes>`_ in the *Amazon EC2 User Guide for Linux Instances.*.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-launchtemplateoverrides.html#cfn-autoscaling-autoscalinggroup-launchtemplateoverrides-instancetype
            '''
            result = self._values.get("instance_type")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def launch_template_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]]:
            '''Provides a launch template for the specified instance type or instance requirements.

            For example, some instance types might require a launch template with a different AMI. If not provided, Amazon EC2 Auto Scaling uses the launch template that's defined for your mixed instances policy. For more information, see `Specifying a different launch template for an instance type <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups-launch-template-overrides.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-launchtemplateoverrides.html#cfn-autoscaling-autoscalinggroup-launchtemplateoverrides-launchtemplatespecification
            '''
            result = self._values.get("launch_template_specification")
            return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def weighted_capacity(self) -> typing.Optional[builtins.str]:
            '''The number of capacity units provided by the instance type specified in ``InstanceType`` in terms of virtual CPUs, memory, storage, throughput, or other relative performance characteristic.

            When a Spot or On-Demand Instance is provisioned, the capacity units count toward the desired capacity. Amazon EC2 Auto Scaling provisions instances until the desired capacity is totally fulfilled, even if this results in an overage. For example, if there are 2 units remaining to fulfill capacity, and Amazon EC2 Auto Scaling can only provision an instance with a ``WeightedCapacity`` of 5 units, the instance is provisioned, and the desired capacity is exceeded by 3 units. For more information, see `Instance weighting for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups-instance-weighting.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . Value must be in the range of 1-999.
            .. epigraph::

               Every Auto Scaling group has three size parameters ( ``DesiredCapacity`` , ``MaxSize`` , and ``MinSize`` ). Usually, you set these sizes based on a specific number of instances. However, if you configure a mixed instances policy that defines weights for the instance types, you must specify these sizes with the same units that you use for weighting instances.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-launchtemplateoverrides.html#cfn-autoscaling-autoscalinggroup-launchtemplateoverrides-weightedcapacity
            '''
            result = self._values.get("weighted_capacity")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LaunchTemplateOverridesProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.LaunchTemplateProperty",
        jsii_struct_bases=[],
        name_mapping={
            "launch_template_specification": "launchTemplateSpecification",
            "overrides": "overrides",
        },
    )
    class LaunchTemplateProperty:
        def __init__(
            self,
            *,
            launch_template_specification: typing.Union["CfnAutoScalingGroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b],
            overrides: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnAutoScalingGroup.LaunchTemplateOverridesProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''``LaunchTemplate`` is a property of the `AWS::AutoScaling::AutoScalingGroup MixedInstancesPolicy <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-mixedinstancespolicy.html>`_ property type that describes a launch template and overrides. The overrides are used to override the instance type specified by the launch template with multiple instance types that can be used to launch On-Demand Instances and Spot Instances.

            :param launch_template_specification: The launch template to use.
            :param overrides: Any properties that you specify override the same properties in the launch template. If not provided, Amazon EC2 Auto Scaling uses the instance type or instance requirements specified in the launch template when it launches an instance. The overrides can include either one or more instance types or a set of instance requirements, but not both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-launchtemplate.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                launch_template_property = autoscaling.CfnAutoScalingGroup.LaunchTemplateProperty(
                    launch_template_specification=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                        version="version",
                
                        # the properties below are optional
                        launch_template_id="launchTemplateId",
                        launch_template_name="launchTemplateName"
                    ),
                
                    # the properties below are optional
                    overrides=[autoscaling.CfnAutoScalingGroup.LaunchTemplateOverridesProperty(
                        instance_requirements=autoscaling.CfnAutoScalingGroup.InstanceRequirementsProperty(
                            accelerator_count=autoscaling.CfnAutoScalingGroup.AcceleratorCountRequestProperty(
                                max=123,
                                min=123
                            ),
                            accelerator_manufacturers=["acceleratorManufacturers"],
                            accelerator_names=["acceleratorNames"],
                            accelerator_total_memory_mi_b=autoscaling.CfnAutoScalingGroup.AcceleratorTotalMemoryMiBRequestProperty(
                                max=123,
                                min=123
                            ),
                            accelerator_types=["acceleratorTypes"],
                            bare_metal="bareMetal",
                            baseline_ebs_bandwidth_mbps=autoscaling.CfnAutoScalingGroup.BaselineEbsBandwidthMbpsRequestProperty(
                                max=123,
                                min=123
                            ),
                            burstable_performance="burstablePerformance",
                            cpu_manufacturers=["cpuManufacturers"],
                            excluded_instance_types=["excludedInstanceTypes"],
                            instance_generations=["instanceGenerations"],
                            local_storage="localStorage",
                            local_storage_types=["localStorageTypes"],
                            memory_gi_bPer_vCpu=autoscaling.CfnAutoScalingGroup.MemoryGiBPerVCpuRequestProperty(
                                max=123,
                                min=123
                            ),
                            memory_mi_b=autoscaling.CfnAutoScalingGroup.MemoryMiBRequestProperty(
                                max=123,
                                min=123
                            ),
                            network_interface_count=autoscaling.CfnAutoScalingGroup.NetworkInterfaceCountRequestProperty(
                                max=123,
                                min=123
                            ),
                            on_demand_max_price_percentage_over_lowest_price=123,
                            require_hibernate_support=False,
                            spot_max_price_percentage_over_lowest_price=123,
                            total_local_storage_gb=autoscaling.CfnAutoScalingGroup.TotalLocalStorageGBRequestProperty(
                                max=123,
                                min=123
                            ),
                            v_cpu_count=autoscaling.CfnAutoScalingGroup.VCpuCountRequestProperty(
                                max=123,
                                min=123
                            )
                        ),
                        instance_type="instanceType",
                        launch_template_specification=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                            version="version",
                
                            # the properties below are optional
                            launch_template_id="launchTemplateId",
                            launch_template_name="launchTemplateName"
                        ),
                        weighted_capacity="weightedCapacity"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "launch_template_specification": launch_template_specification,
            }
            if overrides is not None:
                self._values["overrides"] = overrides

        @builtins.property
        def launch_template_specification(
            self,
        ) -> typing.Union["CfnAutoScalingGroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]:
            '''The launch template to use.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-launchtemplate.html#cfn-as-group-launchtemplate
            '''
            result = self._values.get("launch_template_specification")
            assert result is not None, "Required property 'launch_template_specification' is missing"
            return typing.cast(typing.Union["CfnAutoScalingGroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def overrides(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAutoScalingGroup.LaunchTemplateOverridesProperty", _IResolvable_da3f097b]]]]:
            '''Any properties that you specify override the same properties in the launch template.

            If not provided, Amazon EC2 Auto Scaling uses the instance type or instance requirements specified in the launch template when it launches an instance.

            The overrides can include either one or more instance types or a set of instance requirements, but not both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-mixedinstancespolicy-launchtemplate.html#cfn-as-mixedinstancespolicy-overrides
            '''
            result = self._values.get("overrides")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnAutoScalingGroup.LaunchTemplateOverridesProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LaunchTemplateProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "version": "version",
            "launch_template_id": "launchTemplateId",
            "launch_template_name": "launchTemplateName",
        },
    )
    class LaunchTemplateSpecificationProperty:
        def __init__(
            self,
            *,
            version: builtins.str,
            launch_template_id: typing.Optional[builtins.str] = None,
            launch_template_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``LaunchTemplateSpecification`` specifies a launch template and version for the ``LaunchTemplate`` property of the `AWS::AutoScaling::AutoScalingGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html>`_ resource. It is also a property of the `AWS::AutoScaling::AutoScalingGroup LaunchTemplate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplate.html>`_ and `AWS::AutoScaling::AutoScalingGroup LaunchTemplateOverrides <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html>`_ property types.

            The launch template that is specified must be configured for use with an Auto Scaling group. For information about creating a launch template, see `Creating a launch template for an Auto Scaling group <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-template.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            You can find a sample template snippets in the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#aws-properties-as-group--examples>`_ section of the ``AWS::AutoScaling::AutoScalingGroup`` documentation and in the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-launchtemplate.html#aws-resource-ec2-launchtemplate--examples>`_ section of the ``AWS::EC2::LaunchTemplate`` documentation.

            :param version: The version number. CloudFormation does not support specifying $Latest, or $Default for the template version number. However, you can specify ``LatestVersionNumber`` or ``DefaultVersionNumber`` using the ``Fn::GetAtt`` function. .. epigraph:: For an example of using the ``Fn::GetAtt`` function, see the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#aws-properties-as-group--examples>`_ section of the ``AWS::AutoScaling::AutoScalingGroup`` documentation.
            :param launch_template_id: The ID of the `AWS::EC2::LaunchTemplate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-launchtemplate.html>`_ . You must specify either a ``LaunchTemplateName`` or a ``LaunchTemplateId`` .
            :param launch_template_name: The name of the `AWS::EC2::LaunchTemplate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-launchtemplate.html>`_ . You must specify either a ``LaunchTemplateName`` or a ``LaunchTemplateId`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplatespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                launch_template_specification_property = autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                    version="version",
                
                    # the properties below are optional
                    launch_template_id="launchTemplateId",
                    launch_template_name="launchTemplateName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "version": version,
            }
            if launch_template_id is not None:
                self._values["launch_template_id"] = launch_template_id
            if launch_template_name is not None:
                self._values["launch_template_name"] = launch_template_name

        @builtins.property
        def version(self) -> builtins.str:
            '''The version number.

            CloudFormation does not support specifying $Latest, or $Default for the template version number. However, you can specify ``LatestVersionNumber`` or ``DefaultVersionNumber`` using the ``Fn::GetAtt`` function.
            .. epigraph::

               For an example of using the ``Fn::GetAtt`` function, see the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#aws-properties-as-group--examples>`_ section of the ``AWS::AutoScaling::AutoScalingGroup`` documentation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplatespecification.html#cfn-autoscaling-autoscalinggroup-launchtemplatespecification-version
            '''
            result = self._values.get("version")
            assert result is not None, "Required property 'version' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def launch_template_id(self) -> typing.Optional[builtins.str]:
            '''The ID of the `AWS::EC2::LaunchTemplate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-launchtemplate.html>`_ . You must specify either a ``LaunchTemplateName`` or a ``LaunchTemplateId`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplatespecification.html#cfn-autoscaling-autoscalinggroup-launchtemplatespecification-launchtemplateid
            '''
            result = self._values.get("launch_template_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def launch_template_name(self) -> typing.Optional[builtins.str]:
            '''The name of the `AWS::EC2::LaunchTemplate <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-launchtemplate.html>`_ . You must specify either a ``LaunchTemplateName`` or a ``LaunchTemplateId`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplatespecification.html#cfn-autoscaling-autoscalinggroup-launchtemplatespecification-launchtemplatename
            '''
            result = self._values.get("launch_template_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LaunchTemplateSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.LifecycleHookSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "lifecycle_hook_name": "lifecycleHookName",
            "lifecycle_transition": "lifecycleTransition",
            "default_result": "defaultResult",
            "heartbeat_timeout": "heartbeatTimeout",
            "notification_metadata": "notificationMetadata",
            "notification_target_arn": "notificationTargetArn",
            "role_arn": "roleArn",
        },
    )
    class LifecycleHookSpecificationProperty:
        def __init__(
            self,
            *,
            lifecycle_hook_name: builtins.str,
            lifecycle_transition: builtins.str,
            default_result: typing.Optional[builtins.str] = None,
            heartbeat_timeout: typing.Optional[jsii.Number] = None,
            notification_metadata: typing.Optional[builtins.str] = None,
            notification_target_arn: typing.Optional[builtins.str] = None,
            role_arn: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``LifecycleHookSpecification`` specifies a lifecycle hook for the ``LifecycleHookSpecificationList`` property of the `AWS::AutoScaling::AutoScalingGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html>`_ resource. A lifecycle hook specifies actions to perform when Amazon EC2 Auto Scaling launches or terminates instances.

            For more information, see `Amazon EC2 Auto Scaling lifecycle hooks <https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . You can find a sample template snippet in the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-lifecyclehook.html#aws-resource-as-lifecyclehook--examples>`_ section of the ``AWS::AutoScaling::LifecycleHook`` documentation.

            :param lifecycle_hook_name: The name of the lifecycle hook.
            :param lifecycle_transition: The state of the EC2 instance to attach the lifecycle hook to. The valid values are:. - autoscaling:EC2_INSTANCE_LAUNCHING - autoscaling:EC2_INSTANCE_TERMINATING
            :param default_result: The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs. The valid values are ``CONTINUE`` and ``ABANDON`` (default). For more information, see `Adding lifecycle hooks <https://docs.aws.amazon.com/autoscaling/ec2/userguide/adding-lifecycle-hooks.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
            :param heartbeat_timeout: The maximum time, in seconds, that can elapse before the lifecycle hook times out. If the lifecycle hook times out, Amazon EC2 Auto Scaling performs the default action.
            :param notification_metadata: Additional information that you want to include any time Amazon EC2 Auto Scaling sends a message to the notification target.
            :param notification_target_arn: The Amazon Resource Name (ARN) of the notification target that Amazon EC2 Auto Scaling uses to notify you when an instance is in the transition state for the lifecycle hook. You can specify an Amazon SQS queue or an Amazon SNS topic.
            :param role_arn: The ARN of the IAM role that allows the Auto Scaling group to publish to the specified notification target, for example, an Amazon SNS topic or an Amazon SQS queue. For information about creating this role, see `Configuring a notification target for a lifecycle hook <https://docs.aws.amazon.com/autoscaling/ec2/userguide/configuring-lifecycle-hook-notifications.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-lifecyclehookspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                lifecycle_hook_specification_property = autoscaling.CfnAutoScalingGroup.LifecycleHookSpecificationProperty(
                    lifecycle_hook_name="lifecycleHookName",
                    lifecycle_transition="lifecycleTransition",
                
                    # the properties below are optional
                    default_result="defaultResult",
                    heartbeat_timeout=123,
                    notification_metadata="notificationMetadata",
                    notification_target_arn="notificationTargetArn",
                    role_arn="roleArn"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "lifecycle_hook_name": lifecycle_hook_name,
                "lifecycle_transition": lifecycle_transition,
            }
            if default_result is not None:
                self._values["default_result"] = default_result
            if heartbeat_timeout is not None:
                self._values["heartbeat_timeout"] = heartbeat_timeout
            if notification_metadata is not None:
                self._values["notification_metadata"] = notification_metadata
            if notification_target_arn is not None:
                self._values["notification_target_arn"] = notification_target_arn
            if role_arn is not None:
                self._values["role_arn"] = role_arn

        @builtins.property
        def lifecycle_hook_name(self) -> builtins.str:
            '''The name of the lifecycle hook.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-lifecyclehookspecification.html#cfn-autoscaling-autoscalinggroup-lifecyclehookspecification-lifecyclehookname
            '''
            result = self._values.get("lifecycle_hook_name")
            assert result is not None, "Required property 'lifecycle_hook_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def lifecycle_transition(self) -> builtins.str:
            '''The state of the EC2 instance to attach the lifecycle hook to. The valid values are:.

            - autoscaling:EC2_INSTANCE_LAUNCHING
            - autoscaling:EC2_INSTANCE_TERMINATING

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-lifecyclehookspecification.html#cfn-autoscaling-autoscalinggroup-lifecyclehookspecification-lifecycletransition
            '''
            result = self._values.get("lifecycle_transition")
            assert result is not None, "Required property 'lifecycle_transition' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def default_result(self) -> typing.Optional[builtins.str]:
            '''The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs.

            The valid values are ``CONTINUE`` and ``ABANDON`` (default).

            For more information, see `Adding lifecycle hooks <https://docs.aws.amazon.com/autoscaling/ec2/userguide/adding-lifecycle-hooks.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-lifecyclehookspecification.html#cfn-autoscaling-autoscalinggroup-lifecyclehookspecification-defaultresult
            '''
            result = self._values.get("default_result")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def heartbeat_timeout(self) -> typing.Optional[jsii.Number]:
            '''The maximum time, in seconds, that can elapse before the lifecycle hook times out.

            If the lifecycle hook times out, Amazon EC2 Auto Scaling performs the default action.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-lifecyclehookspecification.html#cfn-autoscaling-autoscalinggroup-lifecyclehookspecification-heartbeattimeout
            '''
            result = self._values.get("heartbeat_timeout")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def notification_metadata(self) -> typing.Optional[builtins.str]:
            '''Additional information that you want to include any time Amazon EC2 Auto Scaling sends a message to the notification target.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-lifecyclehookspecification.html#cfn-autoscaling-autoscalinggroup-lifecyclehookspecification-notificationmetadata
            '''
            result = self._values.get("notification_metadata")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def notification_target_arn(self) -> typing.Optional[builtins.str]:
            '''The Amazon Resource Name (ARN) of the notification target that Amazon EC2 Auto Scaling uses to notify you when an instance is in the transition state for the lifecycle hook.

            You can specify an Amazon SQS queue or an Amazon SNS topic.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-lifecyclehookspecification.html#cfn-autoscaling-autoscalinggroup-lifecyclehookspecification-notificationtargetarn
            '''
            result = self._values.get("notification_target_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def role_arn(self) -> typing.Optional[builtins.str]:
            '''The ARN of the IAM role that allows the Auto Scaling group to publish to the specified notification target, for example, an Amazon SNS topic or an Amazon SQS queue.

            For information about creating this role, see `Configuring a notification target for a lifecycle hook <https://docs.aws.amazon.com/autoscaling/ec2/userguide/configuring-lifecycle-hook-notifications.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-lifecyclehookspecification.html#cfn-autoscaling-autoscalinggroup-lifecyclehookspecification-rolearn
            '''
            result = self._values.get("role_arn")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LifecycleHookSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.MemoryGiBPerVCpuRequestProperty",
        jsii_struct_bases=[],
        name_mapping={"max": "max", "min": "min"},
    )
    class MemoryGiBPerVCpuRequestProperty:
        def __init__(
            self,
            *,
            max: typing.Optional[jsii.Number] = None,
            min: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``MemoryGiBPerVCpuRequest`` is a property of the ``InstanceRequirements`` property of the `AWS::AutoScaling::AutoScalingGroup LaunchTemplateOverrides <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html>`_ property type that describes the minimum and maximum amount of memory per vCPU for an instance type, in GiB.

            :param max: The memory maximum in GiB.
            :param min: The memory minimum in GiB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-memorygibpervcpurequest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                memory_gi_bPer_vCpu_request_property = autoscaling.CfnAutoScalingGroup.MemoryGiBPerVCpuRequestProperty(
                    max=123,
                    min=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max is not None:
                self._values["max"] = max
            if min is not None:
                self._values["min"] = min

        @builtins.property
        def max(self) -> typing.Optional[jsii.Number]:
            '''The memory maximum in GiB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-memorygibpervcpurequest.html#cfn-autoscaling-autoscalinggroup-memorygibpervcpurequest-max
            '''
            result = self._values.get("max")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min(self) -> typing.Optional[jsii.Number]:
            '''The memory minimum in GiB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-memorygibpervcpurequest.html#cfn-autoscaling-autoscalinggroup-memorygibpervcpurequest-min
            '''
            result = self._values.get("min")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MemoryGiBPerVCpuRequestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.MemoryMiBRequestProperty",
        jsii_struct_bases=[],
        name_mapping={"max": "max", "min": "min"},
    )
    class MemoryMiBRequestProperty:
        def __init__(
            self,
            *,
            max: typing.Optional[jsii.Number] = None,
            min: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``MemoryMiBRequest`` is a property of the ``InstanceRequirements`` property of the `AWS::AutoScaling::AutoScalingGroup LaunchTemplateOverrides <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html>`_ property type that describes the minimum and maximum instance memory size for an instance type, in MiB.

            :param max: The memory maximum in MiB.
            :param min: The memory minimum in MiB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-memorymibrequest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                memory_mi_bRequest_property = autoscaling.CfnAutoScalingGroup.MemoryMiBRequestProperty(
                    max=123,
                    min=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max is not None:
                self._values["max"] = max
            if min is not None:
                self._values["min"] = min

        @builtins.property
        def max(self) -> typing.Optional[jsii.Number]:
            '''The memory maximum in MiB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-memorymibrequest.html#cfn-autoscaling-autoscalinggroup-memorymibrequest-max
            '''
            result = self._values.get("max")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min(self) -> typing.Optional[jsii.Number]:
            '''The memory minimum in MiB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-memorymibrequest.html#cfn-autoscaling-autoscalinggroup-memorymibrequest-min
            '''
            result = self._values.get("min")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MemoryMiBRequestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.MetricsCollectionProperty",
        jsii_struct_bases=[],
        name_mapping={"granularity": "granularity", "metrics": "metrics"},
    )
    class MetricsCollectionProperty:
        def __init__(
            self,
            *,
            granularity: builtins.str,
            metrics: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''``MetricsCollection`` is a property of the `AWS::AutoScaling::AutoScalingGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html>`_ resource that describes the group metrics that an Amazon EC2 Auto Scaling group sends to Amazon CloudWatch. These metrics describe the group rather than any of its instances.

            For more information, see `Monitoring CloudWatch metrics for your Auto Scaling groups and instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-monitoring.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . You can find a sample template snippet in the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#aws-properties-as-group--examples>`_ section of the ``AWS::AutoScaling::AutoScalingGroup`` documentation.

            :param granularity: The frequency at which Amazon EC2 Auto Scaling sends aggregated data to CloudWatch. *Allowed Values* : ``1Minute``
            :param metrics: Specifies which group-level metrics to start collecting. *Allowed Values* : - ``GroupMinSize`` - ``GroupMaxSize`` - ``GroupDesiredCapacity`` - ``GroupInServiceInstances`` - ``GroupPendingInstances`` - ``GroupStandbyInstances`` - ``GroupTerminatingInstances`` - ``GroupTotalInstances`` - ``GroupInServiceCapacity`` - ``GroupPendingCapacity`` - ``GroupStandbyCapacity`` - ``GroupTerminatingCapacity`` - ``GroupTotalCapacity`` - ``WarmPoolDesiredCapacity`` - ``WarmPoolWarmedCapacity`` - ``WarmPoolPendingCapacity`` - ``WarmPoolTerminatingCapacity`` - ``WarmPoolTotalCapacity`` - ``GroupAndWarmPoolDesiredCapacity`` - ``GroupAndWarmPoolTotalCapacity`` If you specify ``Granularity`` and don't specify any metrics, all metrics are enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-metricscollection.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                metrics_collection_property = autoscaling.CfnAutoScalingGroup.MetricsCollectionProperty(
                    granularity="granularity",
                
                    # the properties below are optional
                    metrics=["metrics"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "granularity": granularity,
            }
            if metrics is not None:
                self._values["metrics"] = metrics

        @builtins.property
        def granularity(self) -> builtins.str:
            '''The frequency at which Amazon EC2 Auto Scaling sends aggregated data to CloudWatch.

            *Allowed Values* : ``1Minute``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-metricscollection.html#cfn-as-metricscollection-granularity
            '''
            result = self._values.get("granularity")
            assert result is not None, "Required property 'granularity' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def metrics(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Specifies which group-level metrics to start collecting.

            *Allowed Values* :

            - ``GroupMinSize``
            - ``GroupMaxSize``
            - ``GroupDesiredCapacity``
            - ``GroupInServiceInstances``
            - ``GroupPendingInstances``
            - ``GroupStandbyInstances``
            - ``GroupTerminatingInstances``
            - ``GroupTotalInstances``
            - ``GroupInServiceCapacity``
            - ``GroupPendingCapacity``
            - ``GroupStandbyCapacity``
            - ``GroupTerminatingCapacity``
            - ``GroupTotalCapacity``
            - ``WarmPoolDesiredCapacity``
            - ``WarmPoolWarmedCapacity``
            - ``WarmPoolPendingCapacity``
            - ``WarmPoolTerminatingCapacity``
            - ``WarmPoolTotalCapacity``
            - ``GroupAndWarmPoolDesiredCapacity``
            - ``GroupAndWarmPoolTotalCapacity``

            If you specify ``Granularity`` and don't specify any metrics, all metrics are enabled.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-metricscollection.html#cfn-as-metricscollection-metrics
            '''
            result = self._values.get("metrics")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MetricsCollectionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.MixedInstancesPolicyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "launch_template": "launchTemplate",
            "instances_distribution": "instancesDistribution",
        },
    )
    class MixedInstancesPolicyProperty:
        def __init__(
            self,
            *,
            launch_template: typing.Union["CfnAutoScalingGroup.LaunchTemplateProperty", _IResolvable_da3f097b],
            instances_distribution: typing.Optional[typing.Union["CfnAutoScalingGroup.InstancesDistributionProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''``MixedInstancesPolicy`` is a property of the `AWS::AutoScaling::AutoScalingGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html>`_ resource. It allows you to configure a group that diversifies across On-Demand Instances and Spot Instances of multiple instance types. For more information, see `Auto Scaling groups with multiple instance types and purchase options <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            You can create a mixed instances policy for a new Auto Scaling group, or you can create it for an existing group by updating the group to specify ``MixedInstancesPolicy`` as the top-level property instead of a launch template or launch configuration. If you specify a ``MixedInstancesPolicy`` , you must specify a launch template as a property of the policy. You cannot specify a launch configuration for the policy.

            :param launch_template: Specifies the launch template to use and optionally the instance types (overrides) that are used to provision EC2 instances to fulfill On-Demand and Spot capacities.
            :param instances_distribution: The instances distribution to use. If you leave this property unspecified, the value for each property in ``InstancesDistribution`` uses a default value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-group-mixedinstancespolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                mixed_instances_policy_property = autoscaling.CfnAutoScalingGroup.MixedInstancesPolicyProperty(
                    launch_template=autoscaling.CfnAutoScalingGroup.LaunchTemplateProperty(
                        launch_template_specification=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                            version="version",
                
                            # the properties below are optional
                            launch_template_id="launchTemplateId",
                            launch_template_name="launchTemplateName"
                        ),
                
                        # the properties below are optional
                        overrides=[autoscaling.CfnAutoScalingGroup.LaunchTemplateOverridesProperty(
                            instance_requirements=autoscaling.CfnAutoScalingGroup.InstanceRequirementsProperty(
                                accelerator_count=autoscaling.CfnAutoScalingGroup.AcceleratorCountRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                accelerator_manufacturers=["acceleratorManufacturers"],
                                accelerator_names=["acceleratorNames"],
                                accelerator_total_memory_mi_b=autoscaling.CfnAutoScalingGroup.AcceleratorTotalMemoryMiBRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                accelerator_types=["acceleratorTypes"],
                                bare_metal="bareMetal",
                                baseline_ebs_bandwidth_mbps=autoscaling.CfnAutoScalingGroup.BaselineEbsBandwidthMbpsRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                burstable_performance="burstablePerformance",
                                cpu_manufacturers=["cpuManufacturers"],
                                excluded_instance_types=["excludedInstanceTypes"],
                                instance_generations=["instanceGenerations"],
                                local_storage="localStorage",
                                local_storage_types=["localStorageTypes"],
                                memory_gi_bPer_vCpu=autoscaling.CfnAutoScalingGroup.MemoryGiBPerVCpuRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                memory_mi_b=autoscaling.CfnAutoScalingGroup.MemoryMiBRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                network_interface_count=autoscaling.CfnAutoScalingGroup.NetworkInterfaceCountRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                on_demand_max_price_percentage_over_lowest_price=123,
                                require_hibernate_support=False,
                                spot_max_price_percentage_over_lowest_price=123,
                                total_local_storage_gb=autoscaling.CfnAutoScalingGroup.TotalLocalStorageGBRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                v_cpu_count=autoscaling.CfnAutoScalingGroup.VCpuCountRequestProperty(
                                    max=123,
                                    min=123
                                )
                            ),
                            instance_type="instanceType",
                            launch_template_specification=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                                version="version",
                
                                # the properties below are optional
                                launch_template_id="launchTemplateId",
                                launch_template_name="launchTemplateName"
                            ),
                            weighted_capacity="weightedCapacity"
                        )]
                    ),
                
                    # the properties below are optional
                    instances_distribution=autoscaling.CfnAutoScalingGroup.InstancesDistributionProperty(
                        on_demand_allocation_strategy="onDemandAllocationStrategy",
                        on_demand_base_capacity=123,
                        on_demand_percentage_above_base_capacity=123,
                        spot_allocation_strategy="spotAllocationStrategy",
                        spot_instance_pools=123,
                        spot_max_price="spotMaxPrice"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "launch_template": launch_template,
            }
            if instances_distribution is not None:
                self._values["instances_distribution"] = instances_distribution

        @builtins.property
        def launch_template(
            self,
        ) -> typing.Union["CfnAutoScalingGroup.LaunchTemplateProperty", _IResolvable_da3f097b]:
            '''Specifies the launch template to use and optionally the instance types (overrides) that are used to provision EC2 instances to fulfill On-Demand and Spot capacities.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-group-mixedinstancespolicy.html#cfn-as-mixedinstancespolicy-launchtemplate
            '''
            result = self._values.get("launch_template")
            assert result is not None, "Required property 'launch_template' is missing"
            return typing.cast(typing.Union["CfnAutoScalingGroup.LaunchTemplateProperty", _IResolvable_da3f097b], result)

        @builtins.property
        def instances_distribution(
            self,
        ) -> typing.Optional[typing.Union["CfnAutoScalingGroup.InstancesDistributionProperty", _IResolvable_da3f097b]]:
            '''The instances distribution to use.

            If you leave this property unspecified, the value for each property in ``InstancesDistribution`` uses a default value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-as-group-mixedinstancespolicy.html#cfn-as-mixedinstancespolicy-instancesdistribution
            '''
            result = self._values.get("instances_distribution")
            return typing.cast(typing.Optional[typing.Union["CfnAutoScalingGroup.InstancesDistributionProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MixedInstancesPolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.NetworkInterfaceCountRequestProperty",
        jsii_struct_bases=[],
        name_mapping={"max": "max", "min": "min"},
    )
    class NetworkInterfaceCountRequestProperty:
        def __init__(
            self,
            *,
            max: typing.Optional[jsii.Number] = None,
            min: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``NetworkInterfaceCountRequest`` is a property of the ``InstanceRequirements`` property of the `AWS::AutoScaling::AutoScalingGroup LaunchTemplateOverrides <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html>`_ property type that describes the minimum and maximum number of network interfaces for an instance type.

            :param max: The maximum number of network interfaces.
            :param min: The minimum number of network interfaces.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-networkinterfacecountrequest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                network_interface_count_request_property = autoscaling.CfnAutoScalingGroup.NetworkInterfaceCountRequestProperty(
                    max=123,
                    min=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max is not None:
                self._values["max"] = max
            if min is not None:
                self._values["min"] = min

        @builtins.property
        def max(self) -> typing.Optional[jsii.Number]:
            '''The maximum number of network interfaces.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-networkinterfacecountrequest.html#cfn-autoscaling-autoscalinggroup-networkinterfacecountrequest-max
            '''
            result = self._values.get("max")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min(self) -> typing.Optional[jsii.Number]:
            '''The minimum number of network interfaces.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-networkinterfacecountrequest.html#cfn-autoscaling-autoscalinggroup-networkinterfacecountrequest-min
            '''
            result = self._values.get("min")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NetworkInterfaceCountRequestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.NotificationConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "topic_arn": "topicArn",
            "notification_types": "notificationTypes",
        },
    )
    class NotificationConfigurationProperty:
        def __init__(
            self,
            *,
            topic_arn: builtins.str,
            notification_types: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''``NotificationConfiguration`` specifies a notification configuration for the ``NotificationConfigurations`` property of `AWS::AutoScaling::AutoScalingGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html>`_ . ``NotificationConfiguration`` specifies the events that the Amazon EC2 Auto Scaling group sends notifications for.

            For example snippets, see `Declaring an Auto Scaling group with a launch template and notifications <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-autoscaling.html#scenario-as-notification>`_ .

            For more information, see `Getting Amazon SNS notifications when your Auto Scaling group scales <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ASGettingNotifications.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :param topic_arn: The Amazon Resource Name (ARN) of the Amazon SNS topic.
            :param notification_types: A list of event types that trigger a notification. Event types can include any of the following types. *Allowed Values* : - ``autoscaling:EC2_INSTANCE_LAUNCH`` - ``autoscaling:EC2_INSTANCE_LAUNCH_ERROR`` - ``autoscaling:EC2_INSTANCE_TERMINATE`` - ``autoscaling:EC2_INSTANCE_TERMINATE_ERROR`` - ``autoscaling:TEST_NOTIFICATION``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-notificationconfigurations.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                notification_configuration_property = autoscaling.CfnAutoScalingGroup.NotificationConfigurationProperty(
                    topic_arn="topicArn",
                
                    # the properties below are optional
                    notification_types=["notificationTypes"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "topic_arn": topic_arn,
            }
            if notification_types is not None:
                self._values["notification_types"] = notification_types

        @builtins.property
        def topic_arn(self) -> builtins.str:
            '''The Amazon Resource Name (ARN) of the Amazon SNS topic.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-notificationconfigurations.html#cfn-autoscaling-autoscalinggroup-notificationconfigurations-topicarn
            '''
            result = self._values.get("topic_arn")
            assert result is not None, "Required property 'topic_arn' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def notification_types(self) -> typing.Optional[typing.List[builtins.str]]:
            '''A list of event types that trigger a notification. Event types can include any of the following types.

            *Allowed Values* :

            - ``autoscaling:EC2_INSTANCE_LAUNCH``
            - ``autoscaling:EC2_INSTANCE_LAUNCH_ERROR``
            - ``autoscaling:EC2_INSTANCE_TERMINATE``
            - ``autoscaling:EC2_INSTANCE_TERMINATE_ERROR``
            - ``autoscaling:TEST_NOTIFICATION``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-notificationconfigurations.html#cfn-as-group-notificationconfigurations-notificationtypes
            '''
            result = self._values.get("notification_types")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "NotificationConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.TagPropertyProperty",
        jsii_struct_bases=[],
        name_mapping={
            "key": "key",
            "propagate_at_launch": "propagateAtLaunch",
            "value": "value",
        },
    )
    class TagPropertyProperty:
        def __init__(
            self,
            *,
            key: builtins.str,
            propagate_at_launch: typing.Union[builtins.bool, _IResolvable_da3f097b],
            value: builtins.str,
        ) -> None:
            '''``TagProperty`` specifies a tag for the ``Tags`` property of `AWS::AutoScaling::AutoScalingGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html>`_ . ``TagProperty`` adds tags to all associated instances in an Auto Scaling group.

            For more information, see `Tagging Auto Scaling groups and instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-tagging.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . You can find a sample template snippet in the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#aws-properties-as-group--examples>`_ section of the ``AWS::AutoScaling::AutoScalingGroup`` documentation.

            CloudFormation adds the following tags to all Auto Scaling groups and associated instances:

            - aws:cloudformation:stack-name
            - aws:cloudformation:stack-id
            - aws:cloudformation:logical-id

            :param key: The tag key.
            :param propagate_at_launch: Set to ``true`` if you want CloudFormation to copy the tag to EC2 instances that are launched as part of the Auto Scaling group. Set to ``false`` if you want the tag attached only to the Auto Scaling group and not copied to any instances launched as part of the Auto Scaling group.
            :param value: The tag value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-tags.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                tag_property_property = autoscaling.CfnAutoScalingGroup.TagPropertyProperty(
                    key="key",
                    propagate_at_launch=False,
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "key": key,
                "propagate_at_launch": propagate_at_launch,
                "value": value,
            }

        @builtins.property
        def key(self) -> builtins.str:
            '''The tag key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-tags.html#cfn-as-tags-Key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def propagate_at_launch(
            self,
        ) -> typing.Union[builtins.bool, _IResolvable_da3f097b]:
            '''Set to ``true`` if you want CloudFormation to copy the tag to EC2 instances that are launched as part of the Auto Scaling group.

            Set to ``false`` if you want the tag attached only to the Auto Scaling group and not copied to any instances launched as part of the Auto Scaling group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-tags.html#cfn-as-tags-PropagateAtLaunch
            '''
            result = self._values.get("propagate_at_launch")
            assert result is not None, "Required property 'propagate_at_launch' is missing"
            return typing.cast(typing.Union[builtins.bool, _IResolvable_da3f097b], result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The tag value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-tags.html#cfn-as-tags-Value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TagPropertyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.TotalLocalStorageGBRequestProperty",
        jsii_struct_bases=[],
        name_mapping={"max": "max", "min": "min"},
    )
    class TotalLocalStorageGBRequestProperty:
        def __init__(
            self,
            *,
            max: typing.Optional[jsii.Number] = None,
            min: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``TotalLocalStorageGBRequest`` is a property of the ``InstanceRequirements`` property of the `AWS::AutoScaling::AutoScalingGroup LaunchTemplateOverrides <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html>`_ property type that describes the minimum and maximum total local storage size for an instance type, in GB.

            :param max: The storage maximum in GB.
            :param min: The storage minimum in GB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-totallocalstoragegbrequest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                total_local_storage_gBRequest_property = autoscaling.CfnAutoScalingGroup.TotalLocalStorageGBRequestProperty(
                    max=123,
                    min=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max is not None:
                self._values["max"] = max
            if min is not None:
                self._values["min"] = min

        @builtins.property
        def max(self) -> typing.Optional[jsii.Number]:
            '''The storage maximum in GB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-totallocalstoragegbrequest.html#cfn-autoscaling-autoscalinggroup-totallocalstoragegbrequest-max
            '''
            result = self._values.get("max")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min(self) -> typing.Optional[jsii.Number]:
            '''The storage minimum in GB.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-totallocalstoragegbrequest.html#cfn-autoscaling-autoscalinggroup-totallocalstoragegbrequest-min
            '''
            result = self._values.get("min")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TotalLocalStorageGBRequestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroup.VCpuCountRequestProperty",
        jsii_struct_bases=[],
        name_mapping={"max": "max", "min": "min"},
    )
    class VCpuCountRequestProperty:
        def __init__(
            self,
            *,
            max: typing.Optional[jsii.Number] = None,
            min: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``VCpuCountRequest`` is a property of the ``InstanceRequirements`` property of the `AWS::AutoScaling::AutoScalingGroup LaunchTemplateOverrides <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-launchtemplateoverrides.html>`_ property type that describes the minimum and maximum number of vCPUs for an instance type.

            :param max: The maximum number of vCPUs.
            :param min: The minimum number of vCPUs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-vcpucountrequest.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                v_cpu_count_request_property = autoscaling.CfnAutoScalingGroup.VCpuCountRequestProperty(
                    max=123,
                    min=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max is not None:
                self._values["max"] = max
            if min is not None:
                self._values["min"] = min

        @builtins.property
        def max(self) -> typing.Optional[jsii.Number]:
            '''The maximum number of vCPUs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-vcpucountrequest.html#cfn-autoscaling-autoscalinggroup-vcpucountrequest-max
            '''
            result = self._values.get("max")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min(self) -> typing.Optional[jsii.Number]:
            '''The minimum number of vCPUs.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-autoscalinggroup-vcpucountrequest.html#cfn-autoscaling-autoscalinggroup-vcpucountrequest-min
            '''
            result = self._values.get("min")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "VCpuCountRequestProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnAutoScalingGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "max_size": "maxSize",
        "min_size": "minSize",
        "auto_scaling_group_name": "autoScalingGroupName",
        "availability_zones": "availabilityZones",
        "capacity_rebalance": "capacityRebalance",
        "context": "context",
        "cooldown": "cooldown",
        "desired_capacity": "desiredCapacity",
        "desired_capacity_type": "desiredCapacityType",
        "health_check_grace_period": "healthCheckGracePeriod",
        "health_check_type": "healthCheckType",
        "instance_id": "instanceId",
        "launch_configuration_name": "launchConfigurationName",
        "launch_template": "launchTemplate",
        "lifecycle_hook_specification_list": "lifecycleHookSpecificationList",
        "load_balancer_names": "loadBalancerNames",
        "max_instance_lifetime": "maxInstanceLifetime",
        "metrics_collection": "metricsCollection",
        "mixed_instances_policy": "mixedInstancesPolicy",
        "new_instances_protected_from_scale_in": "newInstancesProtectedFromScaleIn",
        "notification_configurations": "notificationConfigurations",
        "placement_group": "placementGroup",
        "service_linked_role_arn": "serviceLinkedRoleArn",
        "tags": "tags",
        "target_group_arns": "targetGroupArns",
        "termination_policies": "terminationPolicies",
        "vpc_zone_identifier": "vpcZoneIdentifier",
    },
)
class CfnAutoScalingGroupProps:
    def __init__(
        self,
        *,
        max_size: builtins.str,
        min_size: builtins.str,
        auto_scaling_group_name: typing.Optional[builtins.str] = None,
        availability_zones: typing.Optional[typing.Sequence[builtins.str]] = None,
        capacity_rebalance: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        context: typing.Optional[builtins.str] = None,
        cooldown: typing.Optional[builtins.str] = None,
        desired_capacity: typing.Optional[builtins.str] = None,
        desired_capacity_type: typing.Optional[builtins.str] = None,
        health_check_grace_period: typing.Optional[jsii.Number] = None,
        health_check_type: typing.Optional[builtins.str] = None,
        instance_id: typing.Optional[builtins.str] = None,
        launch_configuration_name: typing.Optional[builtins.str] = None,
        launch_template: typing.Optional[typing.Union[CfnAutoScalingGroup.LaunchTemplateSpecificationProperty, _IResolvable_da3f097b]] = None,
        lifecycle_hook_specification_list: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnAutoScalingGroup.LifecycleHookSpecificationProperty, _IResolvable_da3f097b]]]] = None,
        load_balancer_names: typing.Optional[typing.Sequence[builtins.str]] = None,
        max_instance_lifetime: typing.Optional[jsii.Number] = None,
        metrics_collection: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnAutoScalingGroup.MetricsCollectionProperty, _IResolvable_da3f097b]]]] = None,
        mixed_instances_policy: typing.Optional[typing.Union[CfnAutoScalingGroup.MixedInstancesPolicyProperty, _IResolvable_da3f097b]] = None,
        new_instances_protected_from_scale_in: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        notification_configurations: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnAutoScalingGroup.NotificationConfigurationProperty, _IResolvable_da3f097b]]]] = None,
        placement_group: typing.Optional[builtins.str] = None,
        service_linked_role_arn: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[CfnAutoScalingGroup.TagPropertyProperty]] = None,
        target_group_arns: typing.Optional[typing.Sequence[builtins.str]] = None,
        termination_policies: typing.Optional[typing.Sequence[builtins.str]] = None,
        vpc_zone_identifier: typing.Optional[typing.Sequence[builtins.str]] = None,
    ) -> None:
        '''Properties for defining a ``CfnAutoScalingGroup``.

        :param max_size: The maximum size of the group. .. epigraph:: With a mixed instances policy that uses instance weighting, Amazon EC2 Auto Scaling may need to go above ``MaxSize`` to meet your capacity requirements. In this event, Amazon EC2 Auto Scaling will never go above ``MaxSize`` by more than your largest instance weight (weights that define how many units each instance contributes to the desired capacity of the group).
        :param min_size: The minimum size of the group.
        :param auto_scaling_group_name: The name of the Auto Scaling group. This name must be unique per Region per account.
        :param availability_zones: A list of Availability Zones where instances in the Auto Scaling group can be created. You must specify one of the following properties: ``VPCZoneIdentifier`` or ``AvailabilityZones`` . If your account supports EC2-Classic and VPC, this property is required to create an Auto Scaling group that launches instances into EC2-Classic.
        :param capacity_rebalance: Indicates whether Capacity Rebalancing is enabled. For more information, see `Amazon EC2 Auto Scaling Capacity Rebalancing <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-capacity-rebalancing.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param context: Reserved.
        :param cooldown: The amount of time, in seconds, after a scaling activity completes before another scaling activity can start. The default value is ``300`` . This setting applies when using simple scaling policies, but not when using other scaling policies or scheduled scaling. For more information, see `Scaling cooldowns for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param desired_capacity: The desired capacity is the initial capacity of the Auto Scaling group at the time of its creation and the capacity it attempts to maintain. It can scale beyond this capacity if you configure automatic scaling. The number must be greater than or equal to the minimum size of the group and less than or equal to the maximum size of the group. If you do not specify a desired capacity when creating the stack, the default is the minimum size of the group. CloudFormation marks the Auto Scaling group as successful (by setting its status to CREATE_COMPLETE) when the desired capacity is reached. However, if a maximum Spot price is set in the launch template or launch configuration that you specified, then desired capacity is not used as a criteria for success. Whether your request is fulfilled depends on Spot Instance capacity and your maximum price.
        :param desired_capacity_type: The unit of measurement for the value specified for desired capacity. Amazon EC2 Auto Scaling supports ``DesiredCapacityType`` for attribute-based instance type selection only. For more information, see `Creating an Auto Scaling group using attribute-based instance type selection <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-instance-type-requirements.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . By default, Amazon EC2 Auto Scaling specifies ``units`` , which translates into number of instances. Valid values: ``units`` | ``vcpu`` | ``memory-mib``
        :param health_check_grace_period: The amount of time, in seconds, that Amazon EC2 Auto Scaling waits before checking the health status of an EC2 instance that has come into service and marking it unhealthy due to a failed health check. The default value is ``0`` . For more information, see `Health checks for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/healthcheck.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . If you are adding an ``ELB`` health check, you must specify this property.
        :param health_check_type: The service to use for the health checks. The valid values are ``EC2`` (default) and ``ELB`` . If you configure an Auto Scaling group to use load balancer (ELB) health checks, it considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks. For more information, see `Health checks for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/healthcheck.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param instance_id: The ID of the instance used to base the launch configuration on. If specified, Amazon EC2 Auto Scaling uses the configuration values from the specified instance to create a new launch configuration. For more information, see `Creating an Auto Scaling group using an EC2 instance <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-from-instance.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . To get the instance ID, use the EC2 `DescribeInstances <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html>`_ API operation. If you specify ``LaunchTemplate`` , ``MixedInstancesPolicy`` , or ``LaunchConfigurationName`` , don't specify ``InstanceId`` .
        :param launch_configuration_name: The name of the `launch configuration <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig.html>`_ to use to launch instances. If you specify ``LaunchTemplate`` , ``MixedInstancesPolicy`` , or ``InstanceId`` , don't specify ``LaunchConfigurationName`` .
        :param launch_template: Properties used to specify the `launch template <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-launchtemplate.html>`_ and version to use to launch instances. You can alternatively associate a launch template to the Auto Scaling group by specifying a ``MixedInstancesPolicy`` . If you omit this property, you must specify ``MixedInstancesPolicy`` , ``LaunchConfigurationName`` , or ``InstanceId`` .
        :param lifecycle_hook_specification_list: One or more lifecycle hooks for the group, which specify actions to perform when Amazon EC2 Auto Scaling launches or terminates instances.
        :param load_balancer_names: A list of Classic Load Balancers associated with this Auto Scaling group. For Application Load Balancers, Network Load Balancers, and Gateway Load Balancers, specify the ``TargetGroupARNs`` property instead.
        :param max_instance_lifetime: The maximum amount of time, in seconds, that an instance can be in service. The default is null. If specified, the value must be either 0 or a number equal to or greater than 86,400 seconds (1 day). For more information, see `Replacing Auto Scaling instances based on maximum instance lifetime <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-max-instance-lifetime.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param metrics_collection: Enables the monitoring of group metrics of an Auto Scaling group. By default, these metrics are disabled.
        :param mixed_instances_policy: An embedded object that specifies a mixed instances policy. The policy includes properties that not only define the distribution of On-Demand Instances and Spot Instances, the maximum price to pay for Spot Instances (optional), and how the Auto Scaling group allocates instance types to fulfill On-Demand and Spot capacities, but also the properties that specify the instance configuration information—the launch template and instance types. The policy can also include a weight for each instance type and different launch templates for individual instance types. For more information, see `Auto Scaling groups with multiple instance types and purchase options <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . If you specify ``LaunchTemplate`` , ``InstanceId`` , or ``LaunchConfigurationName`` , don't specify ``MixedInstancesPolicy`` .
        :param new_instances_protected_from_scale_in: Indicates whether newly launched instances are protected from termination by Amazon EC2 Auto Scaling when scaling in. For more information about preventing instances from terminating on scale in, see `Instance Protection <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html#instance-protection>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param notification_configurations: Configures an Auto Scaling group to send notifications when specified events take place.
        :param placement_group: The name of the placement group into which you want to launch your instances. A placement group is a logical grouping of instances within a single Availability Zone. For more information, see `Placement Groups <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param service_linked_role_arn: The Amazon Resource Name (ARN) of the service-linked role that the Auto Scaling group uses to call other AWS services on your behalf. By default, Amazon EC2 Auto Scaling uses a service-linked role named ``AWSServiceRoleForAutoScaling`` , which it creates if it does not exist. For more information, see `Service-linked roles for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-service-linked-role.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param tags: One or more tags. You can tag your Auto Scaling group and propagate the tags to the Amazon EC2 instances it launches. For more information, see `Tagging Auto Scaling groups and instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-tagging.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param target_group_arns: One or more Amazon Resource Names (ARN) of load balancer target groups to associate with the Auto Scaling group. Instances are registered as targets in a target group, and traffic is routed to the target group. For more information, see `Elastic Load Balancing and Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-load-balancer.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param termination_policies: A policy or a list of policies that are used to select the instances to terminate. The policies are executed in the order that you list them. The termination policies supported by Amazon EC2 Auto Scaling: ``OldestInstance`` , ``OldestLaunchConfiguration`` , ``NewestInstance`` , ``ClosestToNextInstanceHour`` , ``Default`` , ``OldestLaunchTemplate`` , and ``AllocationStrategy`` . For more information, see `Controlling which Auto Scaling instances terminate during scale in <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param vpc_zone_identifier: A list of subnet IDs for a virtual private cloud (VPC) where instances in the Auto Scaling group can be created. If you specify ``VPCZoneIdentifier`` with ``AvailabilityZones`` , the subnets that you specify for this property must reside in those Availability Zones. If this resource specifies public subnets and is also in a VPC that is defined in the same stack template, you must use the `DependsOn attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ to declare a dependency on the `VPC-gateway attachment <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc-gateway-attachment.html>`_ . .. epigraph:: When you update ``VPCZoneIdentifier`` , this retains the same Auto Scaling group and replaces old instances with new ones, according to the specified subnets. You can optionally specify how CloudFormation handles these updates by using an `UpdatePolicy attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            cfn_auto_scaling_group_props = autoscaling.CfnAutoScalingGroupProps(
                max_size="maxSize",
                min_size="minSize",
            
                # the properties below are optional
                auto_scaling_group_name="autoScalingGroupName",
                availability_zones=["availabilityZones"],
                capacity_rebalance=False,
                context="context",
                cooldown="cooldown",
                desired_capacity="desiredCapacity",
                desired_capacity_type="desiredCapacityType",
                health_check_grace_period=123,
                health_check_type="healthCheckType",
                instance_id="instanceId",
                launch_configuration_name="launchConfigurationName",
                launch_template=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                    version="version",
            
                    # the properties below are optional
                    launch_template_id="launchTemplateId",
                    launch_template_name="launchTemplateName"
                ),
                lifecycle_hook_specification_list=[autoscaling.CfnAutoScalingGroup.LifecycleHookSpecificationProperty(
                    lifecycle_hook_name="lifecycleHookName",
                    lifecycle_transition="lifecycleTransition",
            
                    # the properties below are optional
                    default_result="defaultResult",
                    heartbeat_timeout=123,
                    notification_metadata="notificationMetadata",
                    notification_target_arn="notificationTargetArn",
                    role_arn="roleArn"
                )],
                load_balancer_names=["loadBalancerNames"],
                max_instance_lifetime=123,
                metrics_collection=[autoscaling.CfnAutoScalingGroup.MetricsCollectionProperty(
                    granularity="granularity",
            
                    # the properties below are optional
                    metrics=["metrics"]
                )],
                mixed_instances_policy=autoscaling.CfnAutoScalingGroup.MixedInstancesPolicyProperty(
                    launch_template=autoscaling.CfnAutoScalingGroup.LaunchTemplateProperty(
                        launch_template_specification=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                            version="version",
            
                            # the properties below are optional
                            launch_template_id="launchTemplateId",
                            launch_template_name="launchTemplateName"
                        ),
            
                        # the properties below are optional
                        overrides=[autoscaling.CfnAutoScalingGroup.LaunchTemplateOverridesProperty(
                            instance_requirements=autoscaling.CfnAutoScalingGroup.InstanceRequirementsProperty(
                                accelerator_count=autoscaling.CfnAutoScalingGroup.AcceleratorCountRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                accelerator_manufacturers=["acceleratorManufacturers"],
                                accelerator_names=["acceleratorNames"],
                                accelerator_total_memory_mi_b=autoscaling.CfnAutoScalingGroup.AcceleratorTotalMemoryMiBRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                accelerator_types=["acceleratorTypes"],
                                bare_metal="bareMetal",
                                baseline_ebs_bandwidth_mbps=autoscaling.CfnAutoScalingGroup.BaselineEbsBandwidthMbpsRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                burstable_performance="burstablePerformance",
                                cpu_manufacturers=["cpuManufacturers"],
                                excluded_instance_types=["excludedInstanceTypes"],
                                instance_generations=["instanceGenerations"],
                                local_storage="localStorage",
                                local_storage_types=["localStorageTypes"],
                                memory_gi_bPer_vCpu=autoscaling.CfnAutoScalingGroup.MemoryGiBPerVCpuRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                memory_mi_b=autoscaling.CfnAutoScalingGroup.MemoryMiBRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                network_interface_count=autoscaling.CfnAutoScalingGroup.NetworkInterfaceCountRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                on_demand_max_price_percentage_over_lowest_price=123,
                                require_hibernate_support=False,
                                spot_max_price_percentage_over_lowest_price=123,
                                total_local_storage_gb=autoscaling.CfnAutoScalingGroup.TotalLocalStorageGBRequestProperty(
                                    max=123,
                                    min=123
                                ),
                                v_cpu_count=autoscaling.CfnAutoScalingGroup.VCpuCountRequestProperty(
                                    max=123,
                                    min=123
                                )
                            ),
                            instance_type="instanceType",
                            launch_template_specification=autoscaling.CfnAutoScalingGroup.LaunchTemplateSpecificationProperty(
                                version="version",
            
                                # the properties below are optional
                                launch_template_id="launchTemplateId",
                                launch_template_name="launchTemplateName"
                            ),
                            weighted_capacity="weightedCapacity"
                        )]
                    ),
            
                    # the properties below are optional
                    instances_distribution=autoscaling.CfnAutoScalingGroup.InstancesDistributionProperty(
                        on_demand_allocation_strategy="onDemandAllocationStrategy",
                        on_demand_base_capacity=123,
                        on_demand_percentage_above_base_capacity=123,
                        spot_allocation_strategy="spotAllocationStrategy",
                        spot_instance_pools=123,
                        spot_max_price="spotMaxPrice"
                    )
                ),
                new_instances_protected_from_scale_in=False,
                notification_configurations=[autoscaling.CfnAutoScalingGroup.NotificationConfigurationProperty(
                    topic_arn="topicArn",
            
                    # the properties below are optional
                    notification_types=["notificationTypes"]
                )],
                placement_group="placementGroup",
                service_linked_role_arn="serviceLinkedRoleArn",
                tags=[autoscaling.CfnAutoScalingGroup.TagPropertyProperty(
                    key="key",
                    propagate_at_launch=False,
                    value="value"
                )],
                target_group_arns=["targetGroupArns"],
                termination_policies=["terminationPolicies"],
                vpc_zone_identifier=["vpcZoneIdentifier"]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "max_size": max_size,
            "min_size": min_size,
        }
        if auto_scaling_group_name is not None:
            self._values["auto_scaling_group_name"] = auto_scaling_group_name
        if availability_zones is not None:
            self._values["availability_zones"] = availability_zones
        if capacity_rebalance is not None:
            self._values["capacity_rebalance"] = capacity_rebalance
        if context is not None:
            self._values["context"] = context
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if desired_capacity is not None:
            self._values["desired_capacity"] = desired_capacity
        if desired_capacity_type is not None:
            self._values["desired_capacity_type"] = desired_capacity_type
        if health_check_grace_period is not None:
            self._values["health_check_grace_period"] = health_check_grace_period
        if health_check_type is not None:
            self._values["health_check_type"] = health_check_type
        if instance_id is not None:
            self._values["instance_id"] = instance_id
        if launch_configuration_name is not None:
            self._values["launch_configuration_name"] = launch_configuration_name
        if launch_template is not None:
            self._values["launch_template"] = launch_template
        if lifecycle_hook_specification_list is not None:
            self._values["lifecycle_hook_specification_list"] = lifecycle_hook_specification_list
        if load_balancer_names is not None:
            self._values["load_balancer_names"] = load_balancer_names
        if max_instance_lifetime is not None:
            self._values["max_instance_lifetime"] = max_instance_lifetime
        if metrics_collection is not None:
            self._values["metrics_collection"] = metrics_collection
        if mixed_instances_policy is not None:
            self._values["mixed_instances_policy"] = mixed_instances_policy
        if new_instances_protected_from_scale_in is not None:
            self._values["new_instances_protected_from_scale_in"] = new_instances_protected_from_scale_in
        if notification_configurations is not None:
            self._values["notification_configurations"] = notification_configurations
        if placement_group is not None:
            self._values["placement_group"] = placement_group
        if service_linked_role_arn is not None:
            self._values["service_linked_role_arn"] = service_linked_role_arn
        if tags is not None:
            self._values["tags"] = tags
        if target_group_arns is not None:
            self._values["target_group_arns"] = target_group_arns
        if termination_policies is not None:
            self._values["termination_policies"] = termination_policies
        if vpc_zone_identifier is not None:
            self._values["vpc_zone_identifier"] = vpc_zone_identifier

    @builtins.property
    def max_size(self) -> builtins.str:
        '''The maximum size of the group.

        .. epigraph::

           With a mixed instances policy that uses instance weighting, Amazon EC2 Auto Scaling may need to go above ``MaxSize`` to meet your capacity requirements. In this event, Amazon EC2 Auto Scaling will never go above ``MaxSize`` by more than your largest instance weight (weights that define how many units each instance contributes to the desired capacity of the group).

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-maxsize
        '''
        result = self._values.get("max_size")
        assert result is not None, "Required property 'max_size' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def min_size(self) -> builtins.str:
        '''The minimum size of the group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-minsize
        '''
        result = self._values.get("min_size")
        assert result is not None, "Required property 'min_size' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def auto_scaling_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Auto Scaling group.

        This name must be unique per Region per account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-autoscaling-autoscalinggroup-autoscalinggroupname
        '''
        result = self._values.get("auto_scaling_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def availability_zones(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Availability Zones where instances in the Auto Scaling group can be created.

        You must specify one of the following properties: ``VPCZoneIdentifier`` or ``AvailabilityZones`` . If your account supports EC2-Classic and VPC, this property is required to create an Auto Scaling group that launches instances into EC2-Classic.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-availabilityzones
        '''
        result = self._values.get("availability_zones")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def capacity_rebalance(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether Capacity Rebalancing is enabled.

        For more information, see `Amazon EC2 Auto Scaling Capacity Rebalancing <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-capacity-rebalancing.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-capacityrebalance
        '''
        result = self._values.get("capacity_rebalance")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def context(self) -> typing.Optional[builtins.str]:
        '''Reserved.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-context
        '''
        result = self._values.get("context")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cooldown(self) -> typing.Optional[builtins.str]:
        '''The amount of time, in seconds, after a scaling activity completes before another scaling activity can start.

        The default value is ``300`` . This setting applies when using simple scaling policies, but not when using other scaling policies or scheduled scaling. For more information, see `Scaling cooldowns for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-cooldown
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def desired_capacity(self) -> typing.Optional[builtins.str]:
        '''The desired capacity is the initial capacity of the Auto Scaling group at the time of its creation and the capacity it attempts to maintain.

        It can scale beyond this capacity if you configure automatic scaling.

        The number must be greater than or equal to the minimum size of the group and less than or equal to the maximum size of the group. If you do not specify a desired capacity when creating the stack, the default is the minimum size of the group.

        CloudFormation marks the Auto Scaling group as successful (by setting its status to CREATE_COMPLETE) when the desired capacity is reached. However, if a maximum Spot price is set in the launch template or launch configuration that you specified, then desired capacity is not used as a criteria for success. Whether your request is fulfilled depends on Spot Instance capacity and your maximum price.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-desiredcapacity
        '''
        result = self._values.get("desired_capacity")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def desired_capacity_type(self) -> typing.Optional[builtins.str]:
        '''The unit of measurement for the value specified for desired capacity.

        Amazon EC2 Auto Scaling supports ``DesiredCapacityType`` for attribute-based instance type selection only. For more information, see `Creating an Auto Scaling group using attribute-based instance type selection <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-instance-type-requirements.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        By default, Amazon EC2 Auto Scaling specifies ``units`` , which translates into number of instances.

        Valid values: ``units`` | ``vcpu`` | ``memory-mib``

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-desiredcapacitytype
        '''
        result = self._values.get("desired_capacity_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def health_check_grace_period(self) -> typing.Optional[jsii.Number]:
        '''The amount of time, in seconds, that Amazon EC2 Auto Scaling waits before checking the health status of an EC2 instance that has come into service and marking it unhealthy due to a failed health check.

        The default value is ``0`` . For more information, see `Health checks for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/healthcheck.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        If you are adding an ``ELB`` health check, you must specify this property.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-healthcheckgraceperiod
        '''
        result = self._values.get("health_check_grace_period")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def health_check_type(self) -> typing.Optional[builtins.str]:
        '''The service to use for the health checks.

        The valid values are ``EC2`` (default) and ``ELB`` . If you configure an Auto Scaling group to use load balancer (ELB) health checks, it considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks. For more information, see `Health checks for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/healthcheck.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-healthchecktype
        '''
        result = self._values.get("health_check_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the instance used to base the launch configuration on.

        If specified, Amazon EC2 Auto Scaling uses the configuration values from the specified instance to create a new launch configuration. For more information, see `Creating an Auto Scaling group using an EC2 instance <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-asg-from-instance.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        To get the instance ID, use the EC2 `DescribeInstances <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html>`_ API operation.

        If you specify ``LaunchTemplate`` , ``MixedInstancesPolicy`` , or ``LaunchConfigurationName`` , don't specify ``InstanceId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-instanceid
        '''
        result = self._values.get("instance_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def launch_configuration_name(self) -> typing.Optional[builtins.str]:
        '''The name of the `launch configuration <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig.html>`_ to use to launch instances.

        If you specify ``LaunchTemplate`` , ``MixedInstancesPolicy`` , or ``InstanceId`` , don't specify ``LaunchConfigurationName`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-launchconfigurationname
        '''
        result = self._values.get("launch_configuration_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def launch_template(
        self,
    ) -> typing.Optional[typing.Union[CfnAutoScalingGroup.LaunchTemplateSpecificationProperty, _IResolvable_da3f097b]]:
        '''Properties used to specify the `launch template <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-launchtemplate.html>`_ and version to use to launch instances. You can alternatively associate a launch template to the Auto Scaling group by specifying a ``MixedInstancesPolicy`` .

        If you omit this property, you must specify ``MixedInstancesPolicy`` , ``LaunchConfigurationName`` , or ``InstanceId`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-launchtemplate
        '''
        result = self._values.get("launch_template")
        return typing.cast(typing.Optional[typing.Union[CfnAutoScalingGroup.LaunchTemplateSpecificationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def lifecycle_hook_specification_list(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAutoScalingGroup.LifecycleHookSpecificationProperty, _IResolvable_da3f097b]]]]:
        '''One or more lifecycle hooks for the group, which specify actions to perform when Amazon EC2 Auto Scaling launches or terminates instances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-autoscaling-autoscalinggroup-lifecyclehookspecificationlist
        '''
        result = self._values.get("lifecycle_hook_specification_list")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAutoScalingGroup.LifecycleHookSpecificationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def load_balancer_names(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of Classic Load Balancers associated with this Auto Scaling group.

        For Application Load Balancers, Network Load Balancers, and Gateway Load Balancers, specify the ``TargetGroupARNs`` property instead.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-loadbalancernames
        '''
        result = self._values.get("load_balancer_names")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def max_instance_lifetime(self) -> typing.Optional[jsii.Number]:
        '''The maximum amount of time, in seconds, that an instance can be in service.

        The default is null. If specified, the value must be either 0 or a number equal to or greater than 86,400 seconds (1 day). For more information, see `Replacing Auto Scaling instances based on maximum instance lifetime <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-max-instance-lifetime.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-maxinstancelifetime
        '''
        result = self._values.get("max_instance_lifetime")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def metrics_collection(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAutoScalingGroup.MetricsCollectionProperty, _IResolvable_da3f097b]]]]:
        '''Enables the monitoring of group metrics of an Auto Scaling group.

        By default, these metrics are disabled.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-metricscollection
        '''
        result = self._values.get("metrics_collection")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAutoScalingGroup.MetricsCollectionProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def mixed_instances_policy(
        self,
    ) -> typing.Optional[typing.Union[CfnAutoScalingGroup.MixedInstancesPolicyProperty, _IResolvable_da3f097b]]:
        '''An embedded object that specifies a mixed instances policy.

        The policy includes properties that not only define the distribution of On-Demand Instances and Spot Instances, the maximum price to pay for Spot Instances (optional), and how the Auto Scaling group allocates instance types to fulfill On-Demand and Spot capacities, but also the properties that specify the instance configuration information—the launch template and instance types. The policy can also include a weight for each instance type and different launch templates for individual instance types.

        For more information, see `Auto Scaling groups with multiple instance types and purchase options <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-mixed-instances-groups.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        If you specify ``LaunchTemplate`` , ``InstanceId`` , or ``LaunchConfigurationName`` , don't specify ``MixedInstancesPolicy`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-mixedinstancespolicy
        '''
        result = self._values.get("mixed_instances_policy")
        return typing.cast(typing.Optional[typing.Union[CfnAutoScalingGroup.MixedInstancesPolicyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def new_instances_protected_from_scale_in(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Indicates whether newly launched instances are protected from termination by Amazon EC2 Auto Scaling when scaling in.

        For more information about preventing instances from terminating on scale in, see `Instance Protection <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html#instance-protection>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-newinstancesprotectedfromscalein
        '''
        result = self._values.get("new_instances_protected_from_scale_in")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def notification_configurations(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAutoScalingGroup.NotificationConfigurationProperty, _IResolvable_da3f097b]]]]:
        '''Configures an Auto Scaling group to send notifications when specified events take place.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-notificationconfigurations
        '''
        result = self._values.get("notification_configurations")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnAutoScalingGroup.NotificationConfigurationProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def placement_group(self) -> typing.Optional[builtins.str]:
        '''The name of the placement group into which you want to launch your instances.

        A placement group is a logical grouping of instances within a single Availability Zone. For more information, see `Placement Groups <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-placementgroup
        '''
        result = self._values.get("placement_group")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def service_linked_role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the service-linked role that the Auto Scaling group uses to call other AWS services on your behalf.

        By default, Amazon EC2 Auto Scaling uses a service-linked role named ``AWSServiceRoleForAutoScaling`` , which it creates if it does not exist. For more information, see `Service-linked roles for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-service-linked-role.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-autoscaling-autoscalinggroup-servicelinkedrolearn
        '''
        result = self._values.get("service_linked_role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(
        self,
    ) -> typing.Optional[typing.List[CfnAutoScalingGroup.TagPropertyProperty]]:
        '''One or more tags.

        You can tag your Auto Scaling group and propagate the tags to the Amazon EC2 instances it launches. For more information, see `Tagging Auto Scaling groups and instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-tagging.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[CfnAutoScalingGroup.TagPropertyProperty]], result)

    @builtins.property
    def target_group_arns(self) -> typing.Optional[typing.List[builtins.str]]:
        '''One or more Amazon Resource Names (ARN) of load balancer target groups to associate with the Auto Scaling group.

        Instances are registered as targets in a target group, and traffic is routed to the target group. For more information, see `Elastic Load Balancing and Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/autoscaling-load-balancer.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-targetgrouparns
        '''
        result = self._values.get("target_group_arns")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def termination_policies(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A policy or a list of policies that are used to select the instances to terminate.

        The policies are executed in the order that you list them. The termination policies supported by Amazon EC2 Auto Scaling: ``OldestInstance`` , ``OldestLaunchConfiguration`` , ``NewestInstance`` , ``ClosestToNextInstanceHour`` , ``Default`` , ``OldestLaunchTemplate`` , and ``AllocationStrategy`` . For more information, see `Controlling which Auto Scaling instances terminate during scale in <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-termpolicy
        '''
        result = self._values.get("termination_policies")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def vpc_zone_identifier(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list of subnet IDs for a virtual private cloud (VPC) where instances in the Auto Scaling group can be created.

        If you specify ``VPCZoneIdentifier`` with ``AvailabilityZones`` , the subnets that you specify for this property must reside in those Availability Zones.

        If this resource specifies public subnets and is also in a VPC that is defined in the same stack template, you must use the `DependsOn attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ to declare a dependency on the `VPC-gateway attachment <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc-gateway-attachment.html>`_ .
        .. epigraph::

           When you update ``VPCZoneIdentifier`` , this retains the same Auto Scaling group and replaces old instances with new ones, according to the specified subnets. You can optionally specify how CloudFormation handles these updates by using an `UpdatePolicy attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-vpczoneidentifier
        '''
        result = self._values.get("vpc_zone_identifier")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAutoScalingGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnLaunchConfiguration(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnLaunchConfiguration",
):
    '''A CloudFormation ``AWS::AutoScaling::LaunchConfiguration``.

    The ``AWS::AutoScaling::LaunchConfiguration`` resource specifies the launch configuration that can be used by an Auto Scaling group to configure Amazon EC2 instances.

    When you update the launch configuration for an Auto Scaling group, CloudFormation deletes that resource and creates a new launch configuration with the updated properties and a new name. Existing instances are not affected. To update existing instances when you update the ``AWS::AutoScaling::LaunchConfiguration`` resource, you can specify an `UpdatePolicy attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html>`_ for the group. You can find sample update policies for rolling updates in `Auto scaling template snippets <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-autoscaling.html>`_ .

    For more information, see `CreateLaunchConfiguration <https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateLaunchConfiguration.html>`_ in the *Amazon EC2 Auto Scaling API Reference* and `Launch configurations <https://docs.aws.amazon.com/autoscaling/ec2/userguide/LaunchConfiguration.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
    .. epigraph::

       To configure Amazon EC2 instances launched as part of the Auto Scaling group, you can specify a launch template or a launch configuration. We recommend that you use a `launch template <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-launchtemplate.html>`_ to make sure that you can use the latest features of Amazon EC2, such as Dedicated Hosts and T2 Unlimited instances. For more information, see `Creating a launch template for an Auto Scaling group <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-template.html>`_ .

    :cloudformationResource: AWS::AutoScaling::LaunchConfiguration
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_autoscaling as autoscaling
        
        cfn_launch_configuration = autoscaling.CfnLaunchConfiguration(self, "MyCfnLaunchConfiguration",
            image_id="imageId",
            instance_type="instanceType",
        
            # the properties below are optional
            associate_public_ip_address=False,
            block_device_mappings=[autoscaling.CfnLaunchConfiguration.BlockDeviceMappingProperty(
                device_name="deviceName",
        
                # the properties below are optional
                ebs=autoscaling.CfnLaunchConfiguration.BlockDeviceProperty(
                    delete_on_termination=False,
                    encrypted=False,
                    iops=123,
                    snapshot_id="snapshotId",
                    throughput=123,
                    volume_size=123,
                    volume_type="volumeType"
                ),
                no_device=False,
                virtual_name="virtualName"
            )],
            classic_link_vpc_id="classicLinkVpcId",
            classic_link_vpc_security_groups=["classicLinkVpcSecurityGroups"],
            ebs_optimized=False,
            iam_instance_profile="iamInstanceProfile",
            instance_id="instanceId",
            instance_monitoring=False,
            kernel_id="kernelId",
            key_name="keyName",
            launch_configuration_name="launchConfigurationName",
            metadata_options=autoscaling.CfnLaunchConfiguration.MetadataOptionsProperty(
                http_endpoint="httpEndpoint",
                http_put_response_hop_limit=123,
                http_tokens="httpTokens"
            ),
            placement_tenancy="placementTenancy",
            ram_disk_id="ramDiskId",
            security_groups=["securityGroups"],
            spot_price="spotPrice",
            user_data="userData"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        image_id: builtins.str,
        instance_type: builtins.str,
        associate_public_ip_address: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        block_device_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnLaunchConfiguration.BlockDeviceMappingProperty", _IResolvable_da3f097b]]]] = None,
        classic_link_vpc_id: typing.Optional[builtins.str] = None,
        classic_link_vpc_security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        ebs_optimized: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        iam_instance_profile: typing.Optional[builtins.str] = None,
        instance_id: typing.Optional[builtins.str] = None,
        instance_monitoring: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        kernel_id: typing.Optional[builtins.str] = None,
        key_name: typing.Optional[builtins.str] = None,
        launch_configuration_name: typing.Optional[builtins.str] = None,
        metadata_options: typing.Optional[typing.Union["CfnLaunchConfiguration.MetadataOptionsProperty", _IResolvable_da3f097b]] = None,
        placement_tenancy: typing.Optional[builtins.str] = None,
        ram_disk_id: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        spot_price: typing.Optional[builtins.str] = None,
        user_data: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::AutoScaling::LaunchConfiguration``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param image_id: Provides the unique ID of the Amazon Machine Image (AMI) that was assigned during registration. For more information, see `Finding a Linux AMI <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/finding-an-ami.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param instance_type: Specifies the instance type of the EC2 instance. For information about available instance types, see `Available instance types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#AvailableInstanceTypes>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param associate_public_ip_address: For Auto Scaling groups that are running in a virtual private cloud (VPC), specifies whether to assign a public IP address to the group's instances. If you specify ``true`` , each instance in the Auto Scaling group receives a unique public IP address. For more information, see `Launching Auto Scaling instances in a VPC <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-in-vpc.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . If an instance receives a public IP address and is also in a VPC that is defined in the same stack template, you must use the `DependsOn attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ to declare a dependency on the `VPC-gateway attachment <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc-gateway-attachment.html>`_ . .. epigraph:: If the instance is launched into a default subnet, the default is to assign a public IP address, unless you disabled the option to assign a public IP address on the subnet. If the instance is launched into a nondefault subnet, the default is not to assign a public IP address, unless you enabled the option to assign a public IP address on the subnet.
        :param block_device_mappings: Specifies how block devices are exposed to the instance. You can specify virtual devices and EBS volumes.
        :param classic_link_vpc_id: The ID of a ClassicLink-enabled VPC to link your EC2-Classic instances to. For more information, see `ClassicLink <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/vpc-classiclink.html>`_ in the *Amazon EC2 User Guide for Linux Instances* and `Linking EC2-Classic instances to a VPC <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-in-vpc.html#as-ClassicLink>`_ in the *Amazon EC2 Auto Scaling User Guide* . This property can only be used if you are launching EC2-Classic instances.
        :param classic_link_vpc_security_groups: The IDs of one or more security groups for the VPC that you specified in the ``ClassicLinkVPCId`` property. If you specify the ``ClassicLinkVPCId`` property, you must specify this property.
        :param ebs_optimized: Specifies whether the launch configuration is optimized for EBS I/O ( ``true`` ) or not ( ``false`` ). This optimization provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal EBS I/O performance. Additional fees are incurred when you enable EBS optimization for an instance type that is not EBS-optimized by default. For more information, see `Amazon EBS–optimized instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSOptimized.html>`_ in the *Amazon EC2 User Guide for Linux Instances* . The default value is ``false`` .
        :param iam_instance_profile: Provides the name or the Amazon Resource Name (ARN) of the instance profile associated with the IAM role for the instance. The instance profile contains the IAM role. For more information, see `IAM role for applications that run on Amazon EC2 instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/us-iam-role.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param instance_id: The ID of the Amazon EC2 instance you want to use to create the launch configuration. Use this property if you want the launch configuration to use settings from an existing Amazon EC2 instance. When you use an instance to create a launch configuration, all properties are derived from the instance with the exception of ``BlockDeviceMapping`` and ``AssociatePublicIpAddress`` . You can override any properties from the instance by specifying them in the launch configuration.
        :param instance_monitoring: Controls whether instances in this group are launched with detailed ( ``true`` ) or basic ( ``false`` ) monitoring. The default value is ``true`` (enabled). .. epigraph:: When detailed monitoring is enabled, Amazon CloudWatch generates metrics every minute and your account is charged a fee. When you disable detailed monitoring, CloudWatch generates metrics every 5 minutes. For more information, see `Configure monitoring for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/latest/userguide/as-instance-monitoring.html#enable-as-instance-metrics>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param kernel_id: Provides the ID of the kernel associated with the EC2 AMI. .. epigraph:: We recommend that you use PV-GRUB instead of kernels and RAM disks. For more information, see `User provided kernels <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/UserProvidedKernels.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param key_name: Provides the name of the EC2 key pair. .. epigraph:: If you do not specify a key pair, you can't connect to the instance unless you choose an AMI that is configured to allow users another way to log in. For information on creating a key pair, see `Amazon EC2 key pairs and Linux instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param launch_configuration_name: The name of the launch configuration. This name must be unique per Region per account.
        :param metadata_options: The metadata options for the instances. For more information, see `Configuring the Instance Metadata Options <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-config.html#launch-configurations-imds>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param placement_tenancy: The tenancy of the instance, either ``default`` or ``dedicated`` . An instance with ``dedicated`` tenancy runs on isolated, single-tenant hardware and can only be launched into a VPC. You must set the value of this property to ``dedicated`` if want to launch dedicated instances in a shared tenancy VPC (a VPC with the instance placement tenancy attribute set to default). If you specify this property, you must specify at least one subnet in the ``VPCZoneIdentifier`` property of the `AWS::AutoScaling::AutoScalingGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html>`_ resource. For more information, see `Configuring instance tenancy with Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/auto-scaling-dedicated-instances.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param ram_disk_id: The ID of the RAM disk to select. .. epigraph:: We recommend that you use PV-GRUB instead of kernels and RAM disks. For more information, see `User provided kernels <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/UserProvidedKernels.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param security_groups: A list that contains the security groups to assign to the instances in the Auto Scaling group. The list can contain both the IDs of existing security groups and references to `SecurityGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html>`_ resources created in the template. For more information, see `Security groups for your VPC <https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_SecurityGroups.html>`_ in the *Amazon Virtual Private Cloud User Guide* .
        :param spot_price: The maximum hourly price you are willing to pay for any Spot Instances launched to fulfill the request. Spot Instances are launched when the price you specify exceeds the current Spot price. For more information, see `Requesting Spot Instances for fault-tolerant and flexible applications <https://docs.aws.amazon.com/autoscaling/ec2/userguide/launch-configuration-requesting-spot-instances.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . .. epigraph:: When you change your maximum price by creating a new launch configuration, running instances will continue to run as long as the maximum price for those running instances is higher than the current Spot price. Valid Range: Minimum value of 0.001
        :param user_data: The Base64-encoded user data to make available to the launched EC2 instances. For more information, see `Instance metadata and user data <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        '''
        props = CfnLaunchConfigurationProps(
            image_id=image_id,
            instance_type=instance_type,
            associate_public_ip_address=associate_public_ip_address,
            block_device_mappings=block_device_mappings,
            classic_link_vpc_id=classic_link_vpc_id,
            classic_link_vpc_security_groups=classic_link_vpc_security_groups,
            ebs_optimized=ebs_optimized,
            iam_instance_profile=iam_instance_profile,
            instance_id=instance_id,
            instance_monitoring=instance_monitoring,
            kernel_id=kernel_id,
            key_name=key_name,
            launch_configuration_name=launch_configuration_name,
            metadata_options=metadata_options,
            placement_tenancy=placement_tenancy,
            ram_disk_id=ram_disk_id,
            security_groups=security_groups,
            spot_price=spot_price,
            user_data=user_data,
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
    @jsii.member(jsii_name="imageId")
    def image_id(self) -> builtins.str:
        '''Provides the unique ID of the Amazon Machine Image (AMI) that was assigned during registration.

        For more information, see `Finding a Linux AMI <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/finding-an-ami.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-imageid
        '''
        return typing.cast(builtins.str, jsii.get(self, "imageId"))

    @image_id.setter
    def image_id(self, value: builtins.str) -> None:
        jsii.set(self, "imageId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceType")
    def instance_type(self) -> builtins.str:
        '''Specifies the instance type of the EC2 instance.

        For information about available instance types, see `Available instance types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#AvailableInstanceTypes>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-instancetype
        '''
        return typing.cast(builtins.str, jsii.get(self, "instanceType"))

    @instance_type.setter
    def instance_type(self, value: builtins.str) -> None:
        jsii.set(self, "instanceType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="associatePublicIpAddress")
    def associate_public_ip_address(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''For Auto Scaling groups that are running in a virtual private cloud (VPC), specifies whether to assign a public IP address to the group's instances.

        If you specify ``true`` , each instance in the Auto Scaling group receives a unique public IP address. For more information, see `Launching Auto Scaling instances in a VPC <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-in-vpc.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        If an instance receives a public IP address and is also in a VPC that is defined in the same stack template, you must use the `DependsOn attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ to declare a dependency on the `VPC-gateway attachment <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc-gateway-attachment.html>`_ .
        .. epigraph::

           If the instance is launched into a default subnet, the default is to assign a public IP address, unless you disabled the option to assign a public IP address on the subnet. If the instance is launched into a nondefault subnet, the default is not to assign a public IP address, unless you enabled the option to assign a public IP address on the subnet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-associatepublicipaddress
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "associatePublicIpAddress"))

    @associate_public_ip_address.setter
    def associate_public_ip_address(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "associatePublicIpAddress", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="blockDeviceMappings")
    def block_device_mappings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLaunchConfiguration.BlockDeviceMappingProperty", _IResolvable_da3f097b]]]]:
        '''Specifies how block devices are exposed to the instance.

        You can specify virtual devices and EBS volumes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-blockdevicemappings
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLaunchConfiguration.BlockDeviceMappingProperty", _IResolvable_da3f097b]]]], jsii.get(self, "blockDeviceMappings"))

    @block_device_mappings.setter
    def block_device_mappings(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnLaunchConfiguration.BlockDeviceMappingProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "blockDeviceMappings", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="classicLinkVpcId")
    def classic_link_vpc_id(self) -> typing.Optional[builtins.str]:
        '''The ID of a ClassicLink-enabled VPC to link your EC2-Classic instances to.

        For more information, see `ClassicLink <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/vpc-classiclink.html>`_ in the *Amazon EC2 User Guide for Linux Instances* and `Linking EC2-Classic instances to a VPC <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-in-vpc.html#as-ClassicLink>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        This property can only be used if you are launching EC2-Classic instances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-classiclinkvpcid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "classicLinkVpcId"))

    @classic_link_vpc_id.setter
    def classic_link_vpc_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "classicLinkVpcId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="classicLinkVpcSecurityGroups")
    def classic_link_vpc_security_groups(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''The IDs of one or more security groups for the VPC that you specified in the ``ClassicLinkVPCId`` property.

        If you specify the ``ClassicLinkVPCId`` property, you must specify this property.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-classiclinkvpcsecuritygroups
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "classicLinkVpcSecurityGroups"))

    @classic_link_vpc_security_groups.setter
    def classic_link_vpc_security_groups(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "classicLinkVpcSecurityGroups", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ebsOptimized")
    def ebs_optimized(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the launch configuration is optimized for EBS I/O ( ``true`` ) or not ( ``false`` ).

        This optimization provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal EBS I/O performance. Additional fees are incurred when you enable EBS optimization for an instance type that is not EBS-optimized by default. For more information, see `Amazon EBS–optimized instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSOptimized.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        The default value is ``false`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-ebsoptimized
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "ebsOptimized"))

    @ebs_optimized.setter
    def ebs_optimized(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "ebsOptimized", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="iamInstanceProfile")
    def iam_instance_profile(self) -> typing.Optional[builtins.str]:
        '''Provides the name or the Amazon Resource Name (ARN) of the instance profile associated with the IAM role for the instance.

        The instance profile contains the IAM role.

        For more information, see `IAM role for applications that run on Amazon EC2 instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/us-iam-role.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-iaminstanceprofile
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "iamInstanceProfile"))

    @iam_instance_profile.setter
    def iam_instance_profile(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "iamInstanceProfile", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceId")
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the Amazon EC2 instance you want to use to create the launch configuration.

        Use this property if you want the launch configuration to use settings from an existing Amazon EC2 instance. When you use an instance to create a launch configuration, all properties are derived from the instance with the exception of ``BlockDeviceMapping`` and ``AssociatePublicIpAddress`` . You can override any properties from the instance by specifying them in the launch configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-instanceid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "instanceId"))

    @instance_id.setter
    def instance_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "instanceId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceMonitoring")
    def instance_monitoring(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Controls whether instances in this group are launched with detailed ( ``true`` ) or basic ( ``false`` ) monitoring.

        The default value is ``true`` (enabled).
        .. epigraph::

           When detailed monitoring is enabled, Amazon CloudWatch generates metrics every minute and your account is charged a fee. When you disable detailed monitoring, CloudWatch generates metrics every 5 minutes. For more information, see `Configure monitoring for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/latest/userguide/as-instance-monitoring.html#enable-as-instance-metrics>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-instancemonitoring
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "instanceMonitoring"))

    @instance_monitoring.setter
    def instance_monitoring(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "instanceMonitoring", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kernelId")
    def kernel_id(self) -> typing.Optional[builtins.str]:
        '''Provides the ID of the kernel associated with the EC2 AMI.

        .. epigraph::

           We recommend that you use PV-GRUB instead of kernels and RAM disks. For more information, see `User provided kernels <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/UserProvidedKernels.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-kernelid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "kernelId"))

    @kernel_id.setter
    def kernel_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "kernelId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="keyName")
    def key_name(self) -> typing.Optional[builtins.str]:
        '''Provides the name of the EC2 key pair.

        .. epigraph::

           If you do not specify a key pair, you can't connect to the instance unless you choose an AMI that is configured to allow users another way to log in. For information on creating a key pair, see `Amazon EC2 key pairs and Linux instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-keyname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "keyName"))

    @key_name.setter
    def key_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "keyName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="launchConfigurationName")
    def launch_configuration_name(self) -> typing.Optional[builtins.str]:
        '''The name of the launch configuration.

        This name must be unique per Region per account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-launchconfigurationname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "launchConfigurationName"))

    @launch_configuration_name.setter
    def launch_configuration_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "launchConfigurationName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="metadataOptions")
    def metadata_options(
        self,
    ) -> typing.Optional[typing.Union["CfnLaunchConfiguration.MetadataOptionsProperty", _IResolvable_da3f097b]]:
        '''The metadata options for the instances.

        For more information, see `Configuring the Instance Metadata Options <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-config.html#launch-configurations-imds>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-metadataoptions
        '''
        return typing.cast(typing.Optional[typing.Union["CfnLaunchConfiguration.MetadataOptionsProperty", _IResolvable_da3f097b]], jsii.get(self, "metadataOptions"))

    @metadata_options.setter
    def metadata_options(
        self,
        value: typing.Optional[typing.Union["CfnLaunchConfiguration.MetadataOptionsProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "metadataOptions", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="placementTenancy")
    def placement_tenancy(self) -> typing.Optional[builtins.str]:
        '''The tenancy of the instance, either ``default`` or ``dedicated`` .

        An instance with ``dedicated`` tenancy runs on isolated, single-tenant hardware and can only be launched into a VPC. You must set the value of this property to ``dedicated`` if want to launch dedicated instances in a shared tenancy VPC (a VPC with the instance placement tenancy attribute set to default).

        If you specify this property, you must specify at least one subnet in the ``VPCZoneIdentifier`` property of the `AWS::AutoScaling::AutoScalingGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html>`_ resource.

        For more information, see `Configuring instance tenancy with Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/auto-scaling-dedicated-instances.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-placementtenancy
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "placementTenancy"))

    @placement_tenancy.setter
    def placement_tenancy(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "placementTenancy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="ramDiskId")
    def ram_disk_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the RAM disk to select.

        .. epigraph::

           We recommend that you use PV-GRUB instead of kernels and RAM disks. For more information, see `User provided kernels <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/UserProvidedKernels.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-ramdiskid
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "ramDiskId"))

    @ram_disk_id.setter
    def ram_disk_id(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "ramDiskId", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="securityGroups")
    def security_groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list that contains the security groups to assign to the instances in the Auto Scaling group.

        The list can contain both the IDs of existing security groups and references to `SecurityGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html>`_ resources created in the template.

        For more information, see `Security groups for your VPC <https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_SecurityGroups.html>`_ in the *Amazon Virtual Private Cloud User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-securitygroups
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "securityGroups"))

    @security_groups.setter
    def security_groups(
        self,
        value: typing.Optional[typing.List[builtins.str]],
    ) -> None:
        jsii.set(self, "securityGroups", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="spotPrice")
    def spot_price(self) -> typing.Optional[builtins.str]:
        '''The maximum hourly price you are willing to pay for any Spot Instances launched to fulfill the request.

        Spot Instances are launched when the price you specify exceeds the current Spot price. For more information, see `Requesting Spot Instances for fault-tolerant and flexible applications <https://docs.aws.amazon.com/autoscaling/ec2/userguide/launch-configuration-requesting-spot-instances.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        .. epigraph::

           When you change your maximum price by creating a new launch configuration, running instances will continue to run as long as the maximum price for those running instances is higher than the current Spot price.

        Valid Range: Minimum value of 0.001

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-spotprice
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "spotPrice"))

    @spot_price.setter
    def spot_price(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "spotPrice", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userData")
    def user_data(self) -> typing.Optional[builtins.str]:
        '''The Base64-encoded user data to make available to the launched EC2 instances.

        For more information, see `Instance metadata and user data <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-userdata
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "userData"))

    @user_data.setter
    def user_data(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "userData", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnLaunchConfiguration.BlockDeviceMappingProperty",
        jsii_struct_bases=[],
        name_mapping={
            "device_name": "deviceName",
            "ebs": "ebs",
            "no_device": "noDevice",
            "virtual_name": "virtualName",
        },
    )
    class BlockDeviceMappingProperty:
        def __init__(
            self,
            *,
            device_name: builtins.str,
            ebs: typing.Optional[typing.Union["CfnLaunchConfiguration.BlockDeviceProperty", _IResolvable_da3f097b]] = None,
            no_device: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            virtual_name: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``BlockDeviceMapping`` specifies a block device mapping for the ``BlockDeviceMappings`` property of the `AWS::AutoScaling::LaunchConfiguration <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig.html>`_ resource.

            Each instance that is launched has an associated root device volume, either an Amazon EBS volume or an instance store volume. You can use block device mappings to specify additional EBS volumes or instance store volumes to attach to an instance when it is launched.

            For more information, see `Example block device mapping <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-device-mapping-concepts.html#block-device-mapping-ex>`_ in the *Amazon EC2 User Guide for Linux Instances* .

            :param device_name: The device name exposed to the EC2 instance (for example, ``/dev/sdh`` or ``xvdh`` ). For more information, see `Device naming on Linux instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
            :param ebs: Parameters used to automatically set up EBS volumes when an instance is launched. You can specify either ``VirtualName`` or ``Ebs`` , but not both.
            :param no_device: Setting this value to ``true`` suppresses the specified device included in the block device mapping of the AMI. If ``NoDevice`` is ``true`` for the root device, instances might fail the EC2 health check. In that case, Amazon EC2 Auto Scaling launches replacement instances. If you specify ``NoDevice`` , you cannot specify ``Ebs`` .
            :param virtual_name: The name of the virtual device. The name must be in the form ephemeral *X* where *X* is a number starting from zero (0), for example, ``ephemeral0`` . You can specify either ``VirtualName`` or ``Ebs`` , but not both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevicemapping.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                block_device_mapping_property = autoscaling.CfnLaunchConfiguration.BlockDeviceMappingProperty(
                    device_name="deviceName",
                
                    # the properties below are optional
                    ebs=autoscaling.CfnLaunchConfiguration.BlockDeviceProperty(
                        delete_on_termination=False,
                        encrypted=False,
                        iops=123,
                        snapshot_id="snapshotId",
                        throughput=123,
                        volume_size=123,
                        volume_type="volumeType"
                    ),
                    no_device=False,
                    virtual_name="virtualName"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "device_name": device_name,
            }
            if ebs is not None:
                self._values["ebs"] = ebs
            if no_device is not None:
                self._values["no_device"] = no_device
            if virtual_name is not None:
                self._values["virtual_name"] = virtual_name

        @builtins.property
        def device_name(self) -> builtins.str:
            '''The device name exposed to the EC2 instance (for example, ``/dev/sdh`` or ``xvdh`` ).

            For more information, see `Device naming on Linux instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevicemapping.html#cfn-autoscaling-launchconfiguration-blockdevicemapping-devicename
            '''
            result = self._values.get("device_name")
            assert result is not None, "Required property 'device_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def ebs(
            self,
        ) -> typing.Optional[typing.Union["CfnLaunchConfiguration.BlockDeviceProperty", _IResolvable_da3f097b]]:
            '''Parameters used to automatically set up EBS volumes when an instance is launched.

            You can specify either ``VirtualName`` or ``Ebs`` , but not both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevicemapping.html#cfn-autoscaling-launchconfiguration-blockdevicemapping-ebs
            '''
            result = self._values.get("ebs")
            return typing.cast(typing.Optional[typing.Union["CfnLaunchConfiguration.BlockDeviceProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def no_device(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Setting this value to ``true`` suppresses the specified device included in the block device mapping of the AMI.

            If ``NoDevice`` is ``true`` for the root device, instances might fail the EC2 health check. In that case, Amazon EC2 Auto Scaling launches replacement instances.

            If you specify ``NoDevice`` , you cannot specify ``Ebs`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevicemapping.html#cfn-autoscaling-launchconfiguration-blockdevicemapping-nodevice
            '''
            result = self._values.get("no_device")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def virtual_name(self) -> typing.Optional[builtins.str]:
            '''The name of the virtual device.

            The name must be in the form ephemeral *X* where *X* is a number starting from zero (0), for example, ``ephemeral0`` .

            You can specify either ``VirtualName`` or ``Ebs`` , but not both.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevicemapping.html#cfn-autoscaling-launchconfiguration-blockdevicemapping-virtualname
            '''
            result = self._values.get("virtual_name")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BlockDeviceMappingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnLaunchConfiguration.BlockDeviceProperty",
        jsii_struct_bases=[],
        name_mapping={
            "delete_on_termination": "deleteOnTermination",
            "encrypted": "encrypted",
            "iops": "iops",
            "snapshot_id": "snapshotId",
            "throughput": "throughput",
            "volume_size": "volumeSize",
            "volume_type": "volumeType",
        },
    )
    class BlockDeviceProperty:
        def __init__(
            self,
            *,
            delete_on_termination: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            encrypted: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            iops: typing.Optional[jsii.Number] = None,
            snapshot_id: typing.Optional[builtins.str] = None,
            throughput: typing.Optional[jsii.Number] = None,
            volume_size: typing.Optional[jsii.Number] = None,
            volume_type: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``BlockDevice`` is a property of the ``EBS`` property of the `AWS::AutoScaling::LaunchConfiguration BlockDeviceMapping <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig-blockdev-mapping.html>`_ property type that describes an Amazon EBS volume.

            :param delete_on_termination: Indicates whether the volume is deleted on instance termination. For Amazon EC2 Auto Scaling, the default value is ``true`` .
            :param encrypted: Specifies whether the volume should be encrypted. Encrypted EBS volumes can only be attached to instances that support Amazon EBS encryption. For more information, see `Supported instance types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#EBSEncryption_supported_instances>`_ . If your AMI uses encrypted volumes, you can also only launch it on supported instance types. .. epigraph:: If you are creating a volume from a snapshot, you cannot create an unencrypted volume from an encrypted snapshot. Also, you cannot specify a KMS key ID when using a launch configuration. If you enable encryption by default, the EBS volumes that you create are always encrypted, either using the AWS managed KMS key or a customer-managed KMS key, regardless of whether the snapshot was encrypted. For more information, see `Using AWS KMS keys to encrypt Amazon EBS volumes <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-data-protection.html#encryption>`_ in the *Amazon EC2 Auto Scaling User Guide* .
            :param iops: The number of input/output (I/O) operations per second (IOPS) to provision for the volume. For ``gp3`` and ``io1`` volumes, this represents the number of IOPS that are provisioned for the volume. For ``gp2`` volumes, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting. The following are the supported values for each volume type: - ``gp3`` : 3,000-16,000 IOPS - ``io1`` : 100-64,000 IOPS For ``io1`` volumes, we guarantee 64,000 IOPS only for `Instances built on the Nitro System <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#ec2-nitro-instances>`_ . Other instance families guarantee performance up to 32,000 IOPS. ``Iops`` is supported when the volume type is ``gp3`` or ``io1`` and required only when the volume type is ``io1`` . (Not used with ``standard`` , ``gp2`` , ``st1`` , or ``sc1`` volumes.)
            :param snapshot_id: The snapshot ID of the volume to use. You must specify either a ``VolumeSize`` or a ``SnapshotId`` .
            :param throughput: The throughput (MiBps) to provision for a ``gp3`` volume.
            :param volume_size: The volume size, in GiBs. The following are the supported volumes sizes for each volume type:. - ``gp2`` and ``gp3`` : 1-16,384 - ``io1`` : 4-16,384 - ``st1`` and ``sc1`` : 125-16,384 - ``standard`` : 1-1,024 You must specify either a ``SnapshotId`` or a ``VolumeSize`` . If you specify both ``SnapshotId`` and ``VolumeSize`` , the volume size must be equal or greater than the size of the snapshot.
            :param volume_type: The volume type. For more information, see `Amazon EBS Volume Types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html>`_ in the *Amazon EC2 User Guide for Linux Instances* . Valid Values: ``standard`` | ``io1`` | ``gp2`` | ``st1`` | ``sc1`` | ``gp3``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevice.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                block_device_property = autoscaling.CfnLaunchConfiguration.BlockDeviceProperty(
                    delete_on_termination=False,
                    encrypted=False,
                    iops=123,
                    snapshot_id="snapshotId",
                    throughput=123,
                    volume_size=123,
                    volume_type="volumeType"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if delete_on_termination is not None:
                self._values["delete_on_termination"] = delete_on_termination
            if encrypted is not None:
                self._values["encrypted"] = encrypted
            if iops is not None:
                self._values["iops"] = iops
            if snapshot_id is not None:
                self._values["snapshot_id"] = snapshot_id
            if throughput is not None:
                self._values["throughput"] = throughput
            if volume_size is not None:
                self._values["volume_size"] = volume_size
            if volume_type is not None:
                self._values["volume_type"] = volume_type

        @builtins.property
        def delete_on_termination(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether the volume is deleted on instance termination.

            For Amazon EC2 Auto Scaling, the default value is ``true`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevice.html#cfn-autoscaling-launchconfiguration-blockdevice-deleteontermination
            '''
            result = self._values.get("delete_on_termination")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def encrypted(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether the volume should be encrypted.

            Encrypted EBS volumes can only be attached to instances that support Amazon EBS encryption. For more information, see `Supported instance types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#EBSEncryption_supported_instances>`_ . If your AMI uses encrypted volumes, you can also only launch it on supported instance types.
            .. epigraph::

               If you are creating a volume from a snapshot, you cannot create an unencrypted volume from an encrypted snapshot. Also, you cannot specify a KMS key ID when using a launch configuration.

               If you enable encryption by default, the EBS volumes that you create are always encrypted, either using the AWS managed KMS key or a customer-managed KMS key, regardless of whether the snapshot was encrypted.

               For more information, see `Using AWS KMS keys to encrypt Amazon EBS volumes <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-data-protection.html#encryption>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevice.html#cfn-autoscaling-launchconfiguration-blockdevice-encrypted
            '''
            result = self._values.get("encrypted")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def iops(self) -> typing.Optional[jsii.Number]:
            '''The number of input/output (I/O) operations per second (IOPS) to provision for the volume.

            For ``gp3`` and ``io1`` volumes, this represents the number of IOPS that are provisioned for the volume. For ``gp2`` volumes, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting.

            The following are the supported values for each volume type:

            - ``gp3`` : 3,000-16,000 IOPS
            - ``io1`` : 100-64,000 IOPS

            For ``io1`` volumes, we guarantee 64,000 IOPS only for `Instances built on the Nitro System <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#ec2-nitro-instances>`_ . Other instance families guarantee performance up to 32,000 IOPS.

            ``Iops`` is supported when the volume type is ``gp3`` or ``io1`` and required only when the volume type is ``io1`` . (Not used with ``standard`` , ``gp2`` , ``st1`` , or ``sc1`` volumes.)

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevice.html#cfn-autoscaling-launchconfiguration-blockdevice-iops
            '''
            result = self._values.get("iops")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def snapshot_id(self) -> typing.Optional[builtins.str]:
            '''The snapshot ID of the volume to use.

            You must specify either a ``VolumeSize`` or a ``SnapshotId`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevice.html#cfn-autoscaling-launchconfiguration-blockdevice-snapshotid
            '''
            result = self._values.get("snapshot_id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def throughput(self) -> typing.Optional[jsii.Number]:
            '''The throughput (MiBps) to provision for a ``gp3`` volume.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevice.html#cfn-autoscaling-launchconfiguration-blockdevice-throughput
            '''
            result = self._values.get("throughput")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def volume_size(self) -> typing.Optional[jsii.Number]:
            '''The volume size, in GiBs. The following are the supported volumes sizes for each volume type:.

            - ``gp2`` and ``gp3`` : 1-16,384
            - ``io1`` : 4-16,384
            - ``st1`` and ``sc1`` : 125-16,384
            - ``standard`` : 1-1,024

            You must specify either a ``SnapshotId`` or a ``VolumeSize`` . If you specify both ``SnapshotId`` and ``VolumeSize`` , the volume size must be equal or greater than the size of the snapshot.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevice.html#cfn-autoscaling-launchconfiguration-blockdevice-volumesize
            '''
            result = self._values.get("volume_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def volume_type(self) -> typing.Optional[builtins.str]:
            '''The volume type.

            For more information, see `Amazon EBS Volume Types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

            Valid Values: ``standard`` | ``io1`` | ``gp2`` | ``st1`` | ``sc1`` | ``gp3``

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-blockdevice.html#cfn-autoscaling-launchconfiguration-blockdevice-volumetype
            '''
            result = self._values.get("volume_type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "BlockDeviceProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnLaunchConfiguration.MetadataOptionsProperty",
        jsii_struct_bases=[],
        name_mapping={
            "http_endpoint": "httpEndpoint",
            "http_put_response_hop_limit": "httpPutResponseHopLimit",
            "http_tokens": "httpTokens",
        },
    )
    class MetadataOptionsProperty:
        def __init__(
            self,
            *,
            http_endpoint: typing.Optional[builtins.str] = None,
            http_put_response_hop_limit: typing.Optional[jsii.Number] = None,
            http_tokens: typing.Optional[builtins.str] = None,
        ) -> None:
            '''``MetadataOptions`` is a property of `AWS::AutoScaling::LaunchConfiguration <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig.html>`_ that describes metadata options for the instances.

            For more information, see `Configuring the instance metadata options <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-config.html#launch-configurations-imds>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :param http_endpoint: This parameter enables or disables the HTTP metadata endpoint on your instances. If the parameter is not specified, the default state is ``enabled`` . .. epigraph:: If you specify a value of ``disabled`` , you will not be able to access your instance metadata.
            :param http_put_response_hop_limit: The desired HTTP PUT response hop limit for instance metadata requests. The larger the number, the further instance metadata requests can travel. Default: 1
            :param http_tokens: The state of token usage for your instance metadata requests. If the parameter is not specified in the request, the default state is ``optional`` . If the state is ``optional`` , you can choose to retrieve instance metadata with or without a signed token header on your request. If you retrieve the IAM role credentials without a token, the version 1.0 role credentials are returned. If you retrieve the IAM role credentials using a valid signed token, the version 2.0 role credentials are returned. If the state is ``required`` , you must send a signed token header with any instance metadata retrieval requests. In this state, retrieving the IAM role credentials always returns the version 2.0 credentials; the version 1.0 credentials are not available.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-metadataoptions.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                metadata_options_property = autoscaling.CfnLaunchConfiguration.MetadataOptionsProperty(
                    http_endpoint="httpEndpoint",
                    http_put_response_hop_limit=123,
                    http_tokens="httpTokens"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if http_endpoint is not None:
                self._values["http_endpoint"] = http_endpoint
            if http_put_response_hop_limit is not None:
                self._values["http_put_response_hop_limit"] = http_put_response_hop_limit
            if http_tokens is not None:
                self._values["http_tokens"] = http_tokens

        @builtins.property
        def http_endpoint(self) -> typing.Optional[builtins.str]:
            '''This parameter enables or disables the HTTP metadata endpoint on your instances.

            If the parameter is not specified, the default state is ``enabled`` .
            .. epigraph::

               If you specify a value of ``disabled`` , you will not be able to access your instance metadata.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-metadataoptions.html#cfn-autoscaling-launchconfiguration-metadataoptions-httpendpoint
            '''
            result = self._values.get("http_endpoint")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def http_put_response_hop_limit(self) -> typing.Optional[jsii.Number]:
            '''The desired HTTP PUT response hop limit for instance metadata requests.

            The larger the number, the further instance metadata requests can travel.

            Default: 1

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-metadataoptions.html#cfn-autoscaling-launchconfiguration-metadataoptions-httpputresponsehoplimit
            '''
            result = self._values.get("http_put_response_hop_limit")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def http_tokens(self) -> typing.Optional[builtins.str]:
            '''The state of token usage for your instance metadata requests.

            If the parameter is not specified in the request, the default state is ``optional`` .

            If the state is ``optional`` , you can choose to retrieve instance metadata with or without a signed token header on your request. If you retrieve the IAM role credentials without a token, the version 1.0 role credentials are returned. If you retrieve the IAM role credentials using a valid signed token, the version 2.0 role credentials are returned.

            If the state is ``required`` , you must send a signed token header with any instance metadata retrieval requests. In this state, retrieving the IAM role credentials always returns the version 2.0 credentials; the version 1.0 credentials are not available.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-launchconfiguration-metadataoptions.html#cfn-autoscaling-launchconfiguration-metadataoptions-httptokens
            '''
            result = self._values.get("http_tokens")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MetadataOptionsProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnLaunchConfigurationProps",
    jsii_struct_bases=[],
    name_mapping={
        "image_id": "imageId",
        "instance_type": "instanceType",
        "associate_public_ip_address": "associatePublicIpAddress",
        "block_device_mappings": "blockDeviceMappings",
        "classic_link_vpc_id": "classicLinkVpcId",
        "classic_link_vpc_security_groups": "classicLinkVpcSecurityGroups",
        "ebs_optimized": "ebsOptimized",
        "iam_instance_profile": "iamInstanceProfile",
        "instance_id": "instanceId",
        "instance_monitoring": "instanceMonitoring",
        "kernel_id": "kernelId",
        "key_name": "keyName",
        "launch_configuration_name": "launchConfigurationName",
        "metadata_options": "metadataOptions",
        "placement_tenancy": "placementTenancy",
        "ram_disk_id": "ramDiskId",
        "security_groups": "securityGroups",
        "spot_price": "spotPrice",
        "user_data": "userData",
    },
)
class CfnLaunchConfigurationProps:
    def __init__(
        self,
        *,
        image_id: builtins.str,
        instance_type: builtins.str,
        associate_public_ip_address: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        block_device_mappings: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnLaunchConfiguration.BlockDeviceMappingProperty, _IResolvable_da3f097b]]]] = None,
        classic_link_vpc_id: typing.Optional[builtins.str] = None,
        classic_link_vpc_security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        ebs_optimized: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        iam_instance_profile: typing.Optional[builtins.str] = None,
        instance_id: typing.Optional[builtins.str] = None,
        instance_monitoring: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        kernel_id: typing.Optional[builtins.str] = None,
        key_name: typing.Optional[builtins.str] = None,
        launch_configuration_name: typing.Optional[builtins.str] = None,
        metadata_options: typing.Optional[typing.Union[CfnLaunchConfiguration.MetadataOptionsProperty, _IResolvable_da3f097b]] = None,
        placement_tenancy: typing.Optional[builtins.str] = None,
        ram_disk_id: typing.Optional[builtins.str] = None,
        security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        spot_price: typing.Optional[builtins.str] = None,
        user_data: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnLaunchConfiguration``.

        :param image_id: Provides the unique ID of the Amazon Machine Image (AMI) that was assigned during registration. For more information, see `Finding a Linux AMI <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/finding-an-ami.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param instance_type: Specifies the instance type of the EC2 instance. For information about available instance types, see `Available instance types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#AvailableInstanceTypes>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param associate_public_ip_address: For Auto Scaling groups that are running in a virtual private cloud (VPC), specifies whether to assign a public IP address to the group's instances. If you specify ``true`` , each instance in the Auto Scaling group receives a unique public IP address. For more information, see `Launching Auto Scaling instances in a VPC <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-in-vpc.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . If an instance receives a public IP address and is also in a VPC that is defined in the same stack template, you must use the `DependsOn attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ to declare a dependency on the `VPC-gateway attachment <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc-gateway-attachment.html>`_ . .. epigraph:: If the instance is launched into a default subnet, the default is to assign a public IP address, unless you disabled the option to assign a public IP address on the subnet. If the instance is launched into a nondefault subnet, the default is not to assign a public IP address, unless you enabled the option to assign a public IP address on the subnet.
        :param block_device_mappings: Specifies how block devices are exposed to the instance. You can specify virtual devices and EBS volumes.
        :param classic_link_vpc_id: The ID of a ClassicLink-enabled VPC to link your EC2-Classic instances to. For more information, see `ClassicLink <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/vpc-classiclink.html>`_ in the *Amazon EC2 User Guide for Linux Instances* and `Linking EC2-Classic instances to a VPC <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-in-vpc.html#as-ClassicLink>`_ in the *Amazon EC2 Auto Scaling User Guide* . This property can only be used if you are launching EC2-Classic instances.
        :param classic_link_vpc_security_groups: The IDs of one or more security groups for the VPC that you specified in the ``ClassicLinkVPCId`` property. If you specify the ``ClassicLinkVPCId`` property, you must specify this property.
        :param ebs_optimized: Specifies whether the launch configuration is optimized for EBS I/O ( ``true`` ) or not ( ``false`` ). This optimization provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal EBS I/O performance. Additional fees are incurred when you enable EBS optimization for an instance type that is not EBS-optimized by default. For more information, see `Amazon EBS–optimized instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSOptimized.html>`_ in the *Amazon EC2 User Guide for Linux Instances* . The default value is ``false`` .
        :param iam_instance_profile: Provides the name or the Amazon Resource Name (ARN) of the instance profile associated with the IAM role for the instance. The instance profile contains the IAM role. For more information, see `IAM role for applications that run on Amazon EC2 instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/us-iam-role.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param instance_id: The ID of the Amazon EC2 instance you want to use to create the launch configuration. Use this property if you want the launch configuration to use settings from an existing Amazon EC2 instance. When you use an instance to create a launch configuration, all properties are derived from the instance with the exception of ``BlockDeviceMapping`` and ``AssociatePublicIpAddress`` . You can override any properties from the instance by specifying them in the launch configuration.
        :param instance_monitoring: Controls whether instances in this group are launched with detailed ( ``true`` ) or basic ( ``false`` ) monitoring. The default value is ``true`` (enabled). .. epigraph:: When detailed monitoring is enabled, Amazon CloudWatch generates metrics every minute and your account is charged a fee. When you disable detailed monitoring, CloudWatch generates metrics every 5 minutes. For more information, see `Configure monitoring for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/latest/userguide/as-instance-monitoring.html#enable-as-instance-metrics>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param kernel_id: Provides the ID of the kernel associated with the EC2 AMI. .. epigraph:: We recommend that you use PV-GRUB instead of kernels and RAM disks. For more information, see `User provided kernels <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/UserProvidedKernels.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param key_name: Provides the name of the EC2 key pair. .. epigraph:: If you do not specify a key pair, you can't connect to the instance unless you choose an AMI that is configured to allow users another way to log in. For information on creating a key pair, see `Amazon EC2 key pairs and Linux instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param launch_configuration_name: The name of the launch configuration. This name must be unique per Region per account.
        :param metadata_options: The metadata options for the instances. For more information, see `Configuring the Instance Metadata Options <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-config.html#launch-configurations-imds>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param placement_tenancy: The tenancy of the instance, either ``default`` or ``dedicated`` . An instance with ``dedicated`` tenancy runs on isolated, single-tenant hardware and can only be launched into a VPC. You must set the value of this property to ``dedicated`` if want to launch dedicated instances in a shared tenancy VPC (a VPC with the instance placement tenancy attribute set to default). If you specify this property, you must specify at least one subnet in the ``VPCZoneIdentifier`` property of the `AWS::AutoScaling::AutoScalingGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html>`_ resource. For more information, see `Configuring instance tenancy with Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/auto-scaling-dedicated-instances.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param ram_disk_id: The ID of the RAM disk to select. .. epigraph:: We recommend that you use PV-GRUB instead of kernels and RAM disks. For more information, see `User provided kernels <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/UserProvidedKernels.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .
        :param security_groups: A list that contains the security groups to assign to the instances in the Auto Scaling group. The list can contain both the IDs of existing security groups and references to `SecurityGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html>`_ resources created in the template. For more information, see `Security groups for your VPC <https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_SecurityGroups.html>`_ in the *Amazon Virtual Private Cloud User Guide* .
        :param spot_price: The maximum hourly price you are willing to pay for any Spot Instances launched to fulfill the request. Spot Instances are launched when the price you specify exceeds the current Spot price. For more information, see `Requesting Spot Instances for fault-tolerant and flexible applications <https://docs.aws.amazon.com/autoscaling/ec2/userguide/launch-configuration-requesting-spot-instances.html>`_ in the *Amazon EC2 Auto Scaling User Guide* . .. epigraph:: When you change your maximum price by creating a new launch configuration, running instances will continue to run as long as the maximum price for those running instances is higher than the current Spot price. Valid Range: Minimum value of 0.001
        :param user_data: The Base64-encoded user data to make available to the launched EC2 instances. For more information, see `Instance metadata and user data <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            cfn_launch_configuration_props = autoscaling.CfnLaunchConfigurationProps(
                image_id="imageId",
                instance_type="instanceType",
            
                # the properties below are optional
                associate_public_ip_address=False,
                block_device_mappings=[autoscaling.CfnLaunchConfiguration.BlockDeviceMappingProperty(
                    device_name="deviceName",
            
                    # the properties below are optional
                    ebs=autoscaling.CfnLaunchConfiguration.BlockDeviceProperty(
                        delete_on_termination=False,
                        encrypted=False,
                        iops=123,
                        snapshot_id="snapshotId",
                        throughput=123,
                        volume_size=123,
                        volume_type="volumeType"
                    ),
                    no_device=False,
                    virtual_name="virtualName"
                )],
                classic_link_vpc_id="classicLinkVpcId",
                classic_link_vpc_security_groups=["classicLinkVpcSecurityGroups"],
                ebs_optimized=False,
                iam_instance_profile="iamInstanceProfile",
                instance_id="instanceId",
                instance_monitoring=False,
                kernel_id="kernelId",
                key_name="keyName",
                launch_configuration_name="launchConfigurationName",
                metadata_options=autoscaling.CfnLaunchConfiguration.MetadataOptionsProperty(
                    http_endpoint="httpEndpoint",
                    http_put_response_hop_limit=123,
                    http_tokens="httpTokens"
                ),
                placement_tenancy="placementTenancy",
                ram_disk_id="ramDiskId",
                security_groups=["securityGroups"],
                spot_price="spotPrice",
                user_data="userData"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "image_id": image_id,
            "instance_type": instance_type,
        }
        if associate_public_ip_address is not None:
            self._values["associate_public_ip_address"] = associate_public_ip_address
        if block_device_mappings is not None:
            self._values["block_device_mappings"] = block_device_mappings
        if classic_link_vpc_id is not None:
            self._values["classic_link_vpc_id"] = classic_link_vpc_id
        if classic_link_vpc_security_groups is not None:
            self._values["classic_link_vpc_security_groups"] = classic_link_vpc_security_groups
        if ebs_optimized is not None:
            self._values["ebs_optimized"] = ebs_optimized
        if iam_instance_profile is not None:
            self._values["iam_instance_profile"] = iam_instance_profile
        if instance_id is not None:
            self._values["instance_id"] = instance_id
        if instance_monitoring is not None:
            self._values["instance_monitoring"] = instance_monitoring
        if kernel_id is not None:
            self._values["kernel_id"] = kernel_id
        if key_name is not None:
            self._values["key_name"] = key_name
        if launch_configuration_name is not None:
            self._values["launch_configuration_name"] = launch_configuration_name
        if metadata_options is not None:
            self._values["metadata_options"] = metadata_options
        if placement_tenancy is not None:
            self._values["placement_tenancy"] = placement_tenancy
        if ram_disk_id is not None:
            self._values["ram_disk_id"] = ram_disk_id
        if security_groups is not None:
            self._values["security_groups"] = security_groups
        if spot_price is not None:
            self._values["spot_price"] = spot_price
        if user_data is not None:
            self._values["user_data"] = user_data

    @builtins.property
    def image_id(self) -> builtins.str:
        '''Provides the unique ID of the Amazon Machine Image (AMI) that was assigned during registration.

        For more information, see `Finding a Linux AMI <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/finding-an-ami.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-imageid
        '''
        result = self._values.get("image_id")
        assert result is not None, "Required property 'image_id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def instance_type(self) -> builtins.str:
        '''Specifies the instance type of the EC2 instance.

        For information about available instance types, see `Available instance types <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#AvailableInstanceTypes>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-instancetype
        '''
        result = self._values.get("instance_type")
        assert result is not None, "Required property 'instance_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def associate_public_ip_address(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''For Auto Scaling groups that are running in a virtual private cloud (VPC), specifies whether to assign a public IP address to the group's instances.

        If you specify ``true`` , each instance in the Auto Scaling group receives a unique public IP address. For more information, see `Launching Auto Scaling instances in a VPC <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-in-vpc.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        If an instance receives a public IP address and is also in a VPC that is defined in the same stack template, you must use the `DependsOn attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-dependson.html>`_ to declare a dependency on the `VPC-gateway attachment <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-vpc-gateway-attachment.html>`_ .
        .. epigraph::

           If the instance is launched into a default subnet, the default is to assign a public IP address, unless you disabled the option to assign a public IP address on the subnet. If the instance is launched into a nondefault subnet, the default is not to assign a public IP address, unless you enabled the option to assign a public IP address on the subnet.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-associatepublicipaddress
        '''
        result = self._values.get("associate_public_ip_address")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def block_device_mappings(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLaunchConfiguration.BlockDeviceMappingProperty, _IResolvable_da3f097b]]]]:
        '''Specifies how block devices are exposed to the instance.

        You can specify virtual devices and EBS volumes.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-blockdevicemappings
        '''
        result = self._values.get("block_device_mappings")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnLaunchConfiguration.BlockDeviceMappingProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def classic_link_vpc_id(self) -> typing.Optional[builtins.str]:
        '''The ID of a ClassicLink-enabled VPC to link your EC2-Classic instances to.

        For more information, see `ClassicLink <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/vpc-classiclink.html>`_ in the *Amazon EC2 User Guide for Linux Instances* and `Linking EC2-Classic instances to a VPC <https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-in-vpc.html#as-ClassicLink>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        This property can only be used if you are launching EC2-Classic instances.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-classiclinkvpcid
        '''
        result = self._values.get("classic_link_vpc_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def classic_link_vpc_security_groups(
        self,
    ) -> typing.Optional[typing.List[builtins.str]]:
        '''The IDs of one or more security groups for the VPC that you specified in the ``ClassicLinkVPCId`` property.

        If you specify the ``ClassicLinkVPCId`` property, you must specify this property.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-classiclinkvpcsecuritygroups
        '''
        result = self._values.get("classic_link_vpc_security_groups")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def ebs_optimized(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Specifies whether the launch configuration is optimized for EBS I/O ( ``true`` ) or not ( ``false`` ).

        This optimization provides dedicated throughput to Amazon EBS and an optimized configuration stack to provide optimal EBS I/O performance. Additional fees are incurred when you enable EBS optimization for an instance type that is not EBS-optimized by default. For more information, see `Amazon EBS–optimized instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSOptimized.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        The default value is ``false`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-ebsoptimized
        '''
        result = self._values.get("ebs_optimized")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def iam_instance_profile(self) -> typing.Optional[builtins.str]:
        '''Provides the name or the Amazon Resource Name (ARN) of the instance profile associated with the IAM role for the instance.

        The instance profile contains the IAM role.

        For more information, see `IAM role for applications that run on Amazon EC2 instances <https://docs.aws.amazon.com/autoscaling/ec2/userguide/us-iam-role.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-iaminstanceprofile
        '''
        result = self._values.get("iam_instance_profile")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def instance_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the Amazon EC2 instance you want to use to create the launch configuration.

        Use this property if you want the launch configuration to use settings from an existing Amazon EC2 instance. When you use an instance to create a launch configuration, all properties are derived from the instance with the exception of ``BlockDeviceMapping`` and ``AssociatePublicIpAddress`` . You can override any properties from the instance by specifying them in the launch configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-instanceid
        '''
        result = self._values.get("instance_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def instance_monitoring(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Controls whether instances in this group are launched with detailed ( ``true`` ) or basic ( ``false`` ) monitoring.

        The default value is ``true`` (enabled).
        .. epigraph::

           When detailed monitoring is enabled, Amazon CloudWatch generates metrics every minute and your account is charged a fee. When you disable detailed monitoring, CloudWatch generates metrics every 5 minutes. For more information, see `Configure monitoring for Auto Scaling instances <https://docs.aws.amazon.com/autoscaling/latest/userguide/as-instance-monitoring.html#enable-as-instance-metrics>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-instancemonitoring
        '''
        result = self._values.get("instance_monitoring")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def kernel_id(self) -> typing.Optional[builtins.str]:
        '''Provides the ID of the kernel associated with the EC2 AMI.

        .. epigraph::

           We recommend that you use PV-GRUB instead of kernels and RAM disks. For more information, see `User provided kernels <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/UserProvidedKernels.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-kernelid
        '''
        result = self._values.get("kernel_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def key_name(self) -> typing.Optional[builtins.str]:
        '''Provides the name of the EC2 key pair.

        .. epigraph::

           If you do not specify a key pair, you can't connect to the instance unless you choose an AMI that is configured to allow users another way to log in. For information on creating a key pair, see `Amazon EC2 key pairs and Linux instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-keyname
        '''
        result = self._values.get("key_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def launch_configuration_name(self) -> typing.Optional[builtins.str]:
        '''The name of the launch configuration.

        This name must be unique per Region per account.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-launchconfigurationname
        '''
        result = self._values.get("launch_configuration_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def metadata_options(
        self,
    ) -> typing.Optional[typing.Union[CfnLaunchConfiguration.MetadataOptionsProperty, _IResolvable_da3f097b]]:
        '''The metadata options for the instances.

        For more information, see `Configuring the Instance Metadata Options <https://docs.aws.amazon.com/autoscaling/ec2/userguide/create-launch-config.html#launch-configurations-imds>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-metadataoptions
        '''
        result = self._values.get("metadata_options")
        return typing.cast(typing.Optional[typing.Union[CfnLaunchConfiguration.MetadataOptionsProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def placement_tenancy(self) -> typing.Optional[builtins.str]:
        '''The tenancy of the instance, either ``default`` or ``dedicated`` .

        An instance with ``dedicated`` tenancy runs on isolated, single-tenant hardware and can only be launched into a VPC. You must set the value of this property to ``dedicated`` if want to launch dedicated instances in a shared tenancy VPC (a VPC with the instance placement tenancy attribute set to default).

        If you specify this property, you must specify at least one subnet in the ``VPCZoneIdentifier`` property of the `AWS::AutoScaling::AutoScalingGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html>`_ resource.

        For more information, see `Configuring instance tenancy with Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/auto-scaling-dedicated-instances.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-placementtenancy
        '''
        result = self._values.get("placement_tenancy")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def ram_disk_id(self) -> typing.Optional[builtins.str]:
        '''The ID of the RAM disk to select.

        .. epigraph::

           We recommend that you use PV-GRUB instead of kernels and RAM disks. For more information, see `User provided kernels <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/UserProvidedKernels.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-ramdiskid
        '''
        result = self._values.get("ram_disk_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def security_groups(self) -> typing.Optional[typing.List[builtins.str]]:
        '''A list that contains the security groups to assign to the instances in the Auto Scaling group.

        The list can contain both the IDs of existing security groups and references to `SecurityGroup <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html>`_ resources created in the template.

        For more information, see `Security groups for your VPC <https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_SecurityGroups.html>`_ in the *Amazon Virtual Private Cloud User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-securitygroups
        '''
        result = self._values.get("security_groups")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def spot_price(self) -> typing.Optional[builtins.str]:
        '''The maximum hourly price you are willing to pay for any Spot Instances launched to fulfill the request.

        Spot Instances are launched when the price you specify exceeds the current Spot price. For more information, see `Requesting Spot Instances for fault-tolerant and flexible applications <https://docs.aws.amazon.com/autoscaling/ec2/userguide/launch-configuration-requesting-spot-instances.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        .. epigraph::

           When you change your maximum price by creating a new launch configuration, running instances will continue to run as long as the maximum price for those running instances is higher than the current Spot price.

        Valid Range: Minimum value of 0.001

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-spotprice
        '''
        result = self._values.get("spot_price")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def user_data(self) -> typing.Optional[builtins.str]:
        '''The Base64-encoded user data to make available to the launched EC2 instances.

        For more information, see `Instance metadata and user data <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html>`_ in the *Amazon EC2 User Guide for Linux Instances* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-launchconfiguration.html#cfn-autoscaling-launchconfiguration-userdata
        '''
        result = self._values.get("user_data")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLaunchConfigurationProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnLifecycleHook(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnLifecycleHook",
):
    '''A CloudFormation ``AWS::AutoScaling::LifecycleHook``.

    The ``AWS::AutoScaling::LifecycleHook`` resource specifies lifecycle hooks for an Auto Scaling group. These hooks let you create solutions that are aware of events in the Auto Scaling instance lifecycle, and then perform a custom action on instances when the corresponding lifecycle event occurs. A lifecycle hook provides a specified amount of time (one hour by default) to wait for the action to complete before the instance transitions to the next state.

    Use lifecycle hooks to prepare new instances for use or to delay them from being registered behind a load balancer before their configuration has been applied completely. You can also use lifecycle hooks to prepare running instances to be terminated by, for example, downloading logs or other data.

    For more information, see `Amazon EC2 Auto Scaling lifecycle hooks <https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks.html>`_ in the *Amazon EC2 Auto Scaling User Guide* and `PutLifecycleHook <https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutLifecycleHook.html>`_ in the *Amazon EC2 Auto Scaling API Reference* .

    :cloudformationResource: AWS::AutoScaling::LifecycleHook
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_autoscaling as autoscaling
        
        cfn_lifecycle_hook = autoscaling.CfnLifecycleHook(self, "MyCfnLifecycleHook",
            auto_scaling_group_name="autoScalingGroupName",
            lifecycle_transition="lifecycleTransition",
        
            # the properties below are optional
            default_result="defaultResult",
            heartbeat_timeout=123,
            lifecycle_hook_name="lifecycleHookName",
            notification_metadata="notificationMetadata",
            notification_target_arn="notificationTargetArn",
            role_arn="roleArn"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        auto_scaling_group_name: builtins.str,
        lifecycle_transition: builtins.str,
        default_result: typing.Optional[builtins.str] = None,
        heartbeat_timeout: typing.Optional[jsii.Number] = None,
        lifecycle_hook_name: typing.Optional[builtins.str] = None,
        notification_metadata: typing.Optional[builtins.str] = None,
        notification_target_arn: typing.Optional[builtins.str] = None,
        role_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::AutoScaling::LifecycleHook``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param auto_scaling_group_name: The name of the Auto Scaling group for the lifecycle hook.
        :param lifecycle_transition: The instance state to which you want to attach the lifecycle hook. The valid values are:. - autoscaling:EC2_INSTANCE_LAUNCHING - autoscaling:EC2_INSTANCE_TERMINATING
        :param default_result: The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs. The valid values are ``CONTINUE`` and ``ABANDON`` (default). For more information, see `Adding lifecycle hooks <https://docs.aws.amazon.com/autoscaling/ec2/userguide/adding-lifecycle-hooks.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param heartbeat_timeout: The maximum time, in seconds, that can elapse before the lifecycle hook times out. The range is from ``30`` to ``7200`` seconds. The default value is ``3600`` seconds (1 hour). If the lifecycle hook times out, Amazon EC2 Auto Scaling performs the action that you specified in the ``DefaultResult`` property.
        :param lifecycle_hook_name: The name of the lifecycle hook.
        :param notification_metadata: Additional information that is included any time Amazon EC2 Auto Scaling sends a message to the notification target.
        :param notification_target_arn: The Amazon Resource Name (ARN) of the notification target that Amazon EC2 Auto Scaling uses to notify you when an instance is in the transition state for the lifecycle hook. You can specify an Amazon SQS queue or an Amazon SNS topic. The notification message includes the following information: lifecycle action token, user account ID, Auto Scaling group name, lifecycle hook name, instance ID, lifecycle transition, and notification metadata.
        :param role_arn: The ARN of the IAM role that allows the Auto Scaling group to publish to the specified notification target, for example, an Amazon SNS topic or an Amazon SQS queue. For information about creating this role, see `Configuring a notification target for a lifecycle hook <https://docs.aws.amazon.com/autoscaling/ec2/userguide/configuring-lifecycle-hook-notifications.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        '''
        props = CfnLifecycleHookProps(
            auto_scaling_group_name=auto_scaling_group_name,
            lifecycle_transition=lifecycle_transition,
            default_result=default_result,
            heartbeat_timeout=heartbeat_timeout,
            lifecycle_hook_name=lifecycle_hook_name,
            notification_metadata=notification_metadata,
            notification_target_arn=notification_target_arn,
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
    @jsii.member(jsii_name="autoScalingGroupName")
    def auto_scaling_group_name(self) -> builtins.str:
        '''The name of the Auto Scaling group for the lifecycle hook.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-autoscalinggroupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "autoScalingGroupName"))

    @auto_scaling_group_name.setter
    def auto_scaling_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "autoScalingGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lifecycleTransition")
    def lifecycle_transition(self) -> builtins.str:
        '''The instance state to which you want to attach the lifecycle hook. The valid values are:.

        - autoscaling:EC2_INSTANCE_LAUNCHING
        - autoscaling:EC2_INSTANCE_TERMINATING

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-lifecycletransition
        '''
        return typing.cast(builtins.str, jsii.get(self, "lifecycleTransition"))

    @lifecycle_transition.setter
    def lifecycle_transition(self, value: builtins.str) -> None:
        jsii.set(self, "lifecycleTransition", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultResult")
    def default_result(self) -> typing.Optional[builtins.str]:
        '''The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs.

        The valid values are ``CONTINUE`` and ``ABANDON`` (default).

        For more information, see `Adding lifecycle hooks <https://docs.aws.amazon.com/autoscaling/ec2/userguide/adding-lifecycle-hooks.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-defaultresult
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "defaultResult"))

    @default_result.setter
    def default_result(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "defaultResult", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="heartbeatTimeout")
    def heartbeat_timeout(self) -> typing.Optional[jsii.Number]:
        '''The maximum time, in seconds, that can elapse before the lifecycle hook times out.

        The range is from ``30`` to ``7200`` seconds. The default value is ``3600`` seconds (1 hour). If the lifecycle hook times out, Amazon EC2 Auto Scaling performs the action that you specified in the ``DefaultResult`` property.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-heartbeattimeout
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "heartbeatTimeout"))

    @heartbeat_timeout.setter
    def heartbeat_timeout(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "heartbeatTimeout", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lifecycleHookName")
    def lifecycle_hook_name(self) -> typing.Optional[builtins.str]:
        '''The name of the lifecycle hook.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-lifecyclehookname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "lifecycleHookName"))

    @lifecycle_hook_name.setter
    def lifecycle_hook_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "lifecycleHookName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationMetadata")
    def notification_metadata(self) -> typing.Optional[builtins.str]:
        '''Additional information that is included any time Amazon EC2 Auto Scaling sends a message to the notification target.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-notificationmetadata
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "notificationMetadata"))

    @notification_metadata.setter
    def notification_metadata(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "notificationMetadata", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="notificationTargetArn")
    def notification_target_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the notification target that Amazon EC2 Auto Scaling uses to notify you when an instance is in the transition state for the lifecycle hook.

        You can specify an Amazon SQS queue or an Amazon SNS topic. The notification message includes the following information: lifecycle action token, user account ID, Auto Scaling group name, lifecycle hook name, instance ID, lifecycle transition, and notification metadata.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-notificationtargetarn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "notificationTargetArn"))

    @notification_target_arn.setter
    def notification_target_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "notificationTargetArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the IAM role that allows the Auto Scaling group to publish to the specified notification target, for example, an Amazon SNS topic or an Amazon SQS queue.

        For information about creating this role, see `Configuring a notification target for a lifecycle hook <https://docs.aws.amazon.com/autoscaling/ec2/userguide/configuring-lifecycle-hook-notifications.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-rolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "roleArn", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnLifecycleHookProps",
    jsii_struct_bases=[],
    name_mapping={
        "auto_scaling_group_name": "autoScalingGroupName",
        "lifecycle_transition": "lifecycleTransition",
        "default_result": "defaultResult",
        "heartbeat_timeout": "heartbeatTimeout",
        "lifecycle_hook_name": "lifecycleHookName",
        "notification_metadata": "notificationMetadata",
        "notification_target_arn": "notificationTargetArn",
        "role_arn": "roleArn",
    },
)
class CfnLifecycleHookProps:
    def __init__(
        self,
        *,
        auto_scaling_group_name: builtins.str,
        lifecycle_transition: builtins.str,
        default_result: typing.Optional[builtins.str] = None,
        heartbeat_timeout: typing.Optional[jsii.Number] = None,
        lifecycle_hook_name: typing.Optional[builtins.str] = None,
        notification_metadata: typing.Optional[builtins.str] = None,
        notification_target_arn: typing.Optional[builtins.str] = None,
        role_arn: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnLifecycleHook``.

        :param auto_scaling_group_name: The name of the Auto Scaling group for the lifecycle hook.
        :param lifecycle_transition: The instance state to which you want to attach the lifecycle hook. The valid values are:. - autoscaling:EC2_INSTANCE_LAUNCHING - autoscaling:EC2_INSTANCE_TERMINATING
        :param default_result: The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs. The valid values are ``CONTINUE`` and ``ABANDON`` (default). For more information, see `Adding lifecycle hooks <https://docs.aws.amazon.com/autoscaling/ec2/userguide/adding-lifecycle-hooks.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param heartbeat_timeout: The maximum time, in seconds, that can elapse before the lifecycle hook times out. The range is from ``30`` to ``7200`` seconds. The default value is ``3600`` seconds (1 hour). If the lifecycle hook times out, Amazon EC2 Auto Scaling performs the action that you specified in the ``DefaultResult`` property.
        :param lifecycle_hook_name: The name of the lifecycle hook.
        :param notification_metadata: Additional information that is included any time Amazon EC2 Auto Scaling sends a message to the notification target.
        :param notification_target_arn: The Amazon Resource Name (ARN) of the notification target that Amazon EC2 Auto Scaling uses to notify you when an instance is in the transition state for the lifecycle hook. You can specify an Amazon SQS queue or an Amazon SNS topic. The notification message includes the following information: lifecycle action token, user account ID, Auto Scaling group name, lifecycle hook name, instance ID, lifecycle transition, and notification metadata.
        :param role_arn: The ARN of the IAM role that allows the Auto Scaling group to publish to the specified notification target, for example, an Amazon SNS topic or an Amazon SQS queue. For information about creating this role, see `Configuring a notification target for a lifecycle hook <https://docs.aws.amazon.com/autoscaling/ec2/userguide/configuring-lifecycle-hook-notifications.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            cfn_lifecycle_hook_props = autoscaling.CfnLifecycleHookProps(
                auto_scaling_group_name="autoScalingGroupName",
                lifecycle_transition="lifecycleTransition",
            
                # the properties below are optional
                default_result="defaultResult",
                heartbeat_timeout=123,
                lifecycle_hook_name="lifecycleHookName",
                notification_metadata="notificationMetadata",
                notification_target_arn="notificationTargetArn",
                role_arn="roleArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "auto_scaling_group_name": auto_scaling_group_name,
            "lifecycle_transition": lifecycle_transition,
        }
        if default_result is not None:
            self._values["default_result"] = default_result
        if heartbeat_timeout is not None:
            self._values["heartbeat_timeout"] = heartbeat_timeout
        if lifecycle_hook_name is not None:
            self._values["lifecycle_hook_name"] = lifecycle_hook_name
        if notification_metadata is not None:
            self._values["notification_metadata"] = notification_metadata
        if notification_target_arn is not None:
            self._values["notification_target_arn"] = notification_target_arn
        if role_arn is not None:
            self._values["role_arn"] = role_arn

    @builtins.property
    def auto_scaling_group_name(self) -> builtins.str:
        '''The name of the Auto Scaling group for the lifecycle hook.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-autoscalinggroupname
        '''
        result = self._values.get("auto_scaling_group_name")
        assert result is not None, "Required property 'auto_scaling_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def lifecycle_transition(self) -> builtins.str:
        '''The instance state to which you want to attach the lifecycle hook. The valid values are:.

        - autoscaling:EC2_INSTANCE_LAUNCHING
        - autoscaling:EC2_INSTANCE_TERMINATING

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-lifecycletransition
        '''
        result = self._values.get("lifecycle_transition")
        assert result is not None, "Required property 'lifecycle_transition' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def default_result(self) -> typing.Optional[builtins.str]:
        '''The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs.

        The valid values are ``CONTINUE`` and ``ABANDON`` (default).

        For more information, see `Adding lifecycle hooks <https://docs.aws.amazon.com/autoscaling/ec2/userguide/adding-lifecycle-hooks.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-defaultresult
        '''
        result = self._values.get("default_result")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def heartbeat_timeout(self) -> typing.Optional[jsii.Number]:
        '''The maximum time, in seconds, that can elapse before the lifecycle hook times out.

        The range is from ``30`` to ``7200`` seconds. The default value is ``3600`` seconds (1 hour). If the lifecycle hook times out, Amazon EC2 Auto Scaling performs the action that you specified in the ``DefaultResult`` property.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-heartbeattimeout
        '''
        result = self._values.get("heartbeat_timeout")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def lifecycle_hook_name(self) -> typing.Optional[builtins.str]:
        '''The name of the lifecycle hook.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-lifecyclehookname
        '''
        result = self._values.get("lifecycle_hook_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def notification_metadata(self) -> typing.Optional[builtins.str]:
        '''Additional information that is included any time Amazon EC2 Auto Scaling sends a message to the notification target.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-notificationmetadata
        '''
        result = self._values.get("notification_metadata")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def notification_target_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of the notification target that Amazon EC2 Auto Scaling uses to notify you when an instance is in the transition state for the lifecycle hook.

        You can specify an Amazon SQS queue or an Amazon SNS topic. The notification message includes the following information: lifecycle action token, user account ID, Auto Scaling group name, lifecycle hook name, instance ID, lifecycle transition, and notification metadata.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-notificationtargetarn
        '''
        result = self._values.get("notification_target_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def role_arn(self) -> typing.Optional[builtins.str]:
        '''The ARN of the IAM role that allows the Auto Scaling group to publish to the specified notification target, for example, an Amazon SNS topic or an Amazon SQS queue.

        For information about creating this role, see `Configuring a notification target for a lifecycle hook <https://docs.aws.amazon.com/autoscaling/ec2/userguide/configuring-lifecycle-hook-notifications.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-lifecyclehook.html#cfn-autoscaling-lifecyclehook-rolearn
        '''
        result = self._values.get("role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnLifecycleHookProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnScalingPolicy(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicy",
):
    '''A CloudFormation ``AWS::AutoScaling::ScalingPolicy``.

    The ``AWS::AutoScaling::ScalingPolicy`` resource specifies an Amazon EC2 Auto Scaling scaling policy so that the Auto Scaling group can scale the number of instances available for your application.

    For more information about using scaling policies to scale your Auto Scaling group automatically, see `Dynamic scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scale-based-on-demand.html>`_ and `Predictive scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-predictive-scaling.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

    :cloudformationResource: AWS::AutoScaling::ScalingPolicy
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_autoscaling as autoscaling
        
        cfn_scaling_policy = autoscaling.CfnScalingPolicy(self, "MyCfnScalingPolicy",
            auto_scaling_group_name="autoScalingGroupName",
        
            # the properties below are optional
            adjustment_type="adjustmentType",
            cooldown="cooldown",
            estimated_instance_warmup=123,
            metric_aggregation_type="metricAggregationType",
            min_adjustment_magnitude=123,
            policy_type="policyType",
            predictive_scaling_configuration=autoscaling.CfnScalingPolicy.PredictiveScalingConfigurationProperty(
                metric_specifications=[autoscaling.CfnScalingPolicy.PredictiveScalingMetricSpecificationProperty(
                    target_value=123,
        
                    # the properties below are optional
                    predefined_load_metric_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedLoadMetricProperty(
                        predefined_metric_type="predefinedMetricType",
        
                        # the properties below are optional
                        resource_label="resourceLabel"
                    ),
                    predefined_metric_pair_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedMetricPairProperty(
                        predefined_metric_type="predefinedMetricType",
        
                        # the properties below are optional
                        resource_label="resourceLabel"
                    ),
                    predefined_scaling_metric_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedScalingMetricProperty(
                        predefined_metric_type="predefinedMetricType",
        
                        # the properties below are optional
                        resource_label="resourceLabel"
                    )
                )],
        
                # the properties below are optional
                max_capacity_breach_behavior="maxCapacityBreachBehavior",
                max_capacity_buffer=123,
                mode="mode",
                scheduling_buffer_time=123
            ),
            scaling_adjustment=123,
            step_adjustments=[autoscaling.CfnScalingPolicy.StepAdjustmentProperty(
                scaling_adjustment=123,
        
                # the properties below are optional
                metric_interval_lower_bound=123,
                metric_interval_upper_bound=123
            )],
            target_tracking_configuration=autoscaling.CfnScalingPolicy.TargetTrackingConfigurationProperty(
                target_value=123,
        
                # the properties below are optional
                customized_metric_specification=autoscaling.CfnScalingPolicy.CustomizedMetricSpecificationProperty(
                    metric_name="metricName",
                    namespace="namespace",
                    statistic="statistic",
        
                    # the properties below are optional
                    dimensions=[autoscaling.CfnScalingPolicy.MetricDimensionProperty(
                        name="name",
                        value="value"
                    )],
                    unit="unit"
                ),
                disable_scale_in=False,
                predefined_metric_specification=autoscaling.CfnScalingPolicy.PredefinedMetricSpecificationProperty(
                    predefined_metric_type="predefinedMetricType",
        
                    # the properties below are optional
                    resource_label="resourceLabel"
                )
            )
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        auto_scaling_group_name: builtins.str,
        adjustment_type: typing.Optional[builtins.str] = None,
        cooldown: typing.Optional[builtins.str] = None,
        estimated_instance_warmup: typing.Optional[jsii.Number] = None,
        metric_aggregation_type: typing.Optional[builtins.str] = None,
        min_adjustment_magnitude: typing.Optional[jsii.Number] = None,
        policy_type: typing.Optional[builtins.str] = None,
        predictive_scaling_configuration: typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingConfigurationProperty", _IResolvable_da3f097b]] = None,
        scaling_adjustment: typing.Optional[jsii.Number] = None,
        step_adjustments: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnScalingPolicy.StepAdjustmentProperty", _IResolvable_da3f097b]]]] = None,
        target_tracking_configuration: typing.Optional[typing.Union["CfnScalingPolicy.TargetTrackingConfigurationProperty", _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Create a new ``AWS::AutoScaling::ScalingPolicy``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param auto_scaling_group_name: The name of the Auto Scaling group.
        :param adjustment_type: Specifies how the scaling adjustment is interpreted. The valid values are ``ChangeInCapacity`` , ``ExactCapacity`` , and ``PercentChangeInCapacity`` . Required if the policy type is ``StepScaling`` or ``SimpleScaling`` . For more information, see `Scaling adjustment types <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html#as-scaling-adjustment>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param cooldown: The duration of the policy's cooldown period, in seconds. When a cooldown period is specified here, it overrides the default cooldown period defined for the Auto Scaling group. Valid only if the policy type is ``SimpleScaling`` . For more information, see `Scaling cooldowns for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param estimated_instance_warmup: The estimated time, in seconds, until a newly launched instance can contribute to the CloudWatch metrics. If not provided, the default is to use the value from the default cooldown period for the Auto Scaling group. Valid only if the policy type is ``TargetTrackingScaling`` or ``StepScaling`` .
        :param metric_aggregation_type: The aggregation type for the CloudWatch metrics. The valid values are ``Minimum`` , ``Maximum`` , and ``Average`` . If the aggregation type is null, the value is treated as ``Average`` . Valid only if the policy type is ``StepScaling`` .
        :param min_adjustment_magnitude: The minimum value to scale by when the adjustment type is ``PercentChangeInCapacity`` . For example, suppose that you create a step scaling policy to scale out an Auto Scaling group by 25 percent and you specify a ``MinAdjustmentMagnitude`` of 2. If the group has 4 instances and the scaling policy is performed, 25 percent of 4 is 1. However, because you specified a ``MinAdjustmentMagnitude`` of 2, Amazon EC2 Auto Scaling scales out the group by 2 instances. Valid only if the policy type is ``StepScaling`` or ``SimpleScaling`` . For more information, see `Scaling adjustment types <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html#as-scaling-adjustment>`_ in the *Amazon EC2 Auto Scaling User Guide* . .. epigraph:: Some Auto Scaling groups use instance weights. In this case, set the ``MinAdjustmentMagnitude`` to a value that is at least as large as your largest instance weight.
        :param policy_type: One of the following policy types:. - ``TargetTrackingScaling`` - ``StepScaling`` - ``SimpleScaling`` (default) - ``PredictiveScaling`` For more information, see `Target tracking scaling policies <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-target-tracking.html>`_ and `Step and simple scaling policies <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param predictive_scaling_configuration: A predictive scaling policy. Includes support for predefined metrics only.
        :param scaling_adjustment: The amount by which to scale, based on the specified adjustment type. A positive value adds to the current capacity while a negative number removes from the current capacity. For exact capacity, you must specify a positive value. Required if the policy type is ``SimpleScaling`` . (Not used with any other policy type.)
        :param step_adjustments: A set of adjustments that enable you to scale based on the size of the alarm breach. Required if the policy type is ``StepScaling`` . (Not used with any other policy type.)
        :param target_tracking_configuration: A target tracking scaling policy. Includes support for predefined or customized metrics. The following predefined metrics are available: - ``ASGAverageCPUUtilization`` - ``ASGAverageNetworkIn`` - ``ASGAverageNetworkOut`` - ``ALBRequestCountPerTarget`` If you specify ``ALBRequestCountPerTarget`` for the metric, you must specify the ``ResourceLabel`` property with the ``PredefinedMetricSpecification`` .
        '''
        props = CfnScalingPolicyProps(
            auto_scaling_group_name=auto_scaling_group_name,
            adjustment_type=adjustment_type,
            cooldown=cooldown,
            estimated_instance_warmup=estimated_instance_warmup,
            metric_aggregation_type=metric_aggregation_type,
            min_adjustment_magnitude=min_adjustment_magnitude,
            policy_type=policy_type,
            predictive_scaling_configuration=predictive_scaling_configuration,
            scaling_adjustment=scaling_adjustment,
            step_adjustments=step_adjustments,
            target_tracking_configuration=target_tracking_configuration,
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
    @jsii.member(jsii_name="autoScalingGroupName")
    def auto_scaling_group_name(self) -> builtins.str:
        '''The name of the Auto Scaling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-autoscalinggroupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "autoScalingGroupName"))

    @auto_scaling_group_name.setter
    def auto_scaling_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "autoScalingGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="adjustmentType")
    def adjustment_type(self) -> typing.Optional[builtins.str]:
        '''Specifies how the scaling adjustment is interpreted. The valid values are ``ChangeInCapacity`` , ``ExactCapacity`` , and ``PercentChangeInCapacity`` .

        Required if the policy type is ``StepScaling`` or ``SimpleScaling`` . For more information, see `Scaling adjustment types <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html#as-scaling-adjustment>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-adjustmenttype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "adjustmentType"))

    @adjustment_type.setter
    def adjustment_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "adjustmentType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cooldown")
    def cooldown(self) -> typing.Optional[builtins.str]:
        '''The duration of the policy's cooldown period, in seconds.

        When a cooldown period is specified here, it overrides the default cooldown period defined for the Auto Scaling group.

        Valid only if the policy type is ``SimpleScaling`` . For more information, see `Scaling cooldowns for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-cooldown
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "cooldown"))

    @cooldown.setter
    def cooldown(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "cooldown", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="estimatedInstanceWarmup")
    def estimated_instance_warmup(self) -> typing.Optional[jsii.Number]:
        '''The estimated time, in seconds, until a newly launched instance can contribute to the CloudWatch metrics.

        If not provided, the default is to use the value from the default cooldown period for the Auto Scaling group.

        Valid only if the policy type is ``TargetTrackingScaling`` or ``StepScaling`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-estimatedinstancewarmup
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "estimatedInstanceWarmup"))

    @estimated_instance_warmup.setter
    def estimated_instance_warmup(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "estimatedInstanceWarmup", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="metricAggregationType")
    def metric_aggregation_type(self) -> typing.Optional[builtins.str]:
        '''The aggregation type for the CloudWatch metrics.

        The valid values are ``Minimum`` , ``Maximum`` , and ``Average`` . If the aggregation type is null, the value is treated as ``Average`` .

        Valid only if the policy type is ``StepScaling`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-metricaggregationtype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "metricAggregationType"))

    @metric_aggregation_type.setter
    def metric_aggregation_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "metricAggregationType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="minAdjustmentMagnitude")
    def min_adjustment_magnitude(self) -> typing.Optional[jsii.Number]:
        '''The minimum value to scale by when the adjustment type is ``PercentChangeInCapacity`` .

        For example, suppose that you create a step scaling policy to scale out an Auto Scaling group by 25 percent and you specify a ``MinAdjustmentMagnitude`` of 2. If the group has 4 instances and the scaling policy is performed, 25 percent of 4 is 1. However, because you specified a ``MinAdjustmentMagnitude`` of 2, Amazon EC2 Auto Scaling scales out the group by 2 instances.

        Valid only if the policy type is ``StepScaling`` or ``SimpleScaling`` . For more information, see `Scaling adjustment types <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html#as-scaling-adjustment>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        .. epigraph::

           Some Auto Scaling groups use instance weights. In this case, set the ``MinAdjustmentMagnitude`` to a value that is at least as large as your largest instance weight.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-minadjustmentmagnitude
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "minAdjustmentMagnitude"))

    @min_adjustment_magnitude.setter
    def min_adjustment_magnitude(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "minAdjustmentMagnitude", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyType")
    def policy_type(self) -> typing.Optional[builtins.str]:
        '''One of the following policy types:.

        - ``TargetTrackingScaling``
        - ``StepScaling``
        - ``SimpleScaling`` (default)
        - ``PredictiveScaling``

        For more information, see `Target tracking scaling policies <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-target-tracking.html>`_ and `Step and simple scaling policies <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-policytype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "policyType"))

    @policy_type.setter
    def policy_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "policyType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="predictiveScalingConfiguration")
    def predictive_scaling_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingConfigurationProperty", _IResolvable_da3f097b]]:
        '''A predictive scaling policy.

        Includes support for predefined metrics only.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-autoscaling-scalingpolicy-predictivescalingconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "predictiveScalingConfiguration"))

    @predictive_scaling_configuration.setter
    def predictive_scaling_configuration(
        self,
        value: typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "predictiveScalingConfiguration", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scalingAdjustment")
    def scaling_adjustment(self) -> typing.Optional[jsii.Number]:
        '''The amount by which to scale, based on the specified adjustment type.

        A positive value adds to the current capacity while a negative number removes from the current capacity. For exact capacity, you must specify a positive value.

        Required if the policy type is ``SimpleScaling`` . (Not used with any other policy type.)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-scalingadjustment
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "scalingAdjustment"))

    @scaling_adjustment.setter
    def scaling_adjustment(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "scalingAdjustment", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="stepAdjustments")
    def step_adjustments(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScalingPolicy.StepAdjustmentProperty", _IResolvable_da3f097b]]]]:
        '''A set of adjustments that enable you to scale based on the size of the alarm breach.

        Required if the policy type is ``StepScaling`` . (Not used with any other policy type.)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-stepadjustments
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScalingPolicy.StepAdjustmentProperty", _IResolvable_da3f097b]]]], jsii.get(self, "stepAdjustments"))

    @step_adjustments.setter
    def step_adjustments(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScalingPolicy.StepAdjustmentProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "stepAdjustments", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="targetTrackingConfiguration")
    def target_tracking_configuration(
        self,
    ) -> typing.Optional[typing.Union["CfnScalingPolicy.TargetTrackingConfigurationProperty", _IResolvable_da3f097b]]:
        '''A target tracking scaling policy. Includes support for predefined or customized metrics.

        The following predefined metrics are available:

        - ``ASGAverageCPUUtilization``
        - ``ASGAverageNetworkIn``
        - ``ASGAverageNetworkOut``
        - ``ALBRequestCountPerTarget``

        If you specify ``ALBRequestCountPerTarget`` for the metric, you must specify the ``ResourceLabel`` property with the ``PredefinedMetricSpecification`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-autoscaling-scalingpolicy-targettrackingconfiguration
        '''
        return typing.cast(typing.Optional[typing.Union["CfnScalingPolicy.TargetTrackingConfigurationProperty", _IResolvable_da3f097b]], jsii.get(self, "targetTrackingConfiguration"))

    @target_tracking_configuration.setter
    def target_tracking_configuration(
        self,
        value: typing.Optional[typing.Union["CfnScalingPolicy.TargetTrackingConfigurationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "targetTrackingConfiguration", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicy.CustomizedMetricSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "metric_name": "metricName",
            "namespace": "namespace",
            "statistic": "statistic",
            "dimensions": "dimensions",
            "unit": "unit",
        },
    )
    class CustomizedMetricSpecificationProperty:
        def __init__(
            self,
            *,
            metric_name: builtins.str,
            namespace: builtins.str,
            statistic: builtins.str,
            dimensions: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnScalingPolicy.MetricDimensionProperty", _IResolvable_da3f097b]]]] = None,
            unit: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains customized metric specification information for a target tracking scaling policy for Amazon EC2 Auto Scaling.

            To create your customized metric specification:

            - Add values for each required property from CloudWatch. You can use an existing metric, or a new metric that you create. To use your own metric, you must first publish the metric to CloudWatch. For more information, see `Publish Custom Metrics <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/publishingMetrics.html>`_ in the *Amazon CloudWatch User Guide* .
            - Choose a metric that changes proportionally with capacity. The value of the metric should increase or decrease in inverse proportion to the number of capacity units. That is, the value of the metric should decrease when capacity increases.

            For more information about CloudWatch, see `Amazon CloudWatch Concepts <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html>`_ .

            ``CustomizedMetricSpecification`` is a property of the `AWS::AutoScaling::ScalingPolicy TargetTrackingConfiguration <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-targettrackingconfiguration.html>`_ property type.

            :param metric_name: The name of the metric. To get the exact metric name, namespace, and dimensions, inspect the `Metric <https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_Metric.html>`_ object that is returned by a call to `ListMetrics <https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_ListMetrics.html>`_ .
            :param namespace: The namespace of the metric.
            :param statistic: The statistic of the metric.
            :param dimensions: The dimensions of the metric. Conditional: If you published your metric with dimensions, you must specify the same dimensions in your scaling policy.
            :param unit: The unit of the metric. For a complete list of the units that CloudWatch supports, see the `MetricDatum <https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_MetricDatum.html>`_ data type in the *Amazon CloudWatch API Reference* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-customizedmetricspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                customized_metric_specification_property = autoscaling.CfnScalingPolicy.CustomizedMetricSpecificationProperty(
                    metric_name="metricName",
                    namespace="namespace",
                    statistic="statistic",
                
                    # the properties below are optional
                    dimensions=[autoscaling.CfnScalingPolicy.MetricDimensionProperty(
                        name="name",
                        value="value"
                    )],
                    unit="unit"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "metric_name": metric_name,
                "namespace": namespace,
                "statistic": statistic,
            }
            if dimensions is not None:
                self._values["dimensions"] = dimensions
            if unit is not None:
                self._values["unit"] = unit

        @builtins.property
        def metric_name(self) -> builtins.str:
            '''The name of the metric.

            To get the exact metric name, namespace, and dimensions, inspect the `Metric <https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_Metric.html>`_ object that is returned by a call to `ListMetrics <https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_ListMetrics.html>`_ .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-customizedmetricspecification.html#cfn-autoscaling-scalingpolicy-customizedmetricspecification-metricname
            '''
            result = self._values.get("metric_name")
            assert result is not None, "Required property 'metric_name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def namespace(self) -> builtins.str:
            '''The namespace of the metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-customizedmetricspecification.html#cfn-autoscaling-scalingpolicy-customizedmetricspecification-namespace
            '''
            result = self._values.get("namespace")
            assert result is not None, "Required property 'namespace' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def statistic(self) -> builtins.str:
            '''The statistic of the metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-customizedmetricspecification.html#cfn-autoscaling-scalingpolicy-customizedmetricspecification-statistic
            '''
            result = self._values.get("statistic")
            assert result is not None, "Required property 'statistic' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def dimensions(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScalingPolicy.MetricDimensionProperty", _IResolvable_da3f097b]]]]:
            '''The dimensions of the metric.

            Conditional: If you published your metric with dimensions, you must specify the same dimensions in your scaling policy.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-customizedmetricspecification.html#cfn-autoscaling-scalingpolicy-customizedmetricspecification-dimensions
            '''
            result = self._values.get("dimensions")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScalingPolicy.MetricDimensionProperty", _IResolvable_da3f097b]]]], result)

        @builtins.property
        def unit(self) -> typing.Optional[builtins.str]:
            '''The unit of the metric.

            For a complete list of the units that CloudWatch supports, see the `MetricDatum <https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_MetricDatum.html>`_ data type in the *Amazon CloudWatch API Reference* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-customizedmetricspecification.html#cfn-autoscaling-scalingpolicy-customizedmetricspecification-unit
            '''
            result = self._values.get("unit")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "CustomizedMetricSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicy.MetricDimensionProperty",
        jsii_struct_bases=[],
        name_mapping={"name": "name", "value": "value"},
    )
    class MetricDimensionProperty:
        def __init__(self, *, name: builtins.str, value: builtins.str) -> None:
            '''``MetricDimension`` specifies a name/value pair that is part of the identity of a CloudWatch metric for the ``Dimensions`` property of the `AWS::AutoScaling::ScalingPolicy CustomizedMetricSpecification <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-customizedmetricspecification.html>`_ property type. Duplicate dimensions are not allowed.

            :param name: The name of the dimension.
            :param value: The value of the dimension.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-metricdimension.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                metric_dimension_property = autoscaling.CfnScalingPolicy.MetricDimensionProperty(
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
            '''The name of the dimension.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-metricdimension.html#cfn-autoscaling-scalingpolicy-metricdimension-name
            '''
            result = self._values.get("name")
            assert result is not None, "Required property 'name' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''The value of the dimension.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-metricdimension.html#cfn-autoscaling-scalingpolicy-metricdimension-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "MetricDimensionProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicy.PredefinedMetricSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "predefined_metric_type": "predefinedMetricType",
            "resource_label": "resourceLabel",
        },
    )
    class PredefinedMetricSpecificationProperty:
        def __init__(
            self,
            *,
            predefined_metric_type: builtins.str,
            resource_label: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains predefined metric specification information for a target tracking scaling policy for Amazon EC2 Auto Scaling.

            ``PredefinedMetricSpecification`` is a property of the `AWS::AutoScaling::ScalingPolicy TargetTrackingConfiguration <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-targettrackingconfiguration.html>`_ property type.

            :param predefined_metric_type: The metric type. The following predefined metrics are available. - ``ASGAverageCPUUtilization`` - Average CPU utilization of the Auto Scaling group. - ``ASGAverageNetworkIn`` - Average number of bytes received on all network interfaces by the Auto Scaling group. - ``ASGAverageNetworkOut`` - Average number of bytes sent out on all network interfaces by the Auto Scaling group. - ``ALBRequestCountPerTarget`` - Number of requests completed per target in an Application Load Balancer target group.
            :param resource_label: Identifies the resource associated with the metric type. You can't specify a resource label unless the metric type is ``ALBRequestCountPerTarget`` and there is a target group attached to the Auto Scaling group. The format is ``app/ *load-balancer-name* / *load-balancer-id* /targetgroup/ *target-group-name* / *target-group-id*`` , where - ``app/ *load-balancer-name* / *load-balancer-id*`` is the final portion of the load balancer ARN, and - ``targetgroup/ *target-group-name* / *target-group-id*`` is the final portion of the target group ARN.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predefinedmetricspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                predefined_metric_specification_property = autoscaling.CfnScalingPolicy.PredefinedMetricSpecificationProperty(
                    predefined_metric_type="predefinedMetricType",
                
                    # the properties below are optional
                    resource_label="resourceLabel"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "predefined_metric_type": predefined_metric_type,
            }
            if resource_label is not None:
                self._values["resource_label"] = resource_label

        @builtins.property
        def predefined_metric_type(self) -> builtins.str:
            '''The metric type. The following predefined metrics are available.

            - ``ASGAverageCPUUtilization`` - Average CPU utilization of the Auto Scaling group.
            - ``ASGAverageNetworkIn`` - Average number of bytes received on all network interfaces by the Auto Scaling group.
            - ``ASGAverageNetworkOut`` - Average number of bytes sent out on all network interfaces by the Auto Scaling group.
            - ``ALBRequestCountPerTarget`` - Number of requests completed per target in an Application Load Balancer target group.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predefinedmetricspecification.html#cfn-autoscaling-scalingpolicy-predefinedmetricspecification-predefinedmetrictype
            '''
            result = self._values.get("predefined_metric_type")
            assert result is not None, "Required property 'predefined_metric_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def resource_label(self) -> typing.Optional[builtins.str]:
            '''Identifies the resource associated with the metric type.

            You can't specify a resource label unless the metric type is ``ALBRequestCountPerTarget`` and there is a target group attached to the Auto Scaling group.

            The format is ``app/ *load-balancer-name* / *load-balancer-id* /targetgroup/ *target-group-name* / *target-group-id*`` , where

            - ``app/ *load-balancer-name* / *load-balancer-id*`` is the final portion of the load balancer ARN, and
            - ``targetgroup/ *target-group-name* / *target-group-id*`` is the final portion of the target group ARN.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predefinedmetricspecification.html#cfn-autoscaling-scalingpolicy-predefinedmetricspecification-resourcelabel
            '''
            result = self._values.get("resource_label")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PredefinedMetricSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicy.PredictiveScalingConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "metric_specifications": "metricSpecifications",
            "max_capacity_breach_behavior": "maxCapacityBreachBehavior",
            "max_capacity_buffer": "maxCapacityBuffer",
            "mode": "mode",
            "scheduling_buffer_time": "schedulingBufferTime",
        },
    )
    class PredictiveScalingConfigurationProperty:
        def __init__(
            self,
            *,
            metric_specifications: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnScalingPolicy.PredictiveScalingMetricSpecificationProperty", _IResolvable_da3f097b]]],
            max_capacity_breach_behavior: typing.Optional[builtins.str] = None,
            max_capacity_buffer: typing.Optional[jsii.Number] = None,
            mode: typing.Optional[builtins.str] = None,
            scheduling_buffer_time: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``PredictiveScalingConfiguration`` is a property of the `AWS::AutoScaling::ScalingPolicy <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html>`_ resource that specifies a predictive scaling policy for Amazon EC2 Auto Scaling.

            For more information, see `PutScalingPolicy <https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html>`_ in the *Amazon EC2 Auto Scaling API Reference* and `Predictive scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-predictive-scaling.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :param metric_specifications: An array that contains information about the metrics and target utilization to use for predictive scaling. .. epigraph:: Adding more than one predictive scaling metric specification to the array is currently not supported.
            :param max_capacity_breach_behavior: Defines the behavior that should be applied if the forecast capacity approaches or exceeds the maximum capacity of the Auto Scaling group. Defaults to ``HonorMaxCapacity`` if not specified. The following are possible values: - ``HonorMaxCapacity`` - Amazon EC2 Auto Scaling cannot scale out capacity higher than the maximum capacity. The maximum capacity is enforced as a hard limit. - ``IncreaseMaxCapacity`` - Amazon EC2 Auto Scaling can scale out capacity higher than the maximum capacity when the forecast capacity is close to or exceeds the maximum capacity. The upper limit is determined by the forecasted capacity and the value for ``MaxCapacityBuffer`` .
            :param max_capacity_buffer: The size of the capacity buffer to use when the forecast capacity is close to or exceeds the maximum capacity. The value is specified as a percentage relative to the forecast capacity. For example, if the buffer is 10, this means a 10 percent buffer, such that if the forecast capacity is 50, and the maximum capacity is 40, then the effective maximum capacity is 55. If set to 0, Amazon EC2 Auto Scaling may scale capacity higher than the maximum capacity to equal but not exceed forecast capacity. Required if the ``MaxCapacityBreachBehavior`` property is set to ``IncreaseMaxCapacity`` , and cannot be used otherwise.
            :param mode: The predictive scaling mode. Defaults to ``ForecastOnly`` if not specified.
            :param scheduling_buffer_time: The amount of time, in seconds, by which the instance launch time can be advanced. For example, the forecast says to add capacity at 10:00 AM, and you choose to pre-launch instances by 5 minutes. In that case, the instances will be launched at 9:55 AM. The intention is to give resources time to be provisioned. It can take a few minutes to launch an EC2 instance. The actual amount of time required depends on several factors, such as the size of the instance and whether there are startup scripts to complete. The value must be less than the forecast interval duration of 3600 seconds (60 minutes). Defaults to 300 seconds if not specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                predictive_scaling_configuration_property = autoscaling.CfnScalingPolicy.PredictiveScalingConfigurationProperty(
                    metric_specifications=[autoscaling.CfnScalingPolicy.PredictiveScalingMetricSpecificationProperty(
                        target_value=123,
                
                        # the properties below are optional
                        predefined_load_metric_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedLoadMetricProperty(
                            predefined_metric_type="predefinedMetricType",
                
                            # the properties below are optional
                            resource_label="resourceLabel"
                        ),
                        predefined_metric_pair_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedMetricPairProperty(
                            predefined_metric_type="predefinedMetricType",
                
                            # the properties below are optional
                            resource_label="resourceLabel"
                        ),
                        predefined_scaling_metric_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedScalingMetricProperty(
                            predefined_metric_type="predefinedMetricType",
                
                            # the properties below are optional
                            resource_label="resourceLabel"
                        )
                    )],
                
                    # the properties below are optional
                    max_capacity_breach_behavior="maxCapacityBreachBehavior",
                    max_capacity_buffer=123,
                    mode="mode",
                    scheduling_buffer_time=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "metric_specifications": metric_specifications,
            }
            if max_capacity_breach_behavior is not None:
                self._values["max_capacity_breach_behavior"] = max_capacity_breach_behavior
            if max_capacity_buffer is not None:
                self._values["max_capacity_buffer"] = max_capacity_buffer
            if mode is not None:
                self._values["mode"] = mode
            if scheduling_buffer_time is not None:
                self._values["scheduling_buffer_time"] = scheduling_buffer_time

        @builtins.property
        def metric_specifications(
            self,
        ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScalingPolicy.PredictiveScalingMetricSpecificationProperty", _IResolvable_da3f097b]]]:
            '''An array that contains information about the metrics and target utilization to use for predictive scaling.

            .. epigraph::

               Adding more than one predictive scaling metric specification to the array is currently not supported.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingconfiguration.html#cfn-autoscaling-scalingpolicy-predictivescalingconfiguration-metricspecifications
            '''
            result = self._values.get("metric_specifications")
            assert result is not None, "Required property 'metric_specifications' is missing"
            return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnScalingPolicy.PredictiveScalingMetricSpecificationProperty", _IResolvable_da3f097b]]], result)

        @builtins.property
        def max_capacity_breach_behavior(self) -> typing.Optional[builtins.str]:
            '''Defines the behavior that should be applied if the forecast capacity approaches or exceeds the maximum capacity of the Auto Scaling group.

            Defaults to ``HonorMaxCapacity`` if not specified.

            The following are possible values:

            - ``HonorMaxCapacity`` - Amazon EC2 Auto Scaling cannot scale out capacity higher than the maximum capacity. The maximum capacity is enforced as a hard limit.
            - ``IncreaseMaxCapacity`` - Amazon EC2 Auto Scaling can scale out capacity higher than the maximum capacity when the forecast capacity is close to or exceeds the maximum capacity. The upper limit is determined by the forecasted capacity and the value for ``MaxCapacityBuffer`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingconfiguration.html#cfn-autoscaling-scalingpolicy-predictivescalingconfiguration-maxcapacitybreachbehavior
            '''
            result = self._values.get("max_capacity_breach_behavior")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def max_capacity_buffer(self) -> typing.Optional[jsii.Number]:
            '''The size of the capacity buffer to use when the forecast capacity is close to or exceeds the maximum capacity.

            The value is specified as a percentage relative to the forecast capacity. For example, if the buffer is 10, this means a 10 percent buffer, such that if the forecast capacity is 50, and the maximum capacity is 40, then the effective maximum capacity is 55.

            If set to 0, Amazon EC2 Auto Scaling may scale capacity higher than the maximum capacity to equal but not exceed forecast capacity.

            Required if the ``MaxCapacityBreachBehavior`` property is set to ``IncreaseMaxCapacity`` , and cannot be used otherwise.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingconfiguration.html#cfn-autoscaling-scalingpolicy-predictivescalingconfiguration-maxcapacitybuffer
            '''
            result = self._values.get("max_capacity_buffer")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def mode(self) -> typing.Optional[builtins.str]:
            '''The predictive scaling mode.

            Defaults to ``ForecastOnly`` if not specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingconfiguration.html#cfn-autoscaling-scalingpolicy-predictivescalingconfiguration-mode
            '''
            result = self._values.get("mode")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def scheduling_buffer_time(self) -> typing.Optional[jsii.Number]:
            '''The amount of time, in seconds, by which the instance launch time can be advanced.

            For example, the forecast says to add capacity at 10:00 AM, and you choose to pre-launch instances by 5 minutes. In that case, the instances will be launched at 9:55 AM. The intention is to give resources time to be provisioned. It can take a few minutes to launch an EC2 instance. The actual amount of time required depends on several factors, such as the size of the instance and whether there are startup scripts to complete.

            The value must be less than the forecast interval duration of 3600 seconds (60 minutes). Defaults to 300 seconds if not specified.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingconfiguration.html#cfn-autoscaling-scalingpolicy-predictivescalingconfiguration-schedulingbuffertime
            '''
            result = self._values.get("scheduling_buffer_time")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PredictiveScalingConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicy.PredictiveScalingMetricSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "target_value": "targetValue",
            "predefined_load_metric_specification": "predefinedLoadMetricSpecification",
            "predefined_metric_pair_specification": "predefinedMetricPairSpecification",
            "predefined_scaling_metric_specification": "predefinedScalingMetricSpecification",
        },
    )
    class PredictiveScalingMetricSpecificationProperty:
        def __init__(
            self,
            *,
            target_value: jsii.Number,
            predefined_load_metric_specification: typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingPredefinedLoadMetricProperty", _IResolvable_da3f097b]] = None,
            predefined_metric_pair_specification: typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingPredefinedMetricPairProperty", _IResolvable_da3f097b]] = None,
            predefined_scaling_metric_specification: typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingPredefinedScalingMetricProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A structure that specifies a metric specification for the ``MetricSpecifications`` property of the `AWS::AutoScaling::ScalingPolicy PredictiveScalingConfiguration <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingconfiguration.html>`_ property type.

            For more information, see `Predictive scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-predictive-scaling.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :param target_value: Specifies the target utilization. .. epigraph:: Some metrics are based on a count instead of a percentage, such as the request count for an Application Load Balancer or the number of messages in an SQS queue. If the scaling policy specifies one of these metrics, specify the target utilization as the optimal average request or message count per instance during any one-minute interval.
            :param predefined_load_metric_specification: The load metric specification. If you specify ``PredefinedMetricPairSpecification`` , don't specify this property.
            :param predefined_metric_pair_specification: The metric pair specification from which Amazon EC2 Auto Scaling determines the appropriate scaling metric and load metric to use. .. epigraph:: With predictive scaling, you must specify either a metric pair, or a load metric and a scaling metric individually. Specifying a metric pair instead of individual metrics provides a simpler way to configure metrics for a scaling policy. You choose the metric pair, and the policy automatically knows the correct sum and average statistics to use for the load metric and the scaling metric.
            :param predefined_scaling_metric_specification: The scaling metric specification. If you specify ``PredefinedMetricPairSpecification`` , don't specify this property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingmetricspecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                predictive_scaling_metric_specification_property = autoscaling.CfnScalingPolicy.PredictiveScalingMetricSpecificationProperty(
                    target_value=123,
                
                    # the properties below are optional
                    predefined_load_metric_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedLoadMetricProperty(
                        predefined_metric_type="predefinedMetricType",
                
                        # the properties below are optional
                        resource_label="resourceLabel"
                    ),
                    predefined_metric_pair_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedMetricPairProperty(
                        predefined_metric_type="predefinedMetricType",
                
                        # the properties below are optional
                        resource_label="resourceLabel"
                    ),
                    predefined_scaling_metric_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedScalingMetricProperty(
                        predefined_metric_type="predefinedMetricType",
                
                        # the properties below are optional
                        resource_label="resourceLabel"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "target_value": target_value,
            }
            if predefined_load_metric_specification is not None:
                self._values["predefined_load_metric_specification"] = predefined_load_metric_specification
            if predefined_metric_pair_specification is not None:
                self._values["predefined_metric_pair_specification"] = predefined_metric_pair_specification
            if predefined_scaling_metric_specification is not None:
                self._values["predefined_scaling_metric_specification"] = predefined_scaling_metric_specification

        @builtins.property
        def target_value(self) -> jsii.Number:
            '''Specifies the target utilization.

            .. epigraph::

               Some metrics are based on a count instead of a percentage, such as the request count for an Application Load Balancer or the number of messages in an SQS queue. If the scaling policy specifies one of these metrics, specify the target utilization as the optimal average request or message count per instance during any one-minute interval.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingmetricspecification.html#cfn-autoscaling-scalingpolicy-predictivescalingmetricspecification-targetvalue
            '''
            result = self._values.get("target_value")
            assert result is not None, "Required property 'target_value' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def predefined_load_metric_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingPredefinedLoadMetricProperty", _IResolvable_da3f097b]]:
            '''The load metric specification.

            If you specify ``PredefinedMetricPairSpecification`` , don't specify this property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingmetricspecification.html#cfn-autoscaling-scalingpolicy-predictivescalingmetricspecification-predefinedloadmetricspecification
            '''
            result = self._values.get("predefined_load_metric_specification")
            return typing.cast(typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingPredefinedLoadMetricProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def predefined_metric_pair_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingPredefinedMetricPairProperty", _IResolvable_da3f097b]]:
            '''The metric pair specification from which Amazon EC2 Auto Scaling determines the appropriate scaling metric and load metric to use.

            .. epigraph::

               With predictive scaling, you must specify either a metric pair, or a load metric and a scaling metric individually. Specifying a metric pair instead of individual metrics provides a simpler way to configure metrics for a scaling policy. You choose the metric pair, and the policy automatically knows the correct sum and average statistics to use for the load metric and the scaling metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingmetricspecification.html#cfn-autoscaling-scalingpolicy-predictivescalingmetricspecification-predefinedmetricpairspecification
            '''
            result = self._values.get("predefined_metric_pair_specification")
            return typing.cast(typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingPredefinedMetricPairProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def predefined_scaling_metric_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingPredefinedScalingMetricProperty", _IResolvable_da3f097b]]:
            '''The scaling metric specification.

            If you specify ``PredefinedMetricPairSpecification`` , don't specify this property.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingmetricspecification.html#cfn-autoscaling-scalingpolicy-predictivescalingmetricspecification-predefinedscalingmetricspecification
            '''
            result = self._values.get("predefined_scaling_metric_specification")
            return typing.cast(typing.Optional[typing.Union["CfnScalingPolicy.PredictiveScalingPredefinedScalingMetricProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PredictiveScalingMetricSpecificationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedLoadMetricProperty",
        jsii_struct_bases=[],
        name_mapping={
            "predefined_metric_type": "predefinedMetricType",
            "resource_label": "resourceLabel",
        },
    )
    class PredictiveScalingPredefinedLoadMetricProperty:
        def __init__(
            self,
            *,
            predefined_metric_type: builtins.str,
            resource_label: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains load metric information for the ``PredefinedLoadMetricSpecification`` property of the `AWS::AutoScaling::ScalingPolicy PredictiveScalingMetricSpecification <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingmetricspecification.html>`_ property type.

            .. epigraph::

               Does not apply to policies that use a *metric pair* for the metric specification.

            :param predefined_metric_type: The metric type.
            :param resource_label: A label that uniquely identifies a specific Application Load Balancer target group from which to determine the request count served by your Auto Scaling group. You can't specify a resource label unless the target group is attached to the Auto Scaling group. You create the resource label by appending the final portion of the load balancer ARN and the final portion of the target group ARN into a single value, separated by a forward slash (/). The format of the resource label is: ``app/my-alb/778d41231b141a0f/targetgroup/my-alb-target-group/943f017f100becff`` . Where: - app// is the final portion of the load balancer ARN - targetgroup// is the final portion of the target group ARN. To find the ARN for an Application Load Balancer, use the `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ API operation. To find the ARN for the target group, use the `DescribeTargetGroups <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetGroups.html>`_ API operation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingpredefinedloadmetric.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                predictive_scaling_predefined_load_metric_property = autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedLoadMetricProperty(
                    predefined_metric_type="predefinedMetricType",
                
                    # the properties below are optional
                    resource_label="resourceLabel"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "predefined_metric_type": predefined_metric_type,
            }
            if resource_label is not None:
                self._values["resource_label"] = resource_label

        @builtins.property
        def predefined_metric_type(self) -> builtins.str:
            '''The metric type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingpredefinedloadmetric.html#cfn-autoscaling-scalingpolicy-predictivescalingpredefinedloadmetric-predefinedmetrictype
            '''
            result = self._values.get("predefined_metric_type")
            assert result is not None, "Required property 'predefined_metric_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def resource_label(self) -> typing.Optional[builtins.str]:
            '''A label that uniquely identifies a specific Application Load Balancer target group from which to determine the request count served by your Auto Scaling group.

            You can't specify a resource label unless the target group is attached to the Auto Scaling group.

            You create the resource label by appending the final portion of the load balancer ARN and the final portion of the target group ARN into a single value, separated by a forward slash (/). The format of the resource label is:

            ``app/my-alb/778d41231b141a0f/targetgroup/my-alb-target-group/943f017f100becff`` .

            Where:

            - app// is the final portion of the load balancer ARN
            - targetgroup// is the final portion of the target group ARN.

            To find the ARN for an Application Load Balancer, use the `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ API operation. To find the ARN for the target group, use the `DescribeTargetGroups <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetGroups.html>`_ API operation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingpredefinedloadmetric.html#cfn-autoscaling-scalingpolicy-predictivescalingpredefinedloadmetric-resourcelabel
            '''
            result = self._values.get("resource_label")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PredictiveScalingPredefinedLoadMetricProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedMetricPairProperty",
        jsii_struct_bases=[],
        name_mapping={
            "predefined_metric_type": "predefinedMetricType",
            "resource_label": "resourceLabel",
        },
    )
    class PredictiveScalingPredefinedMetricPairProperty:
        def __init__(
            self,
            *,
            predefined_metric_type: builtins.str,
            resource_label: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains metric pair information for the ``PredefinedMetricPairSpecification`` property of the `AWS::AutoScaling::ScalingPolicy PredictiveScalingMetricSpecification <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingmetricspecification.html>`_ property type.

            For more information, see `Predictive scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-predictive-scaling.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :param predefined_metric_type: Indicates which metrics to use. There are two different types of metrics for each metric type: one is a load metric and one is a scaling metric. For example, if the metric type is ``ASGCPUUtilization`` , the Auto Scaling group's total CPU metric is used as the load metric, and the average CPU metric is used for the scaling metric.
            :param resource_label: A label that uniquely identifies a specific Application Load Balancer target group from which to determine the total and average request count served by your Auto Scaling group. You can't specify a resource label unless the target group is attached to the Auto Scaling group. You create the resource label by appending the final portion of the load balancer ARN and the final portion of the target group ARN into a single value, separated by a forward slash (/). The format of the resource label is: ``app/my-alb/778d41231b141a0f/targetgroup/my-alb-target-group/943f017f100becff`` . Where: - app// is the final portion of the load balancer ARN - targetgroup// is the final portion of the target group ARN. To find the ARN for an Application Load Balancer, use the `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ API operation. To find the ARN for the target group, use the `DescribeTargetGroups <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetGroups.html>`_ API operation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingpredefinedmetricpair.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                predictive_scaling_predefined_metric_pair_property = autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedMetricPairProperty(
                    predefined_metric_type="predefinedMetricType",
                
                    # the properties below are optional
                    resource_label="resourceLabel"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "predefined_metric_type": predefined_metric_type,
            }
            if resource_label is not None:
                self._values["resource_label"] = resource_label

        @builtins.property
        def predefined_metric_type(self) -> builtins.str:
            '''Indicates which metrics to use.

            There are two different types of metrics for each metric type: one is a load metric and one is a scaling metric. For example, if the metric type is ``ASGCPUUtilization`` , the Auto Scaling group's total CPU metric is used as the load metric, and the average CPU metric is used for the scaling metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingpredefinedmetricpair.html#cfn-autoscaling-scalingpolicy-predictivescalingpredefinedmetricpair-predefinedmetrictype
            '''
            result = self._values.get("predefined_metric_type")
            assert result is not None, "Required property 'predefined_metric_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def resource_label(self) -> typing.Optional[builtins.str]:
            '''A label that uniquely identifies a specific Application Load Balancer target group from which to determine the total and average request count served by your Auto Scaling group.

            You can't specify a resource label unless the target group is attached to the Auto Scaling group.

            You create the resource label by appending the final portion of the load balancer ARN and the final portion of the target group ARN into a single value, separated by a forward slash (/). The format of the resource label is:

            ``app/my-alb/778d41231b141a0f/targetgroup/my-alb-target-group/943f017f100becff`` .

            Where:

            - app// is the final portion of the load balancer ARN
            - targetgroup// is the final portion of the target group ARN.

            To find the ARN for an Application Load Balancer, use the `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ API operation. To find the ARN for the target group, use the `DescribeTargetGroups <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetGroups.html>`_ API operation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingpredefinedmetricpair.html#cfn-autoscaling-scalingpolicy-predictivescalingpredefinedmetricpair-resourcelabel
            '''
            result = self._values.get("resource_label")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PredictiveScalingPredefinedMetricPairProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedScalingMetricProperty",
        jsii_struct_bases=[],
        name_mapping={
            "predefined_metric_type": "predefinedMetricType",
            "resource_label": "resourceLabel",
        },
    )
    class PredictiveScalingPredefinedScalingMetricProperty:
        def __init__(
            self,
            *,
            predefined_metric_type: builtins.str,
            resource_label: typing.Optional[builtins.str] = None,
        ) -> None:
            '''Contains scaling metric information for the ``PredefinedScalingMetricSpecification`` property of the `AWS::AutoScaling::ScalingPolicy PredictiveScalingMetricSpecification <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingmetricspecification.html>`_ property type.

            .. epigraph::

               Does not apply to policies that use a *metric pair* for the metric specification.

            :param predefined_metric_type: The metric type.
            :param resource_label: A label that uniquely identifies a specific Application Load Balancer target group from which to determine the average request count served by your Auto Scaling group. You can't specify a resource label unless the target group is attached to the Auto Scaling group. You create the resource label by appending the final portion of the load balancer ARN and the final portion of the target group ARN into a single value, separated by a forward slash (/). The format of the resource label is: ``app/my-alb/778d41231b141a0f/targetgroup/my-alb-target-group/943f017f100becff`` . Where: - app// is the final portion of the load balancer ARN - targetgroup// is the final portion of the target group ARN. To find the ARN for an Application Load Balancer, use the `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ API operation. To find the ARN for the target group, use the `DescribeTargetGroups <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetGroups.html>`_ API operation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingpredefinedscalingmetric.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                predictive_scaling_predefined_scaling_metric_property = autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedScalingMetricProperty(
                    predefined_metric_type="predefinedMetricType",
                
                    # the properties below are optional
                    resource_label="resourceLabel"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "predefined_metric_type": predefined_metric_type,
            }
            if resource_label is not None:
                self._values["resource_label"] = resource_label

        @builtins.property
        def predefined_metric_type(self) -> builtins.str:
            '''The metric type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingpredefinedscalingmetric.html#cfn-autoscaling-scalingpolicy-predictivescalingpredefinedscalingmetric-predefinedmetrictype
            '''
            result = self._values.get("predefined_metric_type")
            assert result is not None, "Required property 'predefined_metric_type' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def resource_label(self) -> typing.Optional[builtins.str]:
            '''A label that uniquely identifies a specific Application Load Balancer target group from which to determine the average request count served by your Auto Scaling group.

            You can't specify a resource label unless the target group is attached to the Auto Scaling group.

            You create the resource label by appending the final portion of the load balancer ARN and the final portion of the target group ARN into a single value, separated by a forward slash (/). The format of the resource label is:

            ``app/my-alb/778d41231b141a0f/targetgroup/my-alb-target-group/943f017f100becff`` .

            Where:

            - app// is the final portion of the load balancer ARN
            - targetgroup// is the final portion of the target group ARN.

            To find the ARN for an Application Load Balancer, use the `DescribeLoadBalancers <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancers.html>`_ API operation. To find the ARN for the target group, use the `DescribeTargetGroups <https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeTargetGroups.html>`_ API operation.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-predictivescalingpredefinedscalingmetric.html#cfn-autoscaling-scalingpolicy-predictivescalingpredefinedscalingmetric-resourcelabel
            '''
            result = self._values.get("resource_label")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "PredictiveScalingPredefinedScalingMetricProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicy.StepAdjustmentProperty",
        jsii_struct_bases=[],
        name_mapping={
            "scaling_adjustment": "scalingAdjustment",
            "metric_interval_lower_bound": "metricIntervalLowerBound",
            "metric_interval_upper_bound": "metricIntervalUpperBound",
        },
    )
    class StepAdjustmentProperty:
        def __init__(
            self,
            *,
            scaling_adjustment: jsii.Number,
            metric_interval_lower_bound: typing.Optional[jsii.Number] = None,
            metric_interval_upper_bound: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''``StepAdjustment`` specifies a step adjustment for the ``StepAdjustments`` property of the `AWS::AutoScaling::ScalingPolicy <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html>`_ resource.

            For the following examples, suppose that you have an alarm with a breach threshold of 50:

            - To trigger a step adjustment when the metric is greater than or equal to 50 and less than 60, specify a lower bound of 0 and an upper bound of 10.
            - To trigger a step adjustment when the metric is greater than 40 and less than or equal to 50, specify a lower bound of -10 and an upper bound of 0.

            There are a few rules for the step adjustments for your step policy:

            - The ranges of your step adjustments can't overlap or have a gap.
            - At most one step adjustment can have a null lower bound. If one step adjustment has a negative lower bound, then there must be a step adjustment with a null lower bound.
            - At most one step adjustment can have a null upper bound. If one step adjustment has a positive upper bound, then there must be a step adjustment with a null upper bound.
            - The upper and lower bound can't be null in the same step adjustment.

            For more information, see `Step adjustments <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html#as-scaling-steps>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            You can find a sample template snippet in the `Examples <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#aws-properties-as-policy--examples>`_ section of the ``AWS::AutoScaling::ScalingPolicy`` documentation.

            :param scaling_adjustment: The amount by which to scale. The adjustment is based on the value that you specified in the ``AdjustmentType`` property (either an absolute number or a percentage). A positive value adds to the current capacity and a negative number subtracts from the current capacity.
            :param metric_interval_lower_bound: The lower bound for the difference between the alarm threshold and the CloudWatch metric. If the metric value is above the breach threshold, the lower bound is inclusive (the metric must be greater than or equal to the threshold plus the lower bound). Otherwise, it is exclusive (the metric must be greater than the threshold plus the lower bound). A null value indicates negative infinity.
            :param metric_interval_upper_bound: The upper bound for the difference between the alarm threshold and the CloudWatch metric. If the metric value is above the breach threshold, the upper bound is exclusive (the metric must be less than the threshold plus the upper bound). Otherwise, it is inclusive (the metric must be less than or equal to the threshold plus the upper bound). A null value indicates positive infinity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-stepadjustments.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                step_adjustment_property = autoscaling.CfnScalingPolicy.StepAdjustmentProperty(
                    scaling_adjustment=123,
                
                    # the properties below are optional
                    metric_interval_lower_bound=123,
                    metric_interval_upper_bound=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "scaling_adjustment": scaling_adjustment,
            }
            if metric_interval_lower_bound is not None:
                self._values["metric_interval_lower_bound"] = metric_interval_lower_bound
            if metric_interval_upper_bound is not None:
                self._values["metric_interval_upper_bound"] = metric_interval_upper_bound

        @builtins.property
        def scaling_adjustment(self) -> jsii.Number:
            '''The amount by which to scale.

            The adjustment is based on the value that you specified in the ``AdjustmentType`` property (either an absolute number or a percentage). A positive value adds to the current capacity and a negative number subtracts from the current capacity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-stepadjustments.html#cfn-autoscaling-scalingpolicy-stepadjustment-scalingadjustment
            '''
            result = self._values.get("scaling_adjustment")
            assert result is not None, "Required property 'scaling_adjustment' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def metric_interval_lower_bound(self) -> typing.Optional[jsii.Number]:
            '''The lower bound for the difference between the alarm threshold and the CloudWatch metric.

            If the metric value is above the breach threshold, the lower bound is inclusive (the metric must be greater than or equal to the threshold plus the lower bound). Otherwise, it is exclusive (the metric must be greater than the threshold plus the lower bound). A null value indicates negative infinity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-stepadjustments.html#cfn-autoscaling-scalingpolicy-stepadjustment-metricintervallowerbound
            '''
            result = self._values.get("metric_interval_lower_bound")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def metric_interval_upper_bound(self) -> typing.Optional[jsii.Number]:
            '''The upper bound for the difference between the alarm threshold and the CloudWatch metric.

            If the metric value is above the breach threshold, the upper bound is exclusive (the metric must be less than the threshold plus the upper bound). Otherwise, it is inclusive (the metric must be less than or equal to the threshold plus the upper bound). A null value indicates positive infinity.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-stepadjustments.html#cfn-autoscaling-scalingpolicy-stepadjustment-metricintervalupperbound
            '''
            result = self._values.get("metric_interval_upper_bound")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "StepAdjustmentProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicy.TargetTrackingConfigurationProperty",
        jsii_struct_bases=[],
        name_mapping={
            "target_value": "targetValue",
            "customized_metric_specification": "customizedMetricSpecification",
            "disable_scale_in": "disableScaleIn",
            "predefined_metric_specification": "predefinedMetricSpecification",
        },
    )
    class TargetTrackingConfigurationProperty:
        def __init__(
            self,
            *,
            target_value: jsii.Number,
            customized_metric_specification: typing.Optional[typing.Union["CfnScalingPolicy.CustomizedMetricSpecificationProperty", _IResolvable_da3f097b]] = None,
            disable_scale_in: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            predefined_metric_specification: typing.Optional[typing.Union["CfnScalingPolicy.PredefinedMetricSpecificationProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''``TargetTrackingConfiguration`` is a property of the `AWS::AutoScaling::ScalingPolicy <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html>`_ resource that specifies a target tracking scaling policy configuration for Amazon EC2 Auto Scaling.

            For more information, see `PutScalingPolicy <https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html>`_ in the *Amazon EC2 Auto Scaling API Reference* . For more information about scaling policies, see `Dynamic scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scale-based-on-demand.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :param target_value: The target value for the metric.
            :param customized_metric_specification: A customized metric. You must specify either a predefined metric or a customized metric.
            :param disable_scale_in: Indicates whether scaling in by the target tracking scaling policy is disabled. If scaling in is disabled, the target tracking scaling policy doesn't remove instances from the Auto Scaling group. Otherwise, the target tracking scaling policy can remove instances from the Auto Scaling group. The default is ``false`` .
            :param predefined_metric_specification: A predefined metric. You must specify either a predefined metric or a customized metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-targettrackingconfiguration.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                target_tracking_configuration_property = autoscaling.CfnScalingPolicy.TargetTrackingConfigurationProperty(
                    target_value=123,
                
                    # the properties below are optional
                    customized_metric_specification=autoscaling.CfnScalingPolicy.CustomizedMetricSpecificationProperty(
                        metric_name="metricName",
                        namespace="namespace",
                        statistic="statistic",
                
                        # the properties below are optional
                        dimensions=[autoscaling.CfnScalingPolicy.MetricDimensionProperty(
                            name="name",
                            value="value"
                        )],
                        unit="unit"
                    ),
                    disable_scale_in=False,
                    predefined_metric_specification=autoscaling.CfnScalingPolicy.PredefinedMetricSpecificationProperty(
                        predefined_metric_type="predefinedMetricType",
                
                        # the properties below are optional
                        resource_label="resourceLabel"
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "target_value": target_value,
            }
            if customized_metric_specification is not None:
                self._values["customized_metric_specification"] = customized_metric_specification
            if disable_scale_in is not None:
                self._values["disable_scale_in"] = disable_scale_in
            if predefined_metric_specification is not None:
                self._values["predefined_metric_specification"] = predefined_metric_specification

        @builtins.property
        def target_value(self) -> jsii.Number:
            '''The target value for the metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-targettrackingconfiguration.html#cfn-autoscaling-scalingpolicy-targettrackingconfiguration-targetvalue
            '''
            result = self._values.get("target_value")
            assert result is not None, "Required property 'target_value' is missing"
            return typing.cast(jsii.Number, result)

        @builtins.property
        def customized_metric_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnScalingPolicy.CustomizedMetricSpecificationProperty", _IResolvable_da3f097b]]:
            '''A customized metric.

            You must specify either a predefined metric or a customized metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-targettrackingconfiguration.html#cfn-autoscaling-scalingpolicy-targettrackingconfiguration-customizedmetricspecification
            '''
            result = self._values.get("customized_metric_specification")
            return typing.cast(typing.Optional[typing.Union["CfnScalingPolicy.CustomizedMetricSpecificationProperty", _IResolvable_da3f097b]], result)

        @builtins.property
        def disable_scale_in(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Indicates whether scaling in by the target tracking scaling policy is disabled.

            If scaling in is disabled, the target tracking scaling policy doesn't remove instances from the Auto Scaling group. Otherwise, the target tracking scaling policy can remove instances from the Auto Scaling group. The default is ``false`` .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-targettrackingconfiguration.html#cfn-autoscaling-scalingpolicy-targettrackingconfiguration-disablescalein
            '''
            result = self._values.get("disable_scale_in")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def predefined_metric_specification(
            self,
        ) -> typing.Optional[typing.Union["CfnScalingPolicy.PredefinedMetricSpecificationProperty", _IResolvable_da3f097b]]:
            '''A predefined metric.

            You must specify either a predefined metric or a customized metric.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-scalingpolicy-targettrackingconfiguration.html#cfn-autoscaling-scalingpolicy-targettrackingconfiguration-predefinedmetricspecification
            '''
            result = self._values.get("predefined_metric_specification")
            return typing.cast(typing.Optional[typing.Union["CfnScalingPolicy.PredefinedMetricSpecificationProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TargetTrackingConfigurationProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnScalingPolicyProps",
    jsii_struct_bases=[],
    name_mapping={
        "auto_scaling_group_name": "autoScalingGroupName",
        "adjustment_type": "adjustmentType",
        "cooldown": "cooldown",
        "estimated_instance_warmup": "estimatedInstanceWarmup",
        "metric_aggregation_type": "metricAggregationType",
        "min_adjustment_magnitude": "minAdjustmentMagnitude",
        "policy_type": "policyType",
        "predictive_scaling_configuration": "predictiveScalingConfiguration",
        "scaling_adjustment": "scalingAdjustment",
        "step_adjustments": "stepAdjustments",
        "target_tracking_configuration": "targetTrackingConfiguration",
    },
)
class CfnScalingPolicyProps:
    def __init__(
        self,
        *,
        auto_scaling_group_name: builtins.str,
        adjustment_type: typing.Optional[builtins.str] = None,
        cooldown: typing.Optional[builtins.str] = None,
        estimated_instance_warmup: typing.Optional[jsii.Number] = None,
        metric_aggregation_type: typing.Optional[builtins.str] = None,
        min_adjustment_magnitude: typing.Optional[jsii.Number] = None,
        policy_type: typing.Optional[builtins.str] = None,
        predictive_scaling_configuration: typing.Optional[typing.Union[CfnScalingPolicy.PredictiveScalingConfigurationProperty, _IResolvable_da3f097b]] = None,
        scaling_adjustment: typing.Optional[jsii.Number] = None,
        step_adjustments: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnScalingPolicy.StepAdjustmentProperty, _IResolvable_da3f097b]]]] = None,
        target_tracking_configuration: typing.Optional[typing.Union[CfnScalingPolicy.TargetTrackingConfigurationProperty, _IResolvable_da3f097b]] = None,
    ) -> None:
        '''Properties for defining a ``CfnScalingPolicy``.

        :param auto_scaling_group_name: The name of the Auto Scaling group.
        :param adjustment_type: Specifies how the scaling adjustment is interpreted. The valid values are ``ChangeInCapacity`` , ``ExactCapacity`` , and ``PercentChangeInCapacity`` . Required if the policy type is ``StepScaling`` or ``SimpleScaling`` . For more information, see `Scaling adjustment types <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html#as-scaling-adjustment>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param cooldown: The duration of the policy's cooldown period, in seconds. When a cooldown period is specified here, it overrides the default cooldown period defined for the Auto Scaling group. Valid only if the policy type is ``SimpleScaling`` . For more information, see `Scaling cooldowns for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param estimated_instance_warmup: The estimated time, in seconds, until a newly launched instance can contribute to the CloudWatch metrics. If not provided, the default is to use the value from the default cooldown period for the Auto Scaling group. Valid only if the policy type is ``TargetTrackingScaling`` or ``StepScaling`` .
        :param metric_aggregation_type: The aggregation type for the CloudWatch metrics. The valid values are ``Minimum`` , ``Maximum`` , and ``Average`` . If the aggregation type is null, the value is treated as ``Average`` . Valid only if the policy type is ``StepScaling`` .
        :param min_adjustment_magnitude: The minimum value to scale by when the adjustment type is ``PercentChangeInCapacity`` . For example, suppose that you create a step scaling policy to scale out an Auto Scaling group by 25 percent and you specify a ``MinAdjustmentMagnitude`` of 2. If the group has 4 instances and the scaling policy is performed, 25 percent of 4 is 1. However, because you specified a ``MinAdjustmentMagnitude`` of 2, Amazon EC2 Auto Scaling scales out the group by 2 instances. Valid only if the policy type is ``StepScaling`` or ``SimpleScaling`` . For more information, see `Scaling adjustment types <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html#as-scaling-adjustment>`_ in the *Amazon EC2 Auto Scaling User Guide* . .. epigraph:: Some Auto Scaling groups use instance weights. In this case, set the ``MinAdjustmentMagnitude`` to a value that is at least as large as your largest instance weight.
        :param policy_type: One of the following policy types:. - ``TargetTrackingScaling`` - ``StepScaling`` - ``SimpleScaling`` (default) - ``PredictiveScaling`` For more information, see `Target tracking scaling policies <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-target-tracking.html>`_ and `Step and simple scaling policies <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        :param predictive_scaling_configuration: A predictive scaling policy. Includes support for predefined metrics only.
        :param scaling_adjustment: The amount by which to scale, based on the specified adjustment type. A positive value adds to the current capacity while a negative number removes from the current capacity. For exact capacity, you must specify a positive value. Required if the policy type is ``SimpleScaling`` . (Not used with any other policy type.)
        :param step_adjustments: A set of adjustments that enable you to scale based on the size of the alarm breach. Required if the policy type is ``StepScaling`` . (Not used with any other policy type.)
        :param target_tracking_configuration: A target tracking scaling policy. Includes support for predefined or customized metrics. The following predefined metrics are available: - ``ASGAverageCPUUtilization`` - ``ASGAverageNetworkIn`` - ``ASGAverageNetworkOut`` - ``ALBRequestCountPerTarget`` If you specify ``ALBRequestCountPerTarget`` for the metric, you must specify the ``ResourceLabel`` property with the ``PredefinedMetricSpecification`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            cfn_scaling_policy_props = autoscaling.CfnScalingPolicyProps(
                auto_scaling_group_name="autoScalingGroupName",
            
                # the properties below are optional
                adjustment_type="adjustmentType",
                cooldown="cooldown",
                estimated_instance_warmup=123,
                metric_aggregation_type="metricAggregationType",
                min_adjustment_magnitude=123,
                policy_type="policyType",
                predictive_scaling_configuration=autoscaling.CfnScalingPolicy.PredictiveScalingConfigurationProperty(
                    metric_specifications=[autoscaling.CfnScalingPolicy.PredictiveScalingMetricSpecificationProperty(
                        target_value=123,
            
                        # the properties below are optional
                        predefined_load_metric_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedLoadMetricProperty(
                            predefined_metric_type="predefinedMetricType",
            
                            # the properties below are optional
                            resource_label="resourceLabel"
                        ),
                        predefined_metric_pair_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedMetricPairProperty(
                            predefined_metric_type="predefinedMetricType",
            
                            # the properties below are optional
                            resource_label="resourceLabel"
                        ),
                        predefined_scaling_metric_specification=autoscaling.CfnScalingPolicy.PredictiveScalingPredefinedScalingMetricProperty(
                            predefined_metric_type="predefinedMetricType",
            
                            # the properties below are optional
                            resource_label="resourceLabel"
                        )
                    )],
            
                    # the properties below are optional
                    max_capacity_breach_behavior="maxCapacityBreachBehavior",
                    max_capacity_buffer=123,
                    mode="mode",
                    scheduling_buffer_time=123
                ),
                scaling_adjustment=123,
                step_adjustments=[autoscaling.CfnScalingPolicy.StepAdjustmentProperty(
                    scaling_adjustment=123,
            
                    # the properties below are optional
                    metric_interval_lower_bound=123,
                    metric_interval_upper_bound=123
                )],
                target_tracking_configuration=autoscaling.CfnScalingPolicy.TargetTrackingConfigurationProperty(
                    target_value=123,
            
                    # the properties below are optional
                    customized_metric_specification=autoscaling.CfnScalingPolicy.CustomizedMetricSpecificationProperty(
                        metric_name="metricName",
                        namespace="namespace",
                        statistic="statistic",
            
                        # the properties below are optional
                        dimensions=[autoscaling.CfnScalingPolicy.MetricDimensionProperty(
                            name="name",
                            value="value"
                        )],
                        unit="unit"
                    ),
                    disable_scale_in=False,
                    predefined_metric_specification=autoscaling.CfnScalingPolicy.PredefinedMetricSpecificationProperty(
                        predefined_metric_type="predefinedMetricType",
            
                        # the properties below are optional
                        resource_label="resourceLabel"
                    )
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "auto_scaling_group_name": auto_scaling_group_name,
        }
        if adjustment_type is not None:
            self._values["adjustment_type"] = adjustment_type
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if estimated_instance_warmup is not None:
            self._values["estimated_instance_warmup"] = estimated_instance_warmup
        if metric_aggregation_type is not None:
            self._values["metric_aggregation_type"] = metric_aggregation_type
        if min_adjustment_magnitude is not None:
            self._values["min_adjustment_magnitude"] = min_adjustment_magnitude
        if policy_type is not None:
            self._values["policy_type"] = policy_type
        if predictive_scaling_configuration is not None:
            self._values["predictive_scaling_configuration"] = predictive_scaling_configuration
        if scaling_adjustment is not None:
            self._values["scaling_adjustment"] = scaling_adjustment
        if step_adjustments is not None:
            self._values["step_adjustments"] = step_adjustments
        if target_tracking_configuration is not None:
            self._values["target_tracking_configuration"] = target_tracking_configuration

    @builtins.property
    def auto_scaling_group_name(self) -> builtins.str:
        '''The name of the Auto Scaling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-autoscalinggroupname
        '''
        result = self._values.get("auto_scaling_group_name")
        assert result is not None, "Required property 'auto_scaling_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def adjustment_type(self) -> typing.Optional[builtins.str]:
        '''Specifies how the scaling adjustment is interpreted. The valid values are ``ChangeInCapacity`` , ``ExactCapacity`` , and ``PercentChangeInCapacity`` .

        Required if the policy type is ``StepScaling`` or ``SimpleScaling`` . For more information, see `Scaling adjustment types <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html#as-scaling-adjustment>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-adjustmenttype
        '''
        result = self._values.get("adjustment_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cooldown(self) -> typing.Optional[builtins.str]:
        '''The duration of the policy's cooldown period, in seconds.

        When a cooldown period is specified here, it overrides the default cooldown period defined for the Auto Scaling group.

        Valid only if the policy type is ``SimpleScaling`` . For more information, see `Scaling cooldowns for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-cooldown
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def estimated_instance_warmup(self) -> typing.Optional[jsii.Number]:
        '''The estimated time, in seconds, until a newly launched instance can contribute to the CloudWatch metrics.

        If not provided, the default is to use the value from the default cooldown period for the Auto Scaling group.

        Valid only if the policy type is ``TargetTrackingScaling`` or ``StepScaling`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-estimatedinstancewarmup
        '''
        result = self._values.get("estimated_instance_warmup")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def metric_aggregation_type(self) -> typing.Optional[builtins.str]:
        '''The aggregation type for the CloudWatch metrics.

        The valid values are ``Minimum`` , ``Maximum`` , and ``Average`` . If the aggregation type is null, the value is treated as ``Average`` .

        Valid only if the policy type is ``StepScaling`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-metricaggregationtype
        '''
        result = self._values.get("metric_aggregation_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def min_adjustment_magnitude(self) -> typing.Optional[jsii.Number]:
        '''The minimum value to scale by when the adjustment type is ``PercentChangeInCapacity`` .

        For example, suppose that you create a step scaling policy to scale out an Auto Scaling group by 25 percent and you specify a ``MinAdjustmentMagnitude`` of 2. If the group has 4 instances and the scaling policy is performed, 25 percent of 4 is 1. However, because you specified a ``MinAdjustmentMagnitude`` of 2, Amazon EC2 Auto Scaling scales out the group by 2 instances.

        Valid only if the policy type is ``StepScaling`` or ``SimpleScaling`` . For more information, see `Scaling adjustment types <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html#as-scaling-adjustment>`_ in the *Amazon EC2 Auto Scaling User Guide* .
        .. epigraph::

           Some Auto Scaling groups use instance weights. In this case, set the ``MinAdjustmentMagnitude`` to a value that is at least as large as your largest instance weight.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-minadjustmentmagnitude
        '''
        result = self._values.get("min_adjustment_magnitude")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def policy_type(self) -> typing.Optional[builtins.str]:
        '''One of the following policy types:.

        - ``TargetTrackingScaling``
        - ``StepScaling``
        - ``SimpleScaling`` (default)
        - ``PredictiveScaling``

        For more information, see `Target tracking scaling policies <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-target-tracking.html>`_ and `Step and simple scaling policies <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-scaling-simple-step.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-policytype
        '''
        result = self._values.get("policy_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def predictive_scaling_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnScalingPolicy.PredictiveScalingConfigurationProperty, _IResolvable_da3f097b]]:
        '''A predictive scaling policy.

        Includes support for predefined metrics only.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-autoscaling-scalingpolicy-predictivescalingconfiguration
        '''
        result = self._values.get("predictive_scaling_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnScalingPolicy.PredictiveScalingConfigurationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def scaling_adjustment(self) -> typing.Optional[jsii.Number]:
        '''The amount by which to scale, based on the specified adjustment type.

        A positive value adds to the current capacity while a negative number removes from the current capacity. For exact capacity, you must specify a positive value.

        Required if the policy type is ``SimpleScaling`` . (Not used with any other policy type.)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-scalingadjustment
        '''
        result = self._values.get("scaling_adjustment")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def step_adjustments(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnScalingPolicy.StepAdjustmentProperty, _IResolvable_da3f097b]]]]:
        '''A set of adjustments that enable you to scale based on the size of the alarm breach.

        Required if the policy type is ``StepScaling`` . (Not used with any other policy type.)

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-as-scalingpolicy-stepadjustments
        '''
        result = self._values.get("step_adjustments")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnScalingPolicy.StepAdjustmentProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def target_tracking_configuration(
        self,
    ) -> typing.Optional[typing.Union[CfnScalingPolicy.TargetTrackingConfigurationProperty, _IResolvable_da3f097b]]:
        '''A target tracking scaling policy. Includes support for predefined or customized metrics.

        The following predefined metrics are available:

        - ``ASGAverageCPUUtilization``
        - ``ASGAverageNetworkIn``
        - ``ASGAverageNetworkOut``
        - ``ALBRequestCountPerTarget``

        If you specify ``ALBRequestCountPerTarget`` for the metric, you must specify the ``ResourceLabel`` property with the ``PredefinedMetricSpecification`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-policy.html#cfn-autoscaling-scalingpolicy-targettrackingconfiguration
        '''
        result = self._values.get("target_tracking_configuration")
        return typing.cast(typing.Optional[typing.Union[CfnScalingPolicy.TargetTrackingConfigurationProperty, _IResolvable_da3f097b]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnScalingPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnScheduledAction(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnScheduledAction",
):
    '''A CloudFormation ``AWS::AutoScaling::ScheduledAction``.

    The ``AWS::AutoScaling::ScheduledAction`` resource specifies an Amazon EC2 Auto Scaling scheduled action so that the Auto Scaling group can change the number of instances available for your application in response to predictable load changes.

    When you update a stack with an Auto Scaling group and scheduled action, CloudFormation always sets the min size, max size, and desired capacity properties of your group to the values that are defined in the ``AWS::AutoScaling::AutoScalingGroup`` section of your template. However, you might not want CloudFormation to do that when you have a scheduled action in effect. You can use an `UpdatePolicy attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html>`_ to prevent CloudFormation from changing the min size, max size, or desired capacity property values during a stack update unless you modified the individual values in your template. If you have rolling updates enabled, before you can update the Auto Scaling group, you must suspend scheduled actions by specifying an `UpdatePolicy attribute <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatepolicy.html>`_ for the Auto Scaling group. You can find a sample update policy for rolling updates in `Auto scaling template snippets <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-autoscaling.html>`_ .

    For more information, see `Scheduled scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/schedule_time.html>`_ and `Suspending and resuming scaling processes <https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-suspend-resume-processes.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

    :cloudformationResource: AWS::AutoScaling::ScheduledAction
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_autoscaling as autoscaling
        
        cfn_scheduled_action = autoscaling.CfnScheduledAction(self, "MyCfnScheduledAction",
            auto_scaling_group_name="autoScalingGroupName",
        
            # the properties below are optional
            desired_capacity=123,
            end_time="endTime",
            max_size=123,
            min_size=123,
            recurrence="recurrence",
            start_time="startTime",
            time_zone="timeZone"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        auto_scaling_group_name: builtins.str,
        desired_capacity: typing.Optional[jsii.Number] = None,
        end_time: typing.Optional[builtins.str] = None,
        max_size: typing.Optional[jsii.Number] = None,
        min_size: typing.Optional[jsii.Number] = None,
        recurrence: typing.Optional[builtins.str] = None,
        start_time: typing.Optional[builtins.str] = None,
        time_zone: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::AutoScaling::ScheduledAction``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param auto_scaling_group_name: The name of the Auto Scaling group.
        :param desired_capacity: The desired capacity is the initial capacity of the Auto Scaling group after the scheduled action runs and the capacity it attempts to maintain. It can scale beyond this capacity if you add more scaling conditions. You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .
        :param end_time: The date and time for the recurring schedule to end, in UTC. For example, ``"2021-06-01T00:00:00Z"`` .
        :param max_size: The maximum size of the Auto Scaling group. You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .
        :param min_size: The minimum size of the Auto Scaling group. You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .
        :param recurrence: The recurring schedule for this action. This format consists of five fields separated by white spaces: [Minute] [Hour] [Day_of_Month] [Month_of_Year] [Day_of_Week]. For more information about this format, see `Crontab <https://docs.aws.amazon.com/http://crontab.org>`_ . When ``StartTime`` and ``EndTime`` are specified with ``Recurrence`` , they form the boundaries of when the recurring action starts and stops. Cron expressions use Universal Coordinated Time (UTC) by default.
        :param start_time: The date and time for this action to start, in YYYY-MM-DDThh:mm:ssZ format in UTC/GMT only. For example, ``"2021-06-01T00:00:00Z"`` . If you specify ``Recurrence`` and ``StartTime`` , Amazon EC2 Auto Scaling performs the action at this time, and then performs the action based on the specified recurrence.
        :param time_zone: Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default. Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as ``Etc/GMT+9`` or ``Pacific/Tahiti`` ). For more information, see `https://en.wikipedia.org/wiki/List_of_tz_database_time_zones <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/List_of_tz_database_time_zones>`_ .
        '''
        props = CfnScheduledActionProps(
            auto_scaling_group_name=auto_scaling_group_name,
            desired_capacity=desired_capacity,
            end_time=end_time,
            max_size=max_size,
            min_size=min_size,
            recurrence=recurrence,
            start_time=start_time,
            time_zone=time_zone,
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
    @jsii.member(jsii_name="autoScalingGroupName")
    def auto_scaling_group_name(self) -> builtins.str:
        '''The name of the Auto Scaling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-asgname
        '''
        return typing.cast(builtins.str, jsii.get(self, "autoScalingGroupName"))

    @auto_scaling_group_name.setter
    def auto_scaling_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "autoScalingGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="desiredCapacity")
    def desired_capacity(self) -> typing.Optional[jsii.Number]:
        '''The desired capacity is the initial capacity of the Auto Scaling group after the scheduled action runs and the capacity it attempts to maintain.

        It can scale beyond this capacity if you add more scaling conditions.

        You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-desiredcapacity
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "desiredCapacity"))

    @desired_capacity.setter
    def desired_capacity(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "desiredCapacity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="endTime")
    def end_time(self) -> typing.Optional[builtins.str]:
        '''The date and time for the recurring schedule to end, in UTC.

        For example, ``"2021-06-01T00:00:00Z"`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-endtime
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "endTime"))

    @end_time.setter
    def end_time(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "endTime", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxSize")
    def max_size(self) -> typing.Optional[jsii.Number]:
        '''The maximum size of the Auto Scaling group.

        You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-maxsize
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maxSize"))

    @max_size.setter
    def max_size(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maxSize", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="minSize")
    def min_size(self) -> typing.Optional[jsii.Number]:
        '''The minimum size of the Auto Scaling group.

        You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-minsize
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "minSize"))

    @min_size.setter
    def min_size(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "minSize", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="recurrence")
    def recurrence(self) -> typing.Optional[builtins.str]:
        '''The recurring schedule for this action.

        This format consists of five fields separated by white spaces: [Minute] [Hour] [Day_of_Month] [Month_of_Year] [Day_of_Week]. For more information about this format, see `Crontab <https://docs.aws.amazon.com/http://crontab.org>`_ .

        When ``StartTime`` and ``EndTime`` are specified with ``Recurrence`` , they form the boundaries of when the recurring action starts and stops.

        Cron expressions use Universal Coordinated Time (UTC) by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-recurrence
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "recurrence"))

    @recurrence.setter
    def recurrence(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "recurrence", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="startTime")
    def start_time(self) -> typing.Optional[builtins.str]:
        '''The date and time for this action to start, in YYYY-MM-DDThh:mm:ssZ format in UTC/GMT only. For example, ``"2021-06-01T00:00:00Z"`` .

        If you specify ``Recurrence`` and ``StartTime`` , Amazon EC2 Auto Scaling performs the action at this time, and then performs the action based on the specified recurrence.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-starttime
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "startTime"))

    @start_time.setter
    def start_time(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "startTime", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="timeZone")
    def time_zone(self) -> typing.Optional[builtins.str]:
        '''Specifies the time zone for a cron expression.

        If a time zone is not provided, UTC is used by default.

        Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as ``Etc/GMT+9`` or ``Pacific/Tahiti`` ). For more information, see `https://en.wikipedia.org/wiki/List_of_tz_database_time_zones <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/List_of_tz_database_time_zones>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-timezone
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "timeZone"))

    @time_zone.setter
    def time_zone(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "timeZone", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnScheduledActionProps",
    jsii_struct_bases=[],
    name_mapping={
        "auto_scaling_group_name": "autoScalingGroupName",
        "desired_capacity": "desiredCapacity",
        "end_time": "endTime",
        "max_size": "maxSize",
        "min_size": "minSize",
        "recurrence": "recurrence",
        "start_time": "startTime",
        "time_zone": "timeZone",
    },
)
class CfnScheduledActionProps:
    def __init__(
        self,
        *,
        auto_scaling_group_name: builtins.str,
        desired_capacity: typing.Optional[jsii.Number] = None,
        end_time: typing.Optional[builtins.str] = None,
        max_size: typing.Optional[jsii.Number] = None,
        min_size: typing.Optional[jsii.Number] = None,
        recurrence: typing.Optional[builtins.str] = None,
        start_time: typing.Optional[builtins.str] = None,
        time_zone: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnScheduledAction``.

        :param auto_scaling_group_name: The name of the Auto Scaling group.
        :param desired_capacity: The desired capacity is the initial capacity of the Auto Scaling group after the scheduled action runs and the capacity it attempts to maintain. It can scale beyond this capacity if you add more scaling conditions. You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .
        :param end_time: The date and time for the recurring schedule to end, in UTC. For example, ``"2021-06-01T00:00:00Z"`` .
        :param max_size: The maximum size of the Auto Scaling group. You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .
        :param min_size: The minimum size of the Auto Scaling group. You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .
        :param recurrence: The recurring schedule for this action. This format consists of five fields separated by white spaces: [Minute] [Hour] [Day_of_Month] [Month_of_Year] [Day_of_Week]. For more information about this format, see `Crontab <https://docs.aws.amazon.com/http://crontab.org>`_ . When ``StartTime`` and ``EndTime`` are specified with ``Recurrence`` , they form the boundaries of when the recurring action starts and stops. Cron expressions use Universal Coordinated Time (UTC) by default.
        :param start_time: The date and time for this action to start, in YYYY-MM-DDThh:mm:ssZ format in UTC/GMT only. For example, ``"2021-06-01T00:00:00Z"`` . If you specify ``Recurrence`` and ``StartTime`` , Amazon EC2 Auto Scaling performs the action at this time, and then performs the action based on the specified recurrence.
        :param time_zone: Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default. Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as ``Etc/GMT+9`` or ``Pacific/Tahiti`` ). For more information, see `https://en.wikipedia.org/wiki/List_of_tz_database_time_zones <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/List_of_tz_database_time_zones>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            cfn_scheduled_action_props = autoscaling.CfnScheduledActionProps(
                auto_scaling_group_name="autoScalingGroupName",
            
                # the properties below are optional
                desired_capacity=123,
                end_time="endTime",
                max_size=123,
                min_size=123,
                recurrence="recurrence",
                start_time="startTime",
                time_zone="timeZone"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "auto_scaling_group_name": auto_scaling_group_name,
        }
        if desired_capacity is not None:
            self._values["desired_capacity"] = desired_capacity
        if end_time is not None:
            self._values["end_time"] = end_time
        if max_size is not None:
            self._values["max_size"] = max_size
        if min_size is not None:
            self._values["min_size"] = min_size
        if recurrence is not None:
            self._values["recurrence"] = recurrence
        if start_time is not None:
            self._values["start_time"] = start_time
        if time_zone is not None:
            self._values["time_zone"] = time_zone

    @builtins.property
    def auto_scaling_group_name(self) -> builtins.str:
        '''The name of the Auto Scaling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-asgname
        '''
        result = self._values.get("auto_scaling_group_name")
        assert result is not None, "Required property 'auto_scaling_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def desired_capacity(self) -> typing.Optional[jsii.Number]:
        '''The desired capacity is the initial capacity of the Auto Scaling group after the scheduled action runs and the capacity it attempts to maintain.

        It can scale beyond this capacity if you add more scaling conditions.

        You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-desiredcapacity
        '''
        result = self._values.get("desired_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def end_time(self) -> typing.Optional[builtins.str]:
        '''The date and time for the recurring schedule to end, in UTC.

        For example, ``"2021-06-01T00:00:00Z"`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-endtime
        '''
        result = self._values.get("end_time")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def max_size(self) -> typing.Optional[jsii.Number]:
        '''The maximum size of the Auto Scaling group.

        You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-maxsize
        '''
        result = self._values.get("max_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_size(self) -> typing.Optional[jsii.Number]:
        '''The minimum size of the Auto Scaling group.

        You must specify at least one of the following properties: ``MaxSize`` , ``MinSize`` , or ``DesiredCapacity`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-minsize
        '''
        result = self._values.get("min_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def recurrence(self) -> typing.Optional[builtins.str]:
        '''The recurring schedule for this action.

        This format consists of five fields separated by white spaces: [Minute] [Hour] [Day_of_Month] [Month_of_Year] [Day_of_Week]. For more information about this format, see `Crontab <https://docs.aws.amazon.com/http://crontab.org>`_ .

        When ``StartTime`` and ``EndTime`` are specified with ``Recurrence`` , they form the boundaries of when the recurring action starts and stops.

        Cron expressions use Universal Coordinated Time (UTC) by default.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-recurrence
        '''
        result = self._values.get("recurrence")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def start_time(self) -> typing.Optional[builtins.str]:
        '''The date and time for this action to start, in YYYY-MM-DDThh:mm:ssZ format in UTC/GMT only. For example, ``"2021-06-01T00:00:00Z"`` .

        If you specify ``Recurrence`` and ``StartTime`` , Amazon EC2 Auto Scaling performs the action at this time, and then performs the action based on the specified recurrence.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-starttime
        '''
        result = self._values.get("start_time")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def time_zone(self) -> typing.Optional[builtins.str]:
        '''Specifies the time zone for a cron expression.

        If a time zone is not provided, UTC is used by default.

        Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as ``Etc/GMT+9`` or ``Pacific/Tahiti`` ). For more information, see `https://en.wikipedia.org/wiki/List_of_tz_database_time_zones <https://docs.aws.amazon.com/https://en.wikipedia.org/wiki/List_of_tz_database_time_zones>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-as-scheduledaction.html#cfn-as-scheduledaction-timezone
        '''
        result = self._values.get("time_zone")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnScheduledActionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnWarmPool(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnWarmPool",
):
    '''A CloudFormation ``AWS::AutoScaling::WarmPool``.

    The ``AWS::AutoScaling::WarmPool`` resource creates a pool of pre-initialized EC2 instances that sits alongside the Auto Scaling group. Whenever your application needs to scale out, the Auto Scaling group can draw on the warm pool to meet its new desired capacity.

    When you create a warm pool, you can define a minimum size. When your Auto Scaling group scales out and the size of the warm pool shrinks, Amazon EC2 Auto Scaling launches new instances into the warm pool to maintain its minimum size.

    For more information, see `Warm pools for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-warm-pools.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .
    .. epigraph::

       CloudFormation supports the ``UpdatePolicy`` attribute for Auto Scaling groups. During an update, if ``UpdatePolicy`` is set to ``AutoScalingRollingUpdate`` , CloudFormation replaces ``InService`` instances only. Instances in the warm pool are not replaced. The difference in which instances are replaced can potentially result in different instance configurations after the stack update completes. If ``UpdatePolicy`` is set to ``AutoScalingReplacingUpdate`` , you do not encounter this issue because CloudFormation replaces both the Auto Scaling group and the warm pool.

    :cloudformationResource: AWS::AutoScaling::WarmPool
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_autoscaling as autoscaling
        
        cfn_warm_pool = autoscaling.CfnWarmPool(self, "MyCfnWarmPool",
            auto_scaling_group_name="autoScalingGroupName",
        
            # the properties below are optional
            instance_reuse_policy=autoscaling.CfnWarmPool.InstanceReusePolicyProperty(
                reuse_on_scale_in=False
            ),
            max_group_prepared_capacity=123,
            min_size=123,
            pool_state="poolState"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        auto_scaling_group_name: builtins.str,
        instance_reuse_policy: typing.Optional[typing.Union["CfnWarmPool.InstanceReusePolicyProperty", _IResolvable_da3f097b]] = None,
        max_group_prepared_capacity: typing.Optional[jsii.Number] = None,
        min_size: typing.Optional[jsii.Number] = None,
        pool_state: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::AutoScaling::WarmPool``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param auto_scaling_group_name: The name of the Auto Scaling group.
        :param instance_reuse_policy: Indicates whether instances in the Auto Scaling group can be returned to the warm pool on scale in. The default is to terminate instances in the Auto Scaling group when the group scales in.
        :param max_group_prepared_capacity: Specifies the maximum number of instances that are allowed to be in the warm pool or in any state except ``Terminated`` for the Auto Scaling group. This is an optional property. Specify it only if you do not want the warm pool size to be determined by the difference between the group's maximum capacity and its desired capacity. .. epigraph:: If a value for ``MaxGroupPreparedCapacity`` is not specified, Amazon EC2 Auto Scaling launches and maintains the difference between the group's maximum capacity and its desired capacity. If you specify a value for ``MaxGroupPreparedCapacity`` , Amazon EC2 Auto Scaling uses the difference between the ``MaxGroupPreparedCapacity`` and the desired capacity instead. The size of the warm pool is dynamic. Only when ``MaxGroupPreparedCapacity`` and ``MinSize`` are set to the same value does the warm pool have an absolute size. If the desired capacity of the Auto Scaling group is higher than the ``MaxGroupPreparedCapacity`` , the capacity of the warm pool is 0, unless you specify a value for ``MinSize`` . To remove a value that you previously set, include the property but specify -1 for the value.
        :param min_size: Specifies the minimum number of instances to maintain in the warm pool. This helps you to ensure that there is always a certain number of warmed instances available to handle traffic spikes. Defaults to 0 if not specified.
        :param pool_state: Sets the instance state to transition to after the lifecycle actions are complete. Default is ``Stopped`` .
        '''
        props = CfnWarmPoolProps(
            auto_scaling_group_name=auto_scaling_group_name,
            instance_reuse_policy=instance_reuse_policy,
            max_group_prepared_capacity=max_group_prepared_capacity,
            min_size=min_size,
            pool_state=pool_state,
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
    @jsii.member(jsii_name="autoScalingGroupName")
    def auto_scaling_group_name(self) -> builtins.str:
        '''The name of the Auto Scaling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html#cfn-autoscaling-warmpool-autoscalinggroupname
        '''
        return typing.cast(builtins.str, jsii.get(self, "autoScalingGroupName"))

    @auto_scaling_group_name.setter
    def auto_scaling_group_name(self, value: builtins.str) -> None:
        jsii.set(self, "autoScalingGroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceReusePolicy")
    def instance_reuse_policy(
        self,
    ) -> typing.Optional[typing.Union["CfnWarmPool.InstanceReusePolicyProperty", _IResolvable_da3f097b]]:
        '''Indicates whether instances in the Auto Scaling group can be returned to the warm pool on scale in.

        The default is to terminate instances in the Auto Scaling group when the group scales in.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html#cfn-autoscaling-warmpool-instancereusepolicy
        '''
        return typing.cast(typing.Optional[typing.Union["CfnWarmPool.InstanceReusePolicyProperty", _IResolvable_da3f097b]], jsii.get(self, "instanceReusePolicy"))

    @instance_reuse_policy.setter
    def instance_reuse_policy(
        self,
        value: typing.Optional[typing.Union["CfnWarmPool.InstanceReusePolicyProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "instanceReusePolicy", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxGroupPreparedCapacity")
    def max_group_prepared_capacity(self) -> typing.Optional[jsii.Number]:
        '''Specifies the maximum number of instances that are allowed to be in the warm pool or in any state except ``Terminated`` for the Auto Scaling group.

        This is an optional property. Specify it only if you do not want the warm pool size to be determined by the difference between the group's maximum capacity and its desired capacity.
        .. epigraph::

           If a value for ``MaxGroupPreparedCapacity`` is not specified, Amazon EC2 Auto Scaling launches and maintains the difference between the group's maximum capacity and its desired capacity. If you specify a value for ``MaxGroupPreparedCapacity`` , Amazon EC2 Auto Scaling uses the difference between the ``MaxGroupPreparedCapacity`` and the desired capacity instead.

           The size of the warm pool is dynamic. Only when ``MaxGroupPreparedCapacity`` and ``MinSize`` are set to the same value does the warm pool have an absolute size.

        If the desired capacity of the Auto Scaling group is higher than the ``MaxGroupPreparedCapacity`` , the capacity of the warm pool is 0, unless you specify a value for ``MinSize`` . To remove a value that you previously set, include the property but specify -1 for the value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html#cfn-autoscaling-warmpool-maxgrouppreparedcapacity
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "maxGroupPreparedCapacity"))

    @max_group_prepared_capacity.setter
    def max_group_prepared_capacity(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "maxGroupPreparedCapacity", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="minSize")
    def min_size(self) -> typing.Optional[jsii.Number]:
        '''Specifies the minimum number of instances to maintain in the warm pool.

        This helps you to ensure that there is always a certain number of warmed instances available to handle traffic spikes. Defaults to 0 if not specified.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html#cfn-autoscaling-warmpool-minsize
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "minSize"))

    @min_size.setter
    def min_size(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "minSize", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="poolState")
    def pool_state(self) -> typing.Optional[builtins.str]:
        '''Sets the instance state to transition to after the lifecycle actions are complete.

        Default is ``Stopped`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html#cfn-autoscaling-warmpool-poolstate
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "poolState"))

    @pool_state.setter
    def pool_state(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "poolState", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_autoscaling.CfnWarmPool.InstanceReusePolicyProperty",
        jsii_struct_bases=[],
        name_mapping={"reuse_on_scale_in": "reuseOnScaleIn"},
    )
    class InstanceReusePolicyProperty:
        def __init__(
            self,
            *,
            reuse_on_scale_in: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        ) -> None:
            '''A structure that specifies an instance reuse policy for the ``InstanceReusePolicy`` property of the `AWS::AutoScaling::WarmPool <https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html>`_ resource type.

            For more information, see `Warm pools for Amazon EC2 Auto Scaling <https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-warm-pools.html>`_ in the *Amazon EC2 Auto Scaling User Guide* .

            :param reuse_on_scale_in: Specifies whether instances in the Auto Scaling group can be returned to the warm pool on scale in.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-warmpool-instancereusepolicy.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_autoscaling as autoscaling
                
                instance_reuse_policy_property = autoscaling.CfnWarmPool.InstanceReusePolicyProperty(
                    reuse_on_scale_in=False
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if reuse_on_scale_in is not None:
                self._values["reuse_on_scale_in"] = reuse_on_scale_in

        @builtins.property
        def reuse_on_scale_in(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Specifies whether instances in the Auto Scaling group can be returned to the warm pool on scale in.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-autoscaling-warmpool-instancereusepolicy.html#cfn-autoscaling-warmpool-instancereusepolicy-reuseonscalein
            '''
            result = self._values.get("reuse_on_scale_in")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "InstanceReusePolicyProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.CfnWarmPoolProps",
    jsii_struct_bases=[],
    name_mapping={
        "auto_scaling_group_name": "autoScalingGroupName",
        "instance_reuse_policy": "instanceReusePolicy",
        "max_group_prepared_capacity": "maxGroupPreparedCapacity",
        "min_size": "minSize",
        "pool_state": "poolState",
    },
)
class CfnWarmPoolProps:
    def __init__(
        self,
        *,
        auto_scaling_group_name: builtins.str,
        instance_reuse_policy: typing.Optional[typing.Union[CfnWarmPool.InstanceReusePolicyProperty, _IResolvable_da3f097b]] = None,
        max_group_prepared_capacity: typing.Optional[jsii.Number] = None,
        min_size: typing.Optional[jsii.Number] = None,
        pool_state: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnWarmPool``.

        :param auto_scaling_group_name: The name of the Auto Scaling group.
        :param instance_reuse_policy: Indicates whether instances in the Auto Scaling group can be returned to the warm pool on scale in. The default is to terminate instances in the Auto Scaling group when the group scales in.
        :param max_group_prepared_capacity: Specifies the maximum number of instances that are allowed to be in the warm pool or in any state except ``Terminated`` for the Auto Scaling group. This is an optional property. Specify it only if you do not want the warm pool size to be determined by the difference between the group's maximum capacity and its desired capacity. .. epigraph:: If a value for ``MaxGroupPreparedCapacity`` is not specified, Amazon EC2 Auto Scaling launches and maintains the difference between the group's maximum capacity and its desired capacity. If you specify a value for ``MaxGroupPreparedCapacity`` , Amazon EC2 Auto Scaling uses the difference between the ``MaxGroupPreparedCapacity`` and the desired capacity instead. The size of the warm pool is dynamic. Only when ``MaxGroupPreparedCapacity`` and ``MinSize`` are set to the same value does the warm pool have an absolute size. If the desired capacity of the Auto Scaling group is higher than the ``MaxGroupPreparedCapacity`` , the capacity of the warm pool is 0, unless you specify a value for ``MinSize`` . To remove a value that you previously set, include the property but specify -1 for the value.
        :param min_size: Specifies the minimum number of instances to maintain in the warm pool. This helps you to ensure that there is always a certain number of warmed instances available to handle traffic spikes. Defaults to 0 if not specified.
        :param pool_state: Sets the instance state to transition to after the lifecycle actions are complete. Default is ``Stopped`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            cfn_warm_pool_props = autoscaling.CfnWarmPoolProps(
                auto_scaling_group_name="autoScalingGroupName",
            
                # the properties below are optional
                instance_reuse_policy=autoscaling.CfnWarmPool.InstanceReusePolicyProperty(
                    reuse_on_scale_in=False
                ),
                max_group_prepared_capacity=123,
                min_size=123,
                pool_state="poolState"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "auto_scaling_group_name": auto_scaling_group_name,
        }
        if instance_reuse_policy is not None:
            self._values["instance_reuse_policy"] = instance_reuse_policy
        if max_group_prepared_capacity is not None:
            self._values["max_group_prepared_capacity"] = max_group_prepared_capacity
        if min_size is not None:
            self._values["min_size"] = min_size
        if pool_state is not None:
            self._values["pool_state"] = pool_state

    @builtins.property
    def auto_scaling_group_name(self) -> builtins.str:
        '''The name of the Auto Scaling group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html#cfn-autoscaling-warmpool-autoscalinggroupname
        '''
        result = self._values.get("auto_scaling_group_name")
        assert result is not None, "Required property 'auto_scaling_group_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def instance_reuse_policy(
        self,
    ) -> typing.Optional[typing.Union[CfnWarmPool.InstanceReusePolicyProperty, _IResolvable_da3f097b]]:
        '''Indicates whether instances in the Auto Scaling group can be returned to the warm pool on scale in.

        The default is to terminate instances in the Auto Scaling group when the group scales in.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html#cfn-autoscaling-warmpool-instancereusepolicy
        '''
        result = self._values.get("instance_reuse_policy")
        return typing.cast(typing.Optional[typing.Union[CfnWarmPool.InstanceReusePolicyProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def max_group_prepared_capacity(self) -> typing.Optional[jsii.Number]:
        '''Specifies the maximum number of instances that are allowed to be in the warm pool or in any state except ``Terminated`` for the Auto Scaling group.

        This is an optional property. Specify it only if you do not want the warm pool size to be determined by the difference between the group's maximum capacity and its desired capacity.
        .. epigraph::

           If a value for ``MaxGroupPreparedCapacity`` is not specified, Amazon EC2 Auto Scaling launches and maintains the difference between the group's maximum capacity and its desired capacity. If you specify a value for ``MaxGroupPreparedCapacity`` , Amazon EC2 Auto Scaling uses the difference between the ``MaxGroupPreparedCapacity`` and the desired capacity instead.

           The size of the warm pool is dynamic. Only when ``MaxGroupPreparedCapacity`` and ``MinSize`` are set to the same value does the warm pool have an absolute size.

        If the desired capacity of the Auto Scaling group is higher than the ``MaxGroupPreparedCapacity`` , the capacity of the warm pool is 0, unless you specify a value for ``MinSize`` . To remove a value that you previously set, include the property but specify -1 for the value.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html#cfn-autoscaling-warmpool-maxgrouppreparedcapacity
        '''
        result = self._values.get("max_group_prepared_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_size(self) -> typing.Optional[jsii.Number]:
        '''Specifies the minimum number of instances to maintain in the warm pool.

        This helps you to ensure that there is always a certain number of warmed instances available to handle traffic spikes. Defaults to 0 if not specified.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html#cfn-autoscaling-warmpool-minsize
        '''
        result = self._values.get("min_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def pool_state(self) -> typing.Optional[builtins.str]:
        '''Sets the instance state to transition to after the lifecycle actions are complete.

        Default is ``Stopped`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-autoscaling-warmpool.html#cfn-autoscaling-warmpool-poolstate
        '''
        result = self._values.get("pool_state")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnWarmPoolProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.CommonAutoScalingGroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "allow_all_outbound": "allowAllOutbound",
        "associate_public_ip_address": "associatePublicIpAddress",
        "auto_scaling_group_name": "autoScalingGroupName",
        "block_devices": "blockDevices",
        "cooldown": "cooldown",
        "desired_capacity": "desiredCapacity",
        "group_metrics": "groupMetrics",
        "health_check": "healthCheck",
        "ignore_unmodified_size_properties": "ignoreUnmodifiedSizeProperties",
        "instance_monitoring": "instanceMonitoring",
        "key_name": "keyName",
        "max_capacity": "maxCapacity",
        "max_instance_lifetime": "maxInstanceLifetime",
        "min_capacity": "minCapacity",
        "new_instances_protected_from_scale_in": "newInstancesProtectedFromScaleIn",
        "notifications": "notifications",
        "signals": "signals",
        "spot_price": "spotPrice",
        "termination_policies": "terminationPolicies",
        "update_policy": "updatePolicy",
        "vpc_subnets": "vpcSubnets",
    },
)
class CommonAutoScalingGroupProps:
    def __init__(
        self,
        *,
        allow_all_outbound: typing.Optional[builtins.bool] = None,
        associate_public_ip_address: typing.Optional[builtins.bool] = None,
        auto_scaling_group_name: typing.Optional[builtins.str] = None,
        block_devices: typing.Optional[typing.Sequence[BlockDevice]] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        desired_capacity: typing.Optional[jsii.Number] = None,
        group_metrics: typing.Optional[typing.Sequence["GroupMetrics"]] = None,
        health_check: typing.Optional["HealthCheck"] = None,
        ignore_unmodified_size_properties: typing.Optional[builtins.bool] = None,
        instance_monitoring: typing.Optional["Monitoring"] = None,
        key_name: typing.Optional[builtins.str] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        max_instance_lifetime: typing.Optional[_Duration_4839e8c3] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
        new_instances_protected_from_scale_in: typing.Optional[builtins.bool] = None,
        notifications: typing.Optional[typing.Sequence["NotificationConfiguration"]] = None,
        signals: typing.Optional["Signals"] = None,
        spot_price: typing.Optional[builtins.str] = None,
        termination_policies: typing.Optional[typing.Sequence["TerminationPolicy"]] = None,
        update_policy: typing.Optional["UpdatePolicy"] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> None:
        '''Basic properties of an AutoScalingGroup, except the exact machines to run and where they should run.

        Constructs that want to create AutoScalingGroups can inherit
        this interface and specialize the essential parts in various ways.

        :param allow_all_outbound: Whether the instances can initiate connections to anywhere by default. Default: true
        :param associate_public_ip_address: Whether instances in the Auto Scaling Group should have public IP addresses associated with them. Default: - Use subnet setting.
        :param auto_scaling_group_name: The name of the Auto Scaling group. This name must be unique per Region per account. Default: - Auto generated by CloudFormation
        :param block_devices: Specifies how block devices are exposed to the instance. You can specify virtual devices and EBS volumes. Each instance that is launched has an associated root device volume, either an Amazon EBS volume or an instance store volume. You can use block device mappings to specify additional EBS volumes or instance store volumes to attach to an instance when it is launched. Default: - Uses the block device mapping of the AMI
        :param cooldown: Default scaling cooldown for this AutoScalingGroup. Default: Duration.minutes(5)
        :param desired_capacity: Initial amount of instances in the fleet. If this is set to a number, every deployment will reset the amount of instances to this number. It is recommended to leave this value blank. Default: minCapacity, and leave unchanged during deployment
        :param group_metrics: Enable monitoring for group metrics, these metrics describe the group rather than any of its instances. To report all group metrics use ``GroupMetrics.all()`` Group metrics are reported in a granularity of 1 minute at no additional charge. Default: - no group metrics will be reported
        :param health_check: Configuration for health checks. Default: - HealthCheck.ec2 with no grace period
        :param ignore_unmodified_size_properties: If the ASG has scheduled actions, don't reset unchanged group sizes. Only used if the ASG has scheduled actions (which may scale your ASG up or down regardless of cdk deployments). If true, the size of the group will only be reset if it has been changed in the CDK app. If false, the sizes will always be changed back to what they were in the CDK app on deployment. Default: true
        :param instance_monitoring: Controls whether instances in this group are launched with detailed or basic monitoring. When detailed monitoring is enabled, Amazon CloudWatch generates metrics every minute and your account is charged a fee. When you disable detailed monitoring, CloudWatch generates metrics every 5 minutes. Default: - Monitoring.DETAILED
        :param key_name: Name of SSH keypair to grant access to instances. Default: - No SSH access will be possible.
        :param max_capacity: Maximum number of instances in the fleet. Default: desiredCapacity
        :param max_instance_lifetime: The maximum amount of time that an instance can be in service. The maximum duration applies to all current and future instances in the group. As an instance approaches its maximum duration, it is terminated and replaced, and cannot be used again. You must specify a value of at least 604,800 seconds (7 days). To clear a previously set value, leave this property undefined. Default: none
        :param min_capacity: Minimum number of instances in the fleet. Default: 1
        :param new_instances_protected_from_scale_in: Whether newly-launched instances are protected from termination by Amazon EC2 Auto Scaling when scaling in. By default, Auto Scaling can terminate an instance at any time after launch when scaling in an Auto Scaling Group, subject to the group's termination policy. However, you may wish to protect newly-launched instances from being scaled in if they are going to run critical applications that should not be prematurely terminated. This flag must be enabled if the Auto Scaling Group will be associated with an ECS Capacity Provider with managed termination protection. Default: false
        :param notifications: Configure autoscaling group to send notifications about fleet changes to an SNS topic(s). Default: - No fleet change notifications will be sent.
        :param signals: Configure waiting for signals during deployment. Use this to pause the CloudFormation deployment to wait for the instances in the AutoScalingGroup to report successful startup during creation and updates. The UserData script needs to invoke ``cfn-signal`` with a success or failure code after it is done setting up the instance. Without waiting for signals, the CloudFormation deployment will proceed as soon as the AutoScalingGroup has been created or updated but before the instances in the group have been started. For example, to have instances wait for an Elastic Load Balancing health check before they signal success, add a health-check verification by using the cfn-init helper script. For an example, see the verify_instance_health command in the Auto Scaling rolling updates sample template: https://github.com/awslabs/aws-cloudformation-templates/blob/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml Default: - Do not wait for signals
        :param spot_price: The maximum hourly price (in USD) to be paid for any Spot Instance launched to fulfill the request. Spot Instances are launched when the price you specify exceeds the current Spot market price. Default: none
        :param termination_policies: A policy or a list of policies that are used to select the instances to terminate. The policies are executed in the order that you list them. Default: - ``TerminationPolicy.DEFAULT``
        :param update_policy: What to do when an AutoScalingGroup's instance configuration is changed. This is applied when any of the settings on the ASG are changed that affect how the instances should be created (VPC, instance type, startup scripts, etc.). It indicates how the existing instances should be replaced with new instances matching the new config. By default, nothing is done and only new instances are launched with the new config. Default: - ``UpdatePolicy.rollingUpdate()`` if using ``init``, ``UpdatePolicy.none()`` otherwise
        :param vpc_subnets: Where to place instances within the VPC. Default: - All Private subnets.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_sns as sns
            
            # block_device_volume: autoscaling.BlockDeviceVolume
            # group_metrics: autoscaling.GroupMetrics
            # health_check: autoscaling.HealthCheck
            # scaling_events: autoscaling.ScalingEvents
            # signals: autoscaling.Signals
            # subnet: ec2.Subnet
            # subnet_filter: ec2.SubnetFilter
            # topic: sns.Topic
            # update_policy: autoscaling.UpdatePolicy
            
            common_auto_scaling_group_props = autoscaling.CommonAutoScalingGroupProps(
                allow_all_outbound=False,
                associate_public_ip_address=False,
                auto_scaling_group_name="autoScalingGroupName",
                block_devices=[autoscaling.BlockDevice(
                    device_name="deviceName",
                    volume=block_device_volume
                )],
                cooldown=cdk.Duration.minutes(30),
                desired_capacity=123,
                group_metrics=[group_metrics],
                health_check=health_check,
                ignore_unmodified_size_properties=False,
                instance_monitoring=autoscaling.Monitoring.BASIC,
                key_name="keyName",
                max_capacity=123,
                max_instance_lifetime=cdk.Duration.minutes(30),
                min_capacity=123,
                new_instances_protected_from_scale_in=False,
                notifications=[autoscaling.NotificationConfiguration(
                    topic=topic,
            
                    # the properties below are optional
                    scaling_events=scaling_events
                )],
                signals=signals,
                spot_price="spotPrice",
                termination_policies=[autoscaling.TerminationPolicy.ALLOCATION_STRATEGY],
                update_policy=update_policy,
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
        self._values: typing.Dict[str, typing.Any] = {}
        if allow_all_outbound is not None:
            self._values["allow_all_outbound"] = allow_all_outbound
        if associate_public_ip_address is not None:
            self._values["associate_public_ip_address"] = associate_public_ip_address
        if auto_scaling_group_name is not None:
            self._values["auto_scaling_group_name"] = auto_scaling_group_name
        if block_devices is not None:
            self._values["block_devices"] = block_devices
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if desired_capacity is not None:
            self._values["desired_capacity"] = desired_capacity
        if group_metrics is not None:
            self._values["group_metrics"] = group_metrics
        if health_check is not None:
            self._values["health_check"] = health_check
        if ignore_unmodified_size_properties is not None:
            self._values["ignore_unmodified_size_properties"] = ignore_unmodified_size_properties
        if instance_monitoring is not None:
            self._values["instance_monitoring"] = instance_monitoring
        if key_name is not None:
            self._values["key_name"] = key_name
        if max_capacity is not None:
            self._values["max_capacity"] = max_capacity
        if max_instance_lifetime is not None:
            self._values["max_instance_lifetime"] = max_instance_lifetime
        if min_capacity is not None:
            self._values["min_capacity"] = min_capacity
        if new_instances_protected_from_scale_in is not None:
            self._values["new_instances_protected_from_scale_in"] = new_instances_protected_from_scale_in
        if notifications is not None:
            self._values["notifications"] = notifications
        if signals is not None:
            self._values["signals"] = signals
        if spot_price is not None:
            self._values["spot_price"] = spot_price
        if termination_policies is not None:
            self._values["termination_policies"] = termination_policies
        if update_policy is not None:
            self._values["update_policy"] = update_policy
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets

    @builtins.property
    def allow_all_outbound(self) -> typing.Optional[builtins.bool]:
        '''Whether the instances can initiate connections to anywhere by default.

        :default: true
        '''
        result = self._values.get("allow_all_outbound")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def associate_public_ip_address(self) -> typing.Optional[builtins.bool]:
        '''Whether instances in the Auto Scaling Group should have public IP addresses associated with them.

        :default: - Use subnet setting.
        '''
        result = self._values.get("associate_public_ip_address")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def auto_scaling_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Auto Scaling group.

        This name must be unique per Region per account.

        :default: - Auto generated by CloudFormation
        '''
        result = self._values.get("auto_scaling_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def block_devices(self) -> typing.Optional[typing.List[BlockDevice]]:
        '''Specifies how block devices are exposed to the instance. You can specify virtual devices and EBS volumes.

        Each instance that is launched has an associated root device volume,
        either an Amazon EBS volume or an instance store volume.
        You can use block device mappings to specify additional EBS volumes or
        instance store volumes to attach to an instance when it is launched.

        :default: - Uses the block device mapping of the AMI

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-device-mapping-concepts.html
        '''
        result = self._values.get("block_devices")
        return typing.cast(typing.Optional[typing.List[BlockDevice]], result)

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Default scaling cooldown for this AutoScalingGroup.

        :default: Duration.minutes(5)
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def desired_capacity(self) -> typing.Optional[jsii.Number]:
        '''Initial amount of instances in the fleet.

        If this is set to a number, every deployment will reset the amount of
        instances to this number. It is recommended to leave this value blank.

        :default: minCapacity, and leave unchanged during deployment

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-desiredcapacity
        '''
        result = self._values.get("desired_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def group_metrics(self) -> typing.Optional[typing.List["GroupMetrics"]]:
        '''Enable monitoring for group metrics, these metrics describe the group rather than any of its instances.

        To report all group metrics use ``GroupMetrics.all()``
        Group metrics are reported in a granularity of 1 minute at no additional charge.

        :default: - no group metrics will be reported
        '''
        result = self._values.get("group_metrics")
        return typing.cast(typing.Optional[typing.List["GroupMetrics"]], result)

    @builtins.property
    def health_check(self) -> typing.Optional["HealthCheck"]:
        '''Configuration for health checks.

        :default: - HealthCheck.ec2 with no grace period
        '''
        result = self._values.get("health_check")
        return typing.cast(typing.Optional["HealthCheck"], result)

    @builtins.property
    def ignore_unmodified_size_properties(self) -> typing.Optional[builtins.bool]:
        '''If the ASG has scheduled actions, don't reset unchanged group sizes.

        Only used if the ASG has scheduled actions (which may scale your ASG up
        or down regardless of cdk deployments). If true, the size of the group
        will only be reset if it has been changed in the CDK app. If false, the
        sizes will always be changed back to what they were in the CDK app
        on deployment.

        :default: true
        '''
        result = self._values.get("ignore_unmodified_size_properties")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def instance_monitoring(self) -> typing.Optional["Monitoring"]:
        '''Controls whether instances in this group are launched with detailed or basic monitoring.

        When detailed monitoring is enabled, Amazon CloudWatch generates metrics every minute and your account
        is charged a fee. When you disable detailed monitoring, CloudWatch generates metrics every 5 minutes.

        :default: - Monitoring.DETAILED

        :see: https://docs.aws.amazon.com/autoscaling/latest/userguide/as-instance-monitoring.html#enable-as-instance-metrics
        '''
        result = self._values.get("instance_monitoring")
        return typing.cast(typing.Optional["Monitoring"], result)

    @builtins.property
    def key_name(self) -> typing.Optional[builtins.str]:
        '''Name of SSH keypair to grant access to instances.

        :default: - No SSH access will be possible.
        '''
        result = self._values.get("key_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def max_capacity(self) -> typing.Optional[jsii.Number]:
        '''Maximum number of instances in the fleet.

        :default: desiredCapacity
        '''
        result = self._values.get("max_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def max_instance_lifetime(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The maximum amount of time that an instance can be in service.

        The maximum duration applies
        to all current and future instances in the group. As an instance approaches its maximum duration,
        it is terminated and replaced, and cannot be used again.

        You must specify a value of at least 604,800 seconds (7 days). To clear a previously set value,
        leave this property undefined.

        :default: none

        :see: https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-max-instance-lifetime.html
        '''
        result = self._values.get("max_instance_lifetime")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def min_capacity(self) -> typing.Optional[jsii.Number]:
        '''Minimum number of instances in the fleet.

        :default: 1
        '''
        result = self._values.get("min_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def new_instances_protected_from_scale_in(self) -> typing.Optional[builtins.bool]:
        '''Whether newly-launched instances are protected from termination by Amazon EC2 Auto Scaling when scaling in.

        By default, Auto Scaling can terminate an instance at any time after launch
        when scaling in an Auto Scaling Group, subject to the group's termination
        policy. However, you may wish to protect newly-launched instances from
        being scaled in if they are going to run critical applications that should
        not be prematurely terminated.

        This flag must be enabled if the Auto Scaling Group will be associated with
        an ECS Capacity Provider with managed termination protection.

        :default: false
        '''
        result = self._values.get("new_instances_protected_from_scale_in")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def notifications(
        self,
    ) -> typing.Optional[typing.List["NotificationConfiguration"]]:
        '''Configure autoscaling group to send notifications about fleet changes to an SNS topic(s).

        :default: - No fleet change notifications will be sent.

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-notificationconfigurations
        '''
        result = self._values.get("notifications")
        return typing.cast(typing.Optional[typing.List["NotificationConfiguration"]], result)

    @builtins.property
    def signals(self) -> typing.Optional["Signals"]:
        '''Configure waiting for signals during deployment.

        Use this to pause the CloudFormation deployment to wait for the instances
        in the AutoScalingGroup to report successful startup during
        creation and updates. The UserData script needs to invoke ``cfn-signal``
        with a success or failure code after it is done setting up the instance.

        Without waiting for signals, the CloudFormation deployment will proceed as
        soon as the AutoScalingGroup has been created or updated but before the
        instances in the group have been started.

        For example, to have instances wait for an Elastic Load Balancing health check before
        they signal success, add a health-check verification by using the
        cfn-init helper script. For an example, see the verify_instance_health
        command in the Auto Scaling rolling updates sample template:

        https://github.com/awslabs/aws-cloudformation-templates/blob/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml

        :default: - Do not wait for signals
        '''
        result = self._values.get("signals")
        return typing.cast(typing.Optional["Signals"], result)

    @builtins.property
    def spot_price(self) -> typing.Optional[builtins.str]:
        '''The maximum hourly price (in USD) to be paid for any Spot Instance launched to fulfill the request.

        Spot Instances are
        launched when the price you specify exceeds the current Spot market price.

        :default: none
        '''
        result = self._values.get("spot_price")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def termination_policies(self) -> typing.Optional[typing.List["TerminationPolicy"]]:
        '''A policy or a list of policies that are used to select the instances to terminate.

        The policies are executed in the order that you list them.

        :default: - ``TerminationPolicy.DEFAULT``

        :see: https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html
        '''
        result = self._values.get("termination_policies")
        return typing.cast(typing.Optional[typing.List["TerminationPolicy"]], result)

    @builtins.property
    def update_policy(self) -> typing.Optional["UpdatePolicy"]:
        '''What to do when an AutoScalingGroup's instance configuration is changed.

        This is applied when any of the settings on the ASG are changed that
        affect how the instances should be created (VPC, instance type, startup
        scripts, etc.). It indicates how the existing instances should be
        replaced with new instances matching the new config. By default, nothing
        is done and only new instances are launched with the new config.

        :default: - ``UpdatePolicy.rollingUpdate()`` if using ``init``, ``UpdatePolicy.none()`` otherwise
        '''
        result = self._values.get("update_policy")
        return typing.cast(typing.Optional["UpdatePolicy"], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''Where to place instances within the VPC.

        :default: - All Private subnets.
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CommonAutoScalingGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.CpuUtilizationScalingProps",
    jsii_struct_bases=[BaseTargetTrackingProps],
    name_mapping={
        "cooldown": "cooldown",
        "disable_scale_in": "disableScaleIn",
        "estimated_instance_warmup": "estimatedInstanceWarmup",
        "target_utilization_percent": "targetUtilizationPercent",
    },
)
class CpuUtilizationScalingProps(BaseTargetTrackingProps):
    def __init__(
        self,
        *,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        target_utilization_percent: jsii.Number,
    ) -> None:
        '''Properties for enabling scaling based on CPU utilization.

        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        :param target_utilization_percent: Target average CPU utilization across the task.

        :exampleMetadata: infused

        Example::

            # auto_scaling_group: autoscaling.AutoScalingGroup
            
            
            auto_scaling_group.scale_on_cpu_utilization("KeepSpareCPU",
                target_utilization_percent=50
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target_utilization_percent": target_utilization_percent,
        }
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if disable_scale_in is not None:
            self._values["disable_scale_in"] = disable_scale_in
        if estimated_instance_warmup is not None:
            self._values["estimated_instance_warmup"] = estimated_instance_warmup

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Period after a scaling completes before another scaling activity can start.

        :default: - The default cooldown configured on the AutoScalingGroup.
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def disable_scale_in(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether scale in by the target tracking policy is disabled.

        If the value is true, scale in is disabled and the target tracking policy
        won't remove capacity from the autoscaling group. Otherwise, scale in is
        enabled and the target tracking policy can remove capacity from the
        group.

        :default: false
        '''
        result = self._values.get("disable_scale_in")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def estimated_instance_warmup(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Estimated time until a newly launched instance can send metrics to CloudWatch.

        :default: - Same as the cooldown.
        '''
        result = self._values.get("estimated_instance_warmup")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def target_utilization_percent(self) -> jsii.Number:
        '''Target average CPU utilization across the task.'''
        result = self._values.get("target_utilization_percent")
        assert result is not None, "Required property 'target_utilization_percent' is missing"
        return typing.cast(jsii.Number, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CpuUtilizationScalingProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.CronOptions",
    jsii_struct_bases=[],
    name_mapping={
        "day": "day",
        "hour": "hour",
        "minute": "minute",
        "month": "month",
        "week_day": "weekDay",
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
    ) -> None:
        '''Options to configure a cron expression.

        All fields are strings so you can use complex expressions. Absence of
        a field implies '*' or '?', whichever one is appropriate.

        :param day: The day of the month to run this rule at. Default: - Every day of the month
        :param hour: The hour to run this rule at. Default: - Every hour
        :param minute: The minute to run this rule at. Default: - Every minute
        :param month: The month to run this rule at. Default: - Every month
        :param week_day: The day of the week to run this rule at. Default: - Any day of the week

        :see: http://crontab.org/
        :exampleMetadata: infused

        Example::

            # auto_scaling_group: autoscaling.AutoScalingGroup
            
            
            auto_scaling_group.scale_on_schedule("PrescaleInTheMorning",
                schedule=autoscaling.Schedule.cron(hour="8", minute="0"),
                min_capacity=20
            )
            
            auto_scaling_group.scale_on_schedule("AllowDownscalingAtNight",
                schedule=autoscaling.Schedule.cron(hour="20", minute="0"),
                min_capacity=1
            )
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

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CronOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_autoscaling.DefaultResult")
class DefaultResult(enum.Enum):
    CONTINUE = "CONTINUE"
    ABANDON = "ABANDON"


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.EbsDeviceOptionsBase",
    jsii_struct_bases=[],
    name_mapping={
        "delete_on_termination": "deleteOnTermination",
        "iops": "iops",
        "volume_type": "volumeType",
    },
)
class EbsDeviceOptionsBase:
    def __init__(
        self,
        *,
        delete_on_termination: typing.Optional[builtins.bool] = None,
        iops: typing.Optional[jsii.Number] = None,
        volume_type: typing.Optional["EbsDeviceVolumeType"] = None,
    ) -> None:
        '''Base block device options for an EBS volume.

        :param delete_on_termination: Indicates whether to delete the volume when the instance is terminated. Default: - true for Amazon EC2 Auto Scaling, false otherwise (e.g. EBS)
        :param iops: The number of I/O operations per second (IOPS) to provision for the volume. Must only be set for {@link volumeType}: {@link EbsDeviceVolumeType.IO1} The maximum ratio of IOPS to volume size (in GiB) is 50:1, so for 5,000 provisioned IOPS, you need at least 100 GiB storage on the volume. Default: - none, required for {@link EbsDeviceVolumeType.IO1}
        :param volume_type: The EBS volume type. Default: {@link EbsDeviceVolumeType.GP2}

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            ebs_device_options_base = autoscaling.EbsDeviceOptionsBase(
                delete_on_termination=False,
                iops=123,
                volume_type=autoscaling.EbsDeviceVolumeType.STANDARD
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if delete_on_termination is not None:
            self._values["delete_on_termination"] = delete_on_termination
        if iops is not None:
            self._values["iops"] = iops
        if volume_type is not None:
            self._values["volume_type"] = volume_type

    @builtins.property
    def delete_on_termination(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether to delete the volume when the instance is terminated.

        :default: - true for Amazon EC2 Auto Scaling, false otherwise (e.g. EBS)
        '''
        result = self._values.get("delete_on_termination")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def iops(self) -> typing.Optional[jsii.Number]:
        '''The number of I/O operations per second (IOPS) to provision for the volume.

        Must only be set for {@link volumeType}: {@link EbsDeviceVolumeType.IO1}

        The maximum ratio of IOPS to volume size (in GiB) is 50:1, so for 5,000 provisioned IOPS,
        you need at least 100 GiB storage on the volume.

        :default: - none, required for {@link EbsDeviceVolumeType.IO1}

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html
        '''
        result = self._values.get("iops")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def volume_type(self) -> typing.Optional["EbsDeviceVolumeType"]:
        '''The EBS volume type.

        :default: {@link EbsDeviceVolumeType.GP2}

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html
        '''
        result = self._values.get("volume_type")
        return typing.cast(typing.Optional["EbsDeviceVolumeType"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EbsDeviceOptionsBase(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.EbsDeviceSnapshotOptions",
    jsii_struct_bases=[EbsDeviceOptionsBase],
    name_mapping={
        "delete_on_termination": "deleteOnTermination",
        "iops": "iops",
        "volume_type": "volumeType",
        "volume_size": "volumeSize",
    },
)
class EbsDeviceSnapshotOptions(EbsDeviceOptionsBase):
    def __init__(
        self,
        *,
        delete_on_termination: typing.Optional[builtins.bool] = None,
        iops: typing.Optional[jsii.Number] = None,
        volume_type: typing.Optional["EbsDeviceVolumeType"] = None,
        volume_size: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Block device options for an EBS volume created from a snapshot.

        :param delete_on_termination: Indicates whether to delete the volume when the instance is terminated. Default: - true for Amazon EC2 Auto Scaling, false otherwise (e.g. EBS)
        :param iops: The number of I/O operations per second (IOPS) to provision for the volume. Must only be set for {@link volumeType}: {@link EbsDeviceVolumeType.IO1} The maximum ratio of IOPS to volume size (in GiB) is 50:1, so for 5,000 provisioned IOPS, you need at least 100 GiB storage on the volume. Default: - none, required for {@link EbsDeviceVolumeType.IO1}
        :param volume_type: The EBS volume type. Default: {@link EbsDeviceVolumeType.GP2}
        :param volume_size: The volume size, in Gibibytes (GiB). If you specify volumeSize, it must be equal or greater than the size of the snapshot. Default: - The snapshot size

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            ebs_device_snapshot_options = autoscaling.EbsDeviceSnapshotOptions(
                delete_on_termination=False,
                iops=123,
                volume_size=123,
                volume_type=autoscaling.EbsDeviceVolumeType.STANDARD
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if delete_on_termination is not None:
            self._values["delete_on_termination"] = delete_on_termination
        if iops is not None:
            self._values["iops"] = iops
        if volume_type is not None:
            self._values["volume_type"] = volume_type
        if volume_size is not None:
            self._values["volume_size"] = volume_size

    @builtins.property
    def delete_on_termination(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether to delete the volume when the instance is terminated.

        :default: - true for Amazon EC2 Auto Scaling, false otherwise (e.g. EBS)
        '''
        result = self._values.get("delete_on_termination")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def iops(self) -> typing.Optional[jsii.Number]:
        '''The number of I/O operations per second (IOPS) to provision for the volume.

        Must only be set for {@link volumeType}: {@link EbsDeviceVolumeType.IO1}

        The maximum ratio of IOPS to volume size (in GiB) is 50:1, so for 5,000 provisioned IOPS,
        you need at least 100 GiB storage on the volume.

        :default: - none, required for {@link EbsDeviceVolumeType.IO1}

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html
        '''
        result = self._values.get("iops")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def volume_type(self) -> typing.Optional["EbsDeviceVolumeType"]:
        '''The EBS volume type.

        :default: {@link EbsDeviceVolumeType.GP2}

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html
        '''
        result = self._values.get("volume_type")
        return typing.cast(typing.Optional["EbsDeviceVolumeType"], result)

    @builtins.property
    def volume_size(self) -> typing.Optional[jsii.Number]:
        '''The volume size, in Gibibytes (GiB).

        If you specify volumeSize, it must be equal or greater than the size of the snapshot.

        :default: - The snapshot size
        '''
        result = self._values.get("volume_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EbsDeviceSnapshotOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_autoscaling.EbsDeviceVolumeType")
class EbsDeviceVolumeType(enum.Enum):
    '''Supported EBS volume types for blockDevices.'''

    STANDARD = "STANDARD"
    '''Magnetic.'''
    IO1 = "IO1"
    '''Provisioned IOPS SSD - IO1.'''
    GP2 = "GP2"
    '''General Purpose SSD - GP2.'''
    GP3 = "GP3"
    '''General Purpose SSD - GP3.'''
    ST1 = "ST1"
    '''Throughput Optimized HDD.'''
    SC1 = "SC1"
    '''Cold HDD.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.Ec2HealthCheckOptions",
    jsii_struct_bases=[],
    name_mapping={"grace": "grace"},
)
class Ec2HealthCheckOptions:
    def __init__(self, *, grace: typing.Optional[_Duration_4839e8c3] = None) -> None:
        '''EC2 Heath check options.

        :param grace: Specified the time Auto Scaling waits before checking the health status of an EC2 instance that has come into service. Default: Duration.seconds(0)

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            
            ec2_health_check_options = autoscaling.Ec2HealthCheckOptions(
                grace=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if grace is not None:
            self._values["grace"] = grace

    @builtins.property
    def grace(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Specified the time Auto Scaling waits before checking the health status of an EC2 instance that has come into service.

        :default: Duration.seconds(0)
        '''
        result = self._values.get("grace")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "Ec2HealthCheckOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.ElbHealthCheckOptions",
    jsii_struct_bases=[],
    name_mapping={"grace": "grace"},
)
class ElbHealthCheckOptions:
    def __init__(self, *, grace: _Duration_4839e8c3) -> None:
        '''ELB Heath check options.

        :param grace: Specified the time Auto Scaling waits before checking the health status of an EC2 instance that has come into service. This option is required for ELB health checks.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            
            elb_health_check_options = autoscaling.ElbHealthCheckOptions(
                grace=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "grace": grace,
        }

    @builtins.property
    def grace(self) -> _Duration_4839e8c3:
        '''Specified the time Auto Scaling waits before checking the health status of an EC2 instance that has come into service.

        This option is required for ELB health checks.
        '''
        result = self._values.get("grace")
        assert result is not None, "Required property 'grace' is missing"
        return typing.cast(_Duration_4839e8c3, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ElbHealthCheckOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class GroupMetric(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.GroupMetric",
):
    '''Group metrics that an Auto Scaling group sends to Amazon CloudWatch.

    :exampleMetadata: infused

    Example::

        # vpc: ec2.Vpc
        # instance_type: ec2.InstanceType
        # machine_image: ec2.IMachineImage
        
        
        # Enable monitoring of all group metrics
        autoscaling.AutoScalingGroup(self, "ASG",
            vpc=vpc,
            instance_type=instance_type,
            machine_image=machine_image,
        
            # ...
        
            group_metrics=[autoscaling.GroupMetrics.all()]
        )
        
        # Enable monitoring for a subset of group metrics
        autoscaling.AutoScalingGroup(self, "ASG",
            vpc=vpc,
            instance_type=instance_type,
            machine_image=machine_image,
        
            # ...
        
            group_metrics=[autoscaling.GroupMetrics(autoscaling.GroupMetric.MIN_SIZE, autoscaling.GroupMetric.MAX_SIZE)]
        )
    '''

    def __init__(self, name: builtins.str) -> None:
        '''
        :param name: -
        '''
        jsii.create(self.__class__, self, [name])

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="DESIRED_CAPACITY")
    def DESIRED_CAPACITY(cls) -> "GroupMetric":
        '''The number of instances that the Auto Scaling group attempts to maintain.'''
        return typing.cast("GroupMetric", jsii.sget(cls, "DESIRED_CAPACITY"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="IN_SERVICE_INSTANCES")
    def IN_SERVICE_INSTANCES(cls) -> "GroupMetric":
        '''The number of instances that are running as part of the Auto Scaling group This metric does not include instances that are pending or terminating.'''
        return typing.cast("GroupMetric", jsii.sget(cls, "IN_SERVICE_INSTANCES"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MAX_SIZE")
    def MAX_SIZE(cls) -> "GroupMetric":
        '''The maximum size of the Auto Scaling group.'''
        return typing.cast("GroupMetric", jsii.sget(cls, "MAX_SIZE"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="MIN_SIZE")
    def MIN_SIZE(cls) -> "GroupMetric":
        '''The minimum size of the Auto Scaling group.'''
        return typing.cast("GroupMetric", jsii.sget(cls, "MIN_SIZE"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="PENDING_INSTANCES")
    def PENDING_INSTANCES(cls) -> "GroupMetric":
        '''The number of instances that are pending A pending instance is not yet in service, this metric does not include instances that are in service or terminating.'''
        return typing.cast("GroupMetric", jsii.sget(cls, "PENDING_INSTANCES"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="STANDBY_INSTANCES")
    def STANDBY_INSTANCES(cls) -> "GroupMetric":
        '''The number of instances that are in a Standby state Instances in this state are still running but are not actively in service.'''
        return typing.cast("GroupMetric", jsii.sget(cls, "STANDBY_INSTANCES"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="TERMINATING_INSTANCES")
    def TERMINATING_INSTANCES(cls) -> "GroupMetric":
        '''The number of instances that are in the process of terminating This metric does not include instances that are in service or pending.'''
        return typing.cast("GroupMetric", jsii.sget(cls, "TERMINATING_INSTANCES"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="TOTAL_INSTANCES")
    def TOTAL_INSTANCES(cls) -> "GroupMetric":
        '''The total number of instances in the Auto Scaling group This metric identifies the number of instances that are in service, pending, and terminating.'''
        return typing.cast("GroupMetric", jsii.sget(cls, "TOTAL_INSTANCES"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> builtins.str:
        '''The name of the group metric.'''
        return typing.cast(builtins.str, jsii.get(self, "name"))


class GroupMetrics(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.GroupMetrics",
):
    '''A set of group metrics.

    :exampleMetadata: infused

    Example::

        # vpc: ec2.Vpc
        # instance_type: ec2.InstanceType
        # machine_image: ec2.IMachineImage
        
        
        # Enable monitoring of all group metrics
        autoscaling.AutoScalingGroup(self, "ASG",
            vpc=vpc,
            instance_type=instance_type,
            machine_image=machine_image,
        
            # ...
        
            group_metrics=[autoscaling.GroupMetrics.all()]
        )
        
        # Enable monitoring for a subset of group metrics
        autoscaling.AutoScalingGroup(self, "ASG",
            vpc=vpc,
            instance_type=instance_type,
            machine_image=machine_image,
        
            # ...
        
            group_metrics=[autoscaling.GroupMetrics(autoscaling.GroupMetric.MIN_SIZE, autoscaling.GroupMetric.MAX_SIZE)]
        )
    '''

    def __init__(self, *metrics: GroupMetric) -> None:
        '''
        :param metrics: -
        '''
        jsii.create(self.__class__, self, [*metrics])

    @jsii.member(jsii_name="all") # type: ignore[misc]
    @builtins.classmethod
    def all(cls) -> "GroupMetrics":
        '''Report all group metrics.'''
        return typing.cast("GroupMetrics", jsii.sinvoke(cls, "all", []))


class HealthCheck(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.HealthCheck",
):
    '''Health check settings.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_autoscaling as autoscaling
        
        health_check = autoscaling.HealthCheck.ec2(
            grace=cdk.Duration.minutes(30)
        )
    '''

    @jsii.member(jsii_name="ec2") # type: ignore[misc]
    @builtins.classmethod
    def ec2(cls, *, grace: typing.Optional[_Duration_4839e8c3] = None) -> "HealthCheck":
        '''Use EC2 for health checks.

        :param grace: Specified the time Auto Scaling waits before checking the health status of an EC2 instance that has come into service. Default: Duration.seconds(0)
        '''
        options = Ec2HealthCheckOptions(grace=grace)

        return typing.cast("HealthCheck", jsii.sinvoke(cls, "ec2", [options]))

    @jsii.member(jsii_name="elb") # type: ignore[misc]
    @builtins.classmethod
    def elb(cls, *, grace: _Duration_4839e8c3) -> "HealthCheck":
        '''Use ELB for health checks.

        It considers the instance unhealthy if it fails either the EC2 status checks or the load balancer health checks.

        :param grace: Specified the time Auto Scaling waits before checking the health status of an EC2 instance that has come into service. This option is required for ELB health checks.
        '''
        options = ElbHealthCheckOptions(grace=grace)

        return typing.cast("HealthCheck", jsii.sinvoke(cls, "elb", [options]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="type")
    def type(self) -> builtins.str:
        return typing.cast(builtins.str, jsii.get(self, "type"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="gracePeriod")
    def grace_period(self) -> typing.Optional[_Duration_4839e8c3]:
        return typing.cast(typing.Optional[_Duration_4839e8c3], jsii.get(self, "gracePeriod"))


@jsii.interface(jsii_type="aws-cdk-lib.aws_autoscaling.IAutoScalingGroup")
class IAutoScalingGroup(
    _IResource_c80c4260,
    _IGrantable_71c4f5de,
    typing_extensions.Protocol,
):
    '''An AutoScalingGroup.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoScalingGroupArn")
    def auto_scaling_group_arn(self) -> builtins.str:
        '''The arn of the AutoScalingGroup.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoScalingGroupName")
    def auto_scaling_group_name(self) -> builtins.str:
        '''The name of the AutoScalingGroup.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="osType")
    def os_type(self) -> _OperatingSystemType_9224a1fe:
        '''The operating system family that the instances in this auto-scaling group belong to.

        Is 'UNKNOWN' for imported ASGs.
        '''
        ...

    @jsii.member(jsii_name="addLifecycleHook")
    def add_lifecycle_hook(
        self,
        id: builtins.str,
        *,
        lifecycle_transition: "LifecycleTransition",
        default_result: typing.Optional[DefaultResult] = None,
        heartbeat_timeout: typing.Optional[_Duration_4839e8c3] = None,
        lifecycle_hook_name: typing.Optional[builtins.str] = None,
        notification_metadata: typing.Optional[builtins.str] = None,
        notification_target: typing.Optional["ILifecycleHookTarget"] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> "LifecycleHook":
        '''Send a message to either an SQS queue or SNS topic when instances launch or terminate.

        :param id: -
        :param lifecycle_transition: The state of the Amazon EC2 instance to which you want to attach the lifecycle hook.
        :param default_result: The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs. Default: Continue
        :param heartbeat_timeout: Maximum time between calls to RecordLifecycleActionHeartbeat for the hook. If the lifecycle hook times out, perform the action in DefaultResult. Default: - No heartbeat timeout.
        :param lifecycle_hook_name: Name of the lifecycle hook. Default: - Automatically generated name.
        :param notification_metadata: Additional data to pass to the lifecycle hook target. Default: - No metadata.
        :param notification_target: The target of the lifecycle hook. Default: - No target.
        :param role: The role that allows publishing to the notification target. Default: - A role will be created if a target is provided. Otherwise, no role is created.
        '''
        ...

    @jsii.member(jsii_name="addUserData")
    def add_user_data(self, *commands: builtins.str) -> None:
        '''Add command to the startup script of fleet instances.

        The command must be in the scripting language supported by the fleet's OS (i.e. Linux/Windows).
        Does nothing for imported ASGs.

        :param commands: -
        '''
        ...

    @jsii.member(jsii_name="scaleOnCpuUtilization")
    def scale_on_cpu_utilization(
        self,
        id: builtins.str,
        *,
        target_utilization_percent: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "TargetTrackingScalingPolicy":
        '''Scale out or in to achieve a target CPU utilization.

        :param id: -
        :param target_utilization_percent: Target average CPU utilization across the task.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        ...

    @jsii.member(jsii_name="scaleOnIncomingBytes")
    def scale_on_incoming_bytes(
        self,
        id: builtins.str,
        *,
        target_bytes_per_second: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "TargetTrackingScalingPolicy":
        '''Scale out or in to achieve a target network ingress rate.

        :param id: -
        :param target_bytes_per_second: Target average bytes/seconds on each instance.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        ...

    @jsii.member(jsii_name="scaleOnMetric")
    def scale_on_metric(
        self,
        id: builtins.str,
        *,
        metric: _IMetric_c7fd29de,
        scaling_steps: typing.Sequence["ScalingInterval"],
        adjustment_type: typing.Optional[AdjustmentType] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        evaluation_periods: typing.Optional[jsii.Number] = None,
        metric_aggregation_type: typing.Optional["MetricAggregationType"] = None,
        min_adjustment_magnitude: typing.Optional[jsii.Number] = None,
    ) -> "StepScalingPolicy":
        '''Scale out or in, in response to a metric.

        :param id: -
        :param metric: Metric to scale on.
        :param scaling_steps: The intervals for scaling. Maps a range of metric values to a particular scaling behavior.
        :param adjustment_type: How the adjustment numbers inside 'intervals' are interpreted. Default: ChangeInCapacity
        :param cooldown: Grace period after scaling activity. Default: Default cooldown period on your AutoScalingGroup
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: Same as the cooldown
        :param evaluation_periods: How many evaluation periods of the metric to wait before triggering a scaling action. Raising this value can be used to smooth out the metric, at the expense of slower response times. Default: 1
        :param metric_aggregation_type: Aggregation to apply to all data points over the evaluation periods. Only has meaning if ``evaluationPeriods != 1``. Default: - The statistic from the metric if applicable (MIN, MAX, AVERAGE), otherwise AVERAGE.
        :param min_adjustment_magnitude: Minimum absolute number to adjust capacity with as result of percentage scaling. Only when using AdjustmentType = PercentChangeInCapacity, this number controls the minimum absolute effect size. Default: No minimum scaling effect
        '''
        ...

    @jsii.member(jsii_name="scaleOnOutgoingBytes")
    def scale_on_outgoing_bytes(
        self,
        id: builtins.str,
        *,
        target_bytes_per_second: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "TargetTrackingScalingPolicy":
        '''Scale out or in to achieve a target network egress rate.

        :param id: -
        :param target_bytes_per_second: Target average bytes/seconds on each instance.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        ...

    @jsii.member(jsii_name="scaleOnSchedule")
    def scale_on_schedule(
        self,
        id: builtins.str,
        *,
        schedule: "Schedule",
        desired_capacity: typing.Optional[jsii.Number] = None,
        end_time: typing.Optional[datetime.datetime] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
        start_time: typing.Optional[datetime.datetime] = None,
        time_zone: typing.Optional[builtins.str] = None,
    ) -> "ScheduledAction":
        '''Scale out or in based on time.

        :param id: -
        :param schedule: When to perform this action. Supports cron expressions. For more information about cron expressions, see https://en.wikipedia.org/wiki/Cron.
        :param desired_capacity: The new desired capacity. At the scheduled time, set the desired capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new desired capacity.
        :param end_time: When this scheduled action expires. Default: - The rule never expires.
        :param max_capacity: The new maximum capacity. At the scheduled time, set the maximum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new maximum capacity.
        :param min_capacity: The new minimum capacity. At the scheduled time, set the minimum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new minimum capacity.
        :param start_time: When this scheduled action becomes active. Default: - The rule is activate immediately.
        :param time_zone: Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default. Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as Etc/GMT+9 or Pacific/Tahiti). For more information, see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones. Default: - UTC
        '''
        ...

    @jsii.member(jsii_name="scaleToTrackMetric")
    def scale_to_track_metric(
        self,
        id: builtins.str,
        *,
        metric: _IMetric_c7fd29de,
        target_value: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "TargetTrackingScalingPolicy":
        '''Scale out or in in order to keep a metric around a target value.

        :param id: -
        :param metric: Metric to track. The metric must represent a utilization, so that if it's higher than the target value, your ASG should scale out, and if it's lower it should scale in.
        :param target_value: Value to keep the metric around.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        ...


class _IAutoScalingGroupProxy(
    jsii.proxy_for(_IResource_c80c4260), # type: ignore[misc]
    jsii.proxy_for(_IGrantable_71c4f5de), # type: ignore[misc]
):
    '''An AutoScalingGroup.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_autoscaling.IAutoScalingGroup"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoScalingGroupArn")
    def auto_scaling_group_arn(self) -> builtins.str:
        '''The arn of the AutoScalingGroup.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "autoScalingGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoScalingGroupName")
    def auto_scaling_group_name(self) -> builtins.str:
        '''The name of the AutoScalingGroup.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "autoScalingGroupName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="osType")
    def os_type(self) -> _OperatingSystemType_9224a1fe:
        '''The operating system family that the instances in this auto-scaling group belong to.

        Is 'UNKNOWN' for imported ASGs.
        '''
        return typing.cast(_OperatingSystemType_9224a1fe, jsii.get(self, "osType"))

    @jsii.member(jsii_name="addLifecycleHook")
    def add_lifecycle_hook(
        self,
        id: builtins.str,
        *,
        lifecycle_transition: "LifecycleTransition",
        default_result: typing.Optional[DefaultResult] = None,
        heartbeat_timeout: typing.Optional[_Duration_4839e8c3] = None,
        lifecycle_hook_name: typing.Optional[builtins.str] = None,
        notification_metadata: typing.Optional[builtins.str] = None,
        notification_target: typing.Optional["ILifecycleHookTarget"] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> "LifecycleHook":
        '''Send a message to either an SQS queue or SNS topic when instances launch or terminate.

        :param id: -
        :param lifecycle_transition: The state of the Amazon EC2 instance to which you want to attach the lifecycle hook.
        :param default_result: The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs. Default: Continue
        :param heartbeat_timeout: Maximum time between calls to RecordLifecycleActionHeartbeat for the hook. If the lifecycle hook times out, perform the action in DefaultResult. Default: - No heartbeat timeout.
        :param lifecycle_hook_name: Name of the lifecycle hook. Default: - Automatically generated name.
        :param notification_metadata: Additional data to pass to the lifecycle hook target. Default: - No metadata.
        :param notification_target: The target of the lifecycle hook. Default: - No target.
        :param role: The role that allows publishing to the notification target. Default: - A role will be created if a target is provided. Otherwise, no role is created.
        '''
        props = BasicLifecycleHookProps(
            lifecycle_transition=lifecycle_transition,
            default_result=default_result,
            heartbeat_timeout=heartbeat_timeout,
            lifecycle_hook_name=lifecycle_hook_name,
            notification_metadata=notification_metadata,
            notification_target=notification_target,
            role=role,
        )

        return typing.cast("LifecycleHook", jsii.invoke(self, "addLifecycleHook", [id, props]))

    @jsii.member(jsii_name="addUserData")
    def add_user_data(self, *commands: builtins.str) -> None:
        '''Add command to the startup script of fleet instances.

        The command must be in the scripting language supported by the fleet's OS (i.e. Linux/Windows).
        Does nothing for imported ASGs.

        :param commands: -
        '''
        return typing.cast(None, jsii.invoke(self, "addUserData", [*commands]))

    @jsii.member(jsii_name="scaleOnCpuUtilization")
    def scale_on_cpu_utilization(
        self,
        id: builtins.str,
        *,
        target_utilization_percent: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "TargetTrackingScalingPolicy":
        '''Scale out or in to achieve a target CPU utilization.

        :param id: -
        :param target_utilization_percent: Target average CPU utilization across the task.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        props = CpuUtilizationScalingProps(
            target_utilization_percent=target_utilization_percent,
            cooldown=cooldown,
            disable_scale_in=disable_scale_in,
            estimated_instance_warmup=estimated_instance_warmup,
        )

        return typing.cast("TargetTrackingScalingPolicy", jsii.invoke(self, "scaleOnCpuUtilization", [id, props]))

    @jsii.member(jsii_name="scaleOnIncomingBytes")
    def scale_on_incoming_bytes(
        self,
        id: builtins.str,
        *,
        target_bytes_per_second: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "TargetTrackingScalingPolicy":
        '''Scale out or in to achieve a target network ingress rate.

        :param id: -
        :param target_bytes_per_second: Target average bytes/seconds on each instance.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        props = NetworkUtilizationScalingProps(
            target_bytes_per_second=target_bytes_per_second,
            cooldown=cooldown,
            disable_scale_in=disable_scale_in,
            estimated_instance_warmup=estimated_instance_warmup,
        )

        return typing.cast("TargetTrackingScalingPolicy", jsii.invoke(self, "scaleOnIncomingBytes", [id, props]))

    @jsii.member(jsii_name="scaleOnMetric")
    def scale_on_metric(
        self,
        id: builtins.str,
        *,
        metric: _IMetric_c7fd29de,
        scaling_steps: typing.Sequence["ScalingInterval"],
        adjustment_type: typing.Optional[AdjustmentType] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        evaluation_periods: typing.Optional[jsii.Number] = None,
        metric_aggregation_type: typing.Optional["MetricAggregationType"] = None,
        min_adjustment_magnitude: typing.Optional[jsii.Number] = None,
    ) -> "StepScalingPolicy":
        '''Scale out or in, in response to a metric.

        :param id: -
        :param metric: Metric to scale on.
        :param scaling_steps: The intervals for scaling. Maps a range of metric values to a particular scaling behavior.
        :param adjustment_type: How the adjustment numbers inside 'intervals' are interpreted. Default: ChangeInCapacity
        :param cooldown: Grace period after scaling activity. Default: Default cooldown period on your AutoScalingGroup
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: Same as the cooldown
        :param evaluation_periods: How many evaluation periods of the metric to wait before triggering a scaling action. Raising this value can be used to smooth out the metric, at the expense of slower response times. Default: 1
        :param metric_aggregation_type: Aggregation to apply to all data points over the evaluation periods. Only has meaning if ``evaluationPeriods != 1``. Default: - The statistic from the metric if applicable (MIN, MAX, AVERAGE), otherwise AVERAGE.
        :param min_adjustment_magnitude: Minimum absolute number to adjust capacity with as result of percentage scaling. Only when using AdjustmentType = PercentChangeInCapacity, this number controls the minimum absolute effect size. Default: No minimum scaling effect
        '''
        props = BasicStepScalingPolicyProps(
            metric=metric,
            scaling_steps=scaling_steps,
            adjustment_type=adjustment_type,
            cooldown=cooldown,
            estimated_instance_warmup=estimated_instance_warmup,
            evaluation_periods=evaluation_periods,
            metric_aggregation_type=metric_aggregation_type,
            min_adjustment_magnitude=min_adjustment_magnitude,
        )

        return typing.cast("StepScalingPolicy", jsii.invoke(self, "scaleOnMetric", [id, props]))

    @jsii.member(jsii_name="scaleOnOutgoingBytes")
    def scale_on_outgoing_bytes(
        self,
        id: builtins.str,
        *,
        target_bytes_per_second: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "TargetTrackingScalingPolicy":
        '''Scale out or in to achieve a target network egress rate.

        :param id: -
        :param target_bytes_per_second: Target average bytes/seconds on each instance.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        props = NetworkUtilizationScalingProps(
            target_bytes_per_second=target_bytes_per_second,
            cooldown=cooldown,
            disable_scale_in=disable_scale_in,
            estimated_instance_warmup=estimated_instance_warmup,
        )

        return typing.cast("TargetTrackingScalingPolicy", jsii.invoke(self, "scaleOnOutgoingBytes", [id, props]))

    @jsii.member(jsii_name="scaleOnSchedule")
    def scale_on_schedule(
        self,
        id: builtins.str,
        *,
        schedule: "Schedule",
        desired_capacity: typing.Optional[jsii.Number] = None,
        end_time: typing.Optional[datetime.datetime] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
        start_time: typing.Optional[datetime.datetime] = None,
        time_zone: typing.Optional[builtins.str] = None,
    ) -> "ScheduledAction":
        '''Scale out or in based on time.

        :param id: -
        :param schedule: When to perform this action. Supports cron expressions. For more information about cron expressions, see https://en.wikipedia.org/wiki/Cron.
        :param desired_capacity: The new desired capacity. At the scheduled time, set the desired capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new desired capacity.
        :param end_time: When this scheduled action expires. Default: - The rule never expires.
        :param max_capacity: The new maximum capacity. At the scheduled time, set the maximum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new maximum capacity.
        :param min_capacity: The new minimum capacity. At the scheduled time, set the minimum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new minimum capacity.
        :param start_time: When this scheduled action becomes active. Default: - The rule is activate immediately.
        :param time_zone: Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default. Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as Etc/GMT+9 or Pacific/Tahiti). For more information, see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones. Default: - UTC
        '''
        props = BasicScheduledActionProps(
            schedule=schedule,
            desired_capacity=desired_capacity,
            end_time=end_time,
            max_capacity=max_capacity,
            min_capacity=min_capacity,
            start_time=start_time,
            time_zone=time_zone,
        )

        return typing.cast("ScheduledAction", jsii.invoke(self, "scaleOnSchedule", [id, props]))

    @jsii.member(jsii_name="scaleToTrackMetric")
    def scale_to_track_metric(
        self,
        id: builtins.str,
        *,
        metric: _IMetric_c7fd29de,
        target_value: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "TargetTrackingScalingPolicy":
        '''Scale out or in in order to keep a metric around a target value.

        :param id: -
        :param metric: Metric to track. The metric must represent a utilization, so that if it's higher than the target value, your ASG should scale out, and if it's lower it should scale in.
        :param target_value: Value to keep the metric around.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        props = MetricTargetTrackingProps(
            metric=metric,
            target_value=target_value,
            cooldown=cooldown,
            disable_scale_in=disable_scale_in,
            estimated_instance_warmup=estimated_instance_warmup,
        )

        return typing.cast("TargetTrackingScalingPolicy", jsii.invoke(self, "scaleToTrackMetric", [id, props]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IAutoScalingGroup).__jsii_proxy_class__ = lambda : _IAutoScalingGroupProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_autoscaling.ILifecycleHook")
class ILifecycleHook(_IResource_c80c4260, typing_extensions.Protocol):
    '''A basic lifecycle hook object.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> _IRole_235f5d8e:
        '''The role for the lifecycle hook to execute.

        :default:

        - A default role is created if 'notificationTarget' is specified.
        Otherwise, no role is created.
        '''
        ...


class _ILifecycleHookProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''A basic lifecycle hook object.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_autoscaling.ILifecycleHook"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> _IRole_235f5d8e:
        '''The role for the lifecycle hook to execute.

        :default:

        - A default role is created if 'notificationTarget' is specified.
        Otherwise, no role is created.
        '''
        return typing.cast(_IRole_235f5d8e, jsii.get(self, "role"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ILifecycleHook).__jsii_proxy_class__ = lambda : _ILifecycleHookProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_autoscaling.ILifecycleHookTarget")
class ILifecycleHookTarget(typing_extensions.Protocol):
    '''Interface for autoscaling lifecycle hook targets.'''

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        scope: constructs.Construct,
        *,
        lifecycle_hook: "LifecycleHook",
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> "LifecycleHookTargetConfig":
        '''Called when this object is used as the target of a lifecycle hook.

        :param scope: -
        :param lifecycle_hook: The lifecycle hook to attach to. [disable-awslint:ref-via-interface]
        :param role: The role to use when attaching to the lifecycle hook. [disable-awslint:ref-via-interface] Default: : a role is not created unless the target arn is specified
        '''
        ...


class _ILifecycleHookTargetProxy:
    '''Interface for autoscaling lifecycle hook targets.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_autoscaling.ILifecycleHookTarget"

    @jsii.member(jsii_name="bind")
    def bind(
        self,
        scope: constructs.Construct,
        *,
        lifecycle_hook: "LifecycleHook",
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> "LifecycleHookTargetConfig":
        '''Called when this object is used as the target of a lifecycle hook.

        :param scope: -
        :param lifecycle_hook: The lifecycle hook to attach to. [disable-awslint:ref-via-interface]
        :param role: The role to use when attaching to the lifecycle hook. [disable-awslint:ref-via-interface] Default: : a role is not created unless the target arn is specified
        '''
        options = BindHookTargetOptions(lifecycle_hook=lifecycle_hook, role=role)

        return typing.cast("LifecycleHookTargetConfig", jsii.invoke(self, "bind", [scope, options]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ILifecycleHookTarget).__jsii_proxy_class__ = lambda : _ILifecycleHookTargetProxy


@jsii.implements(ILifecycleHook)
class LifecycleHook(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.LifecycleHook",
):
    '''Define a life cycle hook.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_autoscaling as autoscaling
        from aws_cdk import aws_iam as iam
        
        # auto_scaling_group: autoscaling.AutoScalingGroup
        # lifecycle_hook_target: autoscaling.ILifecycleHookTarget
        # role: iam.Role
        
        lifecycle_hook = autoscaling.LifecycleHook(self, "MyLifecycleHook",
            auto_scaling_group=auto_scaling_group,
            lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_LAUNCHING,
        
            # the properties below are optional
            default_result=autoscaling.DefaultResult.CONTINUE,
            heartbeat_timeout=cdk.Duration.minutes(30),
            lifecycle_hook_name="lifecycleHookName",
            notification_metadata="notificationMetadata",
            notification_target=lifecycle_hook_target,
            role=role
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        auto_scaling_group: IAutoScalingGroup,
        lifecycle_transition: "LifecycleTransition",
        default_result: typing.Optional[DefaultResult] = None,
        heartbeat_timeout: typing.Optional[_Duration_4839e8c3] = None,
        lifecycle_hook_name: typing.Optional[builtins.str] = None,
        notification_metadata: typing.Optional[builtins.str] = None,
        notification_target: typing.Optional[ILifecycleHookTarget] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param auto_scaling_group: The AutoScalingGroup to add the lifecycle hook to.
        :param lifecycle_transition: The state of the Amazon EC2 instance to which you want to attach the lifecycle hook.
        :param default_result: The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs. Default: Continue
        :param heartbeat_timeout: Maximum time between calls to RecordLifecycleActionHeartbeat for the hook. If the lifecycle hook times out, perform the action in DefaultResult. Default: - No heartbeat timeout.
        :param lifecycle_hook_name: Name of the lifecycle hook. Default: - Automatically generated name.
        :param notification_metadata: Additional data to pass to the lifecycle hook target. Default: - No metadata.
        :param notification_target: The target of the lifecycle hook. Default: - No target.
        :param role: The role that allows publishing to the notification target. Default: - A role will be created if a target is provided. Otherwise, no role is created.
        '''
        props = LifecycleHookProps(
            auto_scaling_group=auto_scaling_group,
            lifecycle_transition=lifecycle_transition,
            default_result=default_result,
            heartbeat_timeout=heartbeat_timeout,
            lifecycle_hook_name=lifecycle_hook_name,
            notification_metadata=notification_metadata,
            notification_target=notification_target,
            role=role,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lifecycleHookName")
    def lifecycle_hook_name(self) -> builtins.str:
        '''The name of this lifecycle hook.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "lifecycleHookName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> _IRole_235f5d8e:
        '''The role that allows the ASG to publish to the notification target.

        :default:

        - A default role is created if 'notificationTarget' is specified.
        Otherwise, no role is created.
        '''
        return typing.cast(_IRole_235f5d8e, jsii.get(self, "role"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.LifecycleHookProps",
    jsii_struct_bases=[BasicLifecycleHookProps],
    name_mapping={
        "lifecycle_transition": "lifecycleTransition",
        "default_result": "defaultResult",
        "heartbeat_timeout": "heartbeatTimeout",
        "lifecycle_hook_name": "lifecycleHookName",
        "notification_metadata": "notificationMetadata",
        "notification_target": "notificationTarget",
        "role": "role",
        "auto_scaling_group": "autoScalingGroup",
    },
)
class LifecycleHookProps(BasicLifecycleHookProps):
    def __init__(
        self,
        *,
        lifecycle_transition: "LifecycleTransition",
        default_result: typing.Optional[DefaultResult] = None,
        heartbeat_timeout: typing.Optional[_Duration_4839e8c3] = None,
        lifecycle_hook_name: typing.Optional[builtins.str] = None,
        notification_metadata: typing.Optional[builtins.str] = None,
        notification_target: typing.Optional[ILifecycleHookTarget] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        auto_scaling_group: IAutoScalingGroup,
    ) -> None:
        '''Properties for a Lifecycle hook.

        :param lifecycle_transition: The state of the Amazon EC2 instance to which you want to attach the lifecycle hook.
        :param default_result: The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs. Default: Continue
        :param heartbeat_timeout: Maximum time between calls to RecordLifecycleActionHeartbeat for the hook. If the lifecycle hook times out, perform the action in DefaultResult. Default: - No heartbeat timeout.
        :param lifecycle_hook_name: Name of the lifecycle hook. Default: - Automatically generated name.
        :param notification_metadata: Additional data to pass to the lifecycle hook target. Default: - No metadata.
        :param notification_target: The target of the lifecycle hook. Default: - No target.
        :param role: The role that allows publishing to the notification target. Default: - A role will be created if a target is provided. Otherwise, no role is created.
        :param auto_scaling_group: The AutoScalingGroup to add the lifecycle hook to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            from aws_cdk import aws_iam as iam
            
            # auto_scaling_group: autoscaling.AutoScalingGroup
            # lifecycle_hook_target: autoscaling.ILifecycleHookTarget
            # role: iam.Role
            
            lifecycle_hook_props = autoscaling.LifecycleHookProps(
                auto_scaling_group=auto_scaling_group,
                lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_LAUNCHING,
            
                # the properties below are optional
                default_result=autoscaling.DefaultResult.CONTINUE,
                heartbeat_timeout=cdk.Duration.minutes(30),
                lifecycle_hook_name="lifecycleHookName",
                notification_metadata="notificationMetadata",
                notification_target=lifecycle_hook_target,
                role=role
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "lifecycle_transition": lifecycle_transition,
            "auto_scaling_group": auto_scaling_group,
        }
        if default_result is not None:
            self._values["default_result"] = default_result
        if heartbeat_timeout is not None:
            self._values["heartbeat_timeout"] = heartbeat_timeout
        if lifecycle_hook_name is not None:
            self._values["lifecycle_hook_name"] = lifecycle_hook_name
        if notification_metadata is not None:
            self._values["notification_metadata"] = notification_metadata
        if notification_target is not None:
            self._values["notification_target"] = notification_target
        if role is not None:
            self._values["role"] = role

    @builtins.property
    def lifecycle_transition(self) -> "LifecycleTransition":
        '''The state of the Amazon EC2 instance to which you want to attach the lifecycle hook.'''
        result = self._values.get("lifecycle_transition")
        assert result is not None, "Required property 'lifecycle_transition' is missing"
        return typing.cast("LifecycleTransition", result)

    @builtins.property
    def default_result(self) -> typing.Optional[DefaultResult]:
        '''The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs.

        :default: Continue
        '''
        result = self._values.get("default_result")
        return typing.cast(typing.Optional[DefaultResult], result)

    @builtins.property
    def heartbeat_timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Maximum time between calls to RecordLifecycleActionHeartbeat for the hook.

        If the lifecycle hook times out, perform the action in DefaultResult.

        :default: - No heartbeat timeout.
        '''
        result = self._values.get("heartbeat_timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def lifecycle_hook_name(self) -> typing.Optional[builtins.str]:
        '''Name of the lifecycle hook.

        :default: - Automatically generated name.
        '''
        result = self._values.get("lifecycle_hook_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def notification_metadata(self) -> typing.Optional[builtins.str]:
        '''Additional data to pass to the lifecycle hook target.

        :default: - No metadata.
        '''
        result = self._values.get("notification_metadata")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def notification_target(self) -> typing.Optional[ILifecycleHookTarget]:
        '''The target of the lifecycle hook.

        :default: - No target.
        '''
        result = self._values.get("notification_target")
        return typing.cast(typing.Optional[ILifecycleHookTarget], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The role that allows publishing to the notification target.

        :default: - A role will be created if a target is provided. Otherwise, no role is created.
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def auto_scaling_group(self) -> IAutoScalingGroup:
        '''The AutoScalingGroup to add the lifecycle hook to.'''
        result = self._values.get("auto_scaling_group")
        assert result is not None, "Required property 'auto_scaling_group' is missing"
        return typing.cast(IAutoScalingGroup, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LifecycleHookProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.LifecycleHookTargetConfig",
    jsii_struct_bases=[],
    name_mapping={
        "created_role": "createdRole",
        "notification_target_arn": "notificationTargetArn",
    },
)
class LifecycleHookTargetConfig:
    def __init__(
        self,
        *,
        created_role: _IRole_235f5d8e,
        notification_target_arn: builtins.str,
    ) -> None:
        '''Result of binding a lifecycle hook to a target.

        :param created_role: The IRole that was used to bind the lifecycle hook to the target.
        :param notification_target_arn: The targetArn that the lifecycle hook was bound to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            from aws_cdk import aws_iam as iam
            
            # role: iam.Role
            
            lifecycle_hook_target_config = autoscaling.LifecycleHookTargetConfig(
                created_role=role,
                notification_target_arn="notificationTargetArn"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "created_role": created_role,
            "notification_target_arn": notification_target_arn,
        }

    @builtins.property
    def created_role(self) -> _IRole_235f5d8e:
        '''The IRole that was used to bind the lifecycle hook to the target.'''
        result = self._values.get("created_role")
        assert result is not None, "Required property 'created_role' is missing"
        return typing.cast(_IRole_235f5d8e, result)

    @builtins.property
    def notification_target_arn(self) -> builtins.str:
        '''The targetArn that the lifecycle hook was bound to.'''
        result = self._values.get("notification_target_arn")
        assert result is not None, "Required property 'notification_target_arn' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LifecycleHookTargetConfig(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_autoscaling.LifecycleTransition")
class LifecycleTransition(enum.Enum):
    '''What instance transition to attach the hook to.'''

    INSTANCE_LAUNCHING = "INSTANCE_LAUNCHING"
    '''Execute the hook when an instance is about to be added.'''
    INSTANCE_TERMINATING = "INSTANCE_TERMINATING"
    '''Execute the hook when an instance is about to be terminated.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_autoscaling.MetricAggregationType")
class MetricAggregationType(enum.Enum):
    '''How the scaling metric is going to be aggregated.'''

    AVERAGE = "AVERAGE"
    '''Average.'''
    MINIMUM = "MINIMUM"
    '''Minimum.'''
    MAXIMUM = "MAXIMUM"
    '''Maximum.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.MetricTargetTrackingProps",
    jsii_struct_bases=[BaseTargetTrackingProps],
    name_mapping={
        "cooldown": "cooldown",
        "disable_scale_in": "disableScaleIn",
        "estimated_instance_warmup": "estimatedInstanceWarmup",
        "metric": "metric",
        "target_value": "targetValue",
    },
)
class MetricTargetTrackingProps(BaseTargetTrackingProps):
    def __init__(
        self,
        *,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        metric: _IMetric_c7fd29de,
        target_value: jsii.Number,
    ) -> None:
        '''Properties for enabling tracking of an arbitrary metric.

        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        :param metric: Metric to track. The metric must represent a utilization, so that if it's higher than the target value, your ASG should scale out, and if it's lower it should scale in.
        :param target_value: Value to keep the metric around.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            from aws_cdk import aws_cloudwatch as cloudwatch
            
            # metric: cloudwatch.Metric
            
            metric_target_tracking_props = autoscaling.MetricTargetTrackingProps(
                metric=metric,
                target_value=123,
            
                # the properties below are optional
                cooldown=cdk.Duration.minutes(30),
                disable_scale_in=False,
                estimated_instance_warmup=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "metric": metric,
            "target_value": target_value,
        }
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if disable_scale_in is not None:
            self._values["disable_scale_in"] = disable_scale_in
        if estimated_instance_warmup is not None:
            self._values["estimated_instance_warmup"] = estimated_instance_warmup

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Period after a scaling completes before another scaling activity can start.

        :default: - The default cooldown configured on the AutoScalingGroup.
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def disable_scale_in(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether scale in by the target tracking policy is disabled.

        If the value is true, scale in is disabled and the target tracking policy
        won't remove capacity from the autoscaling group. Otherwise, scale in is
        enabled and the target tracking policy can remove capacity from the
        group.

        :default: false
        '''
        result = self._values.get("disable_scale_in")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def estimated_instance_warmup(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Estimated time until a newly launched instance can send metrics to CloudWatch.

        :default: - Same as the cooldown.
        '''
        result = self._values.get("estimated_instance_warmup")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def metric(self) -> _IMetric_c7fd29de:
        '''Metric to track.

        The metric must represent a utilization, so that if it's higher than the
        target value, your ASG should scale out, and if it's lower it should
        scale in.
        '''
        result = self._values.get("metric")
        assert result is not None, "Required property 'metric' is missing"
        return typing.cast(_IMetric_c7fd29de, result)

    @builtins.property
    def target_value(self) -> jsii.Number:
        '''Value to keep the metric around.'''
        result = self._values.get("target_value")
        assert result is not None, "Required property 'target_value' is missing"
        return typing.cast(jsii.Number, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "MetricTargetTrackingProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_autoscaling.Monitoring")
class Monitoring(enum.Enum):
    '''The monitoring mode for instances launched in an autoscaling group.'''

    BASIC = "BASIC"
    '''Generates metrics every 5 minutes.'''
    DETAILED = "DETAILED"
    '''Generates metrics every minute.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.NetworkUtilizationScalingProps",
    jsii_struct_bases=[BaseTargetTrackingProps],
    name_mapping={
        "cooldown": "cooldown",
        "disable_scale_in": "disableScaleIn",
        "estimated_instance_warmup": "estimatedInstanceWarmup",
        "target_bytes_per_second": "targetBytesPerSecond",
    },
)
class NetworkUtilizationScalingProps(BaseTargetTrackingProps):
    def __init__(
        self,
        *,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        target_bytes_per_second: jsii.Number,
    ) -> None:
        '''Properties for enabling scaling based on network utilization.

        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        :param target_bytes_per_second: Target average bytes/seconds on each instance.

        :exampleMetadata: infused

        Example::

            # auto_scaling_group: autoscaling.AutoScalingGroup
            
            
            auto_scaling_group.scale_on_incoming_bytes("LimitIngressPerInstance",
                target_bytes_per_second=10 * 1024 * 1024
            )
            auto_scaling_group.scale_on_outgoing_bytes("LimitEgressPerInstance",
                target_bytes_per_second=10 * 1024 * 1024
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target_bytes_per_second": target_bytes_per_second,
        }
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if disable_scale_in is not None:
            self._values["disable_scale_in"] = disable_scale_in
        if estimated_instance_warmup is not None:
            self._values["estimated_instance_warmup"] = estimated_instance_warmup

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Period after a scaling completes before another scaling activity can start.

        :default: - The default cooldown configured on the AutoScalingGroup.
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def disable_scale_in(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether scale in by the target tracking policy is disabled.

        If the value is true, scale in is disabled and the target tracking policy
        won't remove capacity from the autoscaling group. Otherwise, scale in is
        enabled and the target tracking policy can remove capacity from the
        group.

        :default: false
        '''
        result = self._values.get("disable_scale_in")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def estimated_instance_warmup(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Estimated time until a newly launched instance can send metrics to CloudWatch.

        :default: - Same as the cooldown.
        '''
        result = self._values.get("estimated_instance_warmup")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def target_bytes_per_second(self) -> jsii.Number:
        '''Target average bytes/seconds on each instance.'''
        result = self._values.get("target_bytes_per_second")
        assert result is not None, "Required property 'target_bytes_per_second' is missing"
        return typing.cast(jsii.Number, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NetworkUtilizationScalingProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.NotificationConfiguration",
    jsii_struct_bases=[],
    name_mapping={"topic": "topic", "scaling_events": "scalingEvents"},
)
class NotificationConfiguration:
    def __init__(
        self,
        *,
        topic: _ITopic_9eca4852,
        scaling_events: typing.Optional["ScalingEvents"] = None,
    ) -> None:
        '''AutoScalingGroup fleet change notifications configurations.

        You can configure AutoScaling to send an SNS notification whenever your Auto Scaling group scales.

        :param topic: SNS topic to send notifications about fleet scaling events.
        :param scaling_events: Which fleet scaling events triggers a notification. Default: ScalingEvents.ALL

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            from aws_cdk import aws_sns as sns
            
            # scaling_events: autoscaling.ScalingEvents
            # topic: sns.Topic
            
            notification_configuration = autoscaling.NotificationConfiguration(
                topic=topic,
            
                # the properties below are optional
                scaling_events=scaling_events
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "topic": topic,
        }
        if scaling_events is not None:
            self._values["scaling_events"] = scaling_events

    @builtins.property
    def topic(self) -> _ITopic_9eca4852:
        '''SNS topic to send notifications about fleet scaling events.'''
        result = self._values.get("topic")
        assert result is not None, "Required property 'topic' is missing"
        return typing.cast(_ITopic_9eca4852, result)

    @builtins.property
    def scaling_events(self) -> typing.Optional["ScalingEvents"]:
        '''Which fleet scaling events triggers a notification.

        :default: ScalingEvents.ALL
        '''
        result = self._values.get("scaling_events")
        return typing.cast(typing.Optional["ScalingEvents"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NotificationConfiguration(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_autoscaling.PredefinedMetric")
class PredefinedMetric(enum.Enum):
    '''One of the predefined autoscaling metrics.'''

    ASG_AVERAGE_CPU_UTILIZATION = "ASG_AVERAGE_CPU_UTILIZATION"
    '''Average CPU utilization of the Auto Scaling group.'''
    ASG_AVERAGE_NETWORK_IN = "ASG_AVERAGE_NETWORK_IN"
    '''Average number of bytes received on all network interfaces by the Auto Scaling group.'''
    ASG_AVERAGE_NETWORK_OUT = "ASG_AVERAGE_NETWORK_OUT"
    '''Average number of bytes sent out on all network interfaces by the Auto Scaling group.'''
    ALB_REQUEST_COUNT_PER_TARGET = "ALB_REQUEST_COUNT_PER_TARGET"
    '''Number of requests completed per target in an Application Load Balancer target group.

    Specify the ALB to look at in the ``resourceLabel`` field.
    '''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.RenderSignalsOptions",
    jsii_struct_bases=[],
    name_mapping={
        "desired_capacity": "desiredCapacity",
        "min_capacity": "minCapacity",
    },
)
class RenderSignalsOptions:
    def __init__(
        self,
        *,
        desired_capacity: typing.Optional[jsii.Number] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Input for Signals.renderCreationPolicy.

        :param desired_capacity: The desiredCapacity of the ASG. Default: - desired capacity not configured
        :param min_capacity: The minSize of the ASG. Default: - minCapacity not configured

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            render_signals_options = autoscaling.RenderSignalsOptions(
                desired_capacity=123,
                min_capacity=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if desired_capacity is not None:
            self._values["desired_capacity"] = desired_capacity
        if min_capacity is not None:
            self._values["min_capacity"] = min_capacity

    @builtins.property
    def desired_capacity(self) -> typing.Optional[jsii.Number]:
        '''The desiredCapacity of the ASG.

        :default: - desired capacity not configured
        '''
        result = self._values.get("desired_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_capacity(self) -> typing.Optional[jsii.Number]:
        '''The minSize of the ASG.

        :default: - minCapacity not configured
        '''
        result = self._values.get("min_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RenderSignalsOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.RequestCountScalingProps",
    jsii_struct_bases=[BaseTargetTrackingProps],
    name_mapping={
        "cooldown": "cooldown",
        "disable_scale_in": "disableScaleIn",
        "estimated_instance_warmup": "estimatedInstanceWarmup",
        "target_requests_per_minute": "targetRequestsPerMinute",
    },
)
class RequestCountScalingProps(BaseTargetTrackingProps):
    def __init__(
        self,
        *,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        target_requests_per_minute: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Properties for enabling scaling based on request/second.

        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        :param target_requests_per_minute: Target average requests/minute on each instance. Default: - Specify exactly one of 'targetRequestsPerMinute' and 'targetRequestsPerSecond'

        :exampleMetadata: infused

        Example::

            # auto_scaling_group: autoscaling.AutoScalingGroup
            
            
            auto_scaling_group.scale_on_request_count("LimitRPS",
                target_requests_per_second=1000
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if disable_scale_in is not None:
            self._values["disable_scale_in"] = disable_scale_in
        if estimated_instance_warmup is not None:
            self._values["estimated_instance_warmup"] = estimated_instance_warmup
        if target_requests_per_minute is not None:
            self._values["target_requests_per_minute"] = target_requests_per_minute

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Period after a scaling completes before another scaling activity can start.

        :default: - The default cooldown configured on the AutoScalingGroup.
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def disable_scale_in(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether scale in by the target tracking policy is disabled.

        If the value is true, scale in is disabled and the target tracking policy
        won't remove capacity from the autoscaling group. Otherwise, scale in is
        enabled and the target tracking policy can remove capacity from the
        group.

        :default: false
        '''
        result = self._values.get("disable_scale_in")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def estimated_instance_warmup(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Estimated time until a newly launched instance can send metrics to CloudWatch.

        :default: - Same as the cooldown.
        '''
        result = self._values.get("estimated_instance_warmup")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def target_requests_per_minute(self) -> typing.Optional[jsii.Number]:
        '''Target average requests/minute on each instance.

        :default: - Specify exactly one of 'targetRequestsPerMinute' and 'targetRequestsPerSecond'
        '''
        result = self._values.get("target_requests_per_minute")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RequestCountScalingProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.RollingUpdateOptions",
    jsii_struct_bases=[],
    name_mapping={
        "max_batch_size": "maxBatchSize",
        "min_instances_in_service": "minInstancesInService",
        "min_success_percentage": "minSuccessPercentage",
        "pause_time": "pauseTime",
        "suspend_processes": "suspendProcesses",
        "wait_on_resource_signals": "waitOnResourceSignals",
    },
)
class RollingUpdateOptions:
    def __init__(
        self,
        *,
        max_batch_size: typing.Optional[jsii.Number] = None,
        min_instances_in_service: typing.Optional[jsii.Number] = None,
        min_success_percentage: typing.Optional[jsii.Number] = None,
        pause_time: typing.Optional[_Duration_4839e8c3] = None,
        suspend_processes: typing.Optional[typing.Sequence["ScalingProcess"]] = None,
        wait_on_resource_signals: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Options for customizing the rolling update.

        :param max_batch_size: The maximum number of instances that AWS CloudFormation updates at once. This number affects the speed of the replacement. Default: 1
        :param min_instances_in_service: The minimum number of instances that must be in service before more instances are replaced. This number affects the speed of the replacement. Default: 0
        :param min_success_percentage: The percentage of instances that must signal success for the update to succeed. Default: - The ``minSuccessPercentage`` configured for ``signals`` on the AutoScalingGroup
        :param pause_time: The pause time after making a change to a batch of instances. Default: - The ``timeout`` configured for ``signals`` on the AutoScalingGroup
        :param suspend_processes: Specifies the Auto Scaling processes to suspend during a stack update. Suspending processes prevents Auto Scaling from interfering with a stack update. Default: HealthCheck, ReplaceUnhealthy, AZRebalance, AlarmNotification, ScheduledActions.
        :param wait_on_resource_signals: Specifies whether the Auto Scaling group waits on signals from new instances during an update. Default: true if you configured ``signals`` on the AutoScalingGroup, false otherwise

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            
            rolling_update_options = autoscaling.RollingUpdateOptions(
                max_batch_size=123,
                min_instances_in_service=123,
                min_success_percentage=123,
                pause_time=cdk.Duration.minutes(30),
                suspend_processes=[autoscaling.ScalingProcess.LAUNCH],
                wait_on_resource_signals=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if max_batch_size is not None:
            self._values["max_batch_size"] = max_batch_size
        if min_instances_in_service is not None:
            self._values["min_instances_in_service"] = min_instances_in_service
        if min_success_percentage is not None:
            self._values["min_success_percentage"] = min_success_percentage
        if pause_time is not None:
            self._values["pause_time"] = pause_time
        if suspend_processes is not None:
            self._values["suspend_processes"] = suspend_processes
        if wait_on_resource_signals is not None:
            self._values["wait_on_resource_signals"] = wait_on_resource_signals

    @builtins.property
    def max_batch_size(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of instances that AWS CloudFormation updates at once.

        This number affects the speed of the replacement.

        :default: 1
        '''
        result = self._values.get("max_batch_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_instances_in_service(self) -> typing.Optional[jsii.Number]:
        '''The minimum number of instances that must be in service before more instances are replaced.

        This number affects the speed of the replacement.

        :default: 0
        '''
        result = self._values.get("min_instances_in_service")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_success_percentage(self) -> typing.Optional[jsii.Number]:
        '''The percentage of instances that must signal success for the update to succeed.

        :default: - The ``minSuccessPercentage`` configured for ``signals`` on the AutoScalingGroup
        '''
        result = self._values.get("min_success_percentage")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def pause_time(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The pause time after making a change to a batch of instances.

        :default: - The ``timeout`` configured for ``signals`` on the AutoScalingGroup
        '''
        result = self._values.get("pause_time")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def suspend_processes(self) -> typing.Optional[typing.List["ScalingProcess"]]:
        '''Specifies the Auto Scaling processes to suspend during a stack update.

        Suspending processes prevents Auto Scaling from interfering with a stack
        update.

        :default: HealthCheck, ReplaceUnhealthy, AZRebalance, AlarmNotification, ScheduledActions.
        '''
        result = self._values.get("suspend_processes")
        return typing.cast(typing.Optional[typing.List["ScalingProcess"]], result)

    @builtins.property
    def wait_on_resource_signals(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether the Auto Scaling group waits on signals from new instances during an update.

        :default: true if you configured ``signals`` on the AutoScalingGroup, false otherwise
        '''
        result = self._values.get("wait_on_resource_signals")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "RollingUpdateOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_autoscaling.ScalingEvent")
class ScalingEvent(enum.Enum):
    '''Fleet scaling events.'''

    INSTANCE_LAUNCH = "INSTANCE_LAUNCH"
    '''Notify when an instance was launched.'''
    INSTANCE_TERMINATE = "INSTANCE_TERMINATE"
    '''Notify when an instance was terminated.'''
    INSTANCE_TERMINATE_ERROR = "INSTANCE_TERMINATE_ERROR"
    '''Notify when an instance failed to terminate.'''
    INSTANCE_LAUNCH_ERROR = "INSTANCE_LAUNCH_ERROR"
    '''Notify when an instance failed to launch.'''
    TEST_NOTIFICATION = "TEST_NOTIFICATION"
    '''Send a test notification to the topic.'''


class ScalingEvents(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.ScalingEvents",
):
    '''A list of ScalingEvents, you can use one of the predefined lists, such as ScalingEvents.ERRORS or create a custom group by instantiating a ``NotificationTypes`` object, e.g: ``new NotificationTypes(``NotificationType.INSTANCE_LAUNCH``)``.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_autoscaling as autoscaling
        
        scaling_events = autoscaling.ScalingEvents.ALL
    '''

    def __init__(self, *types: ScalingEvent) -> None:
        '''
        :param types: -
        '''
        jsii.create(self.__class__, self, [*types])

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="ALL")
    def ALL(cls) -> "ScalingEvents":
        '''All fleet scaling events.'''
        return typing.cast("ScalingEvents", jsii.sget(cls, "ALL"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="ERRORS")
    def ERRORS(cls) -> "ScalingEvents":
        '''Fleet scaling errors.'''
        return typing.cast("ScalingEvents", jsii.sget(cls, "ERRORS"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="LAUNCH_EVENTS")
    def LAUNCH_EVENTS(cls) -> "ScalingEvents":
        '''Fleet scaling launch events.'''
        return typing.cast("ScalingEvents", jsii.sget(cls, "LAUNCH_EVENTS"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="TERMINATION_EVENTS")
    def TERMINATION_EVENTS(cls) -> "ScalingEvents":
        '''Fleet termination launch events.'''
        return typing.cast("ScalingEvents", jsii.sget(cls, "TERMINATION_EVENTS"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.ScalingInterval",
    jsii_struct_bases=[],
    name_mapping={"change": "change", "lower": "lower", "upper": "upper"},
)
class ScalingInterval:
    def __init__(
        self,
        *,
        change: jsii.Number,
        lower: typing.Optional[jsii.Number] = None,
        upper: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''A range of metric values in which to apply a certain scaling operation.

        :param change: The capacity adjustment to apply in this interval. The number is interpreted differently based on AdjustmentType: - ChangeInCapacity: add the adjustment to the current capacity. The number can be positive or negative. - PercentChangeInCapacity: add or remove the given percentage of the current capacity to itself. The number can be in the range [-100..100]. - ExactCapacity: set the capacity to this number. The number must be positive.
        :param lower: The lower bound of the interval. The scaling adjustment will be applied if the metric is higher than this value. Default: Threshold automatically derived from neighbouring intervals
        :param upper: The upper bound of the interval. The scaling adjustment will be applied if the metric is lower than this value. Default: Threshold automatically derived from neighbouring intervals

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            scaling_interval = autoscaling.ScalingInterval(
                change=123,
            
                # the properties below are optional
                lower=123,
                upper=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "change": change,
        }
        if lower is not None:
            self._values["lower"] = lower
        if upper is not None:
            self._values["upper"] = upper

    @builtins.property
    def change(self) -> jsii.Number:
        '''The capacity adjustment to apply in this interval.

        The number is interpreted differently based on AdjustmentType:

        - ChangeInCapacity: add the adjustment to the current capacity.
          The number can be positive or negative.
        - PercentChangeInCapacity: add or remove the given percentage of the current
          capacity to itself. The number can be in the range [-100..100].
        - ExactCapacity: set the capacity to this number. The number must
          be positive.
        '''
        result = self._values.get("change")
        assert result is not None, "Required property 'change' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def lower(self) -> typing.Optional[jsii.Number]:
        '''The lower bound of the interval.

        The scaling adjustment will be applied if the metric is higher than this value.

        :default: Threshold automatically derived from neighbouring intervals
        '''
        result = self._values.get("lower")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def upper(self) -> typing.Optional[jsii.Number]:
        '''The upper bound of the interval.

        The scaling adjustment will be applied if the metric is lower than this value.

        :default: Threshold automatically derived from neighbouring intervals
        '''
        result = self._values.get("upper")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ScalingInterval(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_autoscaling.ScalingProcess")
class ScalingProcess(enum.Enum):
    LAUNCH = "LAUNCH"
    TERMINATE = "TERMINATE"
    HEALTH_CHECK = "HEALTH_CHECK"
    REPLACE_UNHEALTHY = "REPLACE_UNHEALTHY"
    AZ_REBALANCE = "AZ_REBALANCE"
    ALARM_NOTIFICATION = "ALARM_NOTIFICATION"
    SCHEDULED_ACTIONS = "SCHEDULED_ACTIONS"
    ADD_TO_LOAD_BALANCER = "ADD_TO_LOAD_BALANCER"


class Schedule(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_autoscaling.Schedule",
):
    '''Schedule for scheduled scaling actions.

    :exampleMetadata: infused

    Example::

        # auto_scaling_group: autoscaling.AutoScalingGroup
        
        
        auto_scaling_group.scale_on_schedule("PrescaleInTheMorning",
            schedule=autoscaling.Schedule.cron(hour="8", minute="0"),
            min_capacity=20
        )
        
        auto_scaling_group.scale_on_schedule("AllowDownscalingAtNight",
            schedule=autoscaling.Schedule.cron(hour="20", minute="0"),
            min_capacity=1
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
    ) -> "Schedule":
        '''Create a schedule from a set of cron fields.

        :param day: The day of the month to run this rule at. Default: - Every day of the month
        :param hour: The hour to run this rule at. Default: - Every hour
        :param minute: The minute to run this rule at. Default: - Every minute
        :param month: The month to run this rule at. Default: - Every month
        :param week_day: The day of the week to run this rule at. Default: - Any day of the week
        '''
        options = CronOptions(
            day=day, hour=hour, minute=minute, month=month, week_day=week_day
        )

        return typing.cast("Schedule", jsii.sinvoke(cls, "cron", [options]))

    @jsii.member(jsii_name="expression") # type: ignore[misc]
    @builtins.classmethod
    def expression(cls, expression: builtins.str) -> "Schedule":
        '''Construct a schedule from a literal schedule expression.

        :param expression: The expression to use. Must be in a format that AutoScaling will recognize

        :see: http://crontab.org/
        '''
        return typing.cast("Schedule", jsii.sinvoke(cls, "expression", [expression]))

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


class ScheduledAction(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.ScheduledAction",
):
    '''Define a scheduled scaling action.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_autoscaling as autoscaling
        
        # auto_scaling_group: autoscaling.AutoScalingGroup
        # schedule: autoscaling.Schedule
        
        scheduled_action = autoscaling.ScheduledAction(self, "MyScheduledAction",
            auto_scaling_group=auto_scaling_group,
            schedule=schedule,
        
            # the properties below are optional
            desired_capacity=123,
            end_time=Date(),
            max_capacity=123,
            min_capacity=123,
            start_time=Date(),
            time_zone="timeZone"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        auto_scaling_group: IAutoScalingGroup,
        schedule: Schedule,
        desired_capacity: typing.Optional[jsii.Number] = None,
        end_time: typing.Optional[datetime.datetime] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
        start_time: typing.Optional[datetime.datetime] = None,
        time_zone: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param auto_scaling_group: The AutoScalingGroup to apply the scheduled actions to.
        :param schedule: When to perform this action. Supports cron expressions. For more information about cron expressions, see https://en.wikipedia.org/wiki/Cron.
        :param desired_capacity: The new desired capacity. At the scheduled time, set the desired capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new desired capacity.
        :param end_time: When this scheduled action expires. Default: - The rule never expires.
        :param max_capacity: The new maximum capacity. At the scheduled time, set the maximum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new maximum capacity.
        :param min_capacity: The new minimum capacity. At the scheduled time, set the minimum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new minimum capacity.
        :param start_time: When this scheduled action becomes active. Default: - The rule is activate immediately.
        :param time_zone: Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default. Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as Etc/GMT+9 or Pacific/Tahiti). For more information, see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones. Default: - UTC
        '''
        props = ScheduledActionProps(
            auto_scaling_group=auto_scaling_group,
            schedule=schedule,
            desired_capacity=desired_capacity,
            end_time=end_time,
            max_capacity=max_capacity,
            min_capacity=min_capacity,
            start_time=start_time,
            time_zone=time_zone,
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.ScheduledActionProps",
    jsii_struct_bases=[BasicScheduledActionProps],
    name_mapping={
        "schedule": "schedule",
        "desired_capacity": "desiredCapacity",
        "end_time": "endTime",
        "max_capacity": "maxCapacity",
        "min_capacity": "minCapacity",
        "start_time": "startTime",
        "time_zone": "timeZone",
        "auto_scaling_group": "autoScalingGroup",
    },
)
class ScheduledActionProps(BasicScheduledActionProps):
    def __init__(
        self,
        *,
        schedule: Schedule,
        desired_capacity: typing.Optional[jsii.Number] = None,
        end_time: typing.Optional[datetime.datetime] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
        start_time: typing.Optional[datetime.datetime] = None,
        time_zone: typing.Optional[builtins.str] = None,
        auto_scaling_group: IAutoScalingGroup,
    ) -> None:
        '''Properties for a scheduled action on an AutoScalingGroup.

        :param schedule: When to perform this action. Supports cron expressions. For more information about cron expressions, see https://en.wikipedia.org/wiki/Cron.
        :param desired_capacity: The new desired capacity. At the scheduled time, set the desired capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new desired capacity.
        :param end_time: When this scheduled action expires. Default: - The rule never expires.
        :param max_capacity: The new maximum capacity. At the scheduled time, set the maximum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new maximum capacity.
        :param min_capacity: The new minimum capacity. At the scheduled time, set the minimum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new minimum capacity.
        :param start_time: When this scheduled action becomes active. Default: - The rule is activate immediately.
        :param time_zone: Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default. Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as Etc/GMT+9 or Pacific/Tahiti). For more information, see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones. Default: - UTC
        :param auto_scaling_group: The AutoScalingGroup to apply the scheduled actions to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            # auto_scaling_group: autoscaling.AutoScalingGroup
            # schedule: autoscaling.Schedule
            
            scheduled_action_props = autoscaling.ScheduledActionProps(
                auto_scaling_group=auto_scaling_group,
                schedule=schedule,
            
                # the properties below are optional
                desired_capacity=123,
                end_time=Date(),
                max_capacity=123,
                min_capacity=123,
                start_time=Date(),
                time_zone="timeZone"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "schedule": schedule,
            "auto_scaling_group": auto_scaling_group,
        }
        if desired_capacity is not None:
            self._values["desired_capacity"] = desired_capacity
        if end_time is not None:
            self._values["end_time"] = end_time
        if max_capacity is not None:
            self._values["max_capacity"] = max_capacity
        if min_capacity is not None:
            self._values["min_capacity"] = min_capacity
        if start_time is not None:
            self._values["start_time"] = start_time
        if time_zone is not None:
            self._values["time_zone"] = time_zone

    @builtins.property
    def schedule(self) -> Schedule:
        '''When to perform this action.

        Supports cron expressions.

        For more information about cron expressions, see https://en.wikipedia.org/wiki/Cron.
        '''
        result = self._values.get("schedule")
        assert result is not None, "Required property 'schedule' is missing"
        return typing.cast(Schedule, result)

    @builtins.property
    def desired_capacity(self) -> typing.Optional[jsii.Number]:
        '''The new desired capacity.

        At the scheduled time, set the desired capacity to the given capacity.

        At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied.

        :default: - No new desired capacity.
        '''
        result = self._values.get("desired_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def end_time(self) -> typing.Optional[datetime.datetime]:
        '''When this scheduled action expires.

        :default: - The rule never expires.
        '''
        result = self._values.get("end_time")
        return typing.cast(typing.Optional[datetime.datetime], result)

    @builtins.property
    def max_capacity(self) -> typing.Optional[jsii.Number]:
        '''The new maximum capacity.

        At the scheduled time, set the maximum capacity to the given capacity.

        At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied.

        :default: - No new maximum capacity.
        '''
        result = self._values.get("max_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_capacity(self) -> typing.Optional[jsii.Number]:
        '''The new minimum capacity.

        At the scheduled time, set the minimum capacity to the given capacity.

        At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied.

        :default: - No new minimum capacity.
        '''
        result = self._values.get("min_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def start_time(self) -> typing.Optional[datetime.datetime]:
        '''When this scheduled action becomes active.

        :default: - The rule is activate immediately.
        '''
        result = self._values.get("start_time")
        return typing.cast(typing.Optional[datetime.datetime], result)

    @builtins.property
    def time_zone(self) -> typing.Optional[builtins.str]:
        '''Specifies the time zone for a cron expression.

        If a time zone is not provided, UTC is used by default.

        Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as Etc/GMT+9 or Pacific/Tahiti).

        For more information, see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones.

        :default: - UTC
        '''
        result = self._values.get("time_zone")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def auto_scaling_group(self) -> IAutoScalingGroup:
        '''The AutoScalingGroup to apply the scheduled actions to.'''
        result = self._values.get("auto_scaling_group")
        assert result is not None, "Required property 'auto_scaling_group' is missing"
        return typing.cast(IAutoScalingGroup, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ScheduledActionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class Signals(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_autoscaling.Signals",
):
    '''Configure whether the AutoScalingGroup waits for signals.

    If you do configure waiting for signals, you should make sure the instances
    invoke ``cfn-signal`` somewhere in their UserData to signal that they have
    started up (either successfully or unsuccessfully).

    Signals are used both during intial creation and subsequent updates.

    :exampleMetadata: infused

    Example::

        # vpc: ec2.Vpc
        # instance_type: ec2.InstanceType
        # machine_image: ec2.IMachineImage
        
        
        autoscaling.AutoScalingGroup(self, "ASG",
            vpc=vpc,
            instance_type=instance_type,
            machine_image=machine_image,
        
            # ...
        
            init=ec2.CloudFormationInit.from_elements(
                ec2.InitFile.from_string("/etc/my_instance", "This got written during instance startup")),
            signals=autoscaling.Signals.wait_for_all(
                timeout=Duration.minutes(10)
            )
        )
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="waitForAll") # type: ignore[misc]
    @builtins.classmethod
    def wait_for_all(
        cls,
        *,
        min_success_percentage: typing.Optional[jsii.Number] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "Signals":
        '''Wait for the desiredCapacity of the AutoScalingGroup amount of signals to have been received.

        If no desiredCapacity has been configured, wait for minCapacity signals intead.

        This number is used during initial creation and during replacing updates.
        During rolling updates, all updated instances must send a signal.

        :param min_success_percentage: The percentage of signals that need to be successful. If this number is less than 100, a percentage of signals may be failure signals while still succeeding the creation or update in CloudFormation. Default: 100
        :param timeout: How long to wait for the signals to be sent. This should reflect how long it takes your instances to start up (including instance start time and instance initialization time). Default: Duration.minutes(5)
        '''
        options = SignalsOptions(
            min_success_percentage=min_success_percentage, timeout=timeout
        )

        return typing.cast("Signals", jsii.sinvoke(cls, "waitForAll", [options]))

    @jsii.member(jsii_name="waitForCount") # type: ignore[misc]
    @builtins.classmethod
    def wait_for_count(
        cls,
        count: jsii.Number,
        *,
        min_success_percentage: typing.Optional[jsii.Number] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "Signals":
        '''Wait for a specific amount of signals to have been received.

        You should send one signal per instance, so this represents the number of
        instances to wait for.

        This number is used during initial creation and during replacing updates.
        During rolling updates, all updated instances must send a signal.

        :param count: -
        :param min_success_percentage: The percentage of signals that need to be successful. If this number is less than 100, a percentage of signals may be failure signals while still succeeding the creation or update in CloudFormation. Default: 100
        :param timeout: How long to wait for the signals to be sent. This should reflect how long it takes your instances to start up (including instance start time and instance initialization time). Default: Duration.minutes(5)
        '''
        options = SignalsOptions(
            min_success_percentage=min_success_percentage, timeout=timeout
        )

        return typing.cast("Signals", jsii.sinvoke(cls, "waitForCount", [count, options]))

    @jsii.member(jsii_name="waitForMinCapacity") # type: ignore[misc]
    @builtins.classmethod
    def wait_for_min_capacity(
        cls,
        *,
        min_success_percentage: typing.Optional[jsii.Number] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> "Signals":
        '''Wait for the minCapacity of the AutoScalingGroup amount of signals to have been received.

        This number is used during initial creation and during replacing updates.
        During rolling updates, all updated instances must send a signal.

        :param min_success_percentage: The percentage of signals that need to be successful. If this number is less than 100, a percentage of signals may be failure signals while still succeeding the creation or update in CloudFormation. Default: 100
        :param timeout: How long to wait for the signals to be sent. This should reflect how long it takes your instances to start up (including instance start time and instance initialization time). Default: Duration.minutes(5)
        '''
        options = SignalsOptions(
            min_success_percentage=min_success_percentage, timeout=timeout
        )

        return typing.cast("Signals", jsii.sinvoke(cls, "waitForMinCapacity", [options]))

    @jsii.member(jsii_name="doRender")
    def _do_render(
        self,
        options: "SignalsOptions",
        count: typing.Optional[jsii.Number] = None,
    ) -> _CfnCreationPolicy_d904f690:
        '''Helper to render the actual creation policy, as the logic between them is quite similar.

        :param options: -
        :param count: -
        '''
        return typing.cast(_CfnCreationPolicy_d904f690, jsii.invoke(self, "doRender", [options, count]))

    @jsii.member(jsii_name="renderCreationPolicy") # type: ignore[misc]
    @abc.abstractmethod
    def render_creation_policy(
        self,
        *,
        desired_capacity: typing.Optional[jsii.Number] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
    ) -> _CfnCreationPolicy_d904f690:
        '''Render the ASG's CreationPolicy.

        :param desired_capacity: The desiredCapacity of the ASG. Default: - desired capacity not configured
        :param min_capacity: The minSize of the ASG. Default: - minCapacity not configured
        '''
        ...


class _SignalsProxy(Signals):
    @jsii.member(jsii_name="renderCreationPolicy")
    def render_creation_policy(
        self,
        *,
        desired_capacity: typing.Optional[jsii.Number] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
    ) -> _CfnCreationPolicy_d904f690:
        '''Render the ASG's CreationPolicy.

        :param desired_capacity: The desiredCapacity of the ASG. Default: - desired capacity not configured
        :param min_capacity: The minSize of the ASG. Default: - minCapacity not configured
        '''
        render_options = RenderSignalsOptions(
            desired_capacity=desired_capacity, min_capacity=min_capacity
        )

        return typing.cast(_CfnCreationPolicy_d904f690, jsii.invoke(self, "renderCreationPolicy", [render_options]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, Signals).__jsii_proxy_class__ = lambda : _SignalsProxy


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.SignalsOptions",
    jsii_struct_bases=[],
    name_mapping={
        "min_success_percentage": "minSuccessPercentage",
        "timeout": "timeout",
    },
)
class SignalsOptions:
    def __init__(
        self,
        *,
        min_success_percentage: typing.Optional[jsii.Number] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Customization options for Signal handling.

        :param min_success_percentage: The percentage of signals that need to be successful. If this number is less than 100, a percentage of signals may be failure signals while still succeeding the creation or update in CloudFormation. Default: 100
        :param timeout: How long to wait for the signals to be sent. This should reflect how long it takes your instances to start up (including instance start time and instance initialization time). Default: Duration.minutes(5)

        :exampleMetadata: infused

        Example::

            # vpc: ec2.Vpc
            # instance_type: ec2.InstanceType
            # machine_image: ec2.IMachineImage
            
            
            autoscaling.AutoScalingGroup(self, "ASG",
                vpc=vpc,
                instance_type=instance_type,
                machine_image=machine_image,
            
                # ...
            
                init=ec2.CloudFormationInit.from_elements(
                    ec2.InitFile.from_string("/etc/my_instance", "This got written during instance startup")),
                signals=autoscaling.Signals.wait_for_all(
                    timeout=Duration.minutes(10)
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if min_success_percentage is not None:
            self._values["min_success_percentage"] = min_success_percentage
        if timeout is not None:
            self._values["timeout"] = timeout

    @builtins.property
    def min_success_percentage(self) -> typing.Optional[jsii.Number]:
        '''The percentage of signals that need to be successful.

        If this number is less than 100, a percentage of signals may be failure
        signals while still succeeding the creation or update in CloudFormation.

        :default: 100
        '''
        result = self._values.get("min_success_percentage")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''How long to wait for the signals to be sent.

        This should reflect how long it takes your instances to start up
        (including instance start time and instance initialization time).

        :default: Duration.minutes(5)
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "SignalsOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class StepScalingAction(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.StepScalingAction",
):
    '''Define a step scaling action.

    This kind of scaling policy adjusts the target capacity in configurable
    steps. The size of the step is configurable based on the metric's distance
    to its alarm threshold.

    This Action must be used as the target of a CloudWatch alarm to take effect.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_autoscaling as autoscaling
        
        # auto_scaling_group: autoscaling.AutoScalingGroup
        
        step_scaling_action = autoscaling.StepScalingAction(self, "MyStepScalingAction",
            auto_scaling_group=auto_scaling_group,
        
            # the properties below are optional
            adjustment_type=autoscaling.AdjustmentType.CHANGE_IN_CAPACITY,
            cooldown=cdk.Duration.minutes(30),
            estimated_instance_warmup=cdk.Duration.minutes(30),
            metric_aggregation_type=autoscaling.MetricAggregationType.AVERAGE,
            min_adjustment_magnitude=123
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        auto_scaling_group: IAutoScalingGroup,
        adjustment_type: typing.Optional[AdjustmentType] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        metric_aggregation_type: typing.Optional[MetricAggregationType] = None,
        min_adjustment_magnitude: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param auto_scaling_group: The auto scaling group.
        :param adjustment_type: How the adjustment numbers are interpreted. Default: ChangeInCapacity
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: The default cooldown configured on the AutoScalingGroup
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: Same as the cooldown
        :param metric_aggregation_type: The aggregation type for the CloudWatch metrics. Default: Average
        :param min_adjustment_magnitude: Minimum absolute number to adjust capacity with as result of percentage scaling. Only when using AdjustmentType = PercentChangeInCapacity, this number controls the minimum absolute effect size. Default: No minimum scaling effect
        '''
        props = StepScalingActionProps(
            auto_scaling_group=auto_scaling_group,
            adjustment_type=adjustment_type,
            cooldown=cooldown,
            estimated_instance_warmup=estimated_instance_warmup,
            metric_aggregation_type=metric_aggregation_type,
            min_adjustment_magnitude=min_adjustment_magnitude,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="addAdjustment")
    def add_adjustment(
        self,
        *,
        adjustment: jsii.Number,
        lower_bound: typing.Optional[jsii.Number] = None,
        upper_bound: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Add an adjusment interval to the ScalingAction.

        :param adjustment: What number to adjust the capacity with. The number is interpeted as an added capacity, a new fixed capacity or an added percentage depending on the AdjustmentType value of the StepScalingPolicy. Can be positive or negative.
        :param lower_bound: Lower bound where this scaling tier applies. The scaling tier applies if the difference between the metric value and its alarm threshold is higher than this value. Default: -Infinity if this is the first tier, otherwise the upperBound of the previous tier
        :param upper_bound: Upper bound where this scaling tier applies. The scaling tier applies if the difference between the metric value and its alarm threshold is lower than this value. Default: +Infinity
        '''
        adjustment_ = AdjustmentTier(
            adjustment=adjustment, lower_bound=lower_bound, upper_bound=upper_bound
        )

        return typing.cast(None, jsii.invoke(self, "addAdjustment", [adjustment_]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scalingPolicyArn")
    def scaling_policy_arn(self) -> builtins.str:
        '''ARN of the scaling policy.'''
        return typing.cast(builtins.str, jsii.get(self, "scalingPolicyArn"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.StepScalingActionProps",
    jsii_struct_bases=[],
    name_mapping={
        "auto_scaling_group": "autoScalingGroup",
        "adjustment_type": "adjustmentType",
        "cooldown": "cooldown",
        "estimated_instance_warmup": "estimatedInstanceWarmup",
        "metric_aggregation_type": "metricAggregationType",
        "min_adjustment_magnitude": "minAdjustmentMagnitude",
    },
)
class StepScalingActionProps:
    def __init__(
        self,
        *,
        auto_scaling_group: IAutoScalingGroup,
        adjustment_type: typing.Optional[AdjustmentType] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        metric_aggregation_type: typing.Optional[MetricAggregationType] = None,
        min_adjustment_magnitude: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''Properties for a scaling policy.

        :param auto_scaling_group: The auto scaling group.
        :param adjustment_type: How the adjustment numbers are interpreted. Default: ChangeInCapacity
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: The default cooldown configured on the AutoScalingGroup
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: Same as the cooldown
        :param metric_aggregation_type: The aggregation type for the CloudWatch metrics. Default: Average
        :param min_adjustment_magnitude: Minimum absolute number to adjust capacity with as result of percentage scaling. Only when using AdjustmentType = PercentChangeInCapacity, this number controls the minimum absolute effect size. Default: No minimum scaling effect

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            
            # auto_scaling_group: autoscaling.AutoScalingGroup
            
            step_scaling_action_props = autoscaling.StepScalingActionProps(
                auto_scaling_group=auto_scaling_group,
            
                # the properties below are optional
                adjustment_type=autoscaling.AdjustmentType.CHANGE_IN_CAPACITY,
                cooldown=cdk.Duration.minutes(30),
                estimated_instance_warmup=cdk.Duration.minutes(30),
                metric_aggregation_type=autoscaling.MetricAggregationType.AVERAGE,
                min_adjustment_magnitude=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "auto_scaling_group": auto_scaling_group,
        }
        if adjustment_type is not None:
            self._values["adjustment_type"] = adjustment_type
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if estimated_instance_warmup is not None:
            self._values["estimated_instance_warmup"] = estimated_instance_warmup
        if metric_aggregation_type is not None:
            self._values["metric_aggregation_type"] = metric_aggregation_type
        if min_adjustment_magnitude is not None:
            self._values["min_adjustment_magnitude"] = min_adjustment_magnitude

    @builtins.property
    def auto_scaling_group(self) -> IAutoScalingGroup:
        '''The auto scaling group.'''
        result = self._values.get("auto_scaling_group")
        assert result is not None, "Required property 'auto_scaling_group' is missing"
        return typing.cast(IAutoScalingGroup, result)

    @builtins.property
    def adjustment_type(self) -> typing.Optional[AdjustmentType]:
        '''How the adjustment numbers are interpreted.

        :default: ChangeInCapacity
        '''
        result = self._values.get("adjustment_type")
        return typing.cast(typing.Optional[AdjustmentType], result)

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Period after a scaling completes before another scaling activity can start.

        :default: The default cooldown configured on the AutoScalingGroup
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def estimated_instance_warmup(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Estimated time until a newly launched instance can send metrics to CloudWatch.

        :default: Same as the cooldown
        '''
        result = self._values.get("estimated_instance_warmup")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def metric_aggregation_type(self) -> typing.Optional[MetricAggregationType]:
        '''The aggregation type for the CloudWatch metrics.

        :default: Average
        '''
        result = self._values.get("metric_aggregation_type")
        return typing.cast(typing.Optional[MetricAggregationType], result)

    @builtins.property
    def min_adjustment_magnitude(self) -> typing.Optional[jsii.Number]:
        '''Minimum absolute number to adjust capacity with as result of percentage scaling.

        Only when using AdjustmentType = PercentChangeInCapacity, this number controls
        the minimum absolute effect size.

        :default: No minimum scaling effect
        '''
        result = self._values.get("min_adjustment_magnitude")
        return typing.cast(typing.Optional[jsii.Number], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StepScalingActionProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class StepScalingPolicy(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.StepScalingPolicy",
):
    '''Define a acaling strategy which scales depending on absolute values of some metric.

    You can specify the scaling behavior for various values of the metric.

    Implemented using one or more CloudWatch alarms and Step Scaling Policies.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_autoscaling as autoscaling
        from aws_cdk import aws_cloudwatch as cloudwatch
        
        # auto_scaling_group: autoscaling.AutoScalingGroup
        # metric: cloudwatch.Metric
        
        step_scaling_policy = autoscaling.StepScalingPolicy(self, "MyStepScalingPolicy",
            auto_scaling_group=auto_scaling_group,
            metric=metric,
            scaling_steps=[autoscaling.ScalingInterval(
                change=123,
        
                # the properties below are optional
                lower=123,
                upper=123
            )],
        
            # the properties below are optional
            adjustment_type=autoscaling.AdjustmentType.CHANGE_IN_CAPACITY,
            cooldown=cdk.Duration.minutes(30),
            estimated_instance_warmup=cdk.Duration.minutes(30),
            evaluation_periods=123,
            metric_aggregation_type=autoscaling.MetricAggregationType.AVERAGE,
            min_adjustment_magnitude=123
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        auto_scaling_group: IAutoScalingGroup,
        metric: _IMetric_c7fd29de,
        scaling_steps: typing.Sequence[ScalingInterval],
        adjustment_type: typing.Optional[AdjustmentType] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        evaluation_periods: typing.Optional[jsii.Number] = None,
        metric_aggregation_type: typing.Optional[MetricAggregationType] = None,
        min_adjustment_magnitude: typing.Optional[jsii.Number] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param auto_scaling_group: The auto scaling group.
        :param metric: Metric to scale on.
        :param scaling_steps: The intervals for scaling. Maps a range of metric values to a particular scaling behavior.
        :param adjustment_type: How the adjustment numbers inside 'intervals' are interpreted. Default: ChangeInCapacity
        :param cooldown: Grace period after scaling activity. Default: Default cooldown period on your AutoScalingGroup
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: Same as the cooldown
        :param evaluation_periods: How many evaluation periods of the metric to wait before triggering a scaling action. Raising this value can be used to smooth out the metric, at the expense of slower response times. Default: 1
        :param metric_aggregation_type: Aggregation to apply to all data points over the evaluation periods. Only has meaning if ``evaluationPeriods != 1``. Default: - The statistic from the metric if applicable (MIN, MAX, AVERAGE), otherwise AVERAGE.
        :param min_adjustment_magnitude: Minimum absolute number to adjust capacity with as result of percentage scaling. Only when using AdjustmentType = PercentChangeInCapacity, this number controls the minimum absolute effect size. Default: No minimum scaling effect
        '''
        props = StepScalingPolicyProps(
            auto_scaling_group=auto_scaling_group,
            metric=metric,
            scaling_steps=scaling_steps,
            adjustment_type=adjustment_type,
            cooldown=cooldown,
            estimated_instance_warmup=estimated_instance_warmup,
            evaluation_periods=evaluation_periods,
            metric_aggregation_type=metric_aggregation_type,
            min_adjustment_magnitude=min_adjustment_magnitude,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lowerAction")
    def lower_action(self) -> typing.Optional[StepScalingAction]:
        return typing.cast(typing.Optional[StepScalingAction], jsii.get(self, "lowerAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="lowerAlarm")
    def lower_alarm(self) -> typing.Optional[_Alarm_9fbab1f1]:
        return typing.cast(typing.Optional[_Alarm_9fbab1f1], jsii.get(self, "lowerAlarm"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="upperAction")
    def upper_action(self) -> typing.Optional[StepScalingAction]:
        return typing.cast(typing.Optional[StepScalingAction], jsii.get(self, "upperAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="upperAlarm")
    def upper_alarm(self) -> typing.Optional[_Alarm_9fbab1f1]:
        return typing.cast(typing.Optional[_Alarm_9fbab1f1], jsii.get(self, "upperAlarm"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.StepScalingPolicyProps",
    jsii_struct_bases=[BasicStepScalingPolicyProps],
    name_mapping={
        "metric": "metric",
        "scaling_steps": "scalingSteps",
        "adjustment_type": "adjustmentType",
        "cooldown": "cooldown",
        "estimated_instance_warmup": "estimatedInstanceWarmup",
        "evaluation_periods": "evaluationPeriods",
        "metric_aggregation_type": "metricAggregationType",
        "min_adjustment_magnitude": "minAdjustmentMagnitude",
        "auto_scaling_group": "autoScalingGroup",
    },
)
class StepScalingPolicyProps(BasicStepScalingPolicyProps):
    def __init__(
        self,
        *,
        metric: _IMetric_c7fd29de,
        scaling_steps: typing.Sequence[ScalingInterval],
        adjustment_type: typing.Optional[AdjustmentType] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        evaluation_periods: typing.Optional[jsii.Number] = None,
        metric_aggregation_type: typing.Optional[MetricAggregationType] = None,
        min_adjustment_magnitude: typing.Optional[jsii.Number] = None,
        auto_scaling_group: IAutoScalingGroup,
    ) -> None:
        '''
        :param metric: Metric to scale on.
        :param scaling_steps: The intervals for scaling. Maps a range of metric values to a particular scaling behavior.
        :param adjustment_type: How the adjustment numbers inside 'intervals' are interpreted. Default: ChangeInCapacity
        :param cooldown: Grace period after scaling activity. Default: Default cooldown period on your AutoScalingGroup
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: Same as the cooldown
        :param evaluation_periods: How many evaluation periods of the metric to wait before triggering a scaling action. Raising this value can be used to smooth out the metric, at the expense of slower response times. Default: 1
        :param metric_aggregation_type: Aggregation to apply to all data points over the evaluation periods. Only has meaning if ``evaluationPeriods != 1``. Default: - The statistic from the metric if applicable (MIN, MAX, AVERAGE), otherwise AVERAGE.
        :param min_adjustment_magnitude: Minimum absolute number to adjust capacity with as result of percentage scaling. Only when using AdjustmentType = PercentChangeInCapacity, this number controls the minimum absolute effect size. Default: No minimum scaling effect
        :param auto_scaling_group: The auto scaling group.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            from aws_cdk import aws_cloudwatch as cloudwatch
            
            # auto_scaling_group: autoscaling.AutoScalingGroup
            # metric: cloudwatch.Metric
            
            step_scaling_policy_props = autoscaling.StepScalingPolicyProps(
                auto_scaling_group=auto_scaling_group,
                metric=metric,
                scaling_steps=[autoscaling.ScalingInterval(
                    change=123,
            
                    # the properties below are optional
                    lower=123,
                    upper=123
                )],
            
                # the properties below are optional
                adjustment_type=autoscaling.AdjustmentType.CHANGE_IN_CAPACITY,
                cooldown=cdk.Duration.minutes(30),
                estimated_instance_warmup=cdk.Duration.minutes(30),
                evaluation_periods=123,
                metric_aggregation_type=autoscaling.MetricAggregationType.AVERAGE,
                min_adjustment_magnitude=123
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "metric": metric,
            "scaling_steps": scaling_steps,
            "auto_scaling_group": auto_scaling_group,
        }
        if adjustment_type is not None:
            self._values["adjustment_type"] = adjustment_type
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if estimated_instance_warmup is not None:
            self._values["estimated_instance_warmup"] = estimated_instance_warmup
        if evaluation_periods is not None:
            self._values["evaluation_periods"] = evaluation_periods
        if metric_aggregation_type is not None:
            self._values["metric_aggregation_type"] = metric_aggregation_type
        if min_adjustment_magnitude is not None:
            self._values["min_adjustment_magnitude"] = min_adjustment_magnitude

    @builtins.property
    def metric(self) -> _IMetric_c7fd29de:
        '''Metric to scale on.'''
        result = self._values.get("metric")
        assert result is not None, "Required property 'metric' is missing"
        return typing.cast(_IMetric_c7fd29de, result)

    @builtins.property
    def scaling_steps(self) -> typing.List[ScalingInterval]:
        '''The intervals for scaling.

        Maps a range of metric values to a particular scaling behavior.
        '''
        result = self._values.get("scaling_steps")
        assert result is not None, "Required property 'scaling_steps' is missing"
        return typing.cast(typing.List[ScalingInterval], result)

    @builtins.property
    def adjustment_type(self) -> typing.Optional[AdjustmentType]:
        '''How the adjustment numbers inside 'intervals' are interpreted.

        :default: ChangeInCapacity
        '''
        result = self._values.get("adjustment_type")
        return typing.cast(typing.Optional[AdjustmentType], result)

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Grace period after scaling activity.

        :default: Default cooldown period on your AutoScalingGroup
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def estimated_instance_warmup(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Estimated time until a newly launched instance can send metrics to CloudWatch.

        :default: Same as the cooldown
        '''
        result = self._values.get("estimated_instance_warmup")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def evaluation_periods(self) -> typing.Optional[jsii.Number]:
        '''How many evaluation periods of the metric to wait before triggering a scaling action.

        Raising this value can be used to smooth out the metric, at the expense
        of slower response times.

        :default: 1
        '''
        result = self._values.get("evaluation_periods")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def metric_aggregation_type(self) -> typing.Optional[MetricAggregationType]:
        '''Aggregation to apply to all data points over the evaluation periods.

        Only has meaning if ``evaluationPeriods != 1``.

        :default: - The statistic from the metric if applicable (MIN, MAX, AVERAGE), otherwise AVERAGE.
        '''
        result = self._values.get("metric_aggregation_type")
        return typing.cast(typing.Optional[MetricAggregationType], result)

    @builtins.property
    def min_adjustment_magnitude(self) -> typing.Optional[jsii.Number]:
        '''Minimum absolute number to adjust capacity with as result of percentage scaling.

        Only when using AdjustmentType = PercentChangeInCapacity, this number controls
        the minimum absolute effect size.

        :default: No minimum scaling effect
        '''
        result = self._values.get("min_adjustment_magnitude")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def auto_scaling_group(self) -> IAutoScalingGroup:
        '''The auto scaling group.'''
        result = self._values.get("auto_scaling_group")
        assert result is not None, "Required property 'auto_scaling_group' is missing"
        return typing.cast(IAutoScalingGroup, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "StepScalingPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class TargetTrackingScalingPolicy(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.TargetTrackingScalingPolicy",
):
    '''
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        import aws_cdk as cdk
        from aws_cdk import aws_autoscaling as autoscaling
        from aws_cdk import aws_cloudwatch as cloudwatch
        
        # auto_scaling_group: autoscaling.AutoScalingGroup
        # metric: cloudwatch.Metric
        
        target_tracking_scaling_policy = autoscaling.TargetTrackingScalingPolicy(self, "MyTargetTrackingScalingPolicy",
            auto_scaling_group=auto_scaling_group,
            target_value=123,
        
            # the properties below are optional
            cooldown=cdk.Duration.minutes(30),
            custom_metric=metric,
            disable_scale_in=False,
            estimated_instance_warmup=cdk.Duration.minutes(30),
            predefined_metric=autoscaling.PredefinedMetric.ASG_AVERAGE_CPU_UTILIZATION,
            resource_label="resourceLabel"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        auto_scaling_group: IAutoScalingGroup,
        target_value: jsii.Number,
        custom_metric: typing.Optional[_IMetric_c7fd29de] = None,
        predefined_metric: typing.Optional[PredefinedMetric] = None,
        resource_label: typing.Optional[builtins.str] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param auto_scaling_group: 
        :param target_value: The target value for the metric.
        :param custom_metric: A custom metric for application autoscaling. The metric must track utilization. Scaling out will happen if the metric is higher than the target value, scaling in will happen in the metric is lower than the target value. Exactly one of customMetric or predefinedMetric must be specified. Default: - No custom metric.
        :param predefined_metric: A predefined metric for application autoscaling. The metric must track utilization. Scaling out will happen if the metric is higher than the target value, scaling in will happen in the metric is lower than the target value. Exactly one of customMetric or predefinedMetric must be specified. Default: - No predefined metric.
        :param resource_label: The resource label associated with the predefined metric. Should be supplied if the predefined metric is ALBRequestCountPerTarget, and the format should be: app///targetgroup// Default: - No resource label.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        props = TargetTrackingScalingPolicyProps(
            auto_scaling_group=auto_scaling_group,
            target_value=target_value,
            custom_metric=custom_metric,
            predefined_metric=predefined_metric,
            resource_label=resource_label,
            cooldown=cooldown,
            disable_scale_in=disable_scale_in,
            estimated_instance_warmup=estimated_instance_warmup,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scalingPolicyArn")
    def scaling_policy_arn(self) -> builtins.str:
        '''ARN of the scaling policy.'''
        return typing.cast(builtins.str, jsii.get(self, "scalingPolicyArn"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.TargetTrackingScalingPolicyProps",
    jsii_struct_bases=[BasicTargetTrackingScalingPolicyProps],
    name_mapping={
        "cooldown": "cooldown",
        "disable_scale_in": "disableScaleIn",
        "estimated_instance_warmup": "estimatedInstanceWarmup",
        "target_value": "targetValue",
        "custom_metric": "customMetric",
        "predefined_metric": "predefinedMetric",
        "resource_label": "resourceLabel",
        "auto_scaling_group": "autoScalingGroup",
    },
)
class TargetTrackingScalingPolicyProps(BasicTargetTrackingScalingPolicyProps):
    def __init__(
        self,
        *,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        target_value: jsii.Number,
        custom_metric: typing.Optional[_IMetric_c7fd29de] = None,
        predefined_metric: typing.Optional[PredefinedMetric] = None,
        resource_label: typing.Optional[builtins.str] = None,
        auto_scaling_group: IAutoScalingGroup,
    ) -> None:
        '''Properties for a concrete TargetTrackingPolicy.

        Adds the scalingTarget.

        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        :param target_value: The target value for the metric.
        :param custom_metric: A custom metric for application autoscaling. The metric must track utilization. Scaling out will happen if the metric is higher than the target value, scaling in will happen in the metric is lower than the target value. Exactly one of customMetric or predefinedMetric must be specified. Default: - No custom metric.
        :param predefined_metric: A predefined metric for application autoscaling. The metric must track utilization. Scaling out will happen if the metric is higher than the target value, scaling in will happen in the metric is lower than the target value. Exactly one of customMetric or predefinedMetric must be specified. Default: - No predefined metric.
        :param resource_label: The resource label associated with the predefined metric. Should be supplied if the predefined metric is ALBRequestCountPerTarget, and the format should be: app///targetgroup// Default: - No resource label.
        :param auto_scaling_group: 

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_autoscaling as autoscaling
            from aws_cdk import aws_cloudwatch as cloudwatch
            
            # auto_scaling_group: autoscaling.AutoScalingGroup
            # metric: cloudwatch.Metric
            
            target_tracking_scaling_policy_props = autoscaling.TargetTrackingScalingPolicyProps(
                auto_scaling_group=auto_scaling_group,
                target_value=123,
            
                # the properties below are optional
                cooldown=cdk.Duration.minutes(30),
                custom_metric=metric,
                disable_scale_in=False,
                estimated_instance_warmup=cdk.Duration.minutes(30),
                predefined_metric=autoscaling.PredefinedMetric.ASG_AVERAGE_CPU_UTILIZATION,
                resource_label="resourceLabel"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "target_value": target_value,
            "auto_scaling_group": auto_scaling_group,
        }
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if disable_scale_in is not None:
            self._values["disable_scale_in"] = disable_scale_in
        if estimated_instance_warmup is not None:
            self._values["estimated_instance_warmup"] = estimated_instance_warmup
        if custom_metric is not None:
            self._values["custom_metric"] = custom_metric
        if predefined_metric is not None:
            self._values["predefined_metric"] = predefined_metric
        if resource_label is not None:
            self._values["resource_label"] = resource_label

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Period after a scaling completes before another scaling activity can start.

        :default: - The default cooldown configured on the AutoScalingGroup.
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def disable_scale_in(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether scale in by the target tracking policy is disabled.

        If the value is true, scale in is disabled and the target tracking policy
        won't remove capacity from the autoscaling group. Otherwise, scale in is
        enabled and the target tracking policy can remove capacity from the
        group.

        :default: false
        '''
        result = self._values.get("disable_scale_in")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def estimated_instance_warmup(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Estimated time until a newly launched instance can send metrics to CloudWatch.

        :default: - Same as the cooldown.
        '''
        result = self._values.get("estimated_instance_warmup")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def target_value(self) -> jsii.Number:
        '''The target value for the metric.'''
        result = self._values.get("target_value")
        assert result is not None, "Required property 'target_value' is missing"
        return typing.cast(jsii.Number, result)

    @builtins.property
    def custom_metric(self) -> typing.Optional[_IMetric_c7fd29de]:
        '''A custom metric for application autoscaling.

        The metric must track utilization. Scaling out will happen if the metric is higher than
        the target value, scaling in will happen in the metric is lower than the target value.

        Exactly one of customMetric or predefinedMetric must be specified.

        :default: - No custom metric.
        '''
        result = self._values.get("custom_metric")
        return typing.cast(typing.Optional[_IMetric_c7fd29de], result)

    @builtins.property
    def predefined_metric(self) -> typing.Optional[PredefinedMetric]:
        '''A predefined metric for application autoscaling.

        The metric must track utilization. Scaling out will happen if the metric is higher than
        the target value, scaling in will happen in the metric is lower than the target value.

        Exactly one of customMetric or predefinedMetric must be specified.

        :default: - No predefined metric.
        '''
        result = self._values.get("predefined_metric")
        return typing.cast(typing.Optional[PredefinedMetric], result)

    @builtins.property
    def resource_label(self) -> typing.Optional[builtins.str]:
        '''The resource label associated with the predefined metric.

        Should be supplied if the predefined metric is ALBRequestCountPerTarget, and the
        format should be:

        app///targetgroup//

        :default: - No resource label.
        '''
        result = self._values.get("resource_label")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def auto_scaling_group(self) -> IAutoScalingGroup:
        result = self._values.get("auto_scaling_group")
        assert result is not None, "Required property 'auto_scaling_group' is missing"
        return typing.cast(IAutoScalingGroup, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "TargetTrackingScalingPolicyProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_autoscaling.TerminationPolicy")
class TerminationPolicy(enum.Enum):
    '''Specifies the termination criteria to apply before Amazon EC2 Auto Scaling chooses an instance for termination.

    :exampleMetadata: infused

    Example::

        # vpc: ec2.Vpc
        # instance_type: ec2.InstanceType
        # machine_image: ec2.IMachineImage
        
        
        autoscaling.AutoScalingGroup(self, "ASG",
            vpc=vpc,
            instance_type=instance_type,
            machine_image=machine_image,
        
            # ...
        
            termination_policies=[autoscaling.TerminationPolicy.OLDEST_INSTANCE, autoscaling.TerminationPolicy.DEFAULT
            ]
        )
    '''

    ALLOCATION_STRATEGY = "ALLOCATION_STRATEGY"
    '''Terminate instances in the Auto Scaling group to align the remaining instances to the allocation strategy for the type of instance that is terminating (either a Spot Instance or an On-Demand Instance).'''
    CLOSEST_TO_NEXT_INSTANCE_HOUR = "CLOSEST_TO_NEXT_INSTANCE_HOUR"
    '''Terminate instances that are closest to the next billing hour.'''
    DEFAULT = "DEFAULT"
    '''Terminate instances according to the default termination policy.'''
    NEWEST_INSTANCE = "NEWEST_INSTANCE"
    '''Terminate the newest instance in the group.'''
    OLDEST_INSTANCE = "OLDEST_INSTANCE"
    '''Terminate the oldest instance in the group.'''
    OLDEST_LAUNCH_CONFIGURATION = "OLDEST_LAUNCH_CONFIGURATION"
    '''Terminate instances that have the oldest launch configuration.'''
    OLDEST_LAUNCH_TEMPLATE = "OLDEST_LAUNCH_TEMPLATE"
    '''Terminate instances that have the oldest launch template.'''


class UpdatePolicy(
    metaclass=jsii.JSIIAbstractClass,
    jsii_type="aws-cdk-lib.aws_autoscaling.UpdatePolicy",
):
    '''How existing instances should be updated.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_autoscaling as autoscaling
        
        update_policy = autoscaling.UpdatePolicy.replacing_update()
    '''

    def __init__(self) -> None:
        jsii.create(self.__class__, self, [])

    @jsii.member(jsii_name="replacingUpdate") # type: ignore[misc]
    @builtins.classmethod
    def replacing_update(cls) -> "UpdatePolicy":
        '''Create a new AutoScalingGroup and switch over to it.'''
        return typing.cast("UpdatePolicy", jsii.sinvoke(cls, "replacingUpdate", []))

    @jsii.member(jsii_name="rollingUpdate") # type: ignore[misc]
    @builtins.classmethod
    def rolling_update(
        cls,
        *,
        max_batch_size: typing.Optional[jsii.Number] = None,
        min_instances_in_service: typing.Optional[jsii.Number] = None,
        min_success_percentage: typing.Optional[jsii.Number] = None,
        pause_time: typing.Optional[_Duration_4839e8c3] = None,
        suspend_processes: typing.Optional[typing.Sequence[ScalingProcess]] = None,
        wait_on_resource_signals: typing.Optional[builtins.bool] = None,
    ) -> "UpdatePolicy":
        '''Replace the instances in the AutoScalingGroup one by one, or in batches.

        :param max_batch_size: The maximum number of instances that AWS CloudFormation updates at once. This number affects the speed of the replacement. Default: 1
        :param min_instances_in_service: The minimum number of instances that must be in service before more instances are replaced. This number affects the speed of the replacement. Default: 0
        :param min_success_percentage: The percentage of instances that must signal success for the update to succeed. Default: - The ``minSuccessPercentage`` configured for ``signals`` on the AutoScalingGroup
        :param pause_time: The pause time after making a change to a batch of instances. Default: - The ``timeout`` configured for ``signals`` on the AutoScalingGroup
        :param suspend_processes: Specifies the Auto Scaling processes to suspend during a stack update. Suspending processes prevents Auto Scaling from interfering with a stack update. Default: HealthCheck, ReplaceUnhealthy, AZRebalance, AlarmNotification, ScheduledActions.
        :param wait_on_resource_signals: Specifies whether the Auto Scaling group waits on signals from new instances during an update. Default: true if you configured ``signals`` on the AutoScalingGroup, false otherwise
        '''
        options = RollingUpdateOptions(
            max_batch_size=max_batch_size,
            min_instances_in_service=min_instances_in_service,
            min_success_percentage=min_success_percentage,
            pause_time=pause_time,
            suspend_processes=suspend_processes,
            wait_on_resource_signals=wait_on_resource_signals,
        )

        return typing.cast("UpdatePolicy", jsii.sinvoke(cls, "rollingUpdate", [options]))


class _UpdatePolicyProxy(UpdatePolicy):
    pass

# Adding a "__jsii_proxy_class__(): typing.Type" function to the abstract class
typing.cast(typing.Any, UpdatePolicy).__jsii_proxy_class__ = lambda : _UpdatePolicyProxy


@jsii.implements(_ILoadBalancerTarget_2e052b5c, _IConnectable_10015a05, _IApplicationLoadBalancerTarget_fabf9003, _INetworkLoadBalancerTarget_688b169f, IAutoScalingGroup)
class AutoScalingGroup(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_autoscaling.AutoScalingGroup",
):
    '''A Fleet represents a managed set of EC2 instances.

    The Fleet models a number of AutoScalingGroups, a launch configuration, a
    security group and an instance role.

    It allows adding arbitrary commands to the startup scripts of the instances
    in the fleet.

    The ASG spans the availability zones specified by vpcSubnets, falling back to
    the Vpc default strategy if not specified.

    :exampleMetadata: infused

    Example::

        # vpc: ec2.Vpc
        
        
        my_security_group = ec2.SecurityGroup(self, "SecurityGroup", vpc=vpc)
        autoscaling.AutoScalingGroup(self, "ASG",
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
            machine_image=ec2.AmazonLinuxImage(),
            security_group=my_security_group
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        instance_type: _InstanceType_f64915b9,
        machine_image: _IMachineImage_0e8bd50b,
        vpc: _IVpc_f30d5663,
        init: typing.Optional[_CloudFormationInit_2bb1d1b2] = None,
        init_options: typing.Optional[ApplyCloudFormationInitOptions] = None,
        require_imdsv2: typing.Optional[builtins.bool] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        user_data: typing.Optional[_UserData_b8b32b5e] = None,
        allow_all_outbound: typing.Optional[builtins.bool] = None,
        associate_public_ip_address: typing.Optional[builtins.bool] = None,
        auto_scaling_group_name: typing.Optional[builtins.str] = None,
        block_devices: typing.Optional[typing.Sequence[BlockDevice]] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        desired_capacity: typing.Optional[jsii.Number] = None,
        group_metrics: typing.Optional[typing.Sequence[GroupMetrics]] = None,
        health_check: typing.Optional[HealthCheck] = None,
        ignore_unmodified_size_properties: typing.Optional[builtins.bool] = None,
        instance_monitoring: typing.Optional[Monitoring] = None,
        key_name: typing.Optional[builtins.str] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        max_instance_lifetime: typing.Optional[_Duration_4839e8c3] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
        new_instances_protected_from_scale_in: typing.Optional[builtins.bool] = None,
        notifications: typing.Optional[typing.Sequence[NotificationConfiguration]] = None,
        signals: typing.Optional[Signals] = None,
        spot_price: typing.Optional[builtins.str] = None,
        termination_policies: typing.Optional[typing.Sequence[TerminationPolicy]] = None,
        update_policy: typing.Optional[UpdatePolicy] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param instance_type: Type of instance to launch.
        :param machine_image: AMI to launch.
        :param vpc: VPC to launch these instances in.
        :param init: Apply the given CloudFormation Init configuration to the instances in the AutoScalingGroup at startup. If you specify ``init``, you must also specify ``signals`` to configure the number of instances to wait for and the timeout for waiting for the init process. Default: - no CloudFormation init
        :param init_options: Use the given options for applying CloudFormation Init. Describes the configsets to use and the timeout to wait Default: - default options
        :param require_imdsv2: Whether IMDSv2 should be required on launched instances. Default: - false
        :param role: An IAM role to associate with the instance profile assigned to this Auto Scaling Group. The role must be assumable by the service principal ``ec2.amazonaws.com``: Default: A role will automatically be created, it can be accessed via the ``role`` property
        :param security_group: Security group to launch the instances in. Default: - A SecurityGroup will be created if none is specified.
        :param user_data: Specific UserData to use. The UserData may still be mutated after creation. Default: - A UserData object appropriate for the MachineImage's Operating System is created.
        :param allow_all_outbound: Whether the instances can initiate connections to anywhere by default. Default: true
        :param associate_public_ip_address: Whether instances in the Auto Scaling Group should have public IP addresses associated with them. Default: - Use subnet setting.
        :param auto_scaling_group_name: The name of the Auto Scaling group. This name must be unique per Region per account. Default: - Auto generated by CloudFormation
        :param block_devices: Specifies how block devices are exposed to the instance. You can specify virtual devices and EBS volumes. Each instance that is launched has an associated root device volume, either an Amazon EBS volume or an instance store volume. You can use block device mappings to specify additional EBS volumes or instance store volumes to attach to an instance when it is launched. Default: - Uses the block device mapping of the AMI
        :param cooldown: Default scaling cooldown for this AutoScalingGroup. Default: Duration.minutes(5)
        :param desired_capacity: Initial amount of instances in the fleet. If this is set to a number, every deployment will reset the amount of instances to this number. It is recommended to leave this value blank. Default: minCapacity, and leave unchanged during deployment
        :param group_metrics: Enable monitoring for group metrics, these metrics describe the group rather than any of its instances. To report all group metrics use ``GroupMetrics.all()`` Group metrics are reported in a granularity of 1 minute at no additional charge. Default: - no group metrics will be reported
        :param health_check: Configuration for health checks. Default: - HealthCheck.ec2 with no grace period
        :param ignore_unmodified_size_properties: If the ASG has scheduled actions, don't reset unchanged group sizes. Only used if the ASG has scheduled actions (which may scale your ASG up or down regardless of cdk deployments). If true, the size of the group will only be reset if it has been changed in the CDK app. If false, the sizes will always be changed back to what they were in the CDK app on deployment. Default: true
        :param instance_monitoring: Controls whether instances in this group are launched with detailed or basic monitoring. When detailed monitoring is enabled, Amazon CloudWatch generates metrics every minute and your account is charged a fee. When you disable detailed monitoring, CloudWatch generates metrics every 5 minutes. Default: - Monitoring.DETAILED
        :param key_name: Name of SSH keypair to grant access to instances. Default: - No SSH access will be possible.
        :param max_capacity: Maximum number of instances in the fleet. Default: desiredCapacity
        :param max_instance_lifetime: The maximum amount of time that an instance can be in service. The maximum duration applies to all current and future instances in the group. As an instance approaches its maximum duration, it is terminated and replaced, and cannot be used again. You must specify a value of at least 604,800 seconds (7 days). To clear a previously set value, leave this property undefined. Default: none
        :param min_capacity: Minimum number of instances in the fleet. Default: 1
        :param new_instances_protected_from_scale_in: Whether newly-launched instances are protected from termination by Amazon EC2 Auto Scaling when scaling in. By default, Auto Scaling can terminate an instance at any time after launch when scaling in an Auto Scaling Group, subject to the group's termination policy. However, you may wish to protect newly-launched instances from being scaled in if they are going to run critical applications that should not be prematurely terminated. This flag must be enabled if the Auto Scaling Group will be associated with an ECS Capacity Provider with managed termination protection. Default: false
        :param notifications: Configure autoscaling group to send notifications about fleet changes to an SNS topic(s). Default: - No fleet change notifications will be sent.
        :param signals: Configure waiting for signals during deployment. Use this to pause the CloudFormation deployment to wait for the instances in the AutoScalingGroup to report successful startup during creation and updates. The UserData script needs to invoke ``cfn-signal`` with a success or failure code after it is done setting up the instance. Without waiting for signals, the CloudFormation deployment will proceed as soon as the AutoScalingGroup has been created or updated but before the instances in the group have been started. For example, to have instances wait for an Elastic Load Balancing health check before they signal success, add a health-check verification by using the cfn-init helper script. For an example, see the verify_instance_health command in the Auto Scaling rolling updates sample template: https://github.com/awslabs/aws-cloudformation-templates/blob/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml Default: - Do not wait for signals
        :param spot_price: The maximum hourly price (in USD) to be paid for any Spot Instance launched to fulfill the request. Spot Instances are launched when the price you specify exceeds the current Spot market price. Default: none
        :param termination_policies: A policy or a list of policies that are used to select the instances to terminate. The policies are executed in the order that you list them. Default: - ``TerminationPolicy.DEFAULT``
        :param update_policy: What to do when an AutoScalingGroup's instance configuration is changed. This is applied when any of the settings on the ASG are changed that affect how the instances should be created (VPC, instance type, startup scripts, etc.). It indicates how the existing instances should be replaced with new instances matching the new config. By default, nothing is done and only new instances are launched with the new config. Default: - ``UpdatePolicy.rollingUpdate()`` if using ``init``, ``UpdatePolicy.none()`` otherwise
        :param vpc_subnets: Where to place instances within the VPC. Default: - All Private subnets.
        '''
        props = AutoScalingGroupProps(
            instance_type=instance_type,
            machine_image=machine_image,
            vpc=vpc,
            init=init,
            init_options=init_options,
            require_imdsv2=require_imdsv2,
            role=role,
            security_group=security_group,
            user_data=user_data,
            allow_all_outbound=allow_all_outbound,
            associate_public_ip_address=associate_public_ip_address,
            auto_scaling_group_name=auto_scaling_group_name,
            block_devices=block_devices,
            cooldown=cooldown,
            desired_capacity=desired_capacity,
            group_metrics=group_metrics,
            health_check=health_check,
            ignore_unmodified_size_properties=ignore_unmodified_size_properties,
            instance_monitoring=instance_monitoring,
            key_name=key_name,
            max_capacity=max_capacity,
            max_instance_lifetime=max_instance_lifetime,
            min_capacity=min_capacity,
            new_instances_protected_from_scale_in=new_instances_protected_from_scale_in,
            notifications=notifications,
            signals=signals,
            spot_price=spot_price,
            termination_policies=termination_policies,
            update_policy=update_policy,
            vpc_subnets=vpc_subnets,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromAutoScalingGroupName") # type: ignore[misc]
    @builtins.classmethod
    def from_auto_scaling_group_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        auto_scaling_group_name: builtins.str,
    ) -> IAutoScalingGroup:
        '''
        :param scope: -
        :param id: -
        :param auto_scaling_group_name: -
        '''
        return typing.cast(IAutoScalingGroup, jsii.sinvoke(cls, "fromAutoScalingGroupName", [scope, id, auto_scaling_group_name]))

    @jsii.member(jsii_name="addLifecycleHook")
    def add_lifecycle_hook(
        self,
        id: builtins.str,
        *,
        lifecycle_transition: LifecycleTransition,
        default_result: typing.Optional[DefaultResult] = None,
        heartbeat_timeout: typing.Optional[_Duration_4839e8c3] = None,
        lifecycle_hook_name: typing.Optional[builtins.str] = None,
        notification_metadata: typing.Optional[builtins.str] = None,
        notification_target: typing.Optional[ILifecycleHookTarget] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
    ) -> LifecycleHook:
        '''Send a message to either an SQS queue or SNS topic when instances launch or terminate.

        :param id: -
        :param lifecycle_transition: The state of the Amazon EC2 instance to which you want to attach the lifecycle hook.
        :param default_result: The action the Auto Scaling group takes when the lifecycle hook timeout elapses or if an unexpected failure occurs. Default: Continue
        :param heartbeat_timeout: Maximum time between calls to RecordLifecycleActionHeartbeat for the hook. If the lifecycle hook times out, perform the action in DefaultResult. Default: - No heartbeat timeout.
        :param lifecycle_hook_name: Name of the lifecycle hook. Default: - Automatically generated name.
        :param notification_metadata: Additional data to pass to the lifecycle hook target. Default: - No metadata.
        :param notification_target: The target of the lifecycle hook. Default: - No target.
        :param role: The role that allows publishing to the notification target. Default: - A role will be created if a target is provided. Otherwise, no role is created.
        '''
        props = BasicLifecycleHookProps(
            lifecycle_transition=lifecycle_transition,
            default_result=default_result,
            heartbeat_timeout=heartbeat_timeout,
            lifecycle_hook_name=lifecycle_hook_name,
            notification_metadata=notification_metadata,
            notification_target=notification_target,
            role=role,
        )

        return typing.cast(LifecycleHook, jsii.invoke(self, "addLifecycleHook", [id, props]))

    @jsii.member(jsii_name="addSecurityGroup")
    def add_security_group(self, security_group: _ISecurityGroup_acf8a799) -> None:
        '''Add the security group to all instances via the launch configuration security groups array.

        :param security_group: : The security group to add.
        '''
        return typing.cast(None, jsii.invoke(self, "addSecurityGroup", [security_group]))

    @jsii.member(jsii_name="addToRolePolicy")
    def add_to_role_policy(self, statement: _PolicyStatement_0fe33853) -> None:
        '''Adds a statement to the IAM role assumed by instances of this fleet.

        :param statement: -
        '''
        return typing.cast(None, jsii.invoke(self, "addToRolePolicy", [statement]))

    @jsii.member(jsii_name="addUserData")
    def add_user_data(self, *commands: builtins.str) -> None:
        '''Add command to the startup script of fleet instances.

        The command must be in the scripting language supported by the fleet's OS (i.e. Linux/Windows).
        Does nothing for imported ASGs.

        :param commands: -
        '''
        return typing.cast(None, jsii.invoke(self, "addUserData", [*commands]))

    @jsii.member(jsii_name="applyCloudFormationInit")
    def apply_cloud_formation_init(
        self,
        init: _CloudFormationInit_2bb1d1b2,
        *,
        config_sets: typing.Optional[typing.Sequence[builtins.str]] = None,
        embed_fingerprint: typing.Optional[builtins.bool] = None,
        ignore_failures: typing.Optional[builtins.bool] = None,
        include_role: typing.Optional[builtins.bool] = None,
        include_url: typing.Optional[builtins.bool] = None,
        print_log: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Use a CloudFormation Init configuration at instance startup.

        This does the following:

        - Attaches the CloudFormation Init metadata to the AutoScalingGroup resource.
        - Add commands to the UserData to run ``cfn-init`` and ``cfn-signal``.
        - Update the instance's CreationPolicy to wait for ``cfn-init`` to finish
          before reporting success.

        :param init: -
        :param config_sets: ConfigSet to activate. Default: ['default']
        :param embed_fingerprint: Force instance replacement by embedding a config fingerprint. If ``true`` (the default), a hash of the config will be embedded into the UserData, so that if the config changes, the UserData changes and instances will be replaced (given an UpdatePolicy has been configured on the AutoScalingGroup). If ``false``, no such hash will be embedded, and if the CloudFormation Init config changes nothing will happen to the running instances. If a config update introduces errors, you will not notice until after the CloudFormation deployment successfully finishes and the next instance fails to launch. Default: true
        :param ignore_failures: Don't fail the instance creation when cfn-init fails. You can use this to prevent CloudFormation from rolling back when instances fail to start up, to help in debugging. Default: false
        :param include_role: Include --role argument when running cfn-init and cfn-signal commands. This will be the IAM instance profile attached to the EC2 instance Default: false
        :param include_url: Include --url argument when running cfn-init and cfn-signal commands. This will be the cloudformation endpoint in the deployed region e.g. https://cloudformation.us-east-1.amazonaws.com Default: false
        :param print_log: Print the results of running cfn-init to the Instance System Log. By default, the output of running cfn-init is written to a log file on the instance. Set this to ``true`` to print it to the System Log (visible from the EC2 Console), ``false`` to not print it. (Be aware that the system log is refreshed at certain points in time of the instance life cycle, and successful execution may not always show up). Default: true
        '''
        options = ApplyCloudFormationInitOptions(
            config_sets=config_sets,
            embed_fingerprint=embed_fingerprint,
            ignore_failures=ignore_failures,
            include_role=include_role,
            include_url=include_url,
            print_log=print_log,
        )

        return typing.cast(None, jsii.invoke(self, "applyCloudFormationInit", [init, options]))

    @jsii.member(jsii_name="areNewInstancesProtectedFromScaleIn")
    def are_new_instances_protected_from_scale_in(self) -> builtins.bool:
        '''Returns ``true`` if newly-launched instances are protected from scale-in.'''
        return typing.cast(builtins.bool, jsii.invoke(self, "areNewInstancesProtectedFromScaleIn", []))

    @jsii.member(jsii_name="attachToApplicationTargetGroup")
    def attach_to_application_target_group(
        self,
        target_group: _IApplicationTargetGroup_57799827,
    ) -> _LoadBalancerTargetProps_4c30a73c:
        '''Attach to ELBv2 Application Target Group.

        :param target_group: -
        '''
        return typing.cast(_LoadBalancerTargetProps_4c30a73c, jsii.invoke(self, "attachToApplicationTargetGroup", [target_group]))

    @jsii.member(jsii_name="attachToClassicLB")
    def attach_to_classic_lb(self, load_balancer: _LoadBalancer_a894d40e) -> None:
        '''Attach to a classic load balancer.

        :param load_balancer: -
        '''
        return typing.cast(None, jsii.invoke(self, "attachToClassicLB", [load_balancer]))

    @jsii.member(jsii_name="attachToNetworkTargetGroup")
    def attach_to_network_target_group(
        self,
        target_group: _INetworkTargetGroup_abca2df7,
    ) -> _LoadBalancerTargetProps_4c30a73c:
        '''Attach to ELBv2 Application Target Group.

        :param target_group: -
        '''
        return typing.cast(_LoadBalancerTargetProps_4c30a73c, jsii.invoke(self, "attachToNetworkTargetGroup", [target_group]))

    @jsii.member(jsii_name="protectNewInstancesFromScaleIn")
    def protect_new_instances_from_scale_in(self) -> None:
        '''Ensures newly-launched instances are protected from scale-in.'''
        return typing.cast(None, jsii.invoke(self, "protectNewInstancesFromScaleIn", []))

    @jsii.member(jsii_name="scaleOnCpuUtilization")
    def scale_on_cpu_utilization(
        self,
        id: builtins.str,
        *,
        target_utilization_percent: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> TargetTrackingScalingPolicy:
        '''Scale out or in to achieve a target CPU utilization.

        :param id: -
        :param target_utilization_percent: Target average CPU utilization across the task.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        props = CpuUtilizationScalingProps(
            target_utilization_percent=target_utilization_percent,
            cooldown=cooldown,
            disable_scale_in=disable_scale_in,
            estimated_instance_warmup=estimated_instance_warmup,
        )

        return typing.cast(TargetTrackingScalingPolicy, jsii.invoke(self, "scaleOnCpuUtilization", [id, props]))

    @jsii.member(jsii_name="scaleOnIncomingBytes")
    def scale_on_incoming_bytes(
        self,
        id: builtins.str,
        *,
        target_bytes_per_second: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> TargetTrackingScalingPolicy:
        '''Scale out or in to achieve a target network ingress rate.

        :param id: -
        :param target_bytes_per_second: Target average bytes/seconds on each instance.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        props = NetworkUtilizationScalingProps(
            target_bytes_per_second=target_bytes_per_second,
            cooldown=cooldown,
            disable_scale_in=disable_scale_in,
            estimated_instance_warmup=estimated_instance_warmup,
        )

        return typing.cast(TargetTrackingScalingPolicy, jsii.invoke(self, "scaleOnIncomingBytes", [id, props]))

    @jsii.member(jsii_name="scaleOnMetric")
    def scale_on_metric(
        self,
        id: builtins.str,
        *,
        metric: _IMetric_c7fd29de,
        scaling_steps: typing.Sequence[ScalingInterval],
        adjustment_type: typing.Optional[AdjustmentType] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
        evaluation_periods: typing.Optional[jsii.Number] = None,
        metric_aggregation_type: typing.Optional[MetricAggregationType] = None,
        min_adjustment_magnitude: typing.Optional[jsii.Number] = None,
    ) -> StepScalingPolicy:
        '''Scale out or in, in response to a metric.

        :param id: -
        :param metric: Metric to scale on.
        :param scaling_steps: The intervals for scaling. Maps a range of metric values to a particular scaling behavior.
        :param adjustment_type: How the adjustment numbers inside 'intervals' are interpreted. Default: ChangeInCapacity
        :param cooldown: Grace period after scaling activity. Default: Default cooldown period on your AutoScalingGroup
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: Same as the cooldown
        :param evaluation_periods: How many evaluation periods of the metric to wait before triggering a scaling action. Raising this value can be used to smooth out the metric, at the expense of slower response times. Default: 1
        :param metric_aggregation_type: Aggregation to apply to all data points over the evaluation periods. Only has meaning if ``evaluationPeriods != 1``. Default: - The statistic from the metric if applicable (MIN, MAX, AVERAGE), otherwise AVERAGE.
        :param min_adjustment_magnitude: Minimum absolute number to adjust capacity with as result of percentage scaling. Only when using AdjustmentType = PercentChangeInCapacity, this number controls the minimum absolute effect size. Default: No minimum scaling effect
        '''
        props = BasicStepScalingPolicyProps(
            metric=metric,
            scaling_steps=scaling_steps,
            adjustment_type=adjustment_type,
            cooldown=cooldown,
            estimated_instance_warmup=estimated_instance_warmup,
            evaluation_periods=evaluation_periods,
            metric_aggregation_type=metric_aggregation_type,
            min_adjustment_magnitude=min_adjustment_magnitude,
        )

        return typing.cast(StepScalingPolicy, jsii.invoke(self, "scaleOnMetric", [id, props]))

    @jsii.member(jsii_name="scaleOnOutgoingBytes")
    def scale_on_outgoing_bytes(
        self,
        id: builtins.str,
        *,
        target_bytes_per_second: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> TargetTrackingScalingPolicy:
        '''Scale out or in to achieve a target network egress rate.

        :param id: -
        :param target_bytes_per_second: Target average bytes/seconds on each instance.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        props = NetworkUtilizationScalingProps(
            target_bytes_per_second=target_bytes_per_second,
            cooldown=cooldown,
            disable_scale_in=disable_scale_in,
            estimated_instance_warmup=estimated_instance_warmup,
        )

        return typing.cast(TargetTrackingScalingPolicy, jsii.invoke(self, "scaleOnOutgoingBytes", [id, props]))

    @jsii.member(jsii_name="scaleOnRequestCount")
    def scale_on_request_count(
        self,
        id: builtins.str,
        *,
        target_requests_per_minute: typing.Optional[jsii.Number] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> TargetTrackingScalingPolicy:
        '''Scale out or in to achieve a target request handling rate.

        The AutoScalingGroup must have been attached to an Application Load Balancer
        in order to be able to call this.

        :param id: -
        :param target_requests_per_minute: Target average requests/minute on each instance. Default: - Specify exactly one of 'targetRequestsPerMinute' and 'targetRequestsPerSecond'
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        props = RequestCountScalingProps(
            target_requests_per_minute=target_requests_per_minute,
            cooldown=cooldown,
            disable_scale_in=disable_scale_in,
            estimated_instance_warmup=estimated_instance_warmup,
        )

        return typing.cast(TargetTrackingScalingPolicy, jsii.invoke(self, "scaleOnRequestCount", [id, props]))

    @jsii.member(jsii_name="scaleOnSchedule")
    def scale_on_schedule(
        self,
        id: builtins.str,
        *,
        schedule: Schedule,
        desired_capacity: typing.Optional[jsii.Number] = None,
        end_time: typing.Optional[datetime.datetime] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
        start_time: typing.Optional[datetime.datetime] = None,
        time_zone: typing.Optional[builtins.str] = None,
    ) -> ScheduledAction:
        '''Scale out or in based on time.

        :param id: -
        :param schedule: When to perform this action. Supports cron expressions. For more information about cron expressions, see https://en.wikipedia.org/wiki/Cron.
        :param desired_capacity: The new desired capacity. At the scheduled time, set the desired capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new desired capacity.
        :param end_time: When this scheduled action expires. Default: - The rule never expires.
        :param max_capacity: The new maximum capacity. At the scheduled time, set the maximum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new maximum capacity.
        :param min_capacity: The new minimum capacity. At the scheduled time, set the minimum capacity to the given capacity. At least one of maxCapacity, minCapacity, or desiredCapacity must be supplied. Default: - No new minimum capacity.
        :param start_time: When this scheduled action becomes active. Default: - The rule is activate immediately.
        :param time_zone: Specifies the time zone for a cron expression. If a time zone is not provided, UTC is used by default. Valid values are the canonical names of the IANA time zones, derived from the IANA Time Zone Database (such as Etc/GMT+9 or Pacific/Tahiti). For more information, see https://en.wikipedia.org/wiki/List_of_tz_database_time_zones. Default: - UTC
        '''
        props = BasicScheduledActionProps(
            schedule=schedule,
            desired_capacity=desired_capacity,
            end_time=end_time,
            max_capacity=max_capacity,
            min_capacity=min_capacity,
            start_time=start_time,
            time_zone=time_zone,
        )

        return typing.cast(ScheduledAction, jsii.invoke(self, "scaleOnSchedule", [id, props]))

    @jsii.member(jsii_name="scaleToTrackMetric")
    def scale_to_track_metric(
        self,
        id: builtins.str,
        *,
        metric: _IMetric_c7fd29de,
        target_value: jsii.Number,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        disable_scale_in: typing.Optional[builtins.bool] = None,
        estimated_instance_warmup: typing.Optional[_Duration_4839e8c3] = None,
    ) -> TargetTrackingScalingPolicy:
        '''Scale out or in in order to keep a metric around a target value.

        :param id: -
        :param metric: Metric to track. The metric must represent a utilization, so that if it's higher than the target value, your ASG should scale out, and if it's lower it should scale in.
        :param target_value: Value to keep the metric around.
        :param cooldown: Period after a scaling completes before another scaling activity can start. Default: - The default cooldown configured on the AutoScalingGroup.
        :param disable_scale_in: Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won't remove capacity from the autoscaling group. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the group. Default: false
        :param estimated_instance_warmup: Estimated time until a newly launched instance can send metrics to CloudWatch. Default: - Same as the cooldown.
        '''
        props = MetricTargetTrackingProps(
            metric=metric,
            target_value=target_value,
            cooldown=cooldown,
            disable_scale_in=disable_scale_in,
            estimated_instance_warmup=estimated_instance_warmup,
        )

        return typing.cast(TargetTrackingScalingPolicy, jsii.invoke(self, "scaleToTrackMetric", [id, props]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoScalingGroupArn")
    def auto_scaling_group_arn(self) -> builtins.str:
        '''Arn of the AutoScalingGroup.'''
        return typing.cast(builtins.str, jsii.get(self, "autoScalingGroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="autoScalingGroupName")
    def auto_scaling_group_name(self) -> builtins.str:
        '''Name of the AutoScalingGroup.'''
        return typing.cast(builtins.str, jsii.get(self, "autoScalingGroupName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connections")
    def connections(self) -> _Connections_0f31fce8:
        '''Allows specify security group connections for instances of this fleet.'''
        return typing.cast(_Connections_0f31fce8, jsii.get(self, "connections"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> _IPrincipal_539bb2fd:
        '''The principal to grant permissions to.'''
        return typing.cast(_IPrincipal_539bb2fd, jsii.get(self, "grantPrincipal"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="osType")
    def os_type(self) -> _OperatingSystemType_9224a1fe:
        '''The type of OS instances of this fleet are running.'''
        return typing.cast(_OperatingSystemType_9224a1fe, jsii.get(self, "osType"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> _IRole_235f5d8e:
        '''The IAM role assumed by instances of this fleet.'''
        return typing.cast(_IRole_235f5d8e, jsii.get(self, "role"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="userData")
    def user_data(self) -> _UserData_b8b32b5e:
        '''UserData for the instances.'''
        return typing.cast(_UserData_b8b32b5e, jsii.get(self, "userData"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="maxInstanceLifetime")
    def max_instance_lifetime(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The maximum amount of time that an instance can be in service.'''
        return typing.cast(typing.Optional[_Duration_4839e8c3], jsii.get(self, "maxInstanceLifetime"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="spotPrice")
    def spot_price(self) -> typing.Optional[builtins.str]:
        '''The maximum spot price configured for the autoscaling group.

        ``undefined``
        indicates that this group uses on-demand capacity.
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "spotPrice"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="albTargetGroup")
    def _alb_target_group(self) -> typing.Optional[_ApplicationTargetGroup_906fe365]:
        return typing.cast(typing.Optional[_ApplicationTargetGroup_906fe365], jsii.get(self, "albTargetGroup"))

    @_alb_target_group.setter
    def _alb_target_group(
        self,
        value: typing.Optional[_ApplicationTargetGroup_906fe365],
    ) -> None:
        jsii.set(self, "albTargetGroup", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="newInstancesProtectedFromScaleIn")
    def _new_instances_protected_from_scale_in(self) -> typing.Optional[builtins.bool]:
        return typing.cast(typing.Optional[builtins.bool], jsii.get(self, "newInstancesProtectedFromScaleIn"))

    @_new_instances_protected_from_scale_in.setter
    def _new_instances_protected_from_scale_in(
        self,
        value: typing.Optional[builtins.bool],
    ) -> None:
        jsii.set(self, "newInstancesProtectedFromScaleIn", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.AutoScalingGroupProps",
    jsii_struct_bases=[CommonAutoScalingGroupProps],
    name_mapping={
        "allow_all_outbound": "allowAllOutbound",
        "associate_public_ip_address": "associatePublicIpAddress",
        "auto_scaling_group_name": "autoScalingGroupName",
        "block_devices": "blockDevices",
        "cooldown": "cooldown",
        "desired_capacity": "desiredCapacity",
        "group_metrics": "groupMetrics",
        "health_check": "healthCheck",
        "ignore_unmodified_size_properties": "ignoreUnmodifiedSizeProperties",
        "instance_monitoring": "instanceMonitoring",
        "key_name": "keyName",
        "max_capacity": "maxCapacity",
        "max_instance_lifetime": "maxInstanceLifetime",
        "min_capacity": "minCapacity",
        "new_instances_protected_from_scale_in": "newInstancesProtectedFromScaleIn",
        "notifications": "notifications",
        "signals": "signals",
        "spot_price": "spotPrice",
        "termination_policies": "terminationPolicies",
        "update_policy": "updatePolicy",
        "vpc_subnets": "vpcSubnets",
        "instance_type": "instanceType",
        "machine_image": "machineImage",
        "vpc": "vpc",
        "init": "init",
        "init_options": "initOptions",
        "require_imdsv2": "requireImdsv2",
        "role": "role",
        "security_group": "securityGroup",
        "user_data": "userData",
    },
)
class AutoScalingGroupProps(CommonAutoScalingGroupProps):
    def __init__(
        self,
        *,
        allow_all_outbound: typing.Optional[builtins.bool] = None,
        associate_public_ip_address: typing.Optional[builtins.bool] = None,
        auto_scaling_group_name: typing.Optional[builtins.str] = None,
        block_devices: typing.Optional[typing.Sequence[BlockDevice]] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        desired_capacity: typing.Optional[jsii.Number] = None,
        group_metrics: typing.Optional[typing.Sequence[GroupMetrics]] = None,
        health_check: typing.Optional[HealthCheck] = None,
        ignore_unmodified_size_properties: typing.Optional[builtins.bool] = None,
        instance_monitoring: typing.Optional[Monitoring] = None,
        key_name: typing.Optional[builtins.str] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        max_instance_lifetime: typing.Optional[_Duration_4839e8c3] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
        new_instances_protected_from_scale_in: typing.Optional[builtins.bool] = None,
        notifications: typing.Optional[typing.Sequence[NotificationConfiguration]] = None,
        signals: typing.Optional[Signals] = None,
        spot_price: typing.Optional[builtins.str] = None,
        termination_policies: typing.Optional[typing.Sequence[TerminationPolicy]] = None,
        update_policy: typing.Optional[UpdatePolicy] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
        instance_type: _InstanceType_f64915b9,
        machine_image: _IMachineImage_0e8bd50b,
        vpc: _IVpc_f30d5663,
        init: typing.Optional[_CloudFormationInit_2bb1d1b2] = None,
        init_options: typing.Optional[ApplyCloudFormationInitOptions] = None,
        require_imdsv2: typing.Optional[builtins.bool] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        user_data: typing.Optional[_UserData_b8b32b5e] = None,
    ) -> None:
        '''Properties of a Fleet.

        :param allow_all_outbound: Whether the instances can initiate connections to anywhere by default. Default: true
        :param associate_public_ip_address: Whether instances in the Auto Scaling Group should have public IP addresses associated with them. Default: - Use subnet setting.
        :param auto_scaling_group_name: The name of the Auto Scaling group. This name must be unique per Region per account. Default: - Auto generated by CloudFormation
        :param block_devices: Specifies how block devices are exposed to the instance. You can specify virtual devices and EBS volumes. Each instance that is launched has an associated root device volume, either an Amazon EBS volume or an instance store volume. You can use block device mappings to specify additional EBS volumes or instance store volumes to attach to an instance when it is launched. Default: - Uses the block device mapping of the AMI
        :param cooldown: Default scaling cooldown for this AutoScalingGroup. Default: Duration.minutes(5)
        :param desired_capacity: Initial amount of instances in the fleet. If this is set to a number, every deployment will reset the amount of instances to this number. It is recommended to leave this value blank. Default: minCapacity, and leave unchanged during deployment
        :param group_metrics: Enable monitoring for group metrics, these metrics describe the group rather than any of its instances. To report all group metrics use ``GroupMetrics.all()`` Group metrics are reported in a granularity of 1 minute at no additional charge. Default: - no group metrics will be reported
        :param health_check: Configuration for health checks. Default: - HealthCheck.ec2 with no grace period
        :param ignore_unmodified_size_properties: If the ASG has scheduled actions, don't reset unchanged group sizes. Only used if the ASG has scheduled actions (which may scale your ASG up or down regardless of cdk deployments). If true, the size of the group will only be reset if it has been changed in the CDK app. If false, the sizes will always be changed back to what they were in the CDK app on deployment. Default: true
        :param instance_monitoring: Controls whether instances in this group are launched with detailed or basic monitoring. When detailed monitoring is enabled, Amazon CloudWatch generates metrics every minute and your account is charged a fee. When you disable detailed monitoring, CloudWatch generates metrics every 5 minutes. Default: - Monitoring.DETAILED
        :param key_name: Name of SSH keypair to grant access to instances. Default: - No SSH access will be possible.
        :param max_capacity: Maximum number of instances in the fleet. Default: desiredCapacity
        :param max_instance_lifetime: The maximum amount of time that an instance can be in service. The maximum duration applies to all current and future instances in the group. As an instance approaches its maximum duration, it is terminated and replaced, and cannot be used again. You must specify a value of at least 604,800 seconds (7 days). To clear a previously set value, leave this property undefined. Default: none
        :param min_capacity: Minimum number of instances in the fleet. Default: 1
        :param new_instances_protected_from_scale_in: Whether newly-launched instances are protected from termination by Amazon EC2 Auto Scaling when scaling in. By default, Auto Scaling can terminate an instance at any time after launch when scaling in an Auto Scaling Group, subject to the group's termination policy. However, you may wish to protect newly-launched instances from being scaled in if they are going to run critical applications that should not be prematurely terminated. This flag must be enabled if the Auto Scaling Group will be associated with an ECS Capacity Provider with managed termination protection. Default: false
        :param notifications: Configure autoscaling group to send notifications about fleet changes to an SNS topic(s). Default: - No fleet change notifications will be sent.
        :param signals: Configure waiting for signals during deployment. Use this to pause the CloudFormation deployment to wait for the instances in the AutoScalingGroup to report successful startup during creation and updates. The UserData script needs to invoke ``cfn-signal`` with a success or failure code after it is done setting up the instance. Without waiting for signals, the CloudFormation deployment will proceed as soon as the AutoScalingGroup has been created or updated but before the instances in the group have been started. For example, to have instances wait for an Elastic Load Balancing health check before they signal success, add a health-check verification by using the cfn-init helper script. For an example, see the verify_instance_health command in the Auto Scaling rolling updates sample template: https://github.com/awslabs/aws-cloudformation-templates/blob/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml Default: - Do not wait for signals
        :param spot_price: The maximum hourly price (in USD) to be paid for any Spot Instance launched to fulfill the request. Spot Instances are launched when the price you specify exceeds the current Spot market price. Default: none
        :param termination_policies: A policy or a list of policies that are used to select the instances to terminate. The policies are executed in the order that you list them. Default: - ``TerminationPolicy.DEFAULT``
        :param update_policy: What to do when an AutoScalingGroup's instance configuration is changed. This is applied when any of the settings on the ASG are changed that affect how the instances should be created (VPC, instance type, startup scripts, etc.). It indicates how the existing instances should be replaced with new instances matching the new config. By default, nothing is done and only new instances are launched with the new config. Default: - ``UpdatePolicy.rollingUpdate()`` if using ``init``, ``UpdatePolicy.none()`` otherwise
        :param vpc_subnets: Where to place instances within the VPC. Default: - All Private subnets.
        :param instance_type: Type of instance to launch.
        :param machine_image: AMI to launch.
        :param vpc: VPC to launch these instances in.
        :param init: Apply the given CloudFormation Init configuration to the instances in the AutoScalingGroup at startup. If you specify ``init``, you must also specify ``signals`` to configure the number of instances to wait for and the timeout for waiting for the init process. Default: - no CloudFormation init
        :param init_options: Use the given options for applying CloudFormation Init. Describes the configsets to use and the timeout to wait Default: - default options
        :param require_imdsv2: Whether IMDSv2 should be required on launched instances. Default: - false
        :param role: An IAM role to associate with the instance profile assigned to this Auto Scaling Group. The role must be assumable by the service principal ``ec2.amazonaws.com``: Default: A role will automatically be created, it can be accessed via the ``role`` property
        :param security_group: Security group to launch the instances in. Default: - A SecurityGroup will be created if none is specified.
        :param user_data: Specific UserData to use. The UserData may still be mutated after creation. Default: - A UserData object appropriate for the MachineImage's Operating System is created.

        :exampleMetadata: infused

        Example::

            # vpc: ec2.Vpc
            # instance_type: ec2.InstanceType
            # machine_image: ec2.IMachineImage
            
            
            autoscaling.AutoScalingGroup(self, "ASG",
                vpc=vpc,
                instance_type=instance_type,
                machine_image=machine_image,
            
                # ...
            
                init=ec2.CloudFormationInit.from_elements(
                    ec2.InitFile.from_string("/etc/my_instance", "This got written during instance startup")),
                signals=autoscaling.Signals.wait_for_all(
                    timeout=Duration.minutes(10)
                )
            )
        '''
        if isinstance(vpc_subnets, dict):
            vpc_subnets = _SubnetSelection_e57d76df(**vpc_subnets)
        if isinstance(init_options, dict):
            init_options = ApplyCloudFormationInitOptions(**init_options)
        self._values: typing.Dict[str, typing.Any] = {
            "instance_type": instance_type,
            "machine_image": machine_image,
            "vpc": vpc,
        }
        if allow_all_outbound is not None:
            self._values["allow_all_outbound"] = allow_all_outbound
        if associate_public_ip_address is not None:
            self._values["associate_public_ip_address"] = associate_public_ip_address
        if auto_scaling_group_name is not None:
            self._values["auto_scaling_group_name"] = auto_scaling_group_name
        if block_devices is not None:
            self._values["block_devices"] = block_devices
        if cooldown is not None:
            self._values["cooldown"] = cooldown
        if desired_capacity is not None:
            self._values["desired_capacity"] = desired_capacity
        if group_metrics is not None:
            self._values["group_metrics"] = group_metrics
        if health_check is not None:
            self._values["health_check"] = health_check
        if ignore_unmodified_size_properties is not None:
            self._values["ignore_unmodified_size_properties"] = ignore_unmodified_size_properties
        if instance_monitoring is not None:
            self._values["instance_monitoring"] = instance_monitoring
        if key_name is not None:
            self._values["key_name"] = key_name
        if max_capacity is not None:
            self._values["max_capacity"] = max_capacity
        if max_instance_lifetime is not None:
            self._values["max_instance_lifetime"] = max_instance_lifetime
        if min_capacity is not None:
            self._values["min_capacity"] = min_capacity
        if new_instances_protected_from_scale_in is not None:
            self._values["new_instances_protected_from_scale_in"] = new_instances_protected_from_scale_in
        if notifications is not None:
            self._values["notifications"] = notifications
        if signals is not None:
            self._values["signals"] = signals
        if spot_price is not None:
            self._values["spot_price"] = spot_price
        if termination_policies is not None:
            self._values["termination_policies"] = termination_policies
        if update_policy is not None:
            self._values["update_policy"] = update_policy
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets
        if init is not None:
            self._values["init"] = init
        if init_options is not None:
            self._values["init_options"] = init_options
        if require_imdsv2 is not None:
            self._values["require_imdsv2"] = require_imdsv2
        if role is not None:
            self._values["role"] = role
        if security_group is not None:
            self._values["security_group"] = security_group
        if user_data is not None:
            self._values["user_data"] = user_data

    @builtins.property
    def allow_all_outbound(self) -> typing.Optional[builtins.bool]:
        '''Whether the instances can initiate connections to anywhere by default.

        :default: true
        '''
        result = self._values.get("allow_all_outbound")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def associate_public_ip_address(self) -> typing.Optional[builtins.bool]:
        '''Whether instances in the Auto Scaling Group should have public IP addresses associated with them.

        :default: - Use subnet setting.
        '''
        result = self._values.get("associate_public_ip_address")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def auto_scaling_group_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Auto Scaling group.

        This name must be unique per Region per account.

        :default: - Auto generated by CloudFormation
        '''
        result = self._values.get("auto_scaling_group_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def block_devices(self) -> typing.Optional[typing.List[BlockDevice]]:
        '''Specifies how block devices are exposed to the instance. You can specify virtual devices and EBS volumes.

        Each instance that is launched has an associated root device volume,
        either an Amazon EBS volume or an instance store volume.
        You can use block device mappings to specify additional EBS volumes or
        instance store volumes to attach to an instance when it is launched.

        :default: - Uses the block device mapping of the AMI

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-device-mapping-concepts.html
        '''
        result = self._values.get("block_devices")
        return typing.cast(typing.Optional[typing.List[BlockDevice]], result)

    @builtins.property
    def cooldown(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Default scaling cooldown for this AutoScalingGroup.

        :default: Duration.minutes(5)
        '''
        result = self._values.get("cooldown")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def desired_capacity(self) -> typing.Optional[jsii.Number]:
        '''Initial amount of instances in the fleet.

        If this is set to a number, every deployment will reset the amount of
        instances to this number. It is recommended to leave this value blank.

        :default: minCapacity, and leave unchanged during deployment

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-desiredcapacity
        '''
        result = self._values.get("desired_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def group_metrics(self) -> typing.Optional[typing.List[GroupMetrics]]:
        '''Enable monitoring for group metrics, these metrics describe the group rather than any of its instances.

        To report all group metrics use ``GroupMetrics.all()``
        Group metrics are reported in a granularity of 1 minute at no additional charge.

        :default: - no group metrics will be reported
        '''
        result = self._values.get("group_metrics")
        return typing.cast(typing.Optional[typing.List[GroupMetrics]], result)

    @builtins.property
    def health_check(self) -> typing.Optional[HealthCheck]:
        '''Configuration for health checks.

        :default: - HealthCheck.ec2 with no grace period
        '''
        result = self._values.get("health_check")
        return typing.cast(typing.Optional[HealthCheck], result)

    @builtins.property
    def ignore_unmodified_size_properties(self) -> typing.Optional[builtins.bool]:
        '''If the ASG has scheduled actions, don't reset unchanged group sizes.

        Only used if the ASG has scheduled actions (which may scale your ASG up
        or down regardless of cdk deployments). If true, the size of the group
        will only be reset if it has been changed in the CDK app. If false, the
        sizes will always be changed back to what they were in the CDK app
        on deployment.

        :default: true
        '''
        result = self._values.get("ignore_unmodified_size_properties")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def instance_monitoring(self) -> typing.Optional[Monitoring]:
        '''Controls whether instances in this group are launched with detailed or basic monitoring.

        When detailed monitoring is enabled, Amazon CloudWatch generates metrics every minute and your account
        is charged a fee. When you disable detailed monitoring, CloudWatch generates metrics every 5 minutes.

        :default: - Monitoring.DETAILED

        :see: https://docs.aws.amazon.com/autoscaling/latest/userguide/as-instance-monitoring.html#enable-as-instance-metrics
        '''
        result = self._values.get("instance_monitoring")
        return typing.cast(typing.Optional[Monitoring], result)

    @builtins.property
    def key_name(self) -> typing.Optional[builtins.str]:
        '''Name of SSH keypair to grant access to instances.

        :default: - No SSH access will be possible.
        '''
        result = self._values.get("key_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def max_capacity(self) -> typing.Optional[jsii.Number]:
        '''Maximum number of instances in the fleet.

        :default: desiredCapacity
        '''
        result = self._values.get("max_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def max_instance_lifetime(self) -> typing.Optional[_Duration_4839e8c3]:
        '''The maximum amount of time that an instance can be in service.

        The maximum duration applies
        to all current and future instances in the group. As an instance approaches its maximum duration,
        it is terminated and replaced, and cannot be used again.

        You must specify a value of at least 604,800 seconds (7 days). To clear a previously set value,
        leave this property undefined.

        :default: none

        :see: https://docs.aws.amazon.com/autoscaling/ec2/userguide/asg-max-instance-lifetime.html
        '''
        result = self._values.get("max_instance_lifetime")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def min_capacity(self) -> typing.Optional[jsii.Number]:
        '''Minimum number of instances in the fleet.

        :default: 1
        '''
        result = self._values.get("min_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def new_instances_protected_from_scale_in(self) -> typing.Optional[builtins.bool]:
        '''Whether newly-launched instances are protected from termination by Amazon EC2 Auto Scaling when scaling in.

        By default, Auto Scaling can terminate an instance at any time after launch
        when scaling in an Auto Scaling Group, subject to the group's termination
        policy. However, you may wish to protect newly-launched instances from
        being scaled in if they are going to run critical applications that should
        not be prematurely terminated.

        This flag must be enabled if the Auto Scaling Group will be associated with
        an ECS Capacity Provider with managed termination protection.

        :default: false
        '''
        result = self._values.get("new_instances_protected_from_scale_in")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def notifications(self) -> typing.Optional[typing.List[NotificationConfiguration]]:
        '''Configure autoscaling group to send notifications about fleet changes to an SNS topic(s).

        :default: - No fleet change notifications will be sent.

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-notificationconfigurations
        '''
        result = self._values.get("notifications")
        return typing.cast(typing.Optional[typing.List[NotificationConfiguration]], result)

    @builtins.property
    def signals(self) -> typing.Optional[Signals]:
        '''Configure waiting for signals during deployment.

        Use this to pause the CloudFormation deployment to wait for the instances
        in the AutoScalingGroup to report successful startup during
        creation and updates. The UserData script needs to invoke ``cfn-signal``
        with a success or failure code after it is done setting up the instance.

        Without waiting for signals, the CloudFormation deployment will proceed as
        soon as the AutoScalingGroup has been created or updated but before the
        instances in the group have been started.

        For example, to have instances wait for an Elastic Load Balancing health check before
        they signal success, add a health-check verification by using the
        cfn-init helper script. For an example, see the verify_instance_health
        command in the Auto Scaling rolling updates sample template:

        https://github.com/awslabs/aws-cloudformation-templates/blob/master/aws/services/AutoScaling/AutoScalingRollingUpdates.yaml

        :default: - Do not wait for signals
        '''
        result = self._values.get("signals")
        return typing.cast(typing.Optional[Signals], result)

    @builtins.property
    def spot_price(self) -> typing.Optional[builtins.str]:
        '''The maximum hourly price (in USD) to be paid for any Spot Instance launched to fulfill the request.

        Spot Instances are
        launched when the price you specify exceeds the current Spot market price.

        :default: none
        '''
        result = self._values.get("spot_price")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def termination_policies(self) -> typing.Optional[typing.List[TerminationPolicy]]:
        '''A policy or a list of policies that are used to select the instances to terminate.

        The policies are executed in the order that you list them.

        :default: - ``TerminationPolicy.DEFAULT``

        :see: https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html
        '''
        result = self._values.get("termination_policies")
        return typing.cast(typing.Optional[typing.List[TerminationPolicy]], result)

    @builtins.property
    def update_policy(self) -> typing.Optional[UpdatePolicy]:
        '''What to do when an AutoScalingGroup's instance configuration is changed.

        This is applied when any of the settings on the ASG are changed that
        affect how the instances should be created (VPC, instance type, startup
        scripts, etc.). It indicates how the existing instances should be
        replaced with new instances matching the new config. By default, nothing
        is done and only new instances are launched with the new config.

        :default: - ``UpdatePolicy.rollingUpdate()`` if using ``init``, ``UpdatePolicy.none()`` otherwise
        '''
        result = self._values.get("update_policy")
        return typing.cast(typing.Optional[UpdatePolicy], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''Where to place instances within the VPC.

        :default: - All Private subnets.
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    @builtins.property
    def instance_type(self) -> _InstanceType_f64915b9:
        '''Type of instance to launch.'''
        result = self._values.get("instance_type")
        assert result is not None, "Required property 'instance_type' is missing"
        return typing.cast(_InstanceType_f64915b9, result)

    @builtins.property
    def machine_image(self) -> _IMachineImage_0e8bd50b:
        '''AMI to launch.'''
        result = self._values.get("machine_image")
        assert result is not None, "Required property 'machine_image' is missing"
        return typing.cast(_IMachineImage_0e8bd50b, result)

    @builtins.property
    def vpc(self) -> _IVpc_f30d5663:
        '''VPC to launch these instances in.'''
        result = self._values.get("vpc")
        assert result is not None, "Required property 'vpc' is missing"
        return typing.cast(_IVpc_f30d5663, result)

    @builtins.property
    def init(self) -> typing.Optional[_CloudFormationInit_2bb1d1b2]:
        '''Apply the given CloudFormation Init configuration to the instances in the AutoScalingGroup at startup.

        If you specify ``init``, you must also specify ``signals`` to configure
        the number of instances to wait for and the timeout for waiting for the
        init process.

        :default: - no CloudFormation init
        '''
        result = self._values.get("init")
        return typing.cast(typing.Optional[_CloudFormationInit_2bb1d1b2], result)

    @builtins.property
    def init_options(self) -> typing.Optional[ApplyCloudFormationInitOptions]:
        '''Use the given options for applying CloudFormation Init.

        Describes the configsets to use and the timeout to wait

        :default: - default options
        '''
        result = self._values.get("init_options")
        return typing.cast(typing.Optional[ApplyCloudFormationInitOptions], result)

    @builtins.property
    def require_imdsv2(self) -> typing.Optional[builtins.bool]:
        '''Whether IMDSv2 should be required on launched instances.

        :default: - false
        '''
        result = self._values.get("require_imdsv2")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''An IAM role to associate with the instance profile assigned to this Auto Scaling Group.

        The role must be assumable by the service principal ``ec2.amazonaws.com``:

        :default: A role will automatically be created, it can be accessed via the ``role`` property

        Example::

            role = iam.Role(self, "MyRole",
                assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
            )
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''Security group to launch the instances in.

        :default: - A SecurityGroup will be created if none is specified.
        '''
        result = self._values.get("security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    @builtins.property
    def user_data(self) -> typing.Optional[_UserData_b8b32b5e]:
        '''Specific UserData to use.

        The UserData may still be mutated after creation.

        :default:

        - A UserData object appropriate for the MachineImage's
        Operating System is created.
        '''
        result = self._values.get("user_data")
        return typing.cast(typing.Optional[_UserData_b8b32b5e], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AutoScalingGroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.EbsDeviceOptions",
    jsii_struct_bases=[EbsDeviceOptionsBase],
    name_mapping={
        "delete_on_termination": "deleteOnTermination",
        "iops": "iops",
        "volume_type": "volumeType",
        "encrypted": "encrypted",
    },
)
class EbsDeviceOptions(EbsDeviceOptionsBase):
    def __init__(
        self,
        *,
        delete_on_termination: typing.Optional[builtins.bool] = None,
        iops: typing.Optional[jsii.Number] = None,
        volume_type: typing.Optional[EbsDeviceVolumeType] = None,
        encrypted: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Block device options for an EBS volume.

        :param delete_on_termination: Indicates whether to delete the volume when the instance is terminated. Default: - true for Amazon EC2 Auto Scaling, false otherwise (e.g. EBS)
        :param iops: The number of I/O operations per second (IOPS) to provision for the volume. Must only be set for {@link volumeType}: {@link EbsDeviceVolumeType.IO1} The maximum ratio of IOPS to volume size (in GiB) is 50:1, so for 5,000 provisioned IOPS, you need at least 100 GiB storage on the volume. Default: - none, required for {@link EbsDeviceVolumeType.IO1}
        :param volume_type: The EBS volume type. Default: {@link EbsDeviceVolumeType.GP2}
        :param encrypted: Specifies whether the EBS volume is encrypted. Encrypted EBS volumes can only be attached to instances that support Amazon EBS encryption Default: false

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            ebs_device_options = autoscaling.EbsDeviceOptions(
                delete_on_termination=False,
                encrypted=False,
                iops=123,
                volume_type=autoscaling.EbsDeviceVolumeType.STANDARD
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if delete_on_termination is not None:
            self._values["delete_on_termination"] = delete_on_termination
        if iops is not None:
            self._values["iops"] = iops
        if volume_type is not None:
            self._values["volume_type"] = volume_type
        if encrypted is not None:
            self._values["encrypted"] = encrypted

    @builtins.property
    def delete_on_termination(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether to delete the volume when the instance is terminated.

        :default: - true for Amazon EC2 Auto Scaling, false otherwise (e.g. EBS)
        '''
        result = self._values.get("delete_on_termination")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def iops(self) -> typing.Optional[jsii.Number]:
        '''The number of I/O operations per second (IOPS) to provision for the volume.

        Must only be set for {@link volumeType}: {@link EbsDeviceVolumeType.IO1}

        The maximum ratio of IOPS to volume size (in GiB) is 50:1, so for 5,000 provisioned IOPS,
        you need at least 100 GiB storage on the volume.

        :default: - none, required for {@link EbsDeviceVolumeType.IO1}

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html
        '''
        result = self._values.get("iops")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def volume_type(self) -> typing.Optional[EbsDeviceVolumeType]:
        '''The EBS volume type.

        :default: {@link EbsDeviceVolumeType.GP2}

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html
        '''
        result = self._values.get("volume_type")
        return typing.cast(typing.Optional[EbsDeviceVolumeType], result)

    @builtins.property
    def encrypted(self) -> typing.Optional[builtins.bool]:
        '''Specifies whether the EBS volume is encrypted.

        Encrypted EBS volumes can only be attached to instances that support Amazon EBS encryption

        :default: false

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#EBSEncryption_supported_instances
        '''
        result = self._values.get("encrypted")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EbsDeviceOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_autoscaling.EbsDeviceProps",
    jsii_struct_bases=[EbsDeviceSnapshotOptions],
    name_mapping={
        "delete_on_termination": "deleteOnTermination",
        "iops": "iops",
        "volume_type": "volumeType",
        "volume_size": "volumeSize",
        "snapshot_id": "snapshotId",
    },
)
class EbsDeviceProps(EbsDeviceSnapshotOptions):
    def __init__(
        self,
        *,
        delete_on_termination: typing.Optional[builtins.bool] = None,
        iops: typing.Optional[jsii.Number] = None,
        volume_type: typing.Optional[EbsDeviceVolumeType] = None,
        volume_size: typing.Optional[jsii.Number] = None,
        snapshot_id: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties of an EBS block device.

        :param delete_on_termination: Indicates whether to delete the volume when the instance is terminated. Default: - true for Amazon EC2 Auto Scaling, false otherwise (e.g. EBS)
        :param iops: The number of I/O operations per second (IOPS) to provision for the volume. Must only be set for {@link volumeType}: {@link EbsDeviceVolumeType.IO1} The maximum ratio of IOPS to volume size (in GiB) is 50:1, so for 5,000 provisioned IOPS, you need at least 100 GiB storage on the volume. Default: - none, required for {@link EbsDeviceVolumeType.IO1}
        :param volume_type: The EBS volume type. Default: {@link EbsDeviceVolumeType.GP2}
        :param volume_size: The volume size, in Gibibytes (GiB). If you specify volumeSize, it must be equal or greater than the size of the snapshot. Default: - The snapshot size
        :param snapshot_id: The snapshot ID of the volume to use. Default: - No snapshot will be used

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_autoscaling as autoscaling
            
            ebs_device_props = autoscaling.EbsDeviceProps(
                delete_on_termination=False,
                iops=123,
                snapshot_id="snapshotId",
                volume_size=123,
                volume_type=autoscaling.EbsDeviceVolumeType.STANDARD
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if delete_on_termination is not None:
            self._values["delete_on_termination"] = delete_on_termination
        if iops is not None:
            self._values["iops"] = iops
        if volume_type is not None:
            self._values["volume_type"] = volume_type
        if volume_size is not None:
            self._values["volume_size"] = volume_size
        if snapshot_id is not None:
            self._values["snapshot_id"] = snapshot_id

    @builtins.property
    def delete_on_termination(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether to delete the volume when the instance is terminated.

        :default: - true for Amazon EC2 Auto Scaling, false otherwise (e.g. EBS)
        '''
        result = self._values.get("delete_on_termination")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def iops(self) -> typing.Optional[jsii.Number]:
        '''The number of I/O operations per second (IOPS) to provision for the volume.

        Must only be set for {@link volumeType}: {@link EbsDeviceVolumeType.IO1}

        The maximum ratio of IOPS to volume size (in GiB) is 50:1, so for 5,000 provisioned IOPS,
        you need at least 100 GiB storage on the volume.

        :default: - none, required for {@link EbsDeviceVolumeType.IO1}

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html
        '''
        result = self._values.get("iops")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def volume_type(self) -> typing.Optional[EbsDeviceVolumeType]:
        '''The EBS volume type.

        :default: {@link EbsDeviceVolumeType.GP2}

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html
        '''
        result = self._values.get("volume_type")
        return typing.cast(typing.Optional[EbsDeviceVolumeType], result)

    @builtins.property
    def volume_size(self) -> typing.Optional[jsii.Number]:
        '''The volume size, in Gibibytes (GiB).

        If you specify volumeSize, it must be equal or greater than the size of the snapshot.

        :default: - The snapshot size
        '''
        result = self._values.get("volume_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def snapshot_id(self) -> typing.Optional[builtins.str]:
        '''The snapshot ID of the volume to use.

        :default: - No snapshot will be used
        '''
        result = self._values.get("snapshot_id")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EbsDeviceProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "AdjustmentTier",
    "AdjustmentType",
    "ApplyCloudFormationInitOptions",
    "AutoScalingGroup",
    "AutoScalingGroupProps",
    "AutoScalingGroupRequireImdsv2Aspect",
    "BaseTargetTrackingProps",
    "BasicLifecycleHookProps",
    "BasicScheduledActionProps",
    "BasicStepScalingPolicyProps",
    "BasicTargetTrackingScalingPolicyProps",
    "BindHookTargetOptions",
    "BlockDevice",
    "BlockDeviceVolume",
    "CfnAutoScalingGroup",
    "CfnAutoScalingGroupProps",
    "CfnLaunchConfiguration",
    "CfnLaunchConfigurationProps",
    "CfnLifecycleHook",
    "CfnLifecycleHookProps",
    "CfnScalingPolicy",
    "CfnScalingPolicyProps",
    "CfnScheduledAction",
    "CfnScheduledActionProps",
    "CfnWarmPool",
    "CfnWarmPoolProps",
    "CommonAutoScalingGroupProps",
    "CpuUtilizationScalingProps",
    "CronOptions",
    "DefaultResult",
    "EbsDeviceOptions",
    "EbsDeviceOptionsBase",
    "EbsDeviceProps",
    "EbsDeviceSnapshotOptions",
    "EbsDeviceVolumeType",
    "Ec2HealthCheckOptions",
    "ElbHealthCheckOptions",
    "GroupMetric",
    "GroupMetrics",
    "HealthCheck",
    "IAutoScalingGroup",
    "ILifecycleHook",
    "ILifecycleHookTarget",
    "LifecycleHook",
    "LifecycleHookProps",
    "LifecycleHookTargetConfig",
    "LifecycleTransition",
    "MetricAggregationType",
    "MetricTargetTrackingProps",
    "Monitoring",
    "NetworkUtilizationScalingProps",
    "NotificationConfiguration",
    "PredefinedMetric",
    "RenderSignalsOptions",
    "RequestCountScalingProps",
    "RollingUpdateOptions",
    "ScalingEvent",
    "ScalingEvents",
    "ScalingInterval",
    "ScalingProcess",
    "Schedule",
    "ScheduledAction",
    "ScheduledActionProps",
    "Signals",
    "SignalsOptions",
    "StepScalingAction",
    "StepScalingActionProps",
    "StepScalingPolicy",
    "StepScalingPolicyProps",
    "TargetTrackingScalingPolicy",
    "TargetTrackingScalingPolicyProps",
    "TerminationPolicy",
    "UpdatePolicy",
]

publication.publish()
