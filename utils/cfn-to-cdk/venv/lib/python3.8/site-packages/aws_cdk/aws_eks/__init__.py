'''
# Amazon EKS Construct Library

This construct library allows you to define [Amazon Elastic Container Service for Kubernetes (EKS)](https://aws.amazon.com/eks/) clusters.
In addition, the library also supports defining Kubernetes resource manifests within EKS clusters.

## Table Of Contents

* [Quick Start](#quick-start)
* [API Reference](https://docs.aws.amazon.com/cdk/api/latest/docs/aws-eks-readme.html)
* [Architectural Overview](#architectural-overview)
* [Provisioning clusters](#provisioning-clusters)

  * [Managed node groups](#managed-node-groups)
  * [Fargate Profiles](#fargate-profiles)
  * [Self-managed nodes](#self-managed-nodes)
  * [Endpoint Access](#endpoint-access)
  * [ALB Controller](#alb-controller)
  * [VPC Support](#vpc-support)
  * [Kubectl Support](#kubectl-support)
  * [ARM64 Support](#arm64-support)
  * [Masters Role](#masters-role)
  * [Encryption](#encryption)
* [Permissions and Security](#permissions-and-security)
* [Applying Kubernetes Resources](#applying-kubernetes-resources)

  * [Kubernetes Manifests](#kubernetes-manifests)
  * [Helm Charts](#helm-charts)
  * [CDK8s Charts](#cdk8s-charts)
* [Patching Kubernetes Resources](#patching-kubernetes-resources)
* [Querying Kubernetes Resources](#querying-kubernetes-resources)
* [Using existing clusters](#using-existing-clusters)
* [Known Issues and Limitations](#known-issues-and-limitations)

## Quick Start

This example defines an Amazon EKS cluster with the following configuration:

* Dedicated VPC with default configuration (Implicitly created using [ec2.Vpc](https://docs.aws.amazon.com/cdk/api/latest/docs/aws-ec2-readme.html#vpc))
* A Kubernetes pod with a container based on the [paulbouwer/hello-kubernetes](https://github.com/paulbouwer/hello-kubernetes) image.

```python
# provisiong a cluster
cluster = eks.Cluster(self, "hello-eks",
    version=eks.KubernetesVersion.V1_21
)

# apply a kubernetes manifest to the cluster
cluster.add_manifest("mypod", {
    "api_version": "v1",
    "kind": "Pod",
    "metadata": {"name": "mypod"},
    "spec": {
        "containers": [{
            "name": "hello",
            "image": "paulbouwer/hello-kubernetes:1.5",
            "ports": [{"container_port": 8080}]
        }
        ]
    }
})
```

In order to interact with your cluster through `kubectl`, you can use the `aws eks update-kubeconfig` [AWS CLI command](https://docs.aws.amazon.com/cli/latest/reference/eks/update-kubeconfig.html)
to configure your local kubeconfig. The EKS module will define a CloudFormation output in your stack which contains the command to run. For example:

```plaintext
Outputs:
ClusterConfigCommand43AAE40F = aws eks update-kubeconfig --name cluster-xxxxx --role-arn arn:aws:iam::112233445566:role/yyyyy
```

Execute the `aws eks update-kubeconfig ...` command in your terminal to create or update a local kubeconfig context:

```console
$ aws eks update-kubeconfig --name cluster-xxxxx --role-arn arn:aws:iam::112233445566:role/yyyyy
Added new context arn:aws:eks:rrrrr:112233445566:cluster/cluster-xxxxx to /home/boom/.kube/config
```

And now you can simply use `kubectl`:

```console
$ kubectl get all -n kube-system
NAME                           READY   STATUS    RESTARTS   AGE
pod/aws-node-fpmwv             1/1     Running   0          21m
pod/aws-node-m9htf             1/1     Running   0          21m
pod/coredns-5cb4fb54c7-q222j   1/1     Running   0          23m
pod/coredns-5cb4fb54c7-v9nxx   1/1     Running   0          23m
...
```

## Architectural Overview

The following is a qualitative diagram of the various possible components involved in the cluster deployment.

```text
 +-----------------------------------------------+               +-----------------+
 |                 EKS Cluster                   |    kubectl    |                 |
 |-----------------------------------------------|<-------------+| Kubectl Handler |
 |                                               |               |                 |
 |                                               |               +-----------------+
 | +--------------------+    +-----------------+ |
 | |                    |    |                 | |
 | | Managed Node Group |    | Fargate Profile | |               +-----------------+
 | |                    |    |                 | |               |                 |
 | +--------------------+    +-----------------+ |               | Cluster Handler |
 |                                               |               |                 |
 +-----------------------------------------------+               +-----------------+
    ^                                   ^                          +
    |                                   |                          |
    | connect self managed capacity     |                          | aws-sdk
    |                                   | create/update/delete     |
    +                                   |                          v
 +--------------------+                 +              +-------------------+
 |                    |                 --------------+| eks.amazonaws.com |
 | Auto Scaling Group |                                +-------------------+
 |                    |
 +--------------------+
```

In a nutshell:

* `EKS Cluster` - The cluster endpoint created by EKS.
* `Managed Node Group` - EC2 worker nodes managed by EKS.
* `Fargate Profile` - Fargate worker nodes managed by EKS.
* `Auto Scaling Group` - EC2 worker nodes managed by the user.
* `KubectlHandler` - Lambda function for invoking `kubectl` commands on the cluster - created by CDK.
* `ClusterHandler` - Lambda function for interacting with EKS API to manage the cluster lifecycle - created by CDK.

A more detailed breakdown of each is provided further down this README.

## Provisioning clusters

Creating a new cluster is done using the `Cluster` or `FargateCluster` constructs. The only required property is the kubernetes `version`.

```python
eks.Cluster(self, "HelloEKS",
    version=eks.KubernetesVersion.V1_21
)
```

You can also use `FargateCluster` to provision a cluster that uses only fargate workers.

```python
eks.FargateCluster(self, "HelloEKS",
    version=eks.KubernetesVersion.V1_21
)
```

> **NOTE: Only 1 cluster per stack is supported.** If you have a use-case for multiple clusters per stack, or would like to understand more about this limitation, see [https://github.com/aws/aws-cdk/issues/10073](https://github.com/aws/aws-cdk/issues/10073).

Below you'll find a few important cluster configuration options. First of which is Capacity.
Capacity is the amount and the type of worker nodes that are available to the cluster for deploying resources. Amazon EKS offers 3 ways of configuring capacity, which you can combine as you like:

### Managed node groups

Amazon EKS managed node groups automate the provisioning and lifecycle management of nodes (Amazon EC2 instances) for Amazon EKS Kubernetes clusters.
With Amazon EKS managed node groups, you don’t need to separately provision or register the Amazon EC2 instances that provide compute capacity to run your Kubernetes applications. You can create, update, or terminate nodes for your cluster with a single operation. Nodes run using the latest Amazon EKS optimized AMIs in your AWS account while node updates and terminations gracefully drain nodes to ensure that your applications stay available.

> For more details visit [Amazon EKS Managed Node Groups](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html).

**Managed Node Groups are the recommended way to allocate cluster capacity.**

By default, this library will allocate a managed node group with 2 *m5.large* instances (this instance type suits most common use-cases, and is good value for money).

At cluster instantiation time, you can customize the number of instances and their type:

```python
eks.Cluster(self, "HelloEKS",
    version=eks.KubernetesVersion.V1_21,
    default_capacity=5,
    default_capacity_instance=ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.SMALL)
)
```

To access the node group that was created on your behalf, you can use `cluster.defaultNodegroup`.

Additional customizations are available post instantiation. To apply them, set the default capacity to 0, and use the `cluster.addNodegroupCapacity` method:

```python
cluster = eks.Cluster(self, "HelloEKS",
    version=eks.KubernetesVersion.V1_21,
    default_capacity=0
)

cluster.add_nodegroup_capacity("custom-node-group",
    instance_types=[ec2.InstanceType("m5.large")],
    min_size=4,
    disk_size=100,
    ami_type=eks.NodegroupAmiType.AL2_X86_64_GPU
)
```

To set node taints, you can set `taints` option.

```python
# cluster: eks.Cluster

cluster.add_nodegroup_capacity("custom-node-group",
    instance_types=[ec2.InstanceType("m5.large")],
    taints=[eks.TaintSpec(
        effect=eks.TaintEffect.NO_SCHEDULE,
        key="foo",
        value="bar"
    )
    ]
)
```

#### Spot Instances Support

Use `capacityType` to create managed node groups comprised of spot instances. To maximize the availability of your applications while using
Spot Instances, we recommend that you configure a Spot managed node group to use multiple instance types with the `instanceTypes` property.

> For more details visit [Managed node group capacity types](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html#managed-node-group-capacity-types).

```python
# cluster: eks.Cluster

cluster.add_nodegroup_capacity("extra-ng-spot",
    instance_types=[
        ec2.InstanceType("c5.large"),
        ec2.InstanceType("c5a.large"),
        ec2.InstanceType("c5d.large")
    ],
    min_size=3,
    capacity_type=eks.CapacityType.SPOT
)
```

#### Launch Template Support

You can specify a launch template that the node group will use. For example, this can be useful if you want to use
a custom AMI or add custom user data.

When supplying a custom user data script, it must be encoded in the MIME multi-part archive format, since Amazon EKS merges with its own user data. Visit the [Launch Template Docs](https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html#launch-template-user-data)
for mode details.

```python
# cluster: eks.Cluster


user_data = """MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="==MYBOUNDARY=="

--==MYBOUNDARY==
Content-Type: text/x-shellscript; charset="us-ascii"

#!/bin/bash
echo "Running custom user data script"

--==MYBOUNDARY==--\\
"""
lt = ec2.CfnLaunchTemplate(self, "LaunchTemplate",
    launch_template_data=ec2.CfnLaunchTemplate.LaunchTemplateDataProperty(
        instance_type="t3.small",
        user_data=Fn.base64(user_data)
    )
)

cluster.add_nodegroup_capacity("extra-ng",
    launch_template_spec=eks.LaunchTemplateSpec(
        id=lt.ref,
        version=lt.attr_latest_version_number
    )
)
```

Note that when using a custom AMI, Amazon EKS doesn't merge any user data. Which means you do not need the multi-part encoding. and are responsible for supplying the required bootstrap commands for nodes to join the cluster.
In the following example, `/ect/eks/bootstrap.sh` from the AMI will be used to bootstrap the node.

```python
# cluster: eks.Cluster

user_data = ec2.UserData.for_linux()
user_data.add_commands("set -o xtrace", f"/etc/eks/bootstrap.sh {cluster.clusterName}")
lt = ec2.CfnLaunchTemplate(self, "LaunchTemplate",
    launch_template_data=ec2.CfnLaunchTemplate.LaunchTemplateDataProperty(
        image_id="some-ami-id",  # custom AMI
        instance_type="t3.small",
        user_data=Fn.base64(user_data.render())
    )
)
cluster.add_nodegroup_capacity("extra-ng",
    launch_template_spec=eks.LaunchTemplateSpec(
        id=lt.ref,
        version=lt.attr_latest_version_number
    )
)
```

You may specify one `instanceType` in the launch template or multiple `instanceTypes` in the node group, **but not both**.

> For more details visit [Launch Template Support](https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html).

Graviton 2 instance types are supported including `c6g`, `m6g`, `r6g` and `t4g`.

### Fargate profiles

AWS Fargate is a technology that provides on-demand, right-sized compute
capacity for containers. With AWS Fargate, you no longer have to provision,
configure, or scale groups of virtual machines to run containers. This removes
the need to choose server types, decide when to scale your node groups, or
optimize cluster packing.

You can control which pods start on Fargate and how they run with Fargate
Profiles, which are defined as part of your Amazon EKS cluster.

See [Fargate Considerations](https://docs.aws.amazon.com/eks/latest/userguide/fargate.html#fargate-considerations) in the AWS EKS User Guide.

You can add Fargate Profiles to any EKS cluster defined in your CDK app
through the `addFargateProfile()` method. The following example adds a profile
that will match all pods from the "default" namespace:

```python
# cluster: eks.Cluster

cluster.add_fargate_profile("MyProfile",
    selectors=[eks.Selector(namespace="default")]
)
```

You can also directly use the `FargateProfile` construct to create profiles under different scopes:

```python
# cluster: eks.Cluster

eks.FargateProfile(self, "MyProfile",
    cluster=cluster,
    selectors=[eks.Selector(namespace="default")]
)
```

To create an EKS cluster that **only** uses Fargate capacity, you can use `FargateCluster`.
The following code defines an Amazon EKS cluster with a default Fargate Profile that matches all pods from the "kube-system" and "default" namespaces. It is also configured to [run CoreDNS on Fargate](https://docs.aws.amazon.com/eks/latest/userguide/fargate-getting-started.html#fargate-gs-coredns).

```python
cluster = eks.FargateCluster(self, "MyCluster",
    version=eks.KubernetesVersion.V1_21
)
```

`FargateCluster` will create a default `FargateProfile` which can be accessed via the cluster's `defaultProfile` property. The created profile can also be customized by passing options as with `addFargateProfile`.

**NOTE**: Classic Load Balancers and Network Load Balancers are not supported on
pods running on Fargate. For ingress, we recommend that you use the [ALB Ingress
Controller](https://docs.aws.amazon.com/eks/latest/userguide/alb-ingress.html)
on Amazon EKS (minimum version v1.1.4).

### Self-managed nodes

Another way of allocating capacity to an EKS cluster is by using self-managed nodes.
EC2 instances that are part of the auto-scaling group will serve as worker nodes for the cluster.
This type of capacity is also commonly referred to as *EC2 Capacity** or *EC2 Nodes*.

For a detailed overview please visit [Self Managed Nodes](https://docs.aws.amazon.com/eks/latest/userguide/worker.html).

Creating an auto-scaling group and connecting it to the cluster is done using the `cluster.addAutoScalingGroupCapacity` method:

```python
# cluster: eks.Cluster

cluster.add_auto_scaling_group_capacity("frontend-nodes",
    instance_type=ec2.InstanceType("t2.medium"),
    min_capacity=3,
    vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC)
)
```

To connect an already initialized auto-scaling group, use the `cluster.connectAutoScalingGroupCapacity()` method:

```python
# cluster: eks.Cluster
# asg: autoscaling.AutoScalingGroup

cluster.connect_auto_scaling_group_capacity(asg)
```

To connect a self-managed node group to an imported cluster, use the `cluster.connectAutoScalingGroupCapacity()` method:

```python
# cluster: eks.Cluster
# asg: autoscaling.AutoScalingGroup

imported_cluster = eks.Cluster.from_cluster_attributes(self, "ImportedCluster",
    cluster_name=cluster.cluster_name,
    cluster_security_group_id=cluster.cluster_security_group_id
)

imported_cluster.connect_auto_scaling_group_capacity(asg)
```

In both cases, the [cluster security group](https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html#cluster-sg) will be automatically attached to
the auto-scaling group, allowing for traffic to flow freely between managed and self-managed nodes.

> **Note:** The default `updateType` for auto-scaling groups does not replace existing nodes. Since security groups are determined at launch time, self-managed nodes that were provisioned with version `1.78.0` or lower, will not be updated.
> To apply the new configuration on all your self-managed nodes, you'll need to replace the nodes using the `UpdateType.REPLACING_UPDATE` policy for the [`updateType`](https://docs.aws.amazon.com/cdk/api/latest/docs/@aws-cdk_aws-autoscaling.AutoScalingGroup.html#updatetypespan-classapi-icon-api-icon-deprecated-titlethis-api-element-is-deprecated-its-use-is-not-recommended%EF%B8%8Fspan) property.

You can customize the [/etc/eks/boostrap.sh](https://github.com/awslabs/amazon-eks-ami/blob/master/files/bootstrap.sh) script, which is responsible
for bootstrapping the node to the EKS cluster. For example, you can use `kubeletExtraArgs` to add custom node labels or taints.

```python
# cluster: eks.Cluster

cluster.add_auto_scaling_group_capacity("spot",
    instance_type=ec2.InstanceType("t3.large"),
    min_capacity=2,
    bootstrap_options=eks.BootstrapOptions(
        kubelet_extra_args="--node-labels foo=bar,goo=far",
        aws_api_retry_attempts=5
    )
)
```

To disable bootstrapping altogether (i.e. to fully customize user-data), set `bootstrapEnabled` to `false`.
You can also configure the cluster to use an auto-scaling group as the default capacity:

```python
cluster = eks.Cluster(self, "HelloEKS",
    version=eks.KubernetesVersion.V1_21,
    default_capacity_type=eks.DefaultCapacityType.EC2
)
```

This will allocate an auto-scaling group with 2 *m5.large* instances (this instance type suits most common use-cases, and is good value for money).
To access the `AutoScalingGroup` that was created on your behalf, you can use `cluster.defaultCapacity`.
You can also independently create an `AutoScalingGroup` and connect it to the cluster using the `cluster.connectAutoScalingGroupCapacity` method:

```python
# cluster: eks.Cluster
# asg: autoscaling.AutoScalingGroup

cluster.connect_auto_scaling_group_capacity(asg)
```

This will add the necessary user-data to access the apiserver and configure all connections, roles, and tags needed for the instances in the auto-scaling group to properly join the cluster.

#### Spot Instances

When using self-managed nodes, you can configure the capacity to use spot instances, greatly reducing capacity cost.
To enable spot capacity, use the `spotPrice` property:

```python
# cluster: eks.Cluster

cluster.add_auto_scaling_group_capacity("spot",
    spot_price="0.1094",
    instance_type=ec2.InstanceType("t3.large"),
    max_capacity=10
)
```

> Spot instance nodes will be labeled with `lifecycle=Ec2Spot` and tainted with `PreferNoSchedule`.

The [AWS Node Termination Handler](https://github.com/aws/aws-node-termination-handler) `DaemonSet` will be
installed from [Amazon EKS Helm chart repository](https://github.com/aws/eks-charts/tree/master/stable/aws-node-termination-handler) on these nodes.
The termination handler ensures that the Kubernetes control plane responds appropriately to events that
can cause your EC2 instance to become unavailable, such as [EC2 maintenance events](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-instances-status-check_sched.html)
and [EC2 Spot interruptions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/spot-interruptions.html) and helps gracefully stop all pods running on spot nodes that are about to be
terminated.

> Handler Version: [1.7.0](https://github.com/aws/aws-node-termination-handler/releases/tag/v1.7.0)
>
> Chart Version: [0.9.5](https://github.com/aws/eks-charts/blob/v0.0.28/stable/aws-node-termination-handler/Chart.yaml)

To disable the installation of the termination handler, set the `spotInterruptHandler` property to `false`. This applies both to `addAutoScalingGroupCapacity` and `connectAutoScalingGroupCapacity`.

#### Bottlerocket

[Bottlerocket](https://aws.amazon.com/bottlerocket/) is a Linux-based open-source operating system that is purpose-built by Amazon Web Services for running containers on virtual machines or bare metal hosts.

`Bottlerocket` is supported when using managed nodegroups or self-managed auto-scaling groups.

To create a Bottlerocket managed nodegroup:

```python
# cluster: eks.Cluster

cluster.add_nodegroup_capacity("BottlerocketNG",
    ami_type=eks.NodegroupAmiType.BOTTLEROCKET_X86_64
)
```

The following example will create an auto-scaling group of 2 `t3.small` Linux instances running with the `Bottlerocket` AMI.

```python
# cluster: eks.Cluster

cluster.add_auto_scaling_group_capacity("BottlerocketNodes",
    instance_type=ec2.InstanceType("t3.small"),
    min_capacity=2,
    machine_image_type=eks.MachineImageType.BOTTLEROCKET
)
```

The specific Bottlerocket AMI variant will be auto selected according to the k8s version for the `x86_64` architecture.
For example, if the Amazon EKS cluster version is `1.17`, the Bottlerocket AMI variant will be auto selected as
`aws-k8s-1.17` behind the scene.

> See [Variants](https://github.com/bottlerocket-os/bottlerocket/blob/develop/README.md#variants) for more details.

Please note Bottlerocket does not allow to customize bootstrap options and `bootstrapOptions` properties is not supported when you create the `Bottlerocket` capacity.

For more details about Bottlerocket, see [Bottlerocket FAQs](https://aws.amazon.com/bottlerocket/faqs/) and [Bottlerocket Open Source Blog](https://aws.amazon.com/blogs/opensource/announcing-the-general-availability-of-bottlerocket-an-open-source-linux-distribution-purpose-built-to-run-containers/).

### Endpoint Access

When you create a new cluster, Amazon EKS creates an endpoint for the managed Kubernetes API server that you use to communicate with your cluster (using Kubernetes management tools such as `kubectl`)

By default, this API server endpoint is public to the internet, and access to the API server is secured using a combination of
AWS Identity and Access Management (IAM) and native Kubernetes [Role Based Access Control](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) (RBAC).

You can configure the [cluster endpoint access](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html) by using the `endpointAccess` property:

```python
cluster = eks.Cluster(self, "hello-eks",
    version=eks.KubernetesVersion.V1_21,
    endpoint_access=eks.EndpointAccess.PRIVATE
)
```

The default value is `eks.EndpointAccess.PUBLIC_AND_PRIVATE`. Which means the cluster endpoint is accessible from outside of your VPC, but worker node traffic and `kubectl` commands issued by this library stay within your VPC.

### Alb Controller

Some Kubernetes resources are commonly implemented on AWS with the help of the [ALB Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.3/).

From the docs:

> AWS Load Balancer Controller is a controller to help manage Elastic Load Balancers for a Kubernetes cluster.
>
> * It satisfies Kubernetes Ingress resources by provisioning Application Load Balancers.
> * It satisfies Kubernetes Service resources by provisioning Network Load Balancers.

To deploy the controller on your EKS cluster, configure the `albController` property:

```python
eks.Cluster(self, "HelloEKS",
    version=eks.KubernetesVersion.V1_21,
    alb_controller=eks.AlbControllerOptions(
        version=eks.AlbControllerVersion.V2_3_1
    )
)
```

Querying the controller pods should look something like this:

```console
❯ kubectl get pods -n kube-system
NAME                                            READY   STATUS    RESTARTS   AGE
aws-load-balancer-controller-76bd6c7586-d929p   1/1     Running   0          109m
aws-load-balancer-controller-76bd6c7586-fqxph   1/1     Running   0          109m
...
...
```

Every Kubernetes manifest that utilizes the ALB Controller is effectively dependant on the controller.
If the controller is deleted before the manifest, it might result in dangling ELB/ALB resources.
Currently, the EKS construct library does not detect such dependencies, and they should be done explicitly.

For example:

```python
# cluster: eks.Cluster

manifest = cluster.add_manifest("manifest", {})
if cluster.alb_controller:
    manifest.node.add_dependency(cluster.alb_controller)
```

### VPC Support

You can specify the VPC of the cluster using the `vpc` and `vpcSubnets` properties:

```python
# vpc: ec2.Vpc


eks.Cluster(self, "HelloEKS",
    version=eks.KubernetesVersion.V1_21,
    vpc=vpc,
    vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE)]
)
```

> Note: Isolated VPCs (i.e with no internet access) are not currently supported. See https://github.com/aws/aws-cdk/issues/12171

If you do not specify a VPC, one will be created on your behalf, which you can then access via `cluster.vpc`. The cluster VPC will be associated to any EKS managed capacity (i.e Managed Node Groups and Fargate Profiles).

Please note that the `vpcSubnets` property defines the subnets where EKS will place the *control plane* ENIs. To choose
the subnets where EKS will place the worker nodes, please refer to the **Provisioning clusters** section above.

If you allocate self managed capacity, you can specify which subnets should the auto-scaling group use:

```python
# vpc: ec2.Vpc
# cluster: eks.Cluster

cluster.add_auto_scaling_group_capacity("nodes",
    vpc_subnets=ec2.SubnetSelection(subnets=vpc.private_subnets),
    instance_type=ec2.InstanceType("t2.medium")
)
```

There are two additional components you might want to provision within the VPC.

#### Kubectl Handler

The `KubectlHandler` is a Lambda function responsible to issuing `kubectl` and `helm` commands against the cluster when you add resource manifests to the cluster.

The handler association to the VPC is derived from the `endpointAccess` configuration. The rule of thumb is: *If the cluster VPC can be associated, it will be*.

Breaking this down, it means that if the endpoint exposes private access (via `EndpointAccess.PRIVATE` or `EndpointAccess.PUBLIC_AND_PRIVATE`), and the VPC contains **private** subnets, the Lambda function will be provisioned inside the VPC and use the private subnets to interact with the cluster. This is the common use-case.

If the endpoint does not expose private access (via `EndpointAccess.PUBLIC`) **or** the VPC does not contain private subnets, the function will not be provisioned within the VPC.

If your use-case requires control over the IAM role that the KubeCtl Handler assumes, a custom role can be passed through the ClusterProps (as `kubectlLambdaRole`) of the EKS Cluster construct.

#### Cluster Handler

The `ClusterHandler` is a set of Lambda functions (`onEventHandler`, `isCompleteHandler`) responsible for interacting with the EKS API in order to control the cluster lifecycle. To provision these functions inside the VPC, set the `placeClusterHandlerInVpc` property to `true`. This will place the functions inside the private subnets of the VPC based on the selection strategy specified in the [`vpcSubnets`](https://docs.aws.amazon.com/cdk/api/latest/docs/@aws-cdk_aws-eks.Cluster.html#vpcsubnetsspan-classapi-icon-api-icon-experimental-titlethis-api-element-is-experimental-it-may-change-without-noticespan) property.

You can configure the environment of the Cluster Handler functions by specifying it at cluster instantiation. For example, this can be useful in order to configure an http proxy:

```python
# proxy_instance_security_group: ec2.SecurityGroup

cluster = eks.Cluster(self, "hello-eks",
    version=eks.KubernetesVersion.V1_21,
    cluster_handler_environment={
        "https_proxy": "http://proxy.myproxy.com"
    },
    #
    # If the proxy is not open publicly, you can pass a security group to the
    # Cluster Handler Lambdas so that it can reach the proxy.
    #
    cluster_handler_security_group=proxy_instance_security_group
)
```

### Kubectl Support

The resources are created in the cluster by running `kubectl apply` from a python lambda function.

By default, CDK will create a new python lambda function to apply your k8s manifests. If you want to use an existing kubectl provider function, for example with tight trusted entities on your IAM Roles - you can import the existing provider and then use the imported provider when importing the cluster:

```python
handler_role = iam.Role.from_role_arn(self, "HandlerRole", "arn:aws:iam::123456789012:role/lambda-role")
kubectl_provider = eks.KubectlProvider.from_kubectl_provider_attributes(self, "KubectlProvider",
    function_arn="arn:aws:lambda:us-east-2:123456789012:function:my-function:1",
    kubectl_role_arn="arn:aws:iam::123456789012:role/kubectl-role",
    handler_role=handler_role
)

cluster = eks.Cluster.from_cluster_attributes(self, "Cluster",
    cluster_name="cluster",
    kubectl_provider=kubectl_provider
)
```

#### Environment

You can configure the environment of this function by specifying it at cluster instantiation. For example, this can be useful in order to configure an http proxy:

```python
cluster = eks.Cluster(self, "hello-eks",
    version=eks.KubernetesVersion.V1_21,
    kubectl_environment={
        "http_proxy": "http://proxy.myproxy.com"
    }
)
```

#### Runtime

The kubectl handler uses `kubectl`, `helm` and the `aws` CLI in order to
interact with the cluster. These are bundled into AWS Lambda layers included in
the `@aws-cdk/lambda-layer-awscli` and `@aws-cdk/lambda-layer-kubectl` modules.

You can specify a custom `lambda.LayerVersion` if you wish to use a different
version of these tools. The handler expects the layer to include the following
three executables:

```text
helm/helm
kubectl/kubectl
awscli/aws
```

See more information in the
[Dockerfile](https://github.com/aws/aws-cdk/tree/master/packages/%40aws-cdk/lambda-layer-awscli/layer) for @aws-cdk/lambda-layer-awscli
and the
[Dockerfile](https://github.com/aws/aws-cdk/tree/master/packages/%40aws-cdk/lambda-layer-kubectl/layer) for @aws-cdk/lambda-layer-kubectl.

```python
layer = lambda_.LayerVersion(self, "KubectlLayer",
    code=lambda_.Code.from_asset("layer.zip")
)
```

Now specify when the cluster is defined:

```python
# layer: lambda.LayerVersion
# vpc: ec2.Vpc


cluster1 = eks.Cluster(self, "MyCluster",
    kubectl_layer=layer,
    vpc=vpc,
    cluster_name="cluster-name",
    version=eks.KubernetesVersion.V1_21
)

# or
cluster2 = eks.Cluster.from_cluster_attributes(self, "MyCluster",
    kubectl_layer=layer,
    vpc=vpc,
    cluster_name="cluster-name"
)
```

#### Memory

By default, the kubectl provider is configured with 1024MiB of memory. You can use the `kubectlMemory` option to specify the memory size for the AWS Lambda function:

```python
# or
# vpc: ec2.Vpc
eks.Cluster(self, "MyCluster",
    kubectl_memory=Size.gibibytes(4),
    version=eks.KubernetesVersion.V1_21
)
eks.Cluster.from_cluster_attributes(self, "MyCluster",
    kubectl_memory=Size.gibibytes(4),
    vpc=vpc,
    cluster_name="cluster-name"
)
```

### ARM64 Support

Instance types with `ARM64` architecture are supported in both managed nodegroup and self-managed capacity. Simply specify an ARM64 `instanceType` (such as `m6g.medium`), and the latest
Amazon Linux 2 AMI for ARM64 will be automatically selected.

```python
# cluster: eks.Cluster

# add a managed ARM64 nodegroup
cluster.add_nodegroup_capacity("extra-ng-arm",
    instance_types=[ec2.InstanceType("m6g.medium")],
    min_size=2
)

# add a self-managed ARM64 nodegroup
cluster.add_auto_scaling_group_capacity("self-ng-arm",
    instance_type=ec2.InstanceType("m6g.medium"),
    min_capacity=2
)
```

### Masters Role

When you create a cluster, you can specify a `mastersRole`. The `Cluster` construct will associate this role with the `system:masters` [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) group, giving it super-user access to the cluster.

```python
# role: iam.Role

eks.Cluster(self, "HelloEKS",
    version=eks.KubernetesVersion.V1_21,
    masters_role=role
)
```

If you do not specify it, a default role will be created on your behalf, that can be assumed by anyone in the account with `sts:AssumeRole` permissions for this role.

This is the role you see as part of the stack outputs mentioned in the [Quick Start](#quick-start).

```console
$ aws eks update-kubeconfig --name cluster-xxxxx --role-arn arn:aws:iam::112233445566:role/yyyyy
Added new context arn:aws:eks:rrrrr:112233445566:cluster/cluster-xxxxx to /home/boom/.kube/config
```

### Encryption

When you create an Amazon EKS cluster, envelope encryption of Kubernetes secrets using the AWS Key Management Service (AWS KMS) can be enabled.
The documentation on [creating a cluster](https://docs.aws.amazon.com/eks/latest/userguide/create-cluster.html)
can provide more details about the customer master key (CMK) that can be used for the encryption.

You can use the `secretsEncryptionKey` to configure which key the cluster will use to encrypt Kubernetes secrets. By default, an AWS Managed key will be used.

> This setting can only be specified when the cluster is created and cannot be updated.

```python
secrets_key = kms.Key(self, "SecretsKey")
cluster = eks.Cluster(self, "MyCluster",
    secrets_encryption_key=secrets_key,
    version=eks.KubernetesVersion.V1_21
)
```

You can also use a similar configuration for running a cluster built using the FargateCluster construct.

```python
secrets_key = kms.Key(self, "SecretsKey")
cluster = eks.FargateCluster(self, "MyFargateCluster",
    secrets_encryption_key=secrets_key,
    version=eks.KubernetesVersion.V1_21
)
```

The Amazon Resource Name (ARN) for that CMK can be retrieved.

```python
# cluster: eks.Cluster

cluster_encryption_config_key_arn = cluster.cluster_encryption_config_key_arn
```

## Permissions and Security

Amazon EKS provides several mechanism of securing the cluster and granting permissions to specific IAM users and roles.

### AWS IAM Mapping

As described in the [Amazon EKS User Guide](https://docs.aws.amazon.com/en_us/eks/latest/userguide/add-user-role.html), you can map AWS IAM users and roles to [Kubernetes Role-based access control (RBAC)](https://kubernetes.io/docs/reference/access-authn-authz/rbac).

The Amazon EKS construct manages the *aws-auth* `ConfigMap` Kubernetes resource on your behalf and exposes an API through the `cluster.awsAuth` for mapping
users, roles and accounts.

Furthermore, when auto-scaling group capacity is added to the cluster, the IAM instance role of the auto-scaling group will be automatically mapped to RBAC so nodes can connect to the cluster. No manual mapping is required.

For example, let's say you want to grant an IAM user administrative privileges on your cluster:

```python
# cluster: eks.Cluster

admin_user = iam.User(self, "Admin")
cluster.aws_auth.add_user_mapping(admin_user, groups=["system:masters"])
```

A convenience method for mapping a role to the `system:masters` group is also available:

```python
# cluster: eks.Cluster
# role: iam.Role

cluster.aws_auth.add_masters_role(role)
```

### Cluster Security Group

When you create an Amazon EKS cluster, a [cluster security group](https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html)
is automatically created as well. This security group is designed to allow all traffic from the control plane and managed node groups to flow freely
between each other.

The ID for that security group can be retrieved after creating the cluster.

```python
# cluster: eks.Cluster

cluster_security_group_id = cluster.cluster_security_group_id
```

### Node SSH Access

If you want to be able to SSH into your worker nodes, you must already have an SSH key in the region you're connecting to and pass it when
you add capacity to the cluster. You must also be able to connect to the hosts (meaning they must have a public IP and you
should be allowed to connect to them on port 22):

See [SSH into nodes](test/example.ssh-into-nodes.lit.ts) for a code example.

If you want to SSH into nodes in a private subnet, you should set up a bastion host in a public subnet. That setup is recommended, but is
unfortunately beyond the scope of this documentation.

### Service Accounts

With services account you can provide Kubernetes Pods access to AWS resources.

```python
# cluster: eks.Cluster

# add service account
service_account = cluster.add_service_account("MyServiceAccount")

bucket = s3.Bucket(self, "Bucket")
bucket.grant_read_write(service_account)

mypod = cluster.add_manifest("mypod", {
    "api_version": "v1",
    "kind": "Pod",
    "metadata": {"name": "mypod"},
    "spec": {
        "service_account_name": service_account.service_account_name,
        "containers": [{
            "name": "hello",
            "image": "paulbouwer/hello-kubernetes:1.5",
            "ports": [{"container_port": 8080}]
        }
        ]
    }
})

# create the resource after the service account.
mypod.node.add_dependency(service_account)

# print the IAM role arn for this service account
CfnOutput(self, "ServiceAccountIamRole", value=service_account.role.role_arn)
```

Note that using `serviceAccount.serviceAccountName` above **does not** translate into a resource dependency.
This is why an explicit dependency is needed. See [https://github.com/aws/aws-cdk/issues/9910](https://github.com/aws/aws-cdk/issues/9910) for more details.

You can also add service accounts to existing clusters.
To do so, pass the `openIdConnectProvider` property when you import the cluster into the application.

```python
# or create a new one using an existing issuer url
# issuer_url: str
# you can import an existing provider
provider = eks.OpenIdConnectProvider.from_open_id_connect_provider_arn(self, "Provider", "arn:aws:iam::123456:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/AB123456ABC")
provider2 = eks.OpenIdConnectProvider(self, "Provider",
    url=issuer_url
)

cluster = eks.Cluster.from_cluster_attributes(self, "MyCluster",
    cluster_name="Cluster",
    open_id_connect_provider=provider,
    kubectl_role_arn="arn:aws:iam::123456:role/service-role/k8sservicerole"
)

service_account = cluster.add_service_account("MyServiceAccount")

bucket = s3.Bucket(self, "Bucket")
bucket.grant_read_write(service_account)
```

Note that adding service accounts requires running `kubectl` commands against the cluster.
This means you must also pass the `kubectlRoleArn` when importing the cluster.
See [Using existing Clusters](https://github.com/aws/aws-cdk/tree/master/packages/@aws-cdk/aws-eks#using-existing-clusters).

## Applying Kubernetes Resources

The library supports several popular resource deployment mechanisms, among which are:

### Kubernetes Manifests

The `KubernetesManifest` construct or `cluster.addManifest` method can be used
to apply Kubernetes resource manifests to this cluster.

> When using `cluster.addManifest`, the manifest construct is defined within the cluster's stack scope. If the manifest contains
> attributes from a different stack which depend on the cluster stack, a circular dependency will be created and you will get a synth time error.
> To avoid this, directly use `new KubernetesManifest` to create the manifest in the scope of the other stack.

The following examples will deploy the [paulbouwer/hello-kubernetes](https://github.com/paulbouwer/hello-kubernetes)
service on the cluster:

```python
# cluster: eks.Cluster

app_label = {"app": "hello-kubernetes"}

deployment = {
    "api_version": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "hello-kubernetes"},
    "spec": {
        "replicas": 3,
        "selector": {"match_labels": app_label},
        "template": {
            "metadata": {"labels": app_label},
            "spec": {
                "containers": [{
                    "name": "hello-kubernetes",
                    "image": "paulbouwer/hello-kubernetes:1.5",
                    "ports": [{"container_port": 8080}]
                }
                ]
            }
        }
    }
}

service = {
    "api_version": "v1",
    "kind": "Service",
    "metadata": {"name": "hello-kubernetes"},
    "spec": {
        "type": "LoadBalancer",
        "ports": [{"port": 80, "target_port": 8080}],
        "selector": app_label
    }
}

# option 1: use a construct
eks.KubernetesManifest(self, "hello-kub",
    cluster=cluster,
    manifest=[deployment, service]
)

# or, option2: use `addManifest`
cluster.add_manifest("hello-kub", service, deployment)
```

#### ALB Controller Integration

The `KubernetesManifest` construct can detect ingress resources inside your manifest and automatically add the necessary annotations
so they are picked up by the ALB Controller.

> See [Alb Controller](#alb-controller)

To that end, it offers the following properties:

* `ingressAlb` - Signal that the ingress detection should be done.
* `ingressAlbScheme` - Which ALB scheme should be applied. Defaults to `internal`.

#### Adding resources from a URL

The following example will deploy the resource manifest hosting on remote server:

```text
// This example is only available in TypeScript

import * as yaml from 'js-yaml';
import * as request from 'sync-request';

declare const cluster: eks.Cluster;
const manifestUrl = 'https://url/of/manifest.yaml';
const manifest = yaml.safeLoadAll(request('GET', manifestUrl).getBody());
cluster.addManifest('my-resource', manifest);
```

#### Dependencies

There are cases where Kubernetes resources must be deployed in a specific order.
For example, you cannot define a resource in a Kubernetes namespace before the
namespace was created.

You can represent dependencies between `KubernetesManifest`s using
`resource.node.addDependency()`:

```python
# cluster: eks.Cluster

namespace = cluster.add_manifest("my-namespace", {
    "api_version": "v1",
    "kind": "Namespace",
    "metadata": {"name": "my-app"}
})

service = cluster.add_manifest("my-service", {
    "metadata": {
        "name": "myservice",
        "namespace": "my-app"
    },
    "spec": {}
})

service.node.add_dependency(namespace)
```

**NOTE:** when a `KubernetesManifest` includes multiple resources (either directly
or through `cluster.addManifest()`) (e.g. `cluster.addManifest('foo', r1, r2, r3,...)`), these resources will be applied as a single manifest via `kubectl`
and will be applied sequentially (the standard behavior in `kubectl`).

---


Since Kubernetes manifests are implemented as CloudFormation resources in the
CDK. This means that if the manifest is deleted from your code (or the stack is
deleted), the next `cdk deploy` will issue a `kubectl delete` command and the
Kubernetes resources in that manifest will be deleted.

#### Resource Pruning

When a resource is deleted from a Kubernetes manifest, the EKS module will
automatically delete these resources by injecting a *prune label* to all
manifest resources. This label is then passed to [`kubectl apply --prune`](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/#alternative-kubectl-apply-f-directory-prune-l-your-label).

Pruning is enabled by default but can be disabled through the `prune` option
when a cluster is defined:

```python
eks.Cluster(self, "MyCluster",
    version=eks.KubernetesVersion.V1_21,
    prune=False
)
```

#### Manifests Validation

The `kubectl` CLI supports applying a manifest by skipping the validation.
This can be accomplished by setting the `skipValidation` flag to `true` in the `KubernetesManifest` props.

```python
# cluster: eks.Cluster

eks.KubernetesManifest(self, "HelloAppWithoutValidation",
    cluster=cluster,
    manifest=[{"foo": "bar"}],
    skip_validation=True
)
```

### Helm Charts

The `HelmChart` construct or `cluster.addHelmChart` method can be used
to add Kubernetes resources to this cluster using Helm.

> When using `cluster.addHelmChart`, the manifest construct is defined within the cluster's stack scope. If the manifest contains
> attributes from a different stack which depend on the cluster stack, a circular dependency will be created and you will get a synth time error.
> To avoid this, directly use `new HelmChart` to create the chart in the scope of the other stack.

The following example will install the [NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/) to your cluster using Helm.

```python
# cluster: eks.Cluster

# option 1: use a construct
eks.HelmChart(self, "NginxIngress",
    cluster=cluster,
    chart="nginx-ingress",
    repository="https://helm.nginx.com/stable",
    namespace="kube-system"
)

# or, option2: use `addHelmChart`
cluster.add_helm_chart("NginxIngress",
    chart="nginx-ingress",
    repository="https://helm.nginx.com/stable",
    namespace="kube-system"
)
```

Helm charts will be installed and updated using `helm upgrade --install`, where a few parameters
are being passed down (such as `repo`, `values`, `version`, `namespace`, `wait`, `timeout`, etc).
This means that if the chart is added to CDK with the same release name, it will try to update
the chart in the cluster.

Additionally, the `chartAsset` property can be an `aws-s3-assets.Asset`. This allows the use of local, private helm charts.

```python
import aws_cdk.aws_s3_assets as s3_assets

# cluster: eks.Cluster

chart_asset = s3_assets.Asset(self, "ChartAsset",
    path="/path/to/asset"
)

cluster.add_helm_chart("test-chart",
    chart_asset=chart_asset
)
```

### OCI Charts

OCI charts are also supported.
Also replace the `${VARS}` with appropriate values.

```python
# cluster: eks.Cluster

# option 1: use a construct
eks.HelmChart(self, "MyOCIChart",
    cluster=cluster,
    chart="some-chart",
    repository="oci://${ACCOUNT_ID}.dkr.ecr.${ACCOUNT_REGION}.amazonaws.com/${REPO_NAME}",
    namespace="oci",
    version="0.0.1"
)
```

Helm charts are implemented as CloudFormation resources in CDK.
This means that if the chart is deleted from your code (or the stack is
deleted), the next `cdk deploy` will issue a `helm uninstall` command and the
Helm chart will be deleted.

When there is no `release` defined, a unique ID will be allocated for the release based
on the construct path.

By default, all Helm charts will be installed concurrently. In some cases, this
could cause race conditions where two Helm charts attempt to deploy the same
resource or if Helm charts depend on each other. You can use
`chart.node.addDependency()` in order to declare a dependency order between
charts:

```python
# cluster: eks.Cluster

chart1 = cluster.add_helm_chart("MyChart",
    chart="foo"
)
chart2 = cluster.add_helm_chart("MyChart",
    chart="bar"
)

chart2.node.add_dependency(chart1)
```

#### CDK8s Charts

[CDK8s](https://cdk8s.io/) is an open-source library that enables Kubernetes manifest authoring using familiar programming languages. It is founded on the same technologies as the AWS CDK, such as [`constructs`](https://github.com/aws/constructs) and [`jsii`](https://github.com/aws/jsii).

> To learn more about cdk8s, visit the [Getting Started](https://cdk8s.io/docs/latest/getting-started/) tutorials.

The EKS module natively integrates with cdk8s and allows you to apply cdk8s charts on AWS EKS clusters via the `cluster.addCdk8sChart` method.

In addition to `cdk8s`, you can also use [`cdk8s+`](https://cdk8s.io/docs/latest/plus/), which provides higher level abstraction for the core kubernetes api objects.
You can think of it like the `L2` constructs for Kubernetes. Any other `cdk8s` based libraries are also supported, for example [`cdk8s-debore`](https://github.com/toricls/cdk8s-debore).

To get started, add the following dependencies to your `package.json` file:

```json
"dependencies": {
  "cdk8s": "^1.0.0",
  "cdk8s-plus-21": "^1.0.0-beta.38",
  "constructs": "^3.3.69"
}
```

Note that here we are using `cdk8s-plus-21` as we are targeting Kubernetes version 1.21.0. If you operate a different kubernetes version, you should
use the corresponding `cdk8s-plus-XX` library.
See [Select the appropriate cdk8s+ library](https://cdk8s.io/docs/latest/plus/#i-operate-kubernetes-version-1xx-which-cdk8s-library-should-i-be-using)
for more details.

Similarly to how you would create a stack by extending `@aws-cdk/core.Stack`, we recommend you create a chart of your own that extends `cdk8s.Chart`,
and add your kubernetes resources to it. You can use `aws-cdk` construct attributes and properties inside your `cdk8s` construct freely.

In this example we create a chart that accepts an `s3.Bucket` and passes its name to a kubernetes pod as an environment variable.

Notice that the chart must accept a `constructs.Construct` type as its scope, not an `@aws-cdk/core.Construct` as you would normally use.
For this reason, to avoid possible confusion, we will create the chart in a separate file:

`+ my-chart.ts`

```python
import aws_cdk.aws_s3 as s3
import constructs as constructs
import cdk8s as cdk8s
import cdk8s_plus_21 as kplus

class MyChart(cdk8s.Chart):
    def __init__(self, scope, id, *, bucket):
        super().__init__(scope, id)

        kplus.Pod(self, "Pod",
            containers=[
                kplus.Container(
                    image="my-image",
                    env={
                        "BUCKET_NAME": kplus.EnvValue.from_value(bucket.bucket_name)
                    }
                )
            ]
        )
```

Then, in your AWS CDK app:

```python
# cluster: eks.Cluster


# some bucket..
bucket = s3.Bucket(self, "Bucket")

# create a cdk8s chart and use `cdk8s.App` as the scope.
my_chart = MyChart(cdk8s.App(), "MyChart", bucket=bucket)

# add the cdk8s chart to the cluster
cluster.add_cdk8s_chart("my-chart", my_chart)
```

##### Custom CDK8s Constructs

You can also compose a few stock `cdk8s+` constructs into your own custom construct. However, since mixing scopes between `aws-cdk` and `cdk8s` is currently not supported, the `Construct` class
you'll need to use is the one from the [`constructs`](https://github.com/aws/constructs) module, and not from `@aws-cdk/core` like you normally would.
This is why we used `new cdk8s.App()` as the scope of the chart above.

```python
import constructs as constructs
import cdk8s as cdk8s
import cdk8s_plus_21 as kplus

app = cdk8s.App()
chart = cdk8s.Chart(app, "my-chart")

class LoadBalancedWebService(constructs.Construct):
    def __init__(self, scope, id, props):
        super().__init__(scope, id)

        deployment = kplus.Deployment(chart, "Deployment",
            replicas=props.replicas,
            containers=[kplus.Container(image=props.image)]
        )

        deployment.expose_via_service(
            port=props.port,
            service_type=kplus.ServiceType.LOAD_BALANCER
        )
```

##### Manually importing k8s specs and CRD's

If you find yourself unable to use `cdk8s+`, or just like to directly use the `k8s` native objects or CRD's, you can do so by manually importing them using the `cdk8s-cli`.

See [Importing kubernetes objects](https://cdk8s.io/docs/latest/cli/import/) for detailed instructions.

## Patching Kubernetes Resources

The `KubernetesPatch` construct can be used to update existing kubernetes
resources. The following example can be used to patch the `hello-kubernetes`
deployment from the example above with 5 replicas.

```python
# cluster: eks.Cluster

eks.KubernetesPatch(self, "hello-kub-deployment-label",
    cluster=cluster,
    resource_name="deployment/hello-kubernetes",
    apply_patch={"spec": {"replicas": 5}},
    restore_patch={"spec": {"replicas": 3}}
)
```

## Querying Kubernetes Resources

The `KubernetesObjectValue` construct can be used to query for information about kubernetes objects,
and use that as part of your CDK application.

For example, you can fetch the address of a [`LoadBalancer`](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer) type service:

```python
# cluster: eks.Cluster

# query the load balancer address
my_service_address = eks.KubernetesObjectValue(self, "LoadBalancerAttribute",
    cluster=cluster,
    object_type="service",
    object_name="my-service",
    json_path=".status.loadBalancer.ingress[0].hostname"
)

# pass the address to a lambda function
proxy_function = lambda_.Function(self, "ProxyFunction",
    handler="index.handler",
    code=lambda_.Code.from_inline("my-code"),
    runtime=lambda_.Runtime.NODEJS_14_X,
    environment={
        "my_service_address": my_service_address.value
    }
)
```

Specifically, since the above use-case is quite common, there is an easier way to access that information:

```python
# cluster: eks.Cluster

load_balancer_address = cluster.get_service_load_balancer_address("my-service")
```

## Using existing clusters

The Amazon EKS library allows defining Kubernetes resources such as [Kubernetes
manifests](#kubernetes-resources) and [Helm charts](#helm-charts) on clusters
that are not defined as part of your CDK app.

First, you'll need to "import" a cluster to your CDK app. To do that, use the
`eks.Cluster.fromClusterAttributes()` static method:

```python
cluster = eks.Cluster.from_cluster_attributes(self, "MyCluster",
    cluster_name="my-cluster-name",
    kubectl_role_arn="arn:aws:iam::1111111:role/iam-role-that-has-masters-access"
)
```

Then, you can use `addManifest` or `addHelmChart` to define resources inside
your Kubernetes cluster. For example:

```python
# cluster: eks.Cluster

cluster.add_manifest("Test", {
    "api_version": "v1",
    "kind": "ConfigMap",
    "metadata": {
        "name": "myconfigmap"
    },
    "data": {
        "Key": "value",
        "Another": "123454"
    }
})
```

At the minimum, when importing clusters for `kubectl` management, you will need
to specify:

* `clusterName` - the name of the cluster.
* `kubectlRoleArn` - the ARN of an IAM role mapped to the `system:masters` RBAC
  role. If the cluster you are importing was created using the AWS CDK, the
  CloudFormation stack has an output that includes an IAM role that can be used.
  Otherwise, you can create an IAM role and map it to `system:masters` manually.
  The trust policy of this role should include the the
  `arn:aws::iam::${accountId}:root` principal in order to allow the execution
  role of the kubectl resource to assume it.

If the cluster is configured with private-only or private and restricted public
Kubernetes [endpoint access](#endpoint-access), you must also specify:

* `kubectlSecurityGroupId` - the ID of an EC2 security group that is allowed
  connections to the cluster's control security group. For example, the EKS managed [cluster security group](#cluster-security-group).
* `kubectlPrivateSubnetIds` - a list of private VPC subnets IDs that will be used
  to access the Kubernetes endpoint.

## Logging

EKS supports cluster logging for 5 different types of events:

* API requests to the cluster.
* Cluster access via the Kubernetes API.
* Authentication requests into the cluster.
* State of cluster controllers.
* Scheduling decisions.

You can enable logging for each one separately using the `clusterLogging`
property. For example:

```python
cluster = eks.Cluster(self, "Cluster",
    # ...
    version=eks.KubernetesVersion.V1_21,
    cluster_logging=[eks.ClusterLoggingTypes.API, eks.ClusterLoggingTypes.AUTHENTICATOR, eks.ClusterLoggingTypes.SCHEDULER
    ]
)
```

## Known Issues and Limitations

* [One cluster per stack](https://github.com/aws/aws-cdk/issues/10073)
* [Service Account dependencies](https://github.com/aws/aws-cdk/issues/9910)
* [Support isolated VPCs](https://github.com/aws/aws-cdk/issues/12171)
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
    ITaggable as _ITaggable_36806126,
    NestedStack as _NestedStack_dd393a45,
    Resource as _Resource_45bc6135,
    Size as _Size_7b441c34,
    TagManager as _TagManager_0a598cb3,
    TreeInspector as _TreeInspector_488e0dd5,
)
from ..aws_autoscaling import (
    AutoScalingGroup as _AutoScalingGroup_c547a7b9,
    BlockDevice as _BlockDevice_0cfc0568,
    CommonAutoScalingGroupProps as _CommonAutoScalingGroupProps_808bbf2d,
    GroupMetrics as _GroupMetrics_7cdf729b,
    HealthCheck as _HealthCheck_03a4bd5a,
    Monitoring as _Monitoring_50020f91,
    NotificationConfiguration as _NotificationConfiguration_d5911670,
    Signals as _Signals_69fbeb6e,
    TerminationPolicy as _TerminationPolicy_89633c56,
    UpdatePolicy as _UpdatePolicy_6dffc7ca,
)
from ..aws_ec2 import (
    Connections as _Connections_0f31fce8,
    IConnectable as _IConnectable_10015a05,
    IMachineImage as _IMachineImage_0e8bd50b,
    ISecurityGroup as _ISecurityGroup_acf8a799,
    ISubnet as _ISubnet_d57d1229,
    IVpc as _IVpc_f30d5663,
    InstanceType as _InstanceType_f64915b9,
    MachineImageConfig as _MachineImageConfig_187edaee,
    SubnetSelection as _SubnetSelection_e57d76df,
)
from ..aws_iam import (
    AddToPrincipalPolicyResult as _AddToPrincipalPolicyResult_946c9561,
    IOpenIdConnectProvider as _IOpenIdConnectProvider_203f0793,
    IPrincipal as _IPrincipal_539bb2fd,
    IRole as _IRole_235f5d8e,
    IUser as _IUser_c32311f7,
    OpenIdConnectProvider as _OpenIdConnectProvider_5cb7bc9f,
    PolicyStatement as _PolicyStatement_0fe33853,
    PrincipalPolicyFragment as _PrincipalPolicyFragment_6a855d11,
    Role as _Role_e8c6e11f,
)
from ..aws_kms import IKey as _IKey_5f11635f
from ..aws_lambda import ILayerVersion as _ILayerVersion_5ac127c8
from ..aws_s3_assets import Asset as _Asset_ac2a7e61


class AlbController(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.AlbController",
):
    '''Construct for installing the AWS ALB Contoller on EKS clusters.

    Use the factory functions ``get`` and ``getOrCreate`` to obtain/create instances of this controller.

    :see: https://kubernetes-sigs.github.io/aws-load-balancer-controller
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_eks as eks
        
        # alb_controller_version: eks.AlbControllerVersion
        # cluster: eks.Cluster
        # policy: Any
        
        alb_controller = eks.AlbController(self, "MyAlbController",
            cluster=cluster,
            version=alb_controller_version,
        
            # the properties below are optional
            policy=policy,
            repository="repository"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster: "Cluster",
        version: "AlbControllerVersion",
        policy: typing.Any = None,
        repository: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param cluster: [disable-awslint:ref-via-interface] Cluster to install the controller onto.
        :param version: Version of the controller.
        :param policy: The IAM policy to apply to the service account. If you're using one of the built-in versions, this is not required since CDK ships with the appropriate policies for those versions. However, if you are using a custom version, this is required (and validated). Default: - Corresponds to the predefined version.
        :param repository: The repository to pull the controller image from. Note that the default repository works for most regions, but not all. If the repository is not applicable to your region, use a custom repository according to the information here: https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases. Default: '602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-load-balancer-controller'
        '''
        props = AlbControllerProps(
            cluster=cluster, version=version, policy=policy, repository=repository
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="create") # type: ignore[misc]
    @builtins.classmethod
    def create(
        cls,
        scope: constructs.Construct,
        *,
        cluster: "Cluster",
        version: "AlbControllerVersion",
        policy: typing.Any = None,
        repository: typing.Optional[builtins.str] = None,
    ) -> "AlbController":
        '''Create the controller construct associated with this cluster and scope.

        Singleton per stack/cluster.

        :param scope: -
        :param cluster: [disable-awslint:ref-via-interface] Cluster to install the controller onto.
        :param version: Version of the controller.
        :param policy: The IAM policy to apply to the service account. If you're using one of the built-in versions, this is not required since CDK ships with the appropriate policies for those versions. However, if you are using a custom version, this is required (and validated). Default: - Corresponds to the predefined version.
        :param repository: The repository to pull the controller image from. Note that the default repository works for most regions, but not all. If the repository is not applicable to your region, use a custom repository according to the information here: https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases. Default: '602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-load-balancer-controller'
        '''
        props = AlbControllerProps(
            cluster=cluster, version=version, policy=policy, repository=repository
        )

        return typing.cast("AlbController", jsii.sinvoke(cls, "create", [scope, props]))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.AlbControllerOptions",
    jsii_struct_bases=[],
    name_mapping={
        "version": "version",
        "policy": "policy",
        "repository": "repository",
    },
)
class AlbControllerOptions:
    def __init__(
        self,
        *,
        version: "AlbControllerVersion",
        policy: typing.Any = None,
        repository: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Options for ``AlbController``.

        :param version: Version of the controller.
        :param policy: The IAM policy to apply to the service account. If you're using one of the built-in versions, this is not required since CDK ships with the appropriate policies for those versions. However, if you are using a custom version, this is required (and validated). Default: - Corresponds to the predefined version.
        :param repository: The repository to pull the controller image from. Note that the default repository works for most regions, but not all. If the repository is not applicable to your region, use a custom repository according to the information here: https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases. Default: '602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-load-balancer-controller'

        :exampleMetadata: infused

        Example::

            eks.Cluster(self, "HelloEKS",
                version=eks.KubernetesVersion.V1_21,
                alb_controller=eks.AlbControllerOptions(
                    version=eks.AlbControllerVersion.V2_3_1
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "version": version,
        }
        if policy is not None:
            self._values["policy"] = policy
        if repository is not None:
            self._values["repository"] = repository

    @builtins.property
    def version(self) -> "AlbControllerVersion":
        '''Version of the controller.'''
        result = self._values.get("version")
        assert result is not None, "Required property 'version' is missing"
        return typing.cast("AlbControllerVersion", result)

    @builtins.property
    def policy(self) -> typing.Any:
        '''The IAM policy to apply to the service account.

        If you're using one of the built-in versions, this is not required since
        CDK ships with the appropriate policies for those versions.

        However, if you are using a custom version, this is required (and validated).

        :default: - Corresponds to the predefined version.
        '''
        result = self._values.get("policy")
        return typing.cast(typing.Any, result)

    @builtins.property
    def repository(self) -> typing.Optional[builtins.str]:
        '''The repository to pull the controller image from.

        Note that the default repository works for most regions, but not all.
        If the repository is not applicable to your region, use a custom repository
        according to the information here: https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases.

        :default: '602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-load-balancer-controller'
        '''
        result = self._values.get("repository")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AlbControllerOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.AlbControllerProps",
    jsii_struct_bases=[AlbControllerOptions],
    name_mapping={
        "version": "version",
        "policy": "policy",
        "repository": "repository",
        "cluster": "cluster",
    },
)
class AlbControllerProps(AlbControllerOptions):
    def __init__(
        self,
        *,
        version: "AlbControllerVersion",
        policy: typing.Any = None,
        repository: typing.Optional[builtins.str] = None,
        cluster: "Cluster",
    ) -> None:
        '''Properties for ``AlbController``.

        :param version: Version of the controller.
        :param policy: The IAM policy to apply to the service account. If you're using one of the built-in versions, this is not required since CDK ships with the appropriate policies for those versions. However, if you are using a custom version, this is required (and validated). Default: - Corresponds to the predefined version.
        :param repository: The repository to pull the controller image from. Note that the default repository works for most regions, but not all. If the repository is not applicable to your region, use a custom repository according to the information here: https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases. Default: '602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-load-balancer-controller'
        :param cluster: [disable-awslint:ref-via-interface] Cluster to install the controller onto.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            # alb_controller_version: eks.AlbControllerVersion
            # cluster: eks.Cluster
            # policy: Any
            
            alb_controller_props = eks.AlbControllerProps(
                cluster=cluster,
                version=alb_controller_version,
            
                # the properties below are optional
                policy=policy,
                repository="repository"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "version": version,
            "cluster": cluster,
        }
        if policy is not None:
            self._values["policy"] = policy
        if repository is not None:
            self._values["repository"] = repository

    @builtins.property
    def version(self) -> "AlbControllerVersion":
        '''Version of the controller.'''
        result = self._values.get("version")
        assert result is not None, "Required property 'version' is missing"
        return typing.cast("AlbControllerVersion", result)

    @builtins.property
    def policy(self) -> typing.Any:
        '''The IAM policy to apply to the service account.

        If you're using one of the built-in versions, this is not required since
        CDK ships with the appropriate policies for those versions.

        However, if you are using a custom version, this is required (and validated).

        :default: - Corresponds to the predefined version.
        '''
        result = self._values.get("policy")
        return typing.cast(typing.Any, result)

    @builtins.property
    def repository(self) -> typing.Optional[builtins.str]:
        '''The repository to pull the controller image from.

        Note that the default repository works for most regions, but not all.
        If the repository is not applicable to your region, use a custom repository
        according to the information here: https://github.com/kubernetes-sigs/aws-load-balancer-controller/releases.

        :default: '602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-load-balancer-controller'
        '''
        result = self._values.get("repository")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cluster(self) -> "Cluster":
        '''[disable-awslint:ref-via-interface] Cluster to install the controller onto.'''
        result = self._values.get("cluster")
        assert result is not None, "Required property 'cluster' is missing"
        return typing.cast("Cluster", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AlbControllerProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class AlbControllerVersion(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.AlbControllerVersion",
):
    '''Controller version.

    Corresponds to the image tag of 'amazon/aws-load-balancer-controller' image.

    :exampleMetadata: infused

    Example::

        eks.Cluster(self, "HelloEKS",
            version=eks.KubernetesVersion.V1_21,
            alb_controller=eks.AlbControllerOptions(
                version=eks.AlbControllerVersion.V2_3_1
            )
        )
    '''

    @jsii.member(jsii_name="of") # type: ignore[misc]
    @builtins.classmethod
    def of(cls, version: builtins.str) -> "AlbControllerVersion":
        '''Specify a custom version.

        Use this if the version you need is not available in one of the predefined versions.
        Note that in this case, you will also need to provide an IAM policy in the controller options.

        :param version: The version number.
        '''
        return typing.cast("AlbControllerVersion", jsii.sinvoke(cls, "of", [version]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_0_0")
    def V2_0_0(cls) -> "AlbControllerVersion":
        '''v2.0.0.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_0_0"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_0_1")
    def V2_0_1(cls) -> "AlbControllerVersion":
        '''v2.0.1.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_0_1"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_1_0")
    def V2_1_0(cls) -> "AlbControllerVersion":
        '''v2.1.0.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_1_0"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_1_1")
    def V2_1_1(cls) -> "AlbControllerVersion":
        '''v2.1.1.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_1_1"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_1_2")
    def V2_1_2(cls) -> "AlbControllerVersion":
        '''v2.1.2.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_1_2"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_1_3")
    def V2_1_3(cls) -> "AlbControllerVersion":
        '''v2.1.3.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_1_3"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_2_0")
    def V2_2_0(cls) -> "AlbControllerVersion":
        '''v2.0.0.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_2_0"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_2_1")
    def V2_2_1(cls) -> "AlbControllerVersion":
        '''v2.2.1.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_2_1"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_2_2")
    def V2_2_2(cls) -> "AlbControllerVersion":
        '''v2.2.2.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_2_2"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_2_3")
    def V2_2_3(cls) -> "AlbControllerVersion":
        '''v2.2.3.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_2_3"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_2_4")
    def V2_2_4(cls) -> "AlbControllerVersion":
        '''v2.2.4.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_2_4"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_3_0")
    def V2_3_0(cls) -> "AlbControllerVersion":
        '''v2.3.0.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_3_0"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V2_3_1")
    def V2_3_1(cls) -> "AlbControllerVersion":
        '''v2.3.1.'''
        return typing.cast("AlbControllerVersion", jsii.sget(cls, "V2_3_1"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="custom")
    def custom(self) -> builtins.bool:
        '''Whether or not its a custom version.'''
        return typing.cast(builtins.bool, jsii.get(self, "custom"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="version")
    def version(self) -> builtins.str:
        '''The version string.'''
        return typing.cast(builtins.str, jsii.get(self, "version"))


@jsii.enum(jsii_type="aws-cdk-lib.aws_eks.AlbScheme")
class AlbScheme(enum.Enum):
    '''ALB Scheme.

    :see: https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.3/guide/ingress/annotations/#scheme
    '''

    INTERNAL = "INTERNAL"
    '''The nodes of an internal load balancer have only private IP addresses.

    The DNS name of an internal load balancer is publicly resolvable to the private IP addresses of the nodes.
    Therefore, internal load balancers can only route requests from clients with access to the VPC for the load balancer.
    '''
    INTERNET_FACING = "INTERNET_FACING"
    '''An internet-facing load balancer has a publicly resolvable DNS name, so it can route requests from clients over the internet to the EC2 instances that are registered with the load balancer.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.AutoScalingGroupCapacityOptions",
    jsii_struct_bases=[_CommonAutoScalingGroupProps_808bbf2d],
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
        "bootstrap_enabled": "bootstrapEnabled",
        "bootstrap_options": "bootstrapOptions",
        "machine_image_type": "machineImageType",
        "map_role": "mapRole",
        "spot_interrupt_handler": "spotInterruptHandler",
    },
)
class AutoScalingGroupCapacityOptions(_CommonAutoScalingGroupProps_808bbf2d):
    def __init__(
        self,
        *,
        allow_all_outbound: typing.Optional[builtins.bool] = None,
        associate_public_ip_address: typing.Optional[builtins.bool] = None,
        auto_scaling_group_name: typing.Optional[builtins.str] = None,
        block_devices: typing.Optional[typing.Sequence[_BlockDevice_0cfc0568]] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        desired_capacity: typing.Optional[jsii.Number] = None,
        group_metrics: typing.Optional[typing.Sequence[_GroupMetrics_7cdf729b]] = None,
        health_check: typing.Optional[_HealthCheck_03a4bd5a] = None,
        ignore_unmodified_size_properties: typing.Optional[builtins.bool] = None,
        instance_monitoring: typing.Optional[_Monitoring_50020f91] = None,
        key_name: typing.Optional[builtins.str] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        max_instance_lifetime: typing.Optional[_Duration_4839e8c3] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
        new_instances_protected_from_scale_in: typing.Optional[builtins.bool] = None,
        notifications: typing.Optional[typing.Sequence[_NotificationConfiguration_d5911670]] = None,
        signals: typing.Optional[_Signals_69fbeb6e] = None,
        spot_price: typing.Optional[builtins.str] = None,
        termination_policies: typing.Optional[typing.Sequence[_TerminationPolicy_89633c56]] = None,
        update_policy: typing.Optional[_UpdatePolicy_6dffc7ca] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
        instance_type: _InstanceType_f64915b9,
        bootstrap_enabled: typing.Optional[builtins.bool] = None,
        bootstrap_options: typing.Optional["BootstrapOptions"] = None,
        machine_image_type: typing.Optional["MachineImageType"] = None,
        map_role: typing.Optional[builtins.bool] = None,
        spot_interrupt_handler: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Options for adding worker nodes.

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
        :param instance_type: Instance type of the instances to start.
        :param bootstrap_enabled: Configures the EC2 user-data script for instances in this autoscaling group to bootstrap the node (invoke ``/etc/eks/bootstrap.sh``) and associate it with the EKS cluster. If you wish to provide a custom user data script, set this to ``false`` and manually invoke ``autoscalingGroup.addUserData()``. Default: true
        :param bootstrap_options: EKS node bootstrapping options. Default: - none
        :param machine_image_type: Machine image type. Default: MachineImageType.AMAZON_LINUX_2
        :param map_role: Will automatically update the aws-auth ConfigMap to map the IAM instance role to RBAC. This cannot be explicitly set to ``true`` if the cluster has kubectl disabled. Default: - true if the cluster has kubectl enabled (which is the default).
        :param spot_interrupt_handler: Installs the AWS spot instance interrupt handler on the cluster if it's not already added. Only relevant if ``spotPrice`` is used. Default: true

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            
            cluster.add_auto_scaling_group_capacity("BottlerocketNodes",
                instance_type=ec2.InstanceType("t3.small"),
                min_capacity=2,
                machine_image_type=eks.MachineImageType.BOTTLEROCKET
            )
        '''
        if isinstance(vpc_subnets, dict):
            vpc_subnets = _SubnetSelection_e57d76df(**vpc_subnets)
        if isinstance(bootstrap_options, dict):
            bootstrap_options = BootstrapOptions(**bootstrap_options)
        self._values: typing.Dict[str, typing.Any] = {
            "instance_type": instance_type,
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
        if bootstrap_enabled is not None:
            self._values["bootstrap_enabled"] = bootstrap_enabled
        if bootstrap_options is not None:
            self._values["bootstrap_options"] = bootstrap_options
        if machine_image_type is not None:
            self._values["machine_image_type"] = machine_image_type
        if map_role is not None:
            self._values["map_role"] = map_role
        if spot_interrupt_handler is not None:
            self._values["spot_interrupt_handler"] = spot_interrupt_handler

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
    def block_devices(self) -> typing.Optional[typing.List[_BlockDevice_0cfc0568]]:
        '''Specifies how block devices are exposed to the instance. You can specify virtual devices and EBS volumes.

        Each instance that is launched has an associated root device volume,
        either an Amazon EBS volume or an instance store volume.
        You can use block device mappings to specify additional EBS volumes or
        instance store volumes to attach to an instance when it is launched.

        :default: - Uses the block device mapping of the AMI

        :see: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-device-mapping-concepts.html
        '''
        result = self._values.get("block_devices")
        return typing.cast(typing.Optional[typing.List[_BlockDevice_0cfc0568]], result)

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
    def group_metrics(self) -> typing.Optional[typing.List[_GroupMetrics_7cdf729b]]:
        '''Enable monitoring for group metrics, these metrics describe the group rather than any of its instances.

        To report all group metrics use ``GroupMetrics.all()``
        Group metrics are reported in a granularity of 1 minute at no additional charge.

        :default: - no group metrics will be reported
        '''
        result = self._values.get("group_metrics")
        return typing.cast(typing.Optional[typing.List[_GroupMetrics_7cdf729b]], result)

    @builtins.property
    def health_check(self) -> typing.Optional[_HealthCheck_03a4bd5a]:
        '''Configuration for health checks.

        :default: - HealthCheck.ec2 with no grace period
        '''
        result = self._values.get("health_check")
        return typing.cast(typing.Optional[_HealthCheck_03a4bd5a], result)

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
    def instance_monitoring(self) -> typing.Optional[_Monitoring_50020f91]:
        '''Controls whether instances in this group are launched with detailed or basic monitoring.

        When detailed monitoring is enabled, Amazon CloudWatch generates metrics every minute and your account
        is charged a fee. When you disable detailed monitoring, CloudWatch generates metrics every 5 minutes.

        :default: - Monitoring.DETAILED

        :see: https://docs.aws.amazon.com/autoscaling/latest/userguide/as-instance-monitoring.html#enable-as-instance-metrics
        '''
        result = self._values.get("instance_monitoring")
        return typing.cast(typing.Optional[_Monitoring_50020f91], result)

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
    ) -> typing.Optional[typing.List[_NotificationConfiguration_d5911670]]:
        '''Configure autoscaling group to send notifications about fleet changes to an SNS topic(s).

        :default: - No fleet change notifications will be sent.

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-group.html#cfn-as-group-notificationconfigurations
        '''
        result = self._values.get("notifications")
        return typing.cast(typing.Optional[typing.List[_NotificationConfiguration_d5911670]], result)

    @builtins.property
    def signals(self) -> typing.Optional[_Signals_69fbeb6e]:
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
        return typing.cast(typing.Optional[_Signals_69fbeb6e], result)

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
    def termination_policies(
        self,
    ) -> typing.Optional[typing.List[_TerminationPolicy_89633c56]]:
        '''A policy or a list of policies that are used to select the instances to terminate.

        The policies are executed in the order that you list them.

        :default: - ``TerminationPolicy.DEFAULT``

        :see: https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-instance-termination.html
        '''
        result = self._values.get("termination_policies")
        return typing.cast(typing.Optional[typing.List[_TerminationPolicy_89633c56]], result)

    @builtins.property
    def update_policy(self) -> typing.Optional[_UpdatePolicy_6dffc7ca]:
        '''What to do when an AutoScalingGroup's instance configuration is changed.

        This is applied when any of the settings on the ASG are changed that
        affect how the instances should be created (VPC, instance type, startup
        scripts, etc.). It indicates how the existing instances should be
        replaced with new instances matching the new config. By default, nothing
        is done and only new instances are launched with the new config.

        :default: - ``UpdatePolicy.rollingUpdate()`` if using ``init``, ``UpdatePolicy.none()`` otherwise
        '''
        result = self._values.get("update_policy")
        return typing.cast(typing.Optional[_UpdatePolicy_6dffc7ca], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''Where to place instances within the VPC.

        :default: - All Private subnets.
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    @builtins.property
    def instance_type(self) -> _InstanceType_f64915b9:
        '''Instance type of the instances to start.'''
        result = self._values.get("instance_type")
        assert result is not None, "Required property 'instance_type' is missing"
        return typing.cast(_InstanceType_f64915b9, result)

    @builtins.property
    def bootstrap_enabled(self) -> typing.Optional[builtins.bool]:
        '''Configures the EC2 user-data script for instances in this autoscaling group to bootstrap the node (invoke ``/etc/eks/bootstrap.sh``) and associate it with the EKS cluster.

        If you wish to provide a custom user data script, set this to ``false`` and
        manually invoke ``autoscalingGroup.addUserData()``.

        :default: true
        '''
        result = self._values.get("bootstrap_enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def bootstrap_options(self) -> typing.Optional["BootstrapOptions"]:
        '''EKS node bootstrapping options.

        :default: - none
        '''
        result = self._values.get("bootstrap_options")
        return typing.cast(typing.Optional["BootstrapOptions"], result)

    @builtins.property
    def machine_image_type(self) -> typing.Optional["MachineImageType"]:
        '''Machine image type.

        :default: MachineImageType.AMAZON_LINUX_2
        '''
        result = self._values.get("machine_image_type")
        return typing.cast(typing.Optional["MachineImageType"], result)

    @builtins.property
    def map_role(self) -> typing.Optional[builtins.bool]:
        '''Will automatically update the aws-auth ConfigMap to map the IAM instance role to RBAC.

        This cannot be explicitly set to ``true`` if the cluster has kubectl disabled.

        :default: - true if the cluster has kubectl enabled (which is the default).
        '''
        result = self._values.get("map_role")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def spot_interrupt_handler(self) -> typing.Optional[builtins.bool]:
        '''Installs the AWS spot instance interrupt handler on the cluster if it's not already added.

        Only relevant if ``spotPrice`` is used.

        :default: true
        '''
        result = self._values.get("spot_interrupt_handler")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AutoScalingGroupCapacityOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.AutoScalingGroupOptions",
    jsii_struct_bases=[],
    name_mapping={
        "bootstrap_enabled": "bootstrapEnabled",
        "bootstrap_options": "bootstrapOptions",
        "machine_image_type": "machineImageType",
        "map_role": "mapRole",
        "spot_interrupt_handler": "spotInterruptHandler",
    },
)
class AutoScalingGroupOptions:
    def __init__(
        self,
        *,
        bootstrap_enabled: typing.Optional[builtins.bool] = None,
        bootstrap_options: typing.Optional["BootstrapOptions"] = None,
        machine_image_type: typing.Optional["MachineImageType"] = None,
        map_role: typing.Optional[builtins.bool] = None,
        spot_interrupt_handler: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Options for adding an AutoScalingGroup as capacity.

        :param bootstrap_enabled: Configures the EC2 user-data script for instances in this autoscaling group to bootstrap the node (invoke ``/etc/eks/bootstrap.sh``) and associate it with the EKS cluster. If you wish to provide a custom user data script, set this to ``false`` and manually invoke ``autoscalingGroup.addUserData()``. Default: true
        :param bootstrap_options: Allows options for node bootstrapping through EC2 user data. Default: - default options
        :param machine_image_type: Allow options to specify different machine image type. Default: MachineImageType.AMAZON_LINUX_2
        :param map_role: Will automatically update the aws-auth ConfigMap to map the IAM instance role to RBAC. This cannot be explicitly set to ``true`` if the cluster has kubectl disabled. Default: - true if the cluster has kubectl enabled (which is the default).
        :param spot_interrupt_handler: Installs the AWS spot instance interrupt handler on the cluster if it's not already added. Only relevant if ``spotPrice`` is configured on the auto-scaling group. Default: true

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            # asg: autoscaling.AutoScalingGroup
            
            cluster.connect_auto_scaling_group_capacity(asg)
        '''
        if isinstance(bootstrap_options, dict):
            bootstrap_options = BootstrapOptions(**bootstrap_options)
        self._values: typing.Dict[str, typing.Any] = {}
        if bootstrap_enabled is not None:
            self._values["bootstrap_enabled"] = bootstrap_enabled
        if bootstrap_options is not None:
            self._values["bootstrap_options"] = bootstrap_options
        if machine_image_type is not None:
            self._values["machine_image_type"] = machine_image_type
        if map_role is not None:
            self._values["map_role"] = map_role
        if spot_interrupt_handler is not None:
            self._values["spot_interrupt_handler"] = spot_interrupt_handler

    @builtins.property
    def bootstrap_enabled(self) -> typing.Optional[builtins.bool]:
        '''Configures the EC2 user-data script for instances in this autoscaling group to bootstrap the node (invoke ``/etc/eks/bootstrap.sh``) and associate it with the EKS cluster.

        If you wish to provide a custom user data script, set this to ``false`` and
        manually invoke ``autoscalingGroup.addUserData()``.

        :default: true
        '''
        result = self._values.get("bootstrap_enabled")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def bootstrap_options(self) -> typing.Optional["BootstrapOptions"]:
        '''Allows options for node bootstrapping through EC2 user data.

        :default: - default options
        '''
        result = self._values.get("bootstrap_options")
        return typing.cast(typing.Optional["BootstrapOptions"], result)

    @builtins.property
    def machine_image_type(self) -> typing.Optional["MachineImageType"]:
        '''Allow options to specify different machine image type.

        :default: MachineImageType.AMAZON_LINUX_2
        '''
        result = self._values.get("machine_image_type")
        return typing.cast(typing.Optional["MachineImageType"], result)

    @builtins.property
    def map_role(self) -> typing.Optional[builtins.bool]:
        '''Will automatically update the aws-auth ConfigMap to map the IAM instance role to RBAC.

        This cannot be explicitly set to ``true`` if the cluster has kubectl disabled.

        :default: - true if the cluster has kubectl enabled (which is the default).
        '''
        result = self._values.get("map_role")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def spot_interrupt_handler(self) -> typing.Optional[builtins.bool]:
        '''Installs the AWS spot instance interrupt handler on the cluster if it's not already added.

        Only relevant if ``spotPrice`` is configured on the auto-scaling group.

        :default: true
        '''
        result = self._values.get("spot_interrupt_handler")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AutoScalingGroupOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class AwsAuth(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.AwsAuth",
):
    '''Manages mapping between IAM users and roles to Kubernetes RBAC configuration.

    :see: https://docs.aws.amazon.com/en_us/eks/latest/userguide/add-user-role.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_eks as eks
        
        # cluster: eks.Cluster
        
        aws_auth = eks.AwsAuth(self, "MyAwsAuth",
            cluster=cluster
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster: "Cluster",
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param cluster: The EKS cluster to apply this configuration to. [disable-awslint:ref-via-interface]
        '''
        props = AwsAuthProps(cluster=cluster)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="addAccount")
    def add_account(self, account_id: builtins.str) -> None:
        '''Additional AWS account to add to the aws-auth configmap.

        :param account_id: account number.
        '''
        return typing.cast(None, jsii.invoke(self, "addAccount", [account_id]))

    @jsii.member(jsii_name="addMastersRole")
    def add_masters_role(
        self,
        role: _IRole_235f5d8e,
        username: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Adds the specified IAM role to the ``system:masters`` RBAC group, which means that anyone that can assume it will be able to administer this Kubernetes system.

        :param role: The IAM role to add.
        :param username: Optional user (defaults to the role ARN).
        '''
        return typing.cast(None, jsii.invoke(self, "addMastersRole", [role, username]))

    @jsii.member(jsii_name="addRoleMapping")
    def add_role_mapping(
        self,
        role: _IRole_235f5d8e,
        *,
        groups: typing.Sequence[builtins.str],
        username: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Adds a mapping between an IAM role to a Kubernetes user and groups.

        :param role: The IAM role to map.
        :param groups: A list of groups within Kubernetes to which the role is mapped.
        :param username: The user name within Kubernetes to map to the IAM role. Default: - By default, the user name is the ARN of the IAM role.
        '''
        mapping = AwsAuthMapping(groups=groups, username=username)

        return typing.cast(None, jsii.invoke(self, "addRoleMapping", [role, mapping]))

    @jsii.member(jsii_name="addUserMapping")
    def add_user_mapping(
        self,
        user: _IUser_c32311f7,
        *,
        groups: typing.Sequence[builtins.str],
        username: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Adds a mapping between an IAM user to a Kubernetes user and groups.

        :param user: The IAM user to map.
        :param groups: A list of groups within Kubernetes to which the role is mapped.
        :param username: The user name within Kubernetes to map to the IAM role. Default: - By default, the user name is the ARN of the IAM role.
        '''
        mapping = AwsAuthMapping(groups=groups, username=username)

        return typing.cast(None, jsii.invoke(self, "addUserMapping", [user, mapping]))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.AwsAuthMapping",
    jsii_struct_bases=[],
    name_mapping={"groups": "groups", "username": "username"},
)
class AwsAuthMapping:
    def __init__(
        self,
        *,
        groups: typing.Sequence[builtins.str],
        username: typing.Optional[builtins.str] = None,
    ) -> None:
        '''AwsAuth mapping.

        :param groups: A list of groups within Kubernetes to which the role is mapped.
        :param username: The user name within Kubernetes to map to the IAM role. Default: - By default, the user name is the ARN of the IAM role.

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            
            admin_user = iam.User(self, "Admin")
            cluster.aws_auth.add_user_mapping(admin_user, groups=["system:masters"])
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "groups": groups,
        }
        if username is not None:
            self._values["username"] = username

    @builtins.property
    def groups(self) -> typing.List[builtins.str]:
        '''A list of groups within Kubernetes to which the role is mapped.

        :see: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings
        '''
        result = self._values.get("groups")
        assert result is not None, "Required property 'groups' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def username(self) -> typing.Optional[builtins.str]:
        '''The user name within Kubernetes to map to the IAM role.

        :default: - By default, the user name is the ARN of the IAM role.
        '''
        result = self._values.get("username")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AwsAuthMapping(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.AwsAuthProps",
    jsii_struct_bases=[],
    name_mapping={"cluster": "cluster"},
)
class AwsAuthProps:
    def __init__(self, *, cluster: "Cluster") -> None:
        '''Configuration props for the AwsAuth construct.

        :param cluster: The EKS cluster to apply this configuration to. [disable-awslint:ref-via-interface]

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            # cluster: eks.Cluster
            
            aws_auth_props = eks.AwsAuthProps(
                cluster=cluster
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster": cluster,
        }

    @builtins.property
    def cluster(self) -> "Cluster":
        '''The EKS cluster to apply this configuration to.

        [disable-awslint:ref-via-interface]
        '''
        result = self._values.get("cluster")
        assert result is not None, "Required property 'cluster' is missing"
        return typing.cast("Cluster", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "AwsAuthProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.BootstrapOptions",
    jsii_struct_bases=[],
    name_mapping={
        "additional_args": "additionalArgs",
        "aws_api_retry_attempts": "awsApiRetryAttempts",
        "dns_cluster_ip": "dnsClusterIp",
        "docker_config_json": "dockerConfigJson",
        "enable_docker_bridge": "enableDockerBridge",
        "kubelet_extra_args": "kubeletExtraArgs",
        "use_max_pods": "useMaxPods",
    },
)
class BootstrapOptions:
    def __init__(
        self,
        *,
        additional_args: typing.Optional[builtins.str] = None,
        aws_api_retry_attempts: typing.Optional[jsii.Number] = None,
        dns_cluster_ip: typing.Optional[builtins.str] = None,
        docker_config_json: typing.Optional[builtins.str] = None,
        enable_docker_bridge: typing.Optional[builtins.bool] = None,
        kubelet_extra_args: typing.Optional[builtins.str] = None,
        use_max_pods: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''EKS node bootstrapping options.

        :param additional_args: Additional command line arguments to pass to the ``/etc/eks/bootstrap.sh`` command. Default: - none
        :param aws_api_retry_attempts: Number of retry attempts for AWS API call (DescribeCluster). Default: 3
        :param dns_cluster_ip: Overrides the IP address to use for DNS queries within the cluster. Default: - 10.100.0.10 or 172.20.0.10 based on the IP address of the primary interface.
        :param docker_config_json: The contents of the ``/etc/docker/daemon.json`` file. Useful if you want a custom config differing from the default one in the EKS AMI. Default: - none
        :param enable_docker_bridge: Restores the docker default bridge network. Default: false
        :param kubelet_extra_args: Extra arguments to add to the kubelet. Useful for adding labels or taints. For example, ``--node-labels foo=bar,goo=far``. Default: - none
        :param use_max_pods: Sets ``--max-pods`` for the kubelet based on the capacity of the EC2 instance. Default: true

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            
            cluster.add_auto_scaling_group_capacity("spot",
                instance_type=ec2.InstanceType("t3.large"),
                min_capacity=2,
                bootstrap_options=eks.BootstrapOptions(
                    kubelet_extra_args="--node-labels foo=bar,goo=far",
                    aws_api_retry_attempts=5
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if additional_args is not None:
            self._values["additional_args"] = additional_args
        if aws_api_retry_attempts is not None:
            self._values["aws_api_retry_attempts"] = aws_api_retry_attempts
        if dns_cluster_ip is not None:
            self._values["dns_cluster_ip"] = dns_cluster_ip
        if docker_config_json is not None:
            self._values["docker_config_json"] = docker_config_json
        if enable_docker_bridge is not None:
            self._values["enable_docker_bridge"] = enable_docker_bridge
        if kubelet_extra_args is not None:
            self._values["kubelet_extra_args"] = kubelet_extra_args
        if use_max_pods is not None:
            self._values["use_max_pods"] = use_max_pods

    @builtins.property
    def additional_args(self) -> typing.Optional[builtins.str]:
        '''Additional command line arguments to pass to the ``/etc/eks/bootstrap.sh`` command.

        :default: - none

        :see: https://github.com/awslabs/amazon-eks-ami/blob/master/files/bootstrap.sh
        '''
        result = self._values.get("additional_args")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def aws_api_retry_attempts(self) -> typing.Optional[jsii.Number]:
        '''Number of retry attempts for AWS API call (DescribeCluster).

        :default: 3
        '''
        result = self._values.get("aws_api_retry_attempts")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def dns_cluster_ip(self) -> typing.Optional[builtins.str]:
        '''Overrides the IP address to use for DNS queries within the cluster.

        :default:

        - 10.100.0.10 or 172.20.0.10 based on the IP
        address of the primary interface.
        '''
        result = self._values.get("dns_cluster_ip")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def docker_config_json(self) -> typing.Optional[builtins.str]:
        '''The contents of the ``/etc/docker/daemon.json`` file. Useful if you want a custom config differing from the default one in the EKS AMI.

        :default: - none
        '''
        result = self._values.get("docker_config_json")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def enable_docker_bridge(self) -> typing.Optional[builtins.bool]:
        '''Restores the docker default bridge network.

        :default: false
        '''
        result = self._values.get("enable_docker_bridge")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def kubelet_extra_args(self) -> typing.Optional[builtins.str]:
        '''Extra arguments to add to the kubelet. Useful for adding labels or taints.

        For example, ``--node-labels foo=bar,goo=far``.

        :default: - none
        '''
        result = self._values.get("kubelet_extra_args")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def use_max_pods(self) -> typing.Optional[builtins.bool]:
        '''Sets ``--max-pods`` for the kubelet based on the capacity of the EC2 instance.

        :default: true
        '''
        result = self._values.get("use_max_pods")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "BootstrapOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_eks.CapacityType")
class CapacityType(enum.Enum):
    '''Capacity type of the managed node group.

    :exampleMetadata: infused

    Example::

        # cluster: eks.Cluster
        
        cluster.add_nodegroup_capacity("extra-ng-spot",
            instance_types=[
                ec2.InstanceType("c5.large"),
                ec2.InstanceType("c5a.large"),
                ec2.InstanceType("c5d.large")
            ],
            min_size=3,
            capacity_type=eks.CapacityType.SPOT
        )
    '''

    SPOT = "SPOT"
    '''spot instances.'''
    ON_DEMAND = "ON_DEMAND"
    '''on-demand instances.'''


@jsii.implements(_IInspectable_c2943556)
class CfnAddon(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.CfnAddon",
):
    '''A CloudFormation ``AWS::EKS::Addon``.

    Creates an Amazon EKS add-on.

    Amazon EKS add-ons help to automate the provisioning and lifecycle management of common operational software for Amazon EKS clusters. Amazon EKS add-ons require clusters running version 1.18 or later because Amazon EKS add-ons rely on the Server-side Apply Kubernetes feature, which is only available in Kubernetes 1.18 and later. For more information, see `Amazon EKS add-ons <https://docs.aws.amazon.com/eks/latest/userguide/eks-add-ons.html>`_ in the *Amazon EKS User Guide* .

    :cloudformationResource: AWS::EKS::Addon
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_eks as eks
        
        cfn_addon = eks.CfnAddon(self, "MyCfnAddon",
            addon_name="addonName",
            cluster_name="clusterName",
        
            # the properties below are optional
            addon_version="addonVersion",
            resolve_conflicts="resolveConflicts",
            service_account_role_arn="serviceAccountRoleArn",
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
        addon_name: builtins.str,
        cluster_name: builtins.str,
        addon_version: typing.Optional[builtins.str] = None,
        resolve_conflicts: typing.Optional[builtins.str] = None,
        service_account_role_arn: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::EKS::Addon``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param addon_name: The name of the add-on.
        :param cluster_name: The name of the cluster.
        :param addon_version: The version of the add-on.
        :param resolve_conflicts: How to resolve parameter value conflicts when migrating an existing add-on to an Amazon EKS add-on.
        :param service_account_role_arn: The Amazon Resource Name (ARN) of an existing IAM role to bind to the add-on's service account. The role must be assigned the IAM permissions required by the add-on. If you don't specify an existing IAM role, then the add-on uses the permissions assigned to the node IAM role. For more information, see `Amazon EKS node IAM role <https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html>`_ in the *Amazon EKS User Guide* . .. epigraph:: To specify an existing IAM role, you must have an IAM OpenID Connect (OIDC) provider created for your cluster. For more information, see `Enabling IAM roles for service accounts on your cluster <https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html>`_ in the *Amazon EKS User Guide* .
        :param tags: The metadata that you apply to the add-on to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Add-on tags do not propagate to any other resources associated with the cluster.
        '''
        props = CfnAddonProps(
            addon_name=addon_name,
            cluster_name=cluster_name,
            addon_version=addon_version,
            resolve_conflicts=resolve_conflicts,
            service_account_role_arn=service_account_role_arn,
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
        '''The ARN of the add-on, such as ``arn:aws:eks:us-west-2:111122223333:addon/1-19/vpc-cni/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`` .

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
        '''The metadata that you apply to the add-on to assist with categorization and organization.

        Each tag consists of a key and an optional value, both of which you define. Add-on tags do not propagate to any other resources associated with the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="addonName")
    def addon_name(self) -> builtins.str:
        '''The name of the add-on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-addonname
        '''
        return typing.cast(builtins.str, jsii.get(self, "addonName"))

    @addon_name.setter
    def addon_name(self, value: builtins.str) -> None:
        jsii.set(self, "addonName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterName")
    def cluster_name(self) -> builtins.str:
        '''The name of the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-clustername
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterName"))

    @cluster_name.setter
    def cluster_name(self, value: builtins.str) -> None:
        jsii.set(self, "clusterName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="addonVersion")
    def addon_version(self) -> typing.Optional[builtins.str]:
        '''The version of the add-on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-addonversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "addonVersion"))

    @addon_version.setter
    def addon_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "addonVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resolveConflicts")
    def resolve_conflicts(self) -> typing.Optional[builtins.str]:
        '''How to resolve parameter value conflicts when migrating an existing add-on to an Amazon EKS add-on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-resolveconflicts
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "resolveConflicts"))

    @resolve_conflicts.setter
    def resolve_conflicts(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "resolveConflicts", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceAccountRoleArn")
    def service_account_role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of an existing IAM role to bind to the add-on's service account.

        The role must be assigned the IAM permissions required by the add-on. If you don't specify an existing IAM role, then the add-on uses the permissions assigned to the node IAM role. For more information, see `Amazon EKS node IAM role <https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html>`_ in the *Amazon EKS User Guide* .
        .. epigraph::

           To specify an existing IAM role, you must have an IAM OpenID Connect (OIDC) provider created for your cluster. For more information, see `Enabling IAM roles for service accounts on your cluster <https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-serviceaccountrolearn
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "serviceAccountRoleArn"))

    @service_account_role_arn.setter
    def service_account_role_arn(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "serviceAccountRoleArn", value)


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.CfnAddonProps",
    jsii_struct_bases=[],
    name_mapping={
        "addon_name": "addonName",
        "cluster_name": "clusterName",
        "addon_version": "addonVersion",
        "resolve_conflicts": "resolveConflicts",
        "service_account_role_arn": "serviceAccountRoleArn",
        "tags": "tags",
    },
)
class CfnAddonProps:
    def __init__(
        self,
        *,
        addon_name: builtins.str,
        cluster_name: builtins.str,
        addon_version: typing.Optional[builtins.str] = None,
        resolve_conflicts: typing.Optional[builtins.str] = None,
        service_account_role_arn: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnAddon``.

        :param addon_name: The name of the add-on.
        :param cluster_name: The name of the cluster.
        :param addon_version: The version of the add-on.
        :param resolve_conflicts: How to resolve parameter value conflicts when migrating an existing add-on to an Amazon EKS add-on.
        :param service_account_role_arn: The Amazon Resource Name (ARN) of an existing IAM role to bind to the add-on's service account. The role must be assigned the IAM permissions required by the add-on. If you don't specify an existing IAM role, then the add-on uses the permissions assigned to the node IAM role. For more information, see `Amazon EKS node IAM role <https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html>`_ in the *Amazon EKS User Guide* . .. epigraph:: To specify an existing IAM role, you must have an IAM OpenID Connect (OIDC) provider created for your cluster. For more information, see `Enabling IAM roles for service accounts on your cluster <https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html>`_ in the *Amazon EKS User Guide* .
        :param tags: The metadata that you apply to the add-on to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Add-on tags do not propagate to any other resources associated with the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            cfn_addon_props = eks.CfnAddonProps(
                addon_name="addonName",
                cluster_name="clusterName",
            
                # the properties below are optional
                addon_version="addonVersion",
                resolve_conflicts="resolveConflicts",
                service_account_role_arn="serviceAccountRoleArn",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "addon_name": addon_name,
            "cluster_name": cluster_name,
        }
        if addon_version is not None:
            self._values["addon_version"] = addon_version
        if resolve_conflicts is not None:
            self._values["resolve_conflicts"] = resolve_conflicts
        if service_account_role_arn is not None:
            self._values["service_account_role_arn"] = service_account_role_arn
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def addon_name(self) -> builtins.str:
        '''The name of the add-on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-addonname
        '''
        result = self._values.get("addon_name")
        assert result is not None, "Required property 'addon_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def cluster_name(self) -> builtins.str:
        '''The name of the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-clustername
        '''
        result = self._values.get("cluster_name")
        assert result is not None, "Required property 'cluster_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def addon_version(self) -> typing.Optional[builtins.str]:
        '''The version of the add-on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-addonversion
        '''
        result = self._values.get("addon_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def resolve_conflicts(self) -> typing.Optional[builtins.str]:
        '''How to resolve parameter value conflicts when migrating an existing add-on to an Amazon EKS add-on.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-resolveconflicts
        '''
        result = self._values.get("resolve_conflicts")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def service_account_role_arn(self) -> typing.Optional[builtins.str]:
        '''The Amazon Resource Name (ARN) of an existing IAM role to bind to the add-on's service account.

        The role must be assigned the IAM permissions required by the add-on. If you don't specify an existing IAM role, then the add-on uses the permissions assigned to the node IAM role. For more information, see `Amazon EKS node IAM role <https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html>`_ in the *Amazon EKS User Guide* .
        .. epigraph::

           To specify an existing IAM role, you must have an IAM OpenID Connect (OIDC) provider created for your cluster. For more information, see `Enabling IAM roles for service accounts on your cluster <https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-serviceaccountrolearn
        '''
        result = self._values.get("service_account_role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The metadata that you apply to the add-on to assist with categorization and organization.

        Each tag consists of a key and an optional value, both of which you define. Add-on tags do not propagate to any other resources associated with the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-addon.html#cfn-eks-addon-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnAddonProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnCluster(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.CfnCluster",
):
    '''A CloudFormation ``AWS::EKS::Cluster``.

    Creates an Amazon EKS control plane.

    The Amazon EKS control plane consists of control plane instances that run the Kubernetes software, such as ``etcd`` and the API server. The control plane runs in an account managed by AWS , and the Kubernetes API is exposed by the Amazon EKS API server endpoint. Each Amazon EKS cluster control plane is single tenant and unique. It runs on its own set of Amazon EC2 instances.

    The cluster control plane is provisioned across multiple Availability Zones and fronted by an Elastic Load Balancing Network Load Balancer. Amazon EKS also provisions elastic network interfaces in your VPC subnets to provide connectivity from the control plane instances to the nodes (for example, to support ``kubectl exec`` , ``logs`` , and ``proxy`` data flows).

    Amazon EKS nodes run in your AWS account and connect to your cluster's control plane over the Kubernetes API server endpoint and a certificate file that is created for your cluster.

    In most cases, it takes several minutes to create a cluster. After you create an Amazon EKS cluster, you must configure your Kubernetes tooling to communicate with the API server and launch nodes into your cluster. For more information, see `Managing Cluster Authentication <https://docs.aws.amazon.com/eks/latest/userguide/managing-auth.html>`_ and `Launching Amazon EKS nodes <https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html>`_ in the *Amazon EKS User Guide* .

    :cloudformationResource: AWS::EKS::Cluster
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_eks as eks
        
        # provider: Any
        
        cfn_cluster = eks.CfnCluster(self, "MyCfnCluster",
            resources_vpc_config=eks.CfnCluster.ResourcesVpcConfigProperty(
                subnet_ids=["subnetIds"],
        
                # the properties below are optional
                endpoint_private_access=False,
                endpoint_public_access=False,
                public_access_cidrs=["publicAccessCidrs"],
                security_group_ids=["securityGroupIds"]
            ),
            role_arn="roleArn",
        
            # the properties below are optional
            encryption_config=[eks.CfnCluster.EncryptionConfigProperty(
                provider=provider,
                resources=["resources"]
            )],
            kubernetes_network_config=eks.CfnCluster.KubernetesNetworkConfigProperty(
                ip_family="ipFamily",
                service_ipv4_cidr="serviceIpv4Cidr",
                service_ipv6_cidr="serviceIpv6Cidr"
            ),
            logging=eks.CfnCluster.LoggingProperty(
                cluster_logging=eks.CfnCluster.ClusterLoggingProperty(
                    enabled_types=[eks.CfnCluster.LoggingTypeConfigProperty(
                        type="type"
                    )]
                )
            ),
            name="name",
            tags=[CfnTag(
                key="key",
                value="value"
            )],
            version="version"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        resources_vpc_config: typing.Union["CfnCluster.ResourcesVpcConfigProperty", _IResolvable_da3f097b],
        role_arn: builtins.str,
        encryption_config: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.EncryptionConfigProperty", _IResolvable_da3f097b]]]] = None,
        kubernetes_network_config: typing.Optional[typing.Union["CfnCluster.KubernetesNetworkConfigProperty", _IResolvable_da3f097b]] = None,
        logging: typing.Optional[typing.Union["CfnCluster.LoggingProperty", _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::EKS::Cluster``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param resources_vpc_config: The VPC configuration that's used by the cluster control plane. Amazon EKS VPC resources have specific requirements to work properly with Kubernetes. For more information, see `Cluster VPC Considerations <https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html>`_ and `Cluster Security Group Considerations <https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html>`_ in the *Amazon EKS User Guide* . You must specify at least two subnets. You can specify up to five security groups, but we recommend that you use a dedicated security group for your cluster control plane. .. epigraph:: Updates require replacement of the ``SecurityGroupIds`` and ``SubnetIds`` sub-properties.
        :param role_arn: The Amazon Resource Name (ARN) of the IAM role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf. For more information, see `Amazon EKS Service IAM Role <https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html>`_ in the **Amazon EKS User Guide** .
        :param encryption_config: The encryption configuration for the cluster.
        :param kubernetes_network_config: The Kubernetes network configuration for the cluster.
        :param logging: The logging configuration for your cluster.
        :param name: The unique name to give to your cluster.
        :param tags: The metadata that you apply to the cluster to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Cluster tags don't propagate to any other resources associated with the cluster. .. epigraph:: You must have the ``eks:TagResource`` and ``eks:UntagResource`` permissions in your IAM user or IAM role used to manage the CloudFormation stack. If you don't have these permissions, there might be unexpected behavior with stack-level tags propagating to the resource during resource creation and update.
        :param version: The desired Kubernetes version for your cluster. If you don't specify a value here, the latest version available in Amazon EKS is used.
        '''
        props = CfnClusterProps(
            resources_vpc_config=resources_vpc_config,
            role_arn=role_arn,
            encryption_config=encryption_config,
            kubernetes_network_config=kubernetes_network_config,
            logging=logging,
            name=name,
            tags=tags,
            version=version,
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
        '''The ARN of the cluster, such as ``arn:aws:eks:us-west-2:666666666666:cluster/prod`` .

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrCertificateAuthorityData")
    def attr_certificate_authority_data(self) -> builtins.str:
        '''The ``certificate-authority-data`` for your cluster.

        :cloudformationAttribute: CertificateAuthorityData
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrCertificateAuthorityData"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrClusterSecurityGroupId")
    def attr_cluster_security_group_id(self) -> builtins.str:
        '''The cluster security group that was created by Amazon EKS for the cluster.

        Managed node groups use this security group for control plane to data plane communication.

        This parameter is only returned by Amazon EKS clusters that support managed node groups. For more information, see `Managed node groups <https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html>`_ in the *Amazon EKS User Guide* .

        :cloudformationAttribute: ClusterSecurityGroupId
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrClusterSecurityGroupId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEncryptionConfigKeyArn")
    def attr_encryption_config_key_arn(self) -> builtins.str:
        '''Amazon Resource Name (ARN) or alias of the customer master key (CMK).

        :cloudformationAttribute: EncryptionConfigKeyArn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEncryptionConfigKeyArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrEndpoint")
    def attr_endpoint(self) -> builtins.str:
        '''The endpoint for your Kubernetes API server, such as ``https://5E1D0CEXAMPLEA591B746AFC5AB30262.yl4.us-west-2.eks.amazonaws.com`` .

        :cloudformationAttribute: Endpoint
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrKubernetesNetworkConfigServiceIpv6Cidr")
    def attr_kubernetes_network_config_service_ipv6_cidr(self) -> builtins.str:
        '''The CIDR block that Kubernetes Service IP addresses are assigned from if you created a 1.21 or later cluster with version 1.10.1 or later of the Amazon VPC CNI add-on and specified ``ipv6`` for *ipFamily* when you created the cluster. Kubernetes assigns Service addresses from the unique local address range ( ``fc00::/7`` ) because you can't specify a custom IPv6 CIDR block when you create the cluster.

        :cloudformationAttribute: KubernetesNetworkConfig.ServiceIpv6Cidr
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrKubernetesNetworkConfigServiceIpv6Cidr"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrOpenIdConnectIssuerUrl")
    def attr_open_id_connect_issuer_url(self) -> builtins.str:
        '''The issuer URL for the OIDC identity provider of the cluster, such as ``https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E`` . If you need to remove ``https://`` from this output value, you can include the following code in your template.

        ``!Select [1, !Split ["//", !GetAtt EKSCluster.OpenIdConnectIssuerUrl]]``

        :cloudformationAttribute: OpenIdConnectIssuerUrl
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrOpenIdConnectIssuerUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The metadata that you apply to the cluster to assist with categorization and organization.

        Each tag consists of a key and an optional value, both of which you define. Cluster tags don't propagate to any other resources associated with the cluster.
        .. epigraph::

           You must have the ``eks:TagResource`` and ``eks:UntagResource`` permissions in your IAM user or IAM role used to manage the CloudFormation stack. If you don't have these permissions, there might be unexpected behavior with stack-level tags propagating to the resource during resource creation and update.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="resourcesVpcConfig")
    def resources_vpc_config(
        self,
    ) -> typing.Union["CfnCluster.ResourcesVpcConfigProperty", _IResolvable_da3f097b]:
        '''The VPC configuration that's used by the cluster control plane.

        Amazon EKS VPC resources have specific requirements to work properly with Kubernetes. For more information, see `Cluster VPC Considerations <https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html>`_ and `Cluster Security Group Considerations <https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html>`_ in the *Amazon EKS User Guide* . You must specify at least two subnets. You can specify up to five security groups, but we recommend that you use a dedicated security group for your cluster control plane.
        .. epigraph::

           Updates require replacement of the ``SecurityGroupIds`` and ``SubnetIds`` sub-properties.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-resourcesvpcconfig
        '''
        return typing.cast(typing.Union["CfnCluster.ResourcesVpcConfigProperty", _IResolvable_da3f097b], jsii.get(self, "resourcesVpcConfig"))

    @resources_vpc_config.setter
    def resources_vpc_config(
        self,
        value: typing.Union["CfnCluster.ResourcesVpcConfigProperty", _IResolvable_da3f097b],
    ) -> None:
        jsii.set(self, "resourcesVpcConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf.

        For more information, see `Amazon EKS Service IAM Role <https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html>`_ in the **Amazon EKS User Guide** .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-rolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @role_arn.setter
    def role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "roleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="encryptionConfig")
    def encryption_config(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.EncryptionConfigProperty", _IResolvable_da3f097b]]]]:
        '''The encryption configuration for the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-encryptionconfig
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.EncryptionConfigProperty", _IResolvable_da3f097b]]]], jsii.get(self, "encryptionConfig"))

    @encryption_config.setter
    def encryption_config(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.EncryptionConfigProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "encryptionConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubernetesNetworkConfig")
    def kubernetes_network_config(
        self,
    ) -> typing.Optional[typing.Union["CfnCluster.KubernetesNetworkConfigProperty", _IResolvable_da3f097b]]:
        '''The Kubernetes network configuration for the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-kubernetesnetworkconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCluster.KubernetesNetworkConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "kubernetesNetworkConfig"))

    @kubernetes_network_config.setter
    def kubernetes_network_config(
        self,
        value: typing.Optional[typing.Union["CfnCluster.KubernetesNetworkConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "kubernetesNetworkConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="logging")
    def logging(
        self,
    ) -> typing.Optional[typing.Union["CfnCluster.LoggingProperty", _IResolvable_da3f097b]]:
        '''The logging configuration for your cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-logging
        '''
        return typing.cast(typing.Optional[typing.Union["CfnCluster.LoggingProperty", _IResolvable_da3f097b]], jsii.get(self, "logging"))

    @logging.setter
    def logging(
        self,
        value: typing.Optional[typing.Union["CfnCluster.LoggingProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "logging", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="name")
    def name(self) -> typing.Optional[builtins.str]:
        '''The unique name to give to your cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-name
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "name"))

    @name.setter
    def name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "name", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="version")
    def version(self) -> typing.Optional[builtins.str]:
        '''The desired Kubernetes version for your cluster.

        If you don't specify a value here, the latest version available in Amazon EKS is used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-version
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "version"))

    @version.setter
    def version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "version", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnCluster.ClusterLoggingProperty",
        jsii_struct_bases=[],
        name_mapping={"enabled_types": "enabledTypes"},
    )
    class ClusterLoggingProperty:
        def __init__(
            self,
            *,
            enabled_types: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnCluster.LoggingTypeConfigProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''The cluster control plane logging configuration for your cluster.

            .. epigraph::

               When updating a resource, you must include this ``ClusterLogging`` property if the previous CloudFormation template of the resource had it.

            :param enabled_types: The enabled control plane logs for your cluster. All log types are disabled if the array is empty. .. epigraph:: When updating a resource, you must include this ``EnabledTypes`` property if the previous CloudFormation template of the resource had it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-clusterlogging.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                cluster_logging_property = eks.CfnCluster.ClusterLoggingProperty(
                    enabled_types=[eks.CfnCluster.LoggingTypeConfigProperty(
                        type="type"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if enabled_types is not None:
                self._values["enabled_types"] = enabled_types

        @builtins.property
        def enabled_types(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.LoggingTypeConfigProperty", _IResolvable_da3f097b]]]]:
            '''The enabled control plane logs for your cluster. All log types are disabled if the array is empty.

            .. epigraph::

               When updating a resource, you must include this ``EnabledTypes`` property if the previous CloudFormation template of the resource had it.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-clusterlogging.html#cfn-eks-cluster-clusterlogging-enabledtypes
            '''
            result = self._values.get("enabled_types")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnCluster.LoggingTypeConfigProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ClusterLoggingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnCluster.EncryptionConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"provider": "provider", "resources": "resources"},
    )
    class EncryptionConfigProperty:
        def __init__(
            self,
            *,
            provider: typing.Any = None,
            resources: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''The encryption configuration for the cluster.

            :param provider: The encryption provider for the cluster.
            :param resources: Specifies the resources to be encrypted. The only supported value is "secrets".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                # provider: Any
                
                encryption_config_property = eks.CfnCluster.EncryptionConfigProperty(
                    provider=provider,
                    resources=["resources"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if provider is not None:
                self._values["provider"] = provider
            if resources is not None:
                self._values["resources"] = resources

        @builtins.property
        def provider(self) -> typing.Any:
            '''The encryption provider for the cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html#cfn-eks-cluster-encryptionconfig-provider
            '''
            result = self._values.get("provider")
            return typing.cast(typing.Any, result)

        @builtins.property
        def resources(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Specifies the resources to be encrypted.

            The only supported value is "secrets".

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-encryptionconfig.html#cfn-eks-cluster-encryptionconfig-resources
            '''
            result = self._values.get("resources")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "EncryptionConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnCluster.KubernetesNetworkConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ip_family": "ipFamily",
            "service_ipv4_cidr": "serviceIpv4Cidr",
            "service_ipv6_cidr": "serviceIpv6Cidr",
        },
    )
    class KubernetesNetworkConfigProperty:
        def __init__(
            self,
            *,
            ip_family: typing.Optional[builtins.str] = None,
            service_ipv4_cidr: typing.Optional[builtins.str] = None,
            service_ipv6_cidr: typing.Optional[builtins.str] = None,
        ) -> None:
            '''The Kubernetes network configuration for the cluster.

            :param ip_family: Specify which IP family is used to assign Kubernetes pod and service IP addresses. If you don't specify a value, ``ipv4`` is used by default. You can only specify an IP family when you create a cluster and can't change this value once the cluster is created. If you specify ``ipv6`` , the VPC and subnets that you specify for cluster creation must have both IPv4 and IPv6 CIDR blocks assigned to them. You can't specify ``ipv6`` for clusters in China Regions. You can only specify ``ipv6`` for 1.21 and later clusters that use version 1.10.1 or later of the Amazon VPC CNI add-on. If you specify ``ipv6`` , then ensure that your VPC meets the requirements listed in the considerations listed in `Assigning IPv6 addresses to pods and services <https://docs.aws.amazon.com/eks/latest/userguide/cni-ipv6.html>`_ in the Amazon EKS User Guide. Kubernetes assigns services IPv6 addresses from the unique local address range (fc00::/7). You can't specify a custom IPv6 CIDR block. Pod addresses are assigned from the subnet's IPv6 CIDR.
            :param service_ipv4_cidr: Don't specify a value if you select ``ipv6`` for *ipFamily* . The CIDR block to assign Kubernetes service IP addresses from. If you don't specify a block, Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks. We recommend that you specify a block that does not overlap with resources in other networks that are peered or connected to your VPC. The block must meet the following requirements: - Within one of the following private IP address blocks: 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16. - Doesn't overlap with any CIDR block assigned to the VPC that you selected for VPC. - Between /24 and /12. .. epigraph:: You can only specify a custom CIDR block when you create a cluster and can't change this value once the cluster is created.
            :param service_ipv6_cidr: The CIDR block that Kubernetes pod and service IP addresses are assigned from if you created a 1.21 or later cluster with version 1.10.1 or later of the Amazon VPC CNI add-on and specified ``ipv6`` for *ipFamily* when you created the cluster. Kubernetes assigns service addresses from the unique local address range ( ``fc00::/7`` ) because you can't specify a custom IPv6 CIDR block when you create the cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-kubernetesnetworkconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                kubernetes_network_config_property = eks.CfnCluster.KubernetesNetworkConfigProperty(
                    ip_family="ipFamily",
                    service_ipv4_cidr="serviceIpv4Cidr",
                    service_ipv6_cidr="serviceIpv6Cidr"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if ip_family is not None:
                self._values["ip_family"] = ip_family
            if service_ipv4_cidr is not None:
                self._values["service_ipv4_cidr"] = service_ipv4_cidr
            if service_ipv6_cidr is not None:
                self._values["service_ipv6_cidr"] = service_ipv6_cidr

        @builtins.property
        def ip_family(self) -> typing.Optional[builtins.str]:
            '''Specify which IP family is used to assign Kubernetes pod and service IP addresses.

            If you don't specify a value, ``ipv4`` is used by default. You can only specify an IP family when you create a cluster and can't change this value once the cluster is created. If you specify ``ipv6`` , the VPC and subnets that you specify for cluster creation must have both IPv4 and IPv6 CIDR blocks assigned to them. You can't specify ``ipv6`` for clusters in China Regions.

            You can only specify ``ipv6`` for 1.21 and later clusters that use version 1.10.1 or later of the Amazon VPC CNI add-on. If you specify ``ipv6`` , then ensure that your VPC meets the requirements listed in the considerations listed in `Assigning IPv6 addresses to pods and services <https://docs.aws.amazon.com/eks/latest/userguide/cni-ipv6.html>`_ in the Amazon EKS User Guide. Kubernetes assigns services IPv6 addresses from the unique local address range (fc00::/7). You can't specify a custom IPv6 CIDR block. Pod addresses are assigned from the subnet's IPv6 CIDR.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-kubernetesnetworkconfig.html#cfn-eks-cluster-kubernetesnetworkconfig-ipfamily
            '''
            result = self._values.get("ip_family")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def service_ipv4_cidr(self) -> typing.Optional[builtins.str]:
            '''Don't specify a value if you select ``ipv6`` for *ipFamily* .

            The CIDR block to assign Kubernetes service IP addresses from. If you don't specify a block, Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks. We recommend that you specify a block that does not overlap with resources in other networks that are peered or connected to your VPC. The block must meet the following requirements:

            - Within one of the following private IP address blocks: 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16.
            - Doesn't overlap with any CIDR block assigned to the VPC that you selected for VPC.
            - Between /24 and /12.

            .. epigraph::

               You can only specify a custom CIDR block when you create a cluster and can't change this value once the cluster is created.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-kubernetesnetworkconfig.html#cfn-eks-cluster-kubernetesnetworkconfig-serviceipv4cidr
            '''
            result = self._values.get("service_ipv4_cidr")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def service_ipv6_cidr(self) -> typing.Optional[builtins.str]:
            '''The CIDR block that Kubernetes pod and service IP addresses are assigned from if you created a 1.21 or later cluster with version 1.10.1 or later of the Amazon VPC CNI add-on and specified ``ipv6`` for *ipFamily* when you created the cluster. Kubernetes assigns service addresses from the unique local address range ( ``fc00::/7`` ) because you can't specify a custom IPv6 CIDR block when you create the cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-kubernetesnetworkconfig.html#cfn-eks-cluster-kubernetesnetworkconfig-serviceipv6cidr
            '''
            result = self._values.get("service_ipv6_cidr")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "KubernetesNetworkConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnCluster.LoggingProperty",
        jsii_struct_bases=[],
        name_mapping={"cluster_logging": "clusterLogging"},
    )
    class LoggingProperty:
        def __init__(
            self,
            *,
            cluster_logging: typing.Optional[typing.Union["CfnCluster.ClusterLoggingProperty", _IResolvable_da3f097b]] = None,
        ) -> None:
            '''Enable or disable exporting the Kubernetes control plane logs for your cluster to CloudWatch Logs.

            By default, cluster control plane logs aren't exported to CloudWatch Logs. For more information, see `Amazon EKS Cluster control plane logs <https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html>`_ in the **Amazon EKS User Guide** .
            .. epigraph::

               When updating a resource, you must include this ``Logging`` property if the previous CloudFormation template of the resource had it. > CloudWatch Logs ingestion, archive storage, and data scanning rates apply to exported control plane logs. For more information, see `CloudWatch Pricing <https://docs.aws.amazon.com/cloudwatch/pricing/>`_ .

            :param cluster_logging: The cluster control plane logging configuration for your cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-logging.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                logging_property = eks.CfnCluster.LoggingProperty(
                    cluster_logging=eks.CfnCluster.ClusterLoggingProperty(
                        enabled_types=[eks.CfnCluster.LoggingTypeConfigProperty(
                            type="type"
                        )]
                    )
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if cluster_logging is not None:
                self._values["cluster_logging"] = cluster_logging

        @builtins.property
        def cluster_logging(
            self,
        ) -> typing.Optional[typing.Union["CfnCluster.ClusterLoggingProperty", _IResolvable_da3f097b]]:
            '''The cluster control plane logging configuration for your cluster.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-logging.html#cfn-eks-cluster-logging-clusterlogging
            '''
            result = self._values.get("cluster_logging")
            return typing.cast(typing.Optional[typing.Union["CfnCluster.ClusterLoggingProperty", _IResolvable_da3f097b]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoggingProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnCluster.LoggingTypeConfigProperty",
        jsii_struct_bases=[],
        name_mapping={"type": "type"},
    )
    class LoggingTypeConfigProperty:
        def __init__(self, *, type: typing.Optional[builtins.str] = None) -> None:
            '''The enabled logging type.

            For a list of the valid logging types, see the ```types`` property of ``LogSetup`` <https://docs.aws.amazon.com/eks/latest/APIReference/API_LogSetup.html#AmazonEKS-Type-LogSetup-types>`_ in the *Amazon EKS API Reference* .

            :param type: The name of the log type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-loggingtypeconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                logging_type_config_property = eks.CfnCluster.LoggingTypeConfigProperty(
                    type="type"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if type is not None:
                self._values["type"] = type

        @builtins.property
        def type(self) -> typing.Optional[builtins.str]:
            '''The name of the log type.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-loggingtypeconfig.html#cfn-eks-cluster-loggingtypeconfig-type
            '''
            result = self._values.get("type")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LoggingTypeConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnCluster.ResourcesVpcConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "subnet_ids": "subnetIds",
            "endpoint_private_access": "endpointPrivateAccess",
            "endpoint_public_access": "endpointPublicAccess",
            "public_access_cidrs": "publicAccessCidrs",
            "security_group_ids": "securityGroupIds",
        },
    )
    class ResourcesVpcConfigProperty:
        def __init__(
            self,
            *,
            subnet_ids: typing.Sequence[builtins.str],
            endpoint_private_access: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            endpoint_public_access: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
            public_access_cidrs: typing.Optional[typing.Sequence[builtins.str]] = None,
            security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''An object representing the VPC configuration to use for an Amazon EKS cluster.

            .. epigraph::

               When updating a resource, you must include these properties if the previous CloudFormation template of the resource had them:

               - ``EndpointPublicAccess``
               - ``EndpointPrivateAccess``
               - ``PublicAccessCidrs``

            :param subnet_ids: Specify subnets for your Amazon EKS nodes. Amazon EKS creates cross-account elastic network interfaces in these subnets to allow communication between your nodes and the Kubernetes control plane.
            :param endpoint_private_access: Set this value to ``true`` to enable private access for your cluster's Kubernetes API server endpoint. If you enable private access, Kubernetes API requests from within your cluster's VPC use the private VPC endpoint. The default value for this parameter is ``false`` , which disables private access for your Kubernetes API server. If you disable private access and you have nodes or AWS Fargate pods in the cluster, then ensure that ``publicAccessCidrs`` includes the necessary CIDR blocks for communication with the nodes or Fargate pods. For more information, see `Amazon EKS cluster endpoint access control <https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html>`_ in the **Amazon EKS User Guide** .
            :param endpoint_public_access: Set this value to ``false`` to disable public access to your cluster's Kubernetes API server endpoint. If you disable public access, your cluster's Kubernetes API server can only receive requests from within the cluster VPC. The default value for this parameter is ``true`` , which enables public access for your Kubernetes API server. For more information, see `Amazon EKS cluster endpoint access control <https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html>`_ in the **Amazon EKS User Guide** .
            :param public_access_cidrs: The CIDR blocks that are allowed access to your cluster's public Kubernetes API server endpoint. Communication to the endpoint from addresses outside of the CIDR blocks that you specify is denied. The default value is ``0.0.0.0/0`` . If you've disabled private endpoint access and you have nodes or AWS Fargate pods in the cluster, then ensure that you specify the necessary CIDR blocks. For more information, see `Amazon EKS cluster endpoint access control <https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html>`_ in the **Amazon EKS User Guide** .
            :param security_group_ids: Specify one or more security groups for the cross-account elastic network interfaces that Amazon EKS creates to use that allow communication between your nodes and the Kubernetes control plane. If you don't specify any security groups, then familiarize yourself with the difference between Amazon EKS defaults for clusters deployed with Kubernetes: - 1.14 Amazon EKS platform version ``eks.2`` and earlier - 1.14 Amazon EKS platform version ``eks.3`` and later For more information, see `Amazon EKS security group considerations <https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html>`_ in the **Amazon EKS User Guide** .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-resourcesvpcconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                resources_vpc_config_property = eks.CfnCluster.ResourcesVpcConfigProperty(
                    subnet_ids=["subnetIds"],
                
                    # the properties below are optional
                    endpoint_private_access=False,
                    endpoint_public_access=False,
                    public_access_cidrs=["publicAccessCidrs"],
                    security_group_ids=["securityGroupIds"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "subnet_ids": subnet_ids,
            }
            if endpoint_private_access is not None:
                self._values["endpoint_private_access"] = endpoint_private_access
            if endpoint_public_access is not None:
                self._values["endpoint_public_access"] = endpoint_public_access
            if public_access_cidrs is not None:
                self._values["public_access_cidrs"] = public_access_cidrs
            if security_group_ids is not None:
                self._values["security_group_ids"] = security_group_ids

        @builtins.property
        def subnet_ids(self) -> typing.List[builtins.str]:
            '''Specify subnets for your Amazon EKS nodes.

            Amazon EKS creates cross-account elastic network interfaces in these subnets to allow communication between your nodes and the Kubernetes control plane.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-resourcesvpcconfig.html#cfn-eks-cluster-resourcesvpcconfig-subnetids
            '''
            result = self._values.get("subnet_ids")
            assert result is not None, "Required property 'subnet_ids' is missing"
            return typing.cast(typing.List[builtins.str], result)

        @builtins.property
        def endpoint_private_access(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Set this value to ``true`` to enable private access for your cluster's Kubernetes API server endpoint.

            If you enable private access, Kubernetes API requests from within your cluster's VPC use the private VPC endpoint. The default value for this parameter is ``false`` , which disables private access for your Kubernetes API server. If you disable private access and you have nodes or AWS Fargate pods in the cluster, then ensure that ``publicAccessCidrs`` includes the necessary CIDR blocks for communication with the nodes or Fargate pods. For more information, see `Amazon EKS cluster endpoint access control <https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html>`_ in the **Amazon EKS User Guide** .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-resourcesvpcconfig.html#cfn-eks-cluster-resourcesvpcconfig-endpointprivateaccess
            '''
            result = self._values.get("endpoint_private_access")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def endpoint_public_access(
            self,
        ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
            '''Set this value to ``false`` to disable public access to your cluster's Kubernetes API server endpoint.

            If you disable public access, your cluster's Kubernetes API server can only receive requests from within the cluster VPC. The default value for this parameter is ``true`` , which enables public access for your Kubernetes API server. For more information, see `Amazon EKS cluster endpoint access control <https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html>`_ in the **Amazon EKS User Guide** .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-resourcesvpcconfig.html#cfn-eks-cluster-resourcesvpcconfig-endpointpublicaccess
            '''
            result = self._values.get("endpoint_public_access")
            return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

        @builtins.property
        def public_access_cidrs(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The CIDR blocks that are allowed access to your cluster's public Kubernetes API server endpoint.

            Communication to the endpoint from addresses outside of the CIDR blocks that you specify is denied. The default value is ``0.0.0.0/0`` . If you've disabled private endpoint access and you have nodes or AWS Fargate pods in the cluster, then ensure that you specify the necessary CIDR blocks. For more information, see `Amazon EKS cluster endpoint access control <https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html>`_ in the **Amazon EKS User Guide** .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-resourcesvpcconfig.html#cfn-eks-cluster-resourcesvpcconfig-publicaccesscidrs
            '''
            result = self._values.get("public_access_cidrs")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        @builtins.property
        def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
            '''Specify one or more security groups for the cross-account elastic network interfaces that Amazon EKS creates to use that allow communication between your nodes and the Kubernetes control plane.

            If you don't specify any security groups, then familiarize yourself with the difference between Amazon EKS defaults for clusters deployed with Kubernetes:

            - 1.14 Amazon EKS platform version ``eks.2`` and earlier
            - 1.14 Amazon EKS platform version ``eks.3`` and later

            For more information, see `Amazon EKS security group considerations <https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html>`_ in the **Amazon EKS User Guide** .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-cluster-resourcesvpcconfig.html#cfn-eks-cluster-resourcesvpcconfig-securitygroupids
            '''
            result = self._values.get("security_group_ids")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ResourcesVpcConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.CfnClusterProps",
    jsii_struct_bases=[],
    name_mapping={
        "resources_vpc_config": "resourcesVpcConfig",
        "role_arn": "roleArn",
        "encryption_config": "encryptionConfig",
        "kubernetes_network_config": "kubernetesNetworkConfig",
        "logging": "logging",
        "name": "name",
        "tags": "tags",
        "version": "version",
    },
)
class CfnClusterProps:
    def __init__(
        self,
        *,
        resources_vpc_config: typing.Union[CfnCluster.ResourcesVpcConfigProperty, _IResolvable_da3f097b],
        role_arn: builtins.str,
        encryption_config: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnCluster.EncryptionConfigProperty, _IResolvable_da3f097b]]]] = None,
        kubernetes_network_config: typing.Optional[typing.Union[CfnCluster.KubernetesNetworkConfigProperty, _IResolvable_da3f097b]] = None,
        logging: typing.Optional[typing.Union[CfnCluster.LoggingProperty, _IResolvable_da3f097b]] = None,
        name: typing.Optional[builtins.str] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
        version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnCluster``.

        :param resources_vpc_config: The VPC configuration that's used by the cluster control plane. Amazon EKS VPC resources have specific requirements to work properly with Kubernetes. For more information, see `Cluster VPC Considerations <https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html>`_ and `Cluster Security Group Considerations <https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html>`_ in the *Amazon EKS User Guide* . You must specify at least two subnets. You can specify up to five security groups, but we recommend that you use a dedicated security group for your cluster control plane. .. epigraph:: Updates require replacement of the ``SecurityGroupIds`` and ``SubnetIds`` sub-properties.
        :param role_arn: The Amazon Resource Name (ARN) of the IAM role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf. For more information, see `Amazon EKS Service IAM Role <https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html>`_ in the **Amazon EKS User Guide** .
        :param encryption_config: The encryption configuration for the cluster.
        :param kubernetes_network_config: The Kubernetes network configuration for the cluster.
        :param logging: The logging configuration for your cluster.
        :param name: The unique name to give to your cluster.
        :param tags: The metadata that you apply to the cluster to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Cluster tags don't propagate to any other resources associated with the cluster. .. epigraph:: You must have the ``eks:TagResource`` and ``eks:UntagResource`` permissions in your IAM user or IAM role used to manage the CloudFormation stack. If you don't have these permissions, there might be unexpected behavior with stack-level tags propagating to the resource during resource creation and update.
        :param version: The desired Kubernetes version for your cluster. If you don't specify a value here, the latest version available in Amazon EKS is used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            # provider: Any
            
            cfn_cluster_props = eks.CfnClusterProps(
                resources_vpc_config=eks.CfnCluster.ResourcesVpcConfigProperty(
                    subnet_ids=["subnetIds"],
            
                    # the properties below are optional
                    endpoint_private_access=False,
                    endpoint_public_access=False,
                    public_access_cidrs=["publicAccessCidrs"],
                    security_group_ids=["securityGroupIds"]
                ),
                role_arn="roleArn",
            
                # the properties below are optional
                encryption_config=[eks.CfnCluster.EncryptionConfigProperty(
                    provider=provider,
                    resources=["resources"]
                )],
                kubernetes_network_config=eks.CfnCluster.KubernetesNetworkConfigProperty(
                    ip_family="ipFamily",
                    service_ipv4_cidr="serviceIpv4Cidr",
                    service_ipv6_cidr="serviceIpv6Cidr"
                ),
                logging=eks.CfnCluster.LoggingProperty(
                    cluster_logging=eks.CfnCluster.ClusterLoggingProperty(
                        enabled_types=[eks.CfnCluster.LoggingTypeConfigProperty(
                            type="type"
                        )]
                    )
                ),
                name="name",
                tags=[CfnTag(
                    key="key",
                    value="value"
                )],
                version="version"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "resources_vpc_config": resources_vpc_config,
            "role_arn": role_arn,
        }
        if encryption_config is not None:
            self._values["encryption_config"] = encryption_config
        if kubernetes_network_config is not None:
            self._values["kubernetes_network_config"] = kubernetes_network_config
        if logging is not None:
            self._values["logging"] = logging
        if name is not None:
            self._values["name"] = name
        if tags is not None:
            self._values["tags"] = tags
        if version is not None:
            self._values["version"] = version

    @builtins.property
    def resources_vpc_config(
        self,
    ) -> typing.Union[CfnCluster.ResourcesVpcConfigProperty, _IResolvable_da3f097b]:
        '''The VPC configuration that's used by the cluster control plane.

        Amazon EKS VPC resources have specific requirements to work properly with Kubernetes. For more information, see `Cluster VPC Considerations <https://docs.aws.amazon.com/eks/latest/userguide/network_reqs.html>`_ and `Cluster Security Group Considerations <https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html>`_ in the *Amazon EKS User Guide* . You must specify at least two subnets. You can specify up to five security groups, but we recommend that you use a dedicated security group for your cluster control plane.
        .. epigraph::

           Updates require replacement of the ``SecurityGroupIds`` and ``SubnetIds`` sub-properties.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-resourcesvpcconfig
        '''
        result = self._values.get("resources_vpc_config")
        assert result is not None, "Required property 'resources_vpc_config' is missing"
        return typing.cast(typing.Union[CfnCluster.ResourcesVpcConfigProperty, _IResolvable_da3f097b], result)

    @builtins.property
    def role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf.

        For more information, see `Amazon EKS Service IAM Role <https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html>`_ in the **Amazon EKS User Guide** .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-rolearn
        '''
        result = self._values.get("role_arn")
        assert result is not None, "Required property 'role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def encryption_config(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCluster.EncryptionConfigProperty, _IResolvable_da3f097b]]]]:
        '''The encryption configuration for the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-encryptionconfig
        '''
        result = self._values.get("encryption_config")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnCluster.EncryptionConfigProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def kubernetes_network_config(
        self,
    ) -> typing.Optional[typing.Union[CfnCluster.KubernetesNetworkConfigProperty, _IResolvable_da3f097b]]:
        '''The Kubernetes network configuration for the cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-kubernetesnetworkconfig
        '''
        result = self._values.get("kubernetes_network_config")
        return typing.cast(typing.Optional[typing.Union[CfnCluster.KubernetesNetworkConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def logging(
        self,
    ) -> typing.Optional[typing.Union[CfnCluster.LoggingProperty, _IResolvable_da3f097b]]:
        '''The logging configuration for your cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-logging
        '''
        result = self._values.get("logging")
        return typing.cast(typing.Optional[typing.Union[CfnCluster.LoggingProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The unique name to give to your cluster.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-name
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The metadata that you apply to the cluster to assist with categorization and organization.

        Each tag consists of a key and an optional value, both of which you define. Cluster tags don't propagate to any other resources associated with the cluster.
        .. epigraph::

           You must have the ``eks:TagResource`` and ``eks:UntagResource`` permissions in your IAM user or IAM role used to manage the CloudFormation stack. If you don't have these permissions, there might be unexpected behavior with stack-level tags propagating to the resource during resource creation and update.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    @builtins.property
    def version(self) -> typing.Optional[builtins.str]:
        '''The desired Kubernetes version for your cluster.

        If you don't specify a value here, the latest version available in Amazon EKS is used.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-cluster.html#cfn-eks-cluster-version
        '''
        result = self._values.get("version")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnClusterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnFargateProfile(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.CfnFargateProfile",
):
    '''A CloudFormation ``AWS::EKS::FargateProfile``.

    Creates an AWS Fargate profile for your Amazon EKS cluster. You must have at least one Fargate profile in a cluster to be able to run pods on Fargate.

    The Fargate profile allows an administrator to declare which pods run on Fargate and specify which pods run on which Fargate profile. This declaration is done through the profile’s selectors. Each profile can have up to five selectors that contain a namespace and labels. A namespace is required for every selector. The label field consists of multiple optional key-value pairs. Pods that match the selectors are scheduled on Fargate. If a to-be-scheduled pod matches any of the selectors in the Fargate profile, then that pod is run on Fargate.

    When you create a Fargate profile, you must specify a pod execution role to use with the pods that are scheduled with the profile. This role is added to the cluster's Kubernetes `Role Based Access Control <https://docs.aws.amazon.com/https://kubernetes.io/docs/admin/authorization/rbac/>`_ (RBAC) for authorization so that the ``kubelet`` that is running on the Fargate infrastructure can register with your Amazon EKS cluster so that it can appear in your cluster as a node. The pod execution role also provides IAM permissions to the Fargate infrastructure to allow read access to Amazon ECR image repositories. For more information, see `Pod Execution Role <https://docs.aws.amazon.com/eks/latest/userguide/pod-execution-role.html>`_ in the *Amazon EKS User Guide* .

    Fargate profiles are immutable. However, you can create a new updated profile to replace an existing profile and then delete the original after the updated profile has finished creating.

    If any Fargate profiles in a cluster are in the ``DELETING`` status, you must wait for that Fargate profile to finish deleting before you can create any other profiles in that cluster.

    For more information, see `AWS Fargate Profile <https://docs.aws.amazon.com/eks/latest/userguide/fargate-profile.html>`_ in the *Amazon EKS User Guide* .

    :cloudformationResource: AWS::EKS::FargateProfile
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_eks as eks
        
        cfn_fargate_profile = eks.CfnFargateProfile(self, "MyCfnFargateProfile",
            cluster_name="clusterName",
            pod_execution_role_arn="podExecutionRoleArn",
            selectors=[eks.CfnFargateProfile.SelectorProperty(
                namespace="namespace",
        
                # the properties below are optional
                labels=[eks.CfnFargateProfile.LabelProperty(
                    key="key",
                    value="value"
                )]
            )],
        
            # the properties below are optional
            fargate_profile_name="fargateProfileName",
            subnets=["subnets"],
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
        cluster_name: builtins.str,
        pod_execution_role_arn: builtins.str,
        selectors: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFargateProfile.SelectorProperty", _IResolvable_da3f097b]]],
        fargate_profile_name: typing.Optional[builtins.str] = None,
        subnets: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Create a new ``AWS::EKS::FargateProfile``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param cluster_name: The name of the Amazon EKS cluster to apply the Fargate profile to.
        :param pod_execution_role_arn: The Amazon Resource Name (ARN) of the pod execution role to use for pods that match the selectors in the Fargate profile. The pod execution role allows Fargate infrastructure to register with your cluster as a node, and it provides read access to Amazon ECR image repositories. For more information, see `Pod Execution Role <https://docs.aws.amazon.com/eks/latest/userguide/pod-execution-role.html>`_ in the *Amazon EKS User Guide* .
        :param selectors: The selectors to match for pods to use this Fargate profile. Each selector must have an associated namespace. Optionally, you can also specify labels for a namespace. You may specify up to five selectors in a Fargate profile.
        :param fargate_profile_name: The name of the Fargate profile.
        :param subnets: The IDs of subnets to launch your pods into. At this time, pods running on Fargate are not assigned public IP addresses, so only private subnets (with no direct route to an Internet Gateway) are accepted for this parameter.
        :param tags: The metadata to apply to the Fargate profile to assist with categorization and organization. Each tag consists of a key and an optional value. You define both. Fargate profile tags do not propagate to any other resources associated with the Fargate profile, such as the pods that are scheduled with it.
        '''
        props = CfnFargateProfileProps(
            cluster_name=cluster_name,
            pod_execution_role_arn=pod_execution_role_arn,
            selectors=selectors,
            fargate_profile_name=fargate_profile_name,
            subnets=subnets,
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
        '''The ARN of the cluster, such as ``arn:aws:eks:us-west-2:666666666666:fargateprofile/myCluster/myFargateProfile/1cb1a11a-1dc1-1d11-cf11-1111f11fa111`` .

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
        '''The metadata to apply to the Fargate profile to assist with categorization and organization.

        Each tag consists of a key and an optional value. You define both. Fargate profile tags do not propagate to any other resources associated with the Fargate profile, such as the pods that are scheduled with it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterName")
    def cluster_name(self) -> builtins.str:
        '''The name of the Amazon EKS cluster to apply the Fargate profile to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-clustername
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterName"))

    @cluster_name.setter
    def cluster_name(self, value: builtins.str) -> None:
        jsii.set(self, "clusterName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="podExecutionRoleArn")
    def pod_execution_role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the pod execution role to use for pods that match the selectors in the Fargate profile.

        The pod execution role allows Fargate infrastructure to register with your cluster as a node, and it provides read access to Amazon ECR image repositories. For more information, see `Pod Execution Role <https://docs.aws.amazon.com/eks/latest/userguide/pod-execution-role.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-podexecutionrolearn
        '''
        return typing.cast(builtins.str, jsii.get(self, "podExecutionRoleArn"))

    @pod_execution_role_arn.setter
    def pod_execution_role_arn(self, value: builtins.str) -> None:
        jsii.set(self, "podExecutionRoleArn", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="selectors")
    def selectors(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFargateProfile.SelectorProperty", _IResolvable_da3f097b]]]:
        '''The selectors to match for pods to use this Fargate profile.

        Each selector must have an associated namespace. Optionally, you can also specify labels for a namespace. You may specify up to five selectors in a Fargate profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-selectors
        '''
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFargateProfile.SelectorProperty", _IResolvable_da3f097b]]], jsii.get(self, "selectors"))

    @selectors.setter
    def selectors(
        self,
        value: typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFargateProfile.SelectorProperty", _IResolvable_da3f097b]]],
    ) -> None:
        jsii.set(self, "selectors", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fargateProfileName")
    def fargate_profile_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Fargate profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-fargateprofilename
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "fargateProfileName"))

    @fargate_profile_name.setter
    def fargate_profile_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "fargateProfileName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnets")
    def subnets(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The IDs of subnets to launch your pods into.

        At this time, pods running on Fargate are not assigned public IP addresses, so only private subnets (with no direct route to an Internet Gateway) are accepted for this parameter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-subnets
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "subnets"))

    @subnets.setter
    def subnets(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "subnets", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnFargateProfile.LabelProperty",
        jsii_struct_bases=[],
        name_mapping={"key": "key", "value": "value"},
    )
    class LabelProperty:
        def __init__(self, *, key: builtins.str, value: builtins.str) -> None:
            '''A key-value pair.

            :param key: Enter a key.
            :param value: Enter a value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-fargateprofile-label.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                label_property = eks.CfnFargateProfile.LabelProperty(
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
            '''Enter a key.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-fargateprofile-label.html#cfn-eks-fargateprofile-label-key
            '''
            result = self._values.get("key")
            assert result is not None, "Required property 'key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def value(self) -> builtins.str:
            '''Enter a value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-fargateprofile-label.html#cfn-eks-fargateprofile-label-value
            '''
            result = self._values.get("value")
            assert result is not None, "Required property 'value' is missing"
            return typing.cast(builtins.str, result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "LabelProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnFargateProfile.SelectorProperty",
        jsii_struct_bases=[],
        name_mapping={"namespace": "namespace", "labels": "labels"},
    )
    class SelectorProperty:
        def __init__(
            self,
            *,
            namespace: builtins.str,
            labels: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnFargateProfile.LabelProperty", _IResolvable_da3f097b]]]] = None,
        ) -> None:
            '''An object representing an AWS Fargate profile selector.

            :param namespace: The Kubernetes namespace that the selector should match.
            :param labels: The Kubernetes labels that the selector should match. A pod must contain all of the labels that are specified in the selector for it to be considered a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-fargateprofile-selector.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                selector_property = eks.CfnFargateProfile.SelectorProperty(
                    namespace="namespace",
                
                    # the properties below are optional
                    labels=[eks.CfnFargateProfile.LabelProperty(
                        key="key",
                        value="value"
                    )]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "namespace": namespace,
            }
            if labels is not None:
                self._values["labels"] = labels

        @builtins.property
        def namespace(self) -> builtins.str:
            '''The Kubernetes namespace that the selector should match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-fargateprofile-selector.html#cfn-eks-fargateprofile-selector-namespace
            '''
            result = self._values.get("namespace")
            assert result is not None, "Required property 'namespace' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def labels(
            self,
        ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFargateProfile.LabelProperty", _IResolvable_da3f097b]]]]:
            '''The Kubernetes labels that the selector should match.

            A pod must contain all of the labels that are specified in the selector for it to be considered a match.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-fargateprofile-selector.html#cfn-eks-fargateprofile-selector-labels
            '''
            result = self._values.get("labels")
            return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnFargateProfile.LabelProperty", _IResolvable_da3f097b]]]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "SelectorProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.CfnFargateProfileProps",
    jsii_struct_bases=[],
    name_mapping={
        "cluster_name": "clusterName",
        "pod_execution_role_arn": "podExecutionRoleArn",
        "selectors": "selectors",
        "fargate_profile_name": "fargateProfileName",
        "subnets": "subnets",
        "tags": "tags",
    },
)
class CfnFargateProfileProps:
    def __init__(
        self,
        *,
        cluster_name: builtins.str,
        pod_execution_role_arn: builtins.str,
        selectors: typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnFargateProfile.SelectorProperty, _IResolvable_da3f097b]]],
        fargate_profile_name: typing.Optional[builtins.str] = None,
        subnets: typing.Optional[typing.Sequence[builtins.str]] = None,
        tags: typing.Optional[typing.Sequence[_CfnTag_f6864754]] = None,
    ) -> None:
        '''Properties for defining a ``CfnFargateProfile``.

        :param cluster_name: The name of the Amazon EKS cluster to apply the Fargate profile to.
        :param pod_execution_role_arn: The Amazon Resource Name (ARN) of the pod execution role to use for pods that match the selectors in the Fargate profile. The pod execution role allows Fargate infrastructure to register with your cluster as a node, and it provides read access to Amazon ECR image repositories. For more information, see `Pod Execution Role <https://docs.aws.amazon.com/eks/latest/userguide/pod-execution-role.html>`_ in the *Amazon EKS User Guide* .
        :param selectors: The selectors to match for pods to use this Fargate profile. Each selector must have an associated namespace. Optionally, you can also specify labels for a namespace. You may specify up to five selectors in a Fargate profile.
        :param fargate_profile_name: The name of the Fargate profile.
        :param subnets: The IDs of subnets to launch your pods into. At this time, pods running on Fargate are not assigned public IP addresses, so only private subnets (with no direct route to an Internet Gateway) are accepted for this parameter.
        :param tags: The metadata to apply to the Fargate profile to assist with categorization and organization. Each tag consists of a key and an optional value. You define both. Fargate profile tags do not propagate to any other resources associated with the Fargate profile, such as the pods that are scheduled with it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            cfn_fargate_profile_props = eks.CfnFargateProfileProps(
                cluster_name="clusterName",
                pod_execution_role_arn="podExecutionRoleArn",
                selectors=[eks.CfnFargateProfile.SelectorProperty(
                    namespace="namespace",
            
                    # the properties below are optional
                    labels=[eks.CfnFargateProfile.LabelProperty(
                        key="key",
                        value="value"
                    )]
                )],
            
                # the properties below are optional
                fargate_profile_name="fargateProfileName",
                subnets=["subnets"],
                tags=[CfnTag(
                    key="key",
                    value="value"
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster_name": cluster_name,
            "pod_execution_role_arn": pod_execution_role_arn,
            "selectors": selectors,
        }
        if fargate_profile_name is not None:
            self._values["fargate_profile_name"] = fargate_profile_name
        if subnets is not None:
            self._values["subnets"] = subnets
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def cluster_name(self) -> builtins.str:
        '''The name of the Amazon EKS cluster to apply the Fargate profile to.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-clustername
        '''
        result = self._values.get("cluster_name")
        assert result is not None, "Required property 'cluster_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def pod_execution_role_arn(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the pod execution role to use for pods that match the selectors in the Fargate profile.

        The pod execution role allows Fargate infrastructure to register with your cluster as a node, and it provides read access to Amazon ECR image repositories. For more information, see `Pod Execution Role <https://docs.aws.amazon.com/eks/latest/userguide/pod-execution-role.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-podexecutionrolearn
        '''
        result = self._values.get("pod_execution_role_arn")
        assert result is not None, "Required property 'pod_execution_role_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def selectors(
        self,
    ) -> typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnFargateProfile.SelectorProperty, _IResolvable_da3f097b]]]:
        '''The selectors to match for pods to use this Fargate profile.

        Each selector must have an associated namespace. Optionally, you can also specify labels for a namespace. You may specify up to five selectors in a Fargate profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-selectors
        '''
        result = self._values.get("selectors")
        assert result is not None, "Required property 'selectors' is missing"
        return typing.cast(typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnFargateProfile.SelectorProperty, _IResolvable_da3f097b]]], result)

    @builtins.property
    def fargate_profile_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Fargate profile.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-fargateprofilename
        '''
        result = self._values.get("fargate_profile_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def subnets(self) -> typing.Optional[typing.List[builtins.str]]:
        '''The IDs of subnets to launch your pods into.

        At this time, pods running on Fargate are not assigned public IP addresses, so only private subnets (with no direct route to an Internet Gateway) are accepted for this parameter.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-subnets
        '''
        result = self._values.get("subnets")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.List[_CfnTag_f6864754]]:
        '''The metadata to apply to the Fargate profile to assist with categorization and organization.

        Each tag consists of a key and an optional value. You define both. Fargate profile tags do not propagate to any other resources associated with the Fargate profile, such as the pods that are scheduled with it.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-fargateprofile.html#cfn-eks-fargateprofile-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.List[_CfnTag_f6864754]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnFargateProfileProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IInspectable_c2943556)
class CfnNodegroup(
    _CfnResource_9df397a6,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.CfnNodegroup",
):
    '''A CloudFormation ``AWS::EKS::Nodegroup``.

    Creates a managed node group for an Amazon EKS cluster. You can only create a node group for your cluster that is equal to the current Kubernetes version for the cluster. All node groups are created with the latest AMI release version for the respective minor Kubernetes version of the cluster, unless you deploy a custom AMI using a launch template. For more information about using launch templates, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ .

    An Amazon EKS managed node group is an Amazon EC2 Auto Scaling group and associated Amazon EC2 instances that are managed by AWS for an Amazon EKS cluster. Each node group uses a version of the Amazon EKS optimized Amazon Linux 2 AMI. For more information, see `Managed Node Groups <https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html>`_ in the *Amazon EKS User Guide* .

    :cloudformationResource: AWS::EKS::Nodegroup
    :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html
    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_eks as eks
        
        # labels: Any
        # tags: Any
        
        cfn_nodegroup = eks.CfnNodegroup(self, "MyCfnNodegroup",
            cluster_name="clusterName",
            node_role="nodeRole",
            subnets=["subnets"],
        
            # the properties below are optional
            ami_type="amiType",
            capacity_type="capacityType",
            disk_size=123,
            force_update_enabled=False,
            instance_types=["instanceTypes"],
            labels=labels,
            launch_template=eks.CfnNodegroup.LaunchTemplateSpecificationProperty(
                id="id",
                name="name",
                version="version"
            ),
            nodegroup_name="nodegroupName",
            release_version="releaseVersion",
            remote_access=eks.CfnNodegroup.RemoteAccessProperty(
                ec2_ssh_key="ec2SshKey",
        
                # the properties below are optional
                source_security_groups=["sourceSecurityGroups"]
            ),
            scaling_config=eks.CfnNodegroup.ScalingConfigProperty(
                desired_size=123,
                max_size=123,
                min_size=123
            ),
            tags=tags,
            taints=[eks.CfnNodegroup.TaintProperty(
                effect="effect",
                key="key",
                value="value"
            )],
            update_config=eks.CfnNodegroup.UpdateConfigProperty(
                max_unavailable=123,
                max_unavailable_percentage=123
            ),
            version="version"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster_name: builtins.str,
        node_role: builtins.str,
        subnets: typing.Sequence[builtins.str],
        ami_type: typing.Optional[builtins.str] = None,
        capacity_type: typing.Optional[builtins.str] = None,
        disk_size: typing.Optional[jsii.Number] = None,
        force_update_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        instance_types: typing.Optional[typing.Sequence[builtins.str]] = None,
        labels: typing.Any = None,
        launch_template: typing.Optional[typing.Union["CfnNodegroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]] = None,
        nodegroup_name: typing.Optional[builtins.str] = None,
        release_version: typing.Optional[builtins.str] = None,
        remote_access: typing.Optional[typing.Union["CfnNodegroup.RemoteAccessProperty", _IResolvable_da3f097b]] = None,
        scaling_config: typing.Optional[typing.Union["CfnNodegroup.ScalingConfigProperty", _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
        taints: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union["CfnNodegroup.TaintProperty", _IResolvable_da3f097b]]]] = None,
        update_config: typing.Optional[typing.Union["CfnNodegroup.UpdateConfigProperty", _IResolvable_da3f097b]] = None,
        version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Create a new ``AWS::EKS::Nodegroup``.

        :param scope: - scope in which this resource is defined.
        :param id: - scoped id of the resource.
        :param cluster_name: The name of the cluster to create the node group in.
        :param node_role: The Amazon Resource Name (ARN) of the IAM role to associate with your node group. The Amazon EKS worker node ``kubelet`` daemon makes calls to AWS APIs on your behalf. Nodes receive permissions for these API calls through an IAM instance profile and associated policies. Before you can launch nodes and register them into a cluster, you must create an IAM role for those nodes to use when they are launched. For more information, see `Amazon EKS node IAM role <https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html>`_ in the **Amazon EKS User Guide** . If you specify ``launchTemplate`` , then don't specify ```IamInstanceProfile`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IamInstanceProfile.html>`_ in your launch template, or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param subnets: The subnets to use for the Auto Scaling group that is created for your node group. If you specify ``launchTemplate`` , then don't specify ```SubnetId`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkInterface.html>`_ in your launch template, or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param ami_type: The AMI type for your node group. GPU instance types should use the ``AL2_x86_64_GPU`` AMI type. Non-GPU instances should use the ``AL2_x86_64`` AMI type. Arm instances should use the ``AL2_ARM_64`` AMI type. All types use the Amazon EKS optimized Amazon Linux 2 AMI. If you specify ``launchTemplate`` , and your launch template uses a custom AMI, then don't specify ``amiType`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param capacity_type: The capacity type of your managed node group.
        :param disk_size: The root device disk size (in GiB) for your node group instances. The default disk size is 20 GiB. If you specify ``launchTemplate`` , then don't specify ``diskSize`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param force_update_enabled: Force the update if the existing node group's pods are unable to be drained due to a pod disruption budget issue. If an update fails because pods could not be drained, you can force the update after it fails to terminate the old node whether or not any pods are running on the node.
        :param instance_types: Specify the instance types for a node group. If you specify a GPU instance type, be sure to specify ``AL2_x86_64_GPU`` with the ``amiType`` parameter. If you specify ``launchTemplate`` , then you can specify zero or one instance type in your launch template *or* you can specify 0-20 instance types for ``instanceTypes`` . If however, you specify an instance type in your launch template *and* specify any ``instanceTypes`` , the node group deployment will fail. If you don't specify an instance type in a launch template or for ``instanceTypes`` , then ``t3.medium`` is used, by default. If you specify ``Spot`` for ``capacityType`` , then we recommend specifying multiple values for ``instanceTypes`` . For more information, see `Managed node group capacity types <https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html#managed-node-group-capacity-types>`_ and `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param labels: The Kubernetes labels to be applied to the nodes in the node group when they are created.
        :param launch_template: An object representing a node group's launch template specification. If specified, then do not specify ``instanceTypes`` , ``diskSize`` , or ``remoteAccess`` and make sure that the launch template meets the requirements in ``launchTemplateSpecification`` .
        :param nodegroup_name: The unique name to give your node group.
        :param release_version: The AMI version of the Amazon EKS optimized AMI to use with your node group (for example, ``1.14.7- *YYYYMMDD*`` ). By default, the latest available AMI version for the node group's current Kubernetes version is used. For more information, see `Amazon EKS optimized Linux AMI Versions <https://docs.aws.amazon.com/eks/latest/userguide/eks-linux-ami-versions.html>`_ in the *Amazon EKS User Guide* . .. epigraph:: Changing this value triggers an update of the node group if one is available. However, only the latest available AMI release version is valid as an input. You cannot roll back to a previous AMI release version.
        :param remote_access: The remote access (SSH) configuration to use with your node group. If you specify ``launchTemplate`` , then don't specify ``remoteAccess`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param scaling_config: The scaling configuration details for the Auto Scaling group that is created for your node group.
        :param tags: The metadata to apply to the node group to assist with categorization and organization. Each tag consists of a key and an optional value. You define both. Node group tags do not propagate to any other resources associated with the node group, such as the Amazon EC2 instances or subnets.
        :param taints: The Kubernetes taints to be applied to the nodes in the node group when they are created. Effect is one of ``No_Schedule`` , ``Prefer_No_Schedule`` , or ``No_Execute`` . Kubernetes taints can be used together with tolerations to control how workloads are scheduled to your nodes. For more information, see `Node taints on managed node groups <https://docs.aws.amazon.com/eks/latest/userguide/node-taints-managed-node-groups.html>`_ .
        :param update_config: The node group update configuration.
        :param version: The Kubernetes version to use for your managed nodes. By default, the Kubernetes version of the cluster is used, and this is the only accepted specified value. If you specify ``launchTemplate`` , and your launch template uses a custom AMI, then don't specify ``version`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        '''
        props = CfnNodegroupProps(
            cluster_name=cluster_name,
            node_role=node_role,
            subnets=subnets,
            ami_type=ami_type,
            capacity_type=capacity_type,
            disk_size=disk_size,
            force_update_enabled=force_update_enabled,
            instance_types=instance_types,
            labels=labels,
            launch_template=launch_template,
            nodegroup_name=nodegroup_name,
            release_version=release_version,
            remote_access=remote_access,
            scaling_config=scaling_config,
            tags=tags,
            taints=taints,
            update_config=update_config,
            version=version,
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
        '''The Amazon Resource Name (ARN) associated with the managed node group.

        :cloudformationAttribute: Arn
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrClusterName")
    def attr_cluster_name(self) -> builtins.str:
        '''The name of the cluster that the managed node group resides in.

        :cloudformationAttribute: ClusterName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrClusterName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrId")
    def attr_id(self) -> builtins.str:
        '''
        :cloudformationAttribute: Id
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="attrNodegroupName")
    def attr_nodegroup_name(self) -> builtins.str:
        '''The name associated with an Amazon EKS managed node group.

        :cloudformationAttribute: NodegroupName
        '''
        return typing.cast(builtins.str, jsii.get(self, "attrNodegroupName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cfnProperties")
    def _cfn_properties(self) -> typing.Mapping[builtins.str, typing.Any]:
        return typing.cast(typing.Mapping[builtins.str, typing.Any], jsii.get(self, "cfnProperties"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''The metadata to apply to the node group to assist with categorization and organization.

        Each tag consists of a key and an optional value. You define both. Node group tags do not propagate to any other resources associated with the node group, such as the Amazon EC2 instances or subnets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-tags
        '''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterName")
    def cluster_name(self) -> builtins.str:
        '''The name of the cluster to create the node group in.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-clustername
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterName"))

    @cluster_name.setter
    def cluster_name(self, value: builtins.str) -> None:
        jsii.set(self, "clusterName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="labels")
    def labels(self) -> typing.Any:
        '''The Kubernetes labels to be applied to the nodes in the node group when they are created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-labels
        '''
        return typing.cast(typing.Any, jsii.get(self, "labels"))

    @labels.setter
    def labels(self, value: typing.Any) -> None:
        jsii.set(self, "labels", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="nodeRole")
    def node_role(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role to associate with your node group.

        The Amazon EKS worker node ``kubelet`` daemon makes calls to AWS APIs on your behalf. Nodes receive permissions for these API calls through an IAM instance profile and associated policies. Before you can launch nodes and register them into a cluster, you must create an IAM role for those nodes to use when they are launched. For more information, see `Amazon EKS node IAM role <https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html>`_ in the **Amazon EKS User Guide** . If you specify ``launchTemplate`` , then don't specify ```IamInstanceProfile`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IamInstanceProfile.html>`_ in your launch template, or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-noderole
        '''
        return typing.cast(builtins.str, jsii.get(self, "nodeRole"))

    @node_role.setter
    def node_role(self, value: builtins.str) -> None:
        jsii.set(self, "nodeRole", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="subnets")
    def subnets(self) -> typing.List[builtins.str]:
        '''The subnets to use for the Auto Scaling group that is created for your node group.

        If you specify ``launchTemplate`` , then don't specify ```SubnetId`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkInterface.html>`_ in your launch template, or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-subnets
        '''
        return typing.cast(typing.List[builtins.str], jsii.get(self, "subnets"))

    @subnets.setter
    def subnets(self, value: typing.List[builtins.str]) -> None:
        jsii.set(self, "subnets", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="amiType")
    def ami_type(self) -> typing.Optional[builtins.str]:
        '''The AMI type for your node group.

        GPU instance types should use the ``AL2_x86_64_GPU`` AMI type. Non-GPU instances should use the ``AL2_x86_64`` AMI type. Arm instances should use the ``AL2_ARM_64`` AMI type. All types use the Amazon EKS optimized Amazon Linux 2 AMI. If you specify ``launchTemplate`` , and your launch template uses a custom AMI, then don't specify ``amiType`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-amitype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "amiType"))

    @ami_type.setter
    def ami_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "amiType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="capacityType")
    def capacity_type(self) -> typing.Optional[builtins.str]:
        '''The capacity type of your managed node group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-capacitytype
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "capacityType"))

    @capacity_type.setter
    def capacity_type(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "capacityType", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="diskSize")
    def disk_size(self) -> typing.Optional[jsii.Number]:
        '''The root device disk size (in GiB) for your node group instances.

        The default disk size is 20 GiB. If you specify ``launchTemplate`` , then don't specify ``diskSize`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-disksize
        '''
        return typing.cast(typing.Optional[jsii.Number], jsii.get(self, "diskSize"))

    @disk_size.setter
    def disk_size(self, value: typing.Optional[jsii.Number]) -> None:
        jsii.set(self, "diskSize", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="forceUpdateEnabled")
    def force_update_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Force the update if the existing node group's pods are unable to be drained due to a pod disruption budget issue.

        If an update fails because pods could not be drained, you can force the update after it fails to terminate the old node whether or not any pods are running on the node.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-forceupdateenabled
        '''
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], jsii.get(self, "forceUpdateEnabled"))

    @force_update_enabled.setter
    def force_update_enabled(
        self,
        value: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "forceUpdateEnabled", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="instanceTypes")
    def instance_types(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Specify the instance types for a node group.

        If you specify a GPU instance type, be sure to specify ``AL2_x86_64_GPU`` with the ``amiType`` parameter. If you specify ``launchTemplate`` , then you can specify zero or one instance type in your launch template *or* you can specify 0-20 instance types for ``instanceTypes`` . If however, you specify an instance type in your launch template *and* specify any ``instanceTypes`` , the node group deployment will fail. If you don't specify an instance type in a launch template or for ``instanceTypes`` , then ``t3.medium`` is used, by default. If you specify ``Spot`` for ``capacityType`` , then we recommend specifying multiple values for ``instanceTypes`` . For more information, see `Managed node group capacity types <https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html#managed-node-group-capacity-types>`_ and `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-instancetypes
        '''
        return typing.cast(typing.Optional[typing.List[builtins.str]], jsii.get(self, "instanceTypes"))

    @instance_types.setter
    def instance_types(self, value: typing.Optional[typing.List[builtins.str]]) -> None:
        jsii.set(self, "instanceTypes", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="launchTemplate")
    def launch_template(
        self,
    ) -> typing.Optional[typing.Union["CfnNodegroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]]:
        '''An object representing a node group's launch template specification.

        If specified, then do not specify ``instanceTypes`` , ``diskSize`` , or ``remoteAccess`` and make sure that the launch template meets the requirements in ``launchTemplateSpecification`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-launchtemplate
        '''
        return typing.cast(typing.Optional[typing.Union["CfnNodegroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]], jsii.get(self, "launchTemplate"))

    @launch_template.setter
    def launch_template(
        self,
        value: typing.Optional[typing.Union["CfnNodegroup.LaunchTemplateSpecificationProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "launchTemplate", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="nodegroupName")
    def nodegroup_name(self) -> typing.Optional[builtins.str]:
        '''The unique name to give your node group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-nodegroupname
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "nodegroupName"))

    @nodegroup_name.setter
    def nodegroup_name(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "nodegroupName", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="releaseVersion")
    def release_version(self) -> typing.Optional[builtins.str]:
        '''The AMI version of the Amazon EKS optimized AMI to use with your node group (for example, ``1.14.7- *YYYYMMDD*`` ). By default, the latest available AMI version for the node group's current Kubernetes version is used. For more information, see `Amazon EKS optimized Linux AMI Versions <https://docs.aws.amazon.com/eks/latest/userguide/eks-linux-ami-versions.html>`_ in the *Amazon EKS User Guide* .

        .. epigraph::

           Changing this value triggers an update of the node group if one is available. However, only the latest available AMI release version is valid as an input. You cannot roll back to a previous AMI release version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-releaseversion
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "releaseVersion"))

    @release_version.setter
    def release_version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "releaseVersion", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="remoteAccess")
    def remote_access(
        self,
    ) -> typing.Optional[typing.Union["CfnNodegroup.RemoteAccessProperty", _IResolvable_da3f097b]]:
        '''The remote access (SSH) configuration to use with your node group.

        If you specify ``launchTemplate`` , then don't specify ``remoteAccess`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-remoteaccess
        '''
        return typing.cast(typing.Optional[typing.Union["CfnNodegroup.RemoteAccessProperty", _IResolvable_da3f097b]], jsii.get(self, "remoteAccess"))

    @remote_access.setter
    def remote_access(
        self,
        value: typing.Optional[typing.Union["CfnNodegroup.RemoteAccessProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "remoteAccess", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="scalingConfig")
    def scaling_config(
        self,
    ) -> typing.Optional[typing.Union["CfnNodegroup.ScalingConfigProperty", _IResolvable_da3f097b]]:
        '''The scaling configuration details for the Auto Scaling group that is created for your node group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-scalingconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnNodegroup.ScalingConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "scalingConfig"))

    @scaling_config.setter
    def scaling_config(
        self,
        value: typing.Optional[typing.Union["CfnNodegroup.ScalingConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "scalingConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="taints")
    def taints(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnNodegroup.TaintProperty", _IResolvable_da3f097b]]]]:
        '''The Kubernetes taints to be applied to the nodes in the node group when they are created.

        Effect is one of ``No_Schedule`` , ``Prefer_No_Schedule`` , or ``No_Execute`` . Kubernetes taints can be used together with tolerations to control how workloads are scheduled to your nodes. For more information, see `Node taints on managed node groups <https://docs.aws.amazon.com/eks/latest/userguide/node-taints-managed-node-groups.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-taints
        '''
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnNodegroup.TaintProperty", _IResolvable_da3f097b]]]], jsii.get(self, "taints"))

    @taints.setter
    def taints(
        self,
        value: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union["CfnNodegroup.TaintProperty", _IResolvable_da3f097b]]]],
    ) -> None:
        jsii.set(self, "taints", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="updateConfig")
    def update_config(
        self,
    ) -> typing.Optional[typing.Union["CfnNodegroup.UpdateConfigProperty", _IResolvable_da3f097b]]:
        '''The node group update configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-updateconfig
        '''
        return typing.cast(typing.Optional[typing.Union["CfnNodegroup.UpdateConfigProperty", _IResolvable_da3f097b]], jsii.get(self, "updateConfig"))

    @update_config.setter
    def update_config(
        self,
        value: typing.Optional[typing.Union["CfnNodegroup.UpdateConfigProperty", _IResolvable_da3f097b]],
    ) -> None:
        jsii.set(self, "updateConfig", value)

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="version")
    def version(self) -> typing.Optional[builtins.str]:
        '''The Kubernetes version to use for your managed nodes.

        By default, the Kubernetes version of the cluster is used, and this is the only accepted specified value. If you specify ``launchTemplate`` , and your launch template uses a custom AMI, then don't specify ``version`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-version
        '''
        return typing.cast(typing.Optional[builtins.str], jsii.get(self, "version"))

    @version.setter
    def version(self, value: typing.Optional[builtins.str]) -> None:
        jsii.set(self, "version", value)

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnNodegroup.LaunchTemplateSpecificationProperty",
        jsii_struct_bases=[],
        name_mapping={"id": "id", "name": "name", "version": "version"},
    )
    class LaunchTemplateSpecificationProperty:
        def __init__(
            self,
            *,
            id: typing.Optional[builtins.str] = None,
            name: typing.Optional[builtins.str] = None,
            version: typing.Optional[builtins.str] = None,
        ) -> None:
            '''An object representing a node group launch template specification.

            The launch template cannot include ```SubnetId`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkInterface.html>`_ , ```IamInstanceProfile`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IamInstanceProfile.html>`_ , ```RequestSpotInstances`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RequestSpotInstances.html>`_ , ```HibernationOptions`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_HibernationOptionsRequest.html>`_ , or ```TerminateInstances`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_TerminateInstances.html>`_ , or the node group deployment or update will fail. For more information about launch templates, see ```CreateLaunchTemplate`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateLaunchTemplate.html>`_ in the Amazon EC2 API Reference. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

            Specify either ``name`` or ``id`` , but not both.

            :param id: The ID of the launch template.
            :param name: The name of the launch template.
            :param version: The version of the launch template to use. If no version is specified, then the template's default version is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-launchtemplatespecification.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                launch_template_specification_property = eks.CfnNodegroup.LaunchTemplateSpecificationProperty(
                    id="id",
                    name="name",
                    version="version"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if id is not None:
                self._values["id"] = id
            if name is not None:
                self._values["name"] = name
            if version is not None:
                self._values["version"] = version

        @builtins.property
        def id(self) -> typing.Optional[builtins.str]:
            '''The ID of the launch template.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-launchtemplatespecification.html#cfn-eks-nodegroup-launchtemplatespecification-id
            '''
            result = self._values.get("id")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def name(self) -> typing.Optional[builtins.str]:
            '''The name of the launch template.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-launchtemplatespecification.html#cfn-eks-nodegroup-launchtemplatespecification-name
            '''
            result = self._values.get("name")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def version(self) -> typing.Optional[builtins.str]:
            '''The version of the launch template to use.

            If no version is specified, then the template's default version is used.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-launchtemplatespecification.html#cfn-eks-nodegroup-launchtemplatespecification-version
            '''
            result = self._values.get("version")
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
        jsii_type="aws-cdk-lib.aws_eks.CfnNodegroup.RemoteAccessProperty",
        jsii_struct_bases=[],
        name_mapping={
            "ec2_ssh_key": "ec2SshKey",
            "source_security_groups": "sourceSecurityGroups",
        },
    )
    class RemoteAccessProperty:
        def __init__(
            self,
            *,
            ec2_ssh_key: builtins.str,
            source_security_groups: typing.Optional[typing.Sequence[builtins.str]] = None,
        ) -> None:
            '''An object representing the remote access configuration for the managed node group.

            :param ec2_ssh_key: The Amazon EC2 SSH key that provides access for SSH communication with the nodes in the managed node group. For more information, see `Amazon EC2 key pairs and Linux instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html>`_ in the *Amazon Elastic Compute Cloud User Guide for Linux Instances* .
            :param source_security_groups: The security groups that are allowed SSH access (port 22) to the nodes. If you specify an Amazon EC2 SSH key but do not specify a source security group when you create a managed node group, then port 22 on the nodes is opened to the internet (0.0.0.0/0). For more information, see `Security Groups for Your VPC <https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html>`_ in the *Amazon Virtual Private Cloud User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-remoteaccess.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                remote_access_property = eks.CfnNodegroup.RemoteAccessProperty(
                    ec2_ssh_key="ec2SshKey",
                
                    # the properties below are optional
                    source_security_groups=["sourceSecurityGroups"]
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {
                "ec2_ssh_key": ec2_ssh_key,
            }
            if source_security_groups is not None:
                self._values["source_security_groups"] = source_security_groups

        @builtins.property
        def ec2_ssh_key(self) -> builtins.str:
            '''The Amazon EC2 SSH key that provides access for SSH communication with the nodes in the managed node group.

            For more information, see `Amazon EC2 key pairs and Linux instances <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html>`_ in the *Amazon Elastic Compute Cloud User Guide for Linux Instances* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-remoteaccess.html#cfn-eks-nodegroup-remoteaccess-ec2sshkey
            '''
            result = self._values.get("ec2_ssh_key")
            assert result is not None, "Required property 'ec2_ssh_key' is missing"
            return typing.cast(builtins.str, result)

        @builtins.property
        def source_security_groups(self) -> typing.Optional[typing.List[builtins.str]]:
            '''The security groups that are allowed SSH access (port 22) to the nodes.

            If you specify an Amazon EC2 SSH key but do not specify a source security group when you create a managed node group, then port 22 on the nodes is opened to the internet (0.0.0.0/0). For more information, see `Security Groups for Your VPC <https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html>`_ in the *Amazon Virtual Private Cloud User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-remoteaccess.html#cfn-eks-nodegroup-remoteaccess-sourcesecuritygroups
            '''
            result = self._values.get("source_security_groups")
            return typing.cast(typing.Optional[typing.List[builtins.str]], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "RemoteAccessProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnNodegroup.ScalingConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "desired_size": "desiredSize",
            "max_size": "maxSize",
            "min_size": "minSize",
        },
    )
    class ScalingConfigProperty:
        def __init__(
            self,
            *,
            desired_size: typing.Optional[jsii.Number] = None,
            max_size: typing.Optional[jsii.Number] = None,
            min_size: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''An object representing the scaling configuration details for the Auto Scaling group that is associated with your node group.

            When creating a node group, you must specify all or none of the properties. When updating a node group, you can specify any or none of the properties.

            :param desired_size: The current number of nodes that the managed node group should maintain. .. epigraph:: If you use Cluster Autoscaler, you shouldn't change the desiredSize value directly, as this can cause the Cluster Autoscaler to suddenly scale up or scale down. Whenever this parameter changes, the number of worker nodes in the node group is updated to the specified size. If this parameter is given a value that is smaller than the current number of running worker nodes, the necessary number of worker nodes are terminated to match the given value. When using CloudFormation, no action occurs if you remove this parameter from your CFN template. This parameter can be different from minSize in some cases, such as when starting with extra hosts for testing. This parameter can also be different when you want to start with an estimated number of needed hosts, but let Cluster Autoscaler reduce the number if there are too many. When Cluster Autoscaler is used, the desiredSize parameter is altered by Cluster Autoscaler (but can be out-of-date for short periods of time). Cluster Autoscaler doesn't scale a managed node group lower than minSize or higher than maxSize.
            :param max_size: The maximum number of nodes that the managed node group can scale out to. For information about the maximum number that you can specify, see `Amazon EKS service quotas <https://docs.aws.amazon.com/eks/latest/userguide/service-quotas.html>`_ in the *Amazon EKS User Guide* .
            :param min_size: The minimum number of nodes that the managed node group can scale in to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-scalingconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                scaling_config_property = eks.CfnNodegroup.ScalingConfigProperty(
                    desired_size=123,
                    max_size=123,
                    min_size=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if desired_size is not None:
                self._values["desired_size"] = desired_size
            if max_size is not None:
                self._values["max_size"] = max_size
            if min_size is not None:
                self._values["min_size"] = min_size

        @builtins.property
        def desired_size(self) -> typing.Optional[jsii.Number]:
            '''The current number of nodes that the managed node group should maintain.

            .. epigraph::

               If you use Cluster Autoscaler, you shouldn't change the desiredSize value directly, as this can cause the Cluster Autoscaler to suddenly scale up or scale down.

            Whenever this parameter changes, the number of worker nodes in the node group is updated to the specified size. If this parameter is given a value that is smaller than the current number of running worker nodes, the necessary number of worker nodes are terminated to match the given value. When using CloudFormation, no action occurs if you remove this parameter from your CFN template.

            This parameter can be different from minSize in some cases, such as when starting with extra hosts for testing. This parameter can also be different when you want to start with an estimated number of needed hosts, but let Cluster Autoscaler reduce the number if there are too many. When Cluster Autoscaler is used, the desiredSize parameter is altered by Cluster Autoscaler (but can be out-of-date for short periods of time). Cluster Autoscaler doesn't scale a managed node group lower than minSize or higher than maxSize.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-scalingconfig.html#cfn-eks-nodegroup-scalingconfig-desiredsize
            '''
            result = self._values.get("desired_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def max_size(self) -> typing.Optional[jsii.Number]:
            '''The maximum number of nodes that the managed node group can scale out to.

            For information about the maximum number that you can specify, see `Amazon EKS service quotas <https://docs.aws.amazon.com/eks/latest/userguide/service-quotas.html>`_ in the *Amazon EKS User Guide* .

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-scalingconfig.html#cfn-eks-nodegroup-scalingconfig-maxsize
            '''
            result = self._values.get("max_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def min_size(self) -> typing.Optional[jsii.Number]:
            '''The minimum number of nodes that the managed node group can scale in to.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-scalingconfig.html#cfn-eks-nodegroup-scalingconfig-minsize
            '''
            result = self._values.get("min_size")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "ScalingConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnNodegroup.TaintProperty",
        jsii_struct_bases=[],
        name_mapping={"effect": "effect", "key": "key", "value": "value"},
    )
    class TaintProperty:
        def __init__(
            self,
            *,
            effect: typing.Optional[builtins.str] = None,
            key: typing.Optional[builtins.str] = None,
            value: typing.Optional[builtins.str] = None,
        ) -> None:
            '''A property that allows a node to repel a set of pods.

            For more information, see `Node taints on managed node groups <https://docs.aws.amazon.com/eks/latest/userguide/node-taints-managed-node-groups.html>`_ .

            :param effect: The effect of the taint.
            :param key: The key of the taint.
            :param value: The value of the taint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-taint.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                taint_property = eks.CfnNodegroup.TaintProperty(
                    effect="effect",
                    key="key",
                    value="value"
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if effect is not None:
                self._values["effect"] = effect
            if key is not None:
                self._values["key"] = key
            if value is not None:
                self._values["value"] = value

        @builtins.property
        def effect(self) -> typing.Optional[builtins.str]:
            '''The effect of the taint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-taint.html#cfn-eks-nodegroup-taint-effect
            '''
            result = self._values.get("effect")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def key(self) -> typing.Optional[builtins.str]:
            '''The key of the taint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-taint.html#cfn-eks-nodegroup-taint-key
            '''
            result = self._values.get("key")
            return typing.cast(typing.Optional[builtins.str], result)

        @builtins.property
        def value(self) -> typing.Optional[builtins.str]:
            '''The value of the taint.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-taint.html#cfn-eks-nodegroup-taint-value
            '''
            result = self._values.get("value")
            return typing.cast(typing.Optional[builtins.str], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "TaintProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )

    @jsii.data_type(
        jsii_type="aws-cdk-lib.aws_eks.CfnNodegroup.UpdateConfigProperty",
        jsii_struct_bases=[],
        name_mapping={
            "max_unavailable": "maxUnavailable",
            "max_unavailable_percentage": "maxUnavailablePercentage",
        },
    )
    class UpdateConfigProperty:
        def __init__(
            self,
            *,
            max_unavailable: typing.Optional[jsii.Number] = None,
            max_unavailable_percentage: typing.Optional[jsii.Number] = None,
        ) -> None:
            '''The update configuration for the node group.

            :param max_unavailable: The maximum number of nodes unavailable at once during a version update. Nodes will be updated in parallel. This value or ``maxUnavailablePercentage`` is required to have a value.The maximum number is 100.
            :param max_unavailable_percentage: The maximum percentage of nodes unavailable during a version update. This percentage of nodes will be updated in parallel, up to 100 nodes at once. This value or ``maxUnavailable`` is required to have a value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-updateconfig.html
            :exampleMetadata: fixture=_generated

            Example::

                # The code below shows an example of how to instantiate this type.
                # The values are placeholders you should change.
                from aws_cdk import aws_eks as eks
                
                update_config_property = eks.CfnNodegroup.UpdateConfigProperty(
                    max_unavailable=123,
                    max_unavailable_percentage=123
                )
            '''
            self._values: typing.Dict[str, typing.Any] = {}
            if max_unavailable is not None:
                self._values["max_unavailable"] = max_unavailable
            if max_unavailable_percentage is not None:
                self._values["max_unavailable_percentage"] = max_unavailable_percentage

        @builtins.property
        def max_unavailable(self) -> typing.Optional[jsii.Number]:
            '''The maximum number of nodes unavailable at once during a version update.

            Nodes will be updated in parallel. This value or ``maxUnavailablePercentage`` is required to have a value.The maximum number is 100.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-updateconfig.html#cfn-eks-nodegroup-updateconfig-maxunavailable
            '''
            result = self._values.get("max_unavailable")
            return typing.cast(typing.Optional[jsii.Number], result)

        @builtins.property
        def max_unavailable_percentage(self) -> typing.Optional[jsii.Number]:
            '''The maximum percentage of nodes unavailable during a version update.

            This percentage of nodes will be updated in parallel, up to 100 nodes at once. This value or ``maxUnavailable`` is required to have a value.

            :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-updateconfig.html#cfn-eks-nodegroup-updateconfig-maxunavailablepercentage
            '''
            result = self._values.get("max_unavailable_percentage")
            return typing.cast(typing.Optional[jsii.Number], result)

        def __eq__(self, rhs: typing.Any) -> builtins.bool:
            return isinstance(rhs, self.__class__) and rhs._values == self._values

        def __ne__(self, rhs: typing.Any) -> builtins.bool:
            return not (rhs == self)

        def __repr__(self) -> str:
            return "UpdateConfigProperty(%s)" % ", ".join(
                k + "=" + repr(v) for k, v in self._values.items()
            )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.CfnNodegroupProps",
    jsii_struct_bases=[],
    name_mapping={
        "cluster_name": "clusterName",
        "node_role": "nodeRole",
        "subnets": "subnets",
        "ami_type": "amiType",
        "capacity_type": "capacityType",
        "disk_size": "diskSize",
        "force_update_enabled": "forceUpdateEnabled",
        "instance_types": "instanceTypes",
        "labels": "labels",
        "launch_template": "launchTemplate",
        "nodegroup_name": "nodegroupName",
        "release_version": "releaseVersion",
        "remote_access": "remoteAccess",
        "scaling_config": "scalingConfig",
        "tags": "tags",
        "taints": "taints",
        "update_config": "updateConfig",
        "version": "version",
    },
)
class CfnNodegroupProps:
    def __init__(
        self,
        *,
        cluster_name: builtins.str,
        node_role: builtins.str,
        subnets: typing.Sequence[builtins.str],
        ami_type: typing.Optional[builtins.str] = None,
        capacity_type: typing.Optional[builtins.str] = None,
        disk_size: typing.Optional[jsii.Number] = None,
        force_update_enabled: typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]] = None,
        instance_types: typing.Optional[typing.Sequence[builtins.str]] = None,
        labels: typing.Any = None,
        launch_template: typing.Optional[typing.Union[CfnNodegroup.LaunchTemplateSpecificationProperty, _IResolvable_da3f097b]] = None,
        nodegroup_name: typing.Optional[builtins.str] = None,
        release_version: typing.Optional[builtins.str] = None,
        remote_access: typing.Optional[typing.Union[CfnNodegroup.RemoteAccessProperty, _IResolvable_da3f097b]] = None,
        scaling_config: typing.Optional[typing.Union[CfnNodegroup.ScalingConfigProperty, _IResolvable_da3f097b]] = None,
        tags: typing.Any = None,
        taints: typing.Optional[typing.Union[_IResolvable_da3f097b, typing.Sequence[typing.Union[CfnNodegroup.TaintProperty, _IResolvable_da3f097b]]]] = None,
        update_config: typing.Optional[typing.Union[CfnNodegroup.UpdateConfigProperty, _IResolvable_da3f097b]] = None,
        version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for defining a ``CfnNodegroup``.

        :param cluster_name: The name of the cluster to create the node group in.
        :param node_role: The Amazon Resource Name (ARN) of the IAM role to associate with your node group. The Amazon EKS worker node ``kubelet`` daemon makes calls to AWS APIs on your behalf. Nodes receive permissions for these API calls through an IAM instance profile and associated policies. Before you can launch nodes and register them into a cluster, you must create an IAM role for those nodes to use when they are launched. For more information, see `Amazon EKS node IAM role <https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html>`_ in the **Amazon EKS User Guide** . If you specify ``launchTemplate`` , then don't specify ```IamInstanceProfile`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IamInstanceProfile.html>`_ in your launch template, or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param subnets: The subnets to use for the Auto Scaling group that is created for your node group. If you specify ``launchTemplate`` , then don't specify ```SubnetId`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkInterface.html>`_ in your launch template, or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param ami_type: The AMI type for your node group. GPU instance types should use the ``AL2_x86_64_GPU`` AMI type. Non-GPU instances should use the ``AL2_x86_64`` AMI type. Arm instances should use the ``AL2_ARM_64`` AMI type. All types use the Amazon EKS optimized Amazon Linux 2 AMI. If you specify ``launchTemplate`` , and your launch template uses a custom AMI, then don't specify ``amiType`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param capacity_type: The capacity type of your managed node group.
        :param disk_size: The root device disk size (in GiB) for your node group instances. The default disk size is 20 GiB. If you specify ``launchTemplate`` , then don't specify ``diskSize`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param force_update_enabled: Force the update if the existing node group's pods are unable to be drained due to a pod disruption budget issue. If an update fails because pods could not be drained, you can force the update after it fails to terminate the old node whether or not any pods are running on the node.
        :param instance_types: Specify the instance types for a node group. If you specify a GPU instance type, be sure to specify ``AL2_x86_64_GPU`` with the ``amiType`` parameter. If you specify ``launchTemplate`` , then you can specify zero or one instance type in your launch template *or* you can specify 0-20 instance types for ``instanceTypes`` . If however, you specify an instance type in your launch template *and* specify any ``instanceTypes`` , the node group deployment will fail. If you don't specify an instance type in a launch template or for ``instanceTypes`` , then ``t3.medium`` is used, by default. If you specify ``Spot`` for ``capacityType`` , then we recommend specifying multiple values for ``instanceTypes`` . For more information, see `Managed node group capacity types <https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html#managed-node-group-capacity-types>`_ and `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param labels: The Kubernetes labels to be applied to the nodes in the node group when they are created.
        :param launch_template: An object representing a node group's launch template specification. If specified, then do not specify ``instanceTypes`` , ``diskSize`` , or ``remoteAccess`` and make sure that the launch template meets the requirements in ``launchTemplateSpecification`` .
        :param nodegroup_name: The unique name to give your node group.
        :param release_version: The AMI version of the Amazon EKS optimized AMI to use with your node group (for example, ``1.14.7- *YYYYMMDD*`` ). By default, the latest available AMI version for the node group's current Kubernetes version is used. For more information, see `Amazon EKS optimized Linux AMI Versions <https://docs.aws.amazon.com/eks/latest/userguide/eks-linux-ami-versions.html>`_ in the *Amazon EKS User Guide* . .. epigraph:: Changing this value triggers an update of the node group if one is available. However, only the latest available AMI release version is valid as an input. You cannot roll back to a previous AMI release version.
        :param remote_access: The remote access (SSH) configuration to use with your node group. If you specify ``launchTemplate`` , then don't specify ``remoteAccess`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .
        :param scaling_config: The scaling configuration details for the Auto Scaling group that is created for your node group.
        :param tags: The metadata to apply to the node group to assist with categorization and organization. Each tag consists of a key and an optional value. You define both. Node group tags do not propagate to any other resources associated with the node group, such as the Amazon EC2 instances or subnets.
        :param taints: The Kubernetes taints to be applied to the nodes in the node group when they are created. Effect is one of ``No_Schedule`` , ``Prefer_No_Schedule`` , or ``No_Execute`` . Kubernetes taints can be used together with tolerations to control how workloads are scheduled to your nodes. For more information, see `Node taints on managed node groups <https://docs.aws.amazon.com/eks/latest/userguide/node-taints-managed-node-groups.html>`_ .
        :param update_config: The node group update configuration.
        :param version: The Kubernetes version to use for your managed nodes. By default, the Kubernetes version of the cluster is used, and this is the only accepted specified value. If you specify ``launchTemplate`` , and your launch template uses a custom AMI, then don't specify ``version`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            # labels: Any
            # tags: Any
            
            cfn_nodegroup_props = eks.CfnNodegroupProps(
                cluster_name="clusterName",
                node_role="nodeRole",
                subnets=["subnets"],
            
                # the properties below are optional
                ami_type="amiType",
                capacity_type="capacityType",
                disk_size=123,
                force_update_enabled=False,
                instance_types=["instanceTypes"],
                labels=labels,
                launch_template=eks.CfnNodegroup.LaunchTemplateSpecificationProperty(
                    id="id",
                    name="name",
                    version="version"
                ),
                nodegroup_name="nodegroupName",
                release_version="releaseVersion",
                remote_access=eks.CfnNodegroup.RemoteAccessProperty(
                    ec2_ssh_key="ec2SshKey",
            
                    # the properties below are optional
                    source_security_groups=["sourceSecurityGroups"]
                ),
                scaling_config=eks.CfnNodegroup.ScalingConfigProperty(
                    desired_size=123,
                    max_size=123,
                    min_size=123
                ),
                tags=tags,
                taints=[eks.CfnNodegroup.TaintProperty(
                    effect="effect",
                    key="key",
                    value="value"
                )],
                update_config=eks.CfnNodegroup.UpdateConfigProperty(
                    max_unavailable=123,
                    max_unavailable_percentage=123
                ),
                version="version"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster_name": cluster_name,
            "node_role": node_role,
            "subnets": subnets,
        }
        if ami_type is not None:
            self._values["ami_type"] = ami_type
        if capacity_type is not None:
            self._values["capacity_type"] = capacity_type
        if disk_size is not None:
            self._values["disk_size"] = disk_size
        if force_update_enabled is not None:
            self._values["force_update_enabled"] = force_update_enabled
        if instance_types is not None:
            self._values["instance_types"] = instance_types
        if labels is not None:
            self._values["labels"] = labels
        if launch_template is not None:
            self._values["launch_template"] = launch_template
        if nodegroup_name is not None:
            self._values["nodegroup_name"] = nodegroup_name
        if release_version is not None:
            self._values["release_version"] = release_version
        if remote_access is not None:
            self._values["remote_access"] = remote_access
        if scaling_config is not None:
            self._values["scaling_config"] = scaling_config
        if tags is not None:
            self._values["tags"] = tags
        if taints is not None:
            self._values["taints"] = taints
        if update_config is not None:
            self._values["update_config"] = update_config
        if version is not None:
            self._values["version"] = version

    @builtins.property
    def cluster_name(self) -> builtins.str:
        '''The name of the cluster to create the node group in.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-clustername
        '''
        result = self._values.get("cluster_name")
        assert result is not None, "Required property 'cluster_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def node_role(self) -> builtins.str:
        '''The Amazon Resource Name (ARN) of the IAM role to associate with your node group.

        The Amazon EKS worker node ``kubelet`` daemon makes calls to AWS APIs on your behalf. Nodes receive permissions for these API calls through an IAM instance profile and associated policies. Before you can launch nodes and register them into a cluster, you must create an IAM role for those nodes to use when they are launched. For more information, see `Amazon EKS node IAM role <https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html>`_ in the **Amazon EKS User Guide** . If you specify ``launchTemplate`` , then don't specify ```IamInstanceProfile`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IamInstanceProfile.html>`_ in your launch template, or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-noderole
        '''
        result = self._values.get("node_role")
        assert result is not None, "Required property 'node_role' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def subnets(self) -> typing.List[builtins.str]:
        '''The subnets to use for the Auto Scaling group that is created for your node group.

        If you specify ``launchTemplate`` , then don't specify ```SubnetId`` <https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkInterface.html>`_ in your launch template, or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-subnets
        '''
        result = self._values.get("subnets")
        assert result is not None, "Required property 'subnets' is missing"
        return typing.cast(typing.List[builtins.str], result)

    @builtins.property
    def ami_type(self) -> typing.Optional[builtins.str]:
        '''The AMI type for your node group.

        GPU instance types should use the ``AL2_x86_64_GPU`` AMI type. Non-GPU instances should use the ``AL2_x86_64`` AMI type. Arm instances should use the ``AL2_ARM_64`` AMI type. All types use the Amazon EKS optimized Amazon Linux 2 AMI. If you specify ``launchTemplate`` , and your launch template uses a custom AMI, then don't specify ``amiType`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-amitype
        '''
        result = self._values.get("ami_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def capacity_type(self) -> typing.Optional[builtins.str]:
        '''The capacity type of your managed node group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-capacitytype
        '''
        result = self._values.get("capacity_type")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def disk_size(self) -> typing.Optional[jsii.Number]:
        '''The root device disk size (in GiB) for your node group instances.

        The default disk size is 20 GiB. If you specify ``launchTemplate`` , then don't specify ``diskSize`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-disksize
        '''
        result = self._values.get("disk_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def force_update_enabled(
        self,
    ) -> typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]]:
        '''Force the update if the existing node group's pods are unable to be drained due to a pod disruption budget issue.

        If an update fails because pods could not be drained, you can force the update after it fails to terminate the old node whether or not any pods are running on the node.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-forceupdateenabled
        '''
        result = self._values.get("force_update_enabled")
        return typing.cast(typing.Optional[typing.Union[builtins.bool, _IResolvable_da3f097b]], result)

    @builtins.property
    def instance_types(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Specify the instance types for a node group.

        If you specify a GPU instance type, be sure to specify ``AL2_x86_64_GPU`` with the ``amiType`` parameter. If you specify ``launchTemplate`` , then you can specify zero or one instance type in your launch template *or* you can specify 0-20 instance types for ``instanceTypes`` . If however, you specify an instance type in your launch template *and* specify any ``instanceTypes`` , the node group deployment will fail. If you don't specify an instance type in a launch template or for ``instanceTypes`` , then ``t3.medium`` is used, by default. If you specify ``Spot`` for ``capacityType`` , then we recommend specifying multiple values for ``instanceTypes`` . For more information, see `Managed node group capacity types <https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html#managed-node-group-capacity-types>`_ and `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-instancetypes
        '''
        result = self._values.get("instance_types")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def labels(self) -> typing.Any:
        '''The Kubernetes labels to be applied to the nodes in the node group when they are created.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-labels
        '''
        result = self._values.get("labels")
        return typing.cast(typing.Any, result)

    @builtins.property
    def launch_template(
        self,
    ) -> typing.Optional[typing.Union[CfnNodegroup.LaunchTemplateSpecificationProperty, _IResolvable_da3f097b]]:
        '''An object representing a node group's launch template specification.

        If specified, then do not specify ``instanceTypes`` , ``diskSize`` , or ``remoteAccess`` and make sure that the launch template meets the requirements in ``launchTemplateSpecification`` .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-launchtemplate
        '''
        result = self._values.get("launch_template")
        return typing.cast(typing.Optional[typing.Union[CfnNodegroup.LaunchTemplateSpecificationProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def nodegroup_name(self) -> typing.Optional[builtins.str]:
        '''The unique name to give your node group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-nodegroupname
        '''
        result = self._values.get("nodegroup_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def release_version(self) -> typing.Optional[builtins.str]:
        '''The AMI version of the Amazon EKS optimized AMI to use with your node group (for example, ``1.14.7- *YYYYMMDD*`` ). By default, the latest available AMI version for the node group's current Kubernetes version is used. For more information, see `Amazon EKS optimized Linux AMI Versions <https://docs.aws.amazon.com/eks/latest/userguide/eks-linux-ami-versions.html>`_ in the *Amazon EKS User Guide* .

        .. epigraph::

           Changing this value triggers an update of the node group if one is available. However, only the latest available AMI release version is valid as an input. You cannot roll back to a previous AMI release version.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-releaseversion
        '''
        result = self._values.get("release_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def remote_access(
        self,
    ) -> typing.Optional[typing.Union[CfnNodegroup.RemoteAccessProperty, _IResolvable_da3f097b]]:
        '''The remote access (SSH) configuration to use with your node group.

        If you specify ``launchTemplate`` , then don't specify ``remoteAccess`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-remoteaccess
        '''
        result = self._values.get("remote_access")
        return typing.cast(typing.Optional[typing.Union[CfnNodegroup.RemoteAccessProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def scaling_config(
        self,
    ) -> typing.Optional[typing.Union[CfnNodegroup.ScalingConfigProperty, _IResolvable_da3f097b]]:
        '''The scaling configuration details for the Auto Scaling group that is created for your node group.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-scalingconfig
        '''
        result = self._values.get("scaling_config")
        return typing.cast(typing.Optional[typing.Union[CfnNodegroup.ScalingConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def tags(self) -> typing.Any:
        '''The metadata to apply to the node group to assist with categorization and organization.

        Each tag consists of a key and an optional value. You define both. Node group tags do not propagate to any other resources associated with the node group, such as the Amazon EC2 instances or subnets.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-tags
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Any, result)

    @builtins.property
    def taints(
        self,
    ) -> typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnNodegroup.TaintProperty, _IResolvable_da3f097b]]]]:
        '''The Kubernetes taints to be applied to the nodes in the node group when they are created.

        Effect is one of ``No_Schedule`` , ``Prefer_No_Schedule`` , or ``No_Execute`` . Kubernetes taints can be used together with tolerations to control how workloads are scheduled to your nodes. For more information, see `Node taints on managed node groups <https://docs.aws.amazon.com/eks/latest/userguide/node-taints-managed-node-groups.html>`_ .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-taints
        '''
        result = self._values.get("taints")
        return typing.cast(typing.Optional[typing.Union[_IResolvable_da3f097b, typing.List[typing.Union[CfnNodegroup.TaintProperty, _IResolvable_da3f097b]]]], result)

    @builtins.property
    def update_config(
        self,
    ) -> typing.Optional[typing.Union[CfnNodegroup.UpdateConfigProperty, _IResolvable_da3f097b]]:
        '''The node group update configuration.

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-updateconfig
        '''
        result = self._values.get("update_config")
        return typing.cast(typing.Optional[typing.Union[CfnNodegroup.UpdateConfigProperty, _IResolvable_da3f097b]], result)

    @builtins.property
    def version(self) -> typing.Optional[builtins.str]:
        '''The Kubernetes version to use for your managed nodes.

        By default, the Kubernetes version of the cluster is used, and this is the only accepted specified value. If you specify ``launchTemplate`` , and your launch template uses a custom AMI, then don't specify ``version`` , or the node group deployment will fail. For more information about using launch templates with Amazon EKS, see `Launch template support <https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html>`_ in the *Amazon EKS User Guide* .

        :link: http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-version
        '''
        result = self._values.get("version")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CfnNodegroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.ClusterAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "cluster_name": "clusterName",
        "cluster_certificate_authority_data": "clusterCertificateAuthorityData",
        "cluster_encryption_config_key_arn": "clusterEncryptionConfigKeyArn",
        "cluster_endpoint": "clusterEndpoint",
        "cluster_handler_security_group_id": "clusterHandlerSecurityGroupId",
        "cluster_security_group_id": "clusterSecurityGroupId",
        "kubectl_environment": "kubectlEnvironment",
        "kubectl_lambda_role": "kubectlLambdaRole",
        "kubectl_layer": "kubectlLayer",
        "kubectl_memory": "kubectlMemory",
        "kubectl_private_subnet_ids": "kubectlPrivateSubnetIds",
        "kubectl_provider": "kubectlProvider",
        "kubectl_role_arn": "kubectlRoleArn",
        "kubectl_security_group_id": "kubectlSecurityGroupId",
        "on_event_layer": "onEventLayer",
        "open_id_connect_provider": "openIdConnectProvider",
        "prune": "prune",
        "security_group_ids": "securityGroupIds",
        "vpc": "vpc",
    },
)
class ClusterAttributes:
    def __init__(
        self,
        *,
        cluster_name: builtins.str,
        cluster_certificate_authority_data: typing.Optional[builtins.str] = None,
        cluster_encryption_config_key_arn: typing.Optional[builtins.str] = None,
        cluster_endpoint: typing.Optional[builtins.str] = None,
        cluster_handler_security_group_id: typing.Optional[builtins.str] = None,
        cluster_security_group_id: typing.Optional[builtins.str] = None,
        kubectl_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        kubectl_lambda_role: typing.Optional[_IRole_235f5d8e] = None,
        kubectl_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        kubectl_memory: typing.Optional[_Size_7b441c34] = None,
        kubectl_private_subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        kubectl_provider: typing.Optional["IKubectlProvider"] = None,
        kubectl_role_arn: typing.Optional[builtins.str] = None,
        kubectl_security_group_id: typing.Optional[builtins.str] = None,
        on_event_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        open_id_connect_provider: typing.Optional[_IOpenIdConnectProvider_203f0793] = None,
        prune: typing.Optional[builtins.bool] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> None:
        '''Attributes for EKS clusters.

        :param cluster_name: The physical name of the Cluster.
        :param cluster_certificate_authority_data: The certificate-authority-data for your cluster. Default: - if not specified ``cluster.clusterCertificateAuthorityData`` will throw an error
        :param cluster_encryption_config_key_arn: Amazon Resource Name (ARN) or alias of the customer master key (CMK). Default: - if not specified ``cluster.clusterEncryptionConfigKeyArn`` will throw an error
        :param cluster_endpoint: The API Server endpoint URL. Default: - if not specified ``cluster.clusterEndpoint`` will throw an error.
        :param cluster_handler_security_group_id: A security group id to associate with the Cluster Handler's Lambdas. The Cluster Handler's Lambdas are responsible for calling AWS's EKS API. Default: - No security group.
        :param cluster_security_group_id: The cluster security group that was created by Amazon EKS for the cluster. Default: - if not specified ``cluster.clusterSecurityGroupId`` will throw an error
        :param kubectl_environment: Environment variables to use when running ``kubectl`` against this cluster. Default: - no additional variables
        :param kubectl_lambda_role: An IAM role that can perform kubectl operations against this cluster. The role should be mapped to the ``system:masters`` Kubernetes RBAC role. This role is directly passed to the lambda handler that sends Kube Ctl commands to the cluster. Default: - if not specified, the default role created by a lambda function will be used.
        :param kubectl_layer: An AWS Lambda Layer which includes ``kubectl``, Helm and the AWS CLI. This layer is used by the kubectl handler to apply manifests and install helm charts. The handler expects the layer to include the following executables:: helm/helm kubectl/kubectl awscli/aws Default: - a layer bundled with this module.
        :param kubectl_memory: Amount of memory to allocate to the provider's lambda function. Default: Size.gibibytes(1)
        :param kubectl_private_subnet_ids: Subnets to host the ``kubectl`` compute resources. If not specified, the k8s endpoint is expected to be accessible publicly. Default: - k8s endpoint is expected to be accessible publicly
        :param kubectl_provider: KubectlProvider for issuing kubectl commands. Default: - Default CDK provider
        :param kubectl_role_arn: An IAM role with cluster administrator and "system:masters" permissions. Default: - if not specified, it not be possible to issue ``kubectl`` commands against an imported cluster.
        :param kubectl_security_group_id: A security group to use for ``kubectl`` execution. If not specified, the k8s endpoint is expected to be accessible publicly. Default: - k8s endpoint is expected to be accessible publicly
        :param on_event_layer: An AWS Lambda Layer which includes the NPM dependency ``proxy-agent``. This layer is used by the onEvent handler to route AWS SDK requests through a proxy. The handler expects the layer to include the following node_modules:: proxy-agent Default: - a layer bundled with this module.
        :param open_id_connect_provider: An Open ID Connect provider for this cluster that can be used to configure service accounts. You can either import an existing provider using ``iam.OpenIdConnectProvider.fromProviderArn``, or create a new provider using ``new eks.OpenIdConnectProvider`` Default: - if not specified ``cluster.openIdConnectProvider`` and ``cluster.addServiceAccount`` will throw an error.
        :param prune: Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned. When this is enabled (default), prune labels will be allocated and injected to each resource. These labels will then be used when issuing the ``kubectl apply`` operation with the ``--prune`` switch. Default: true
        :param security_group_ids: Additional security groups associated with this cluster. Default: - if not specified, no additional security groups will be considered in ``cluster.connections``.
        :param vpc: The VPC in which this Cluster was created. Default: - if not specified ``cluster.vpc`` will throw an error

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            # asg: autoscaling.AutoScalingGroup
            
            imported_cluster = eks.Cluster.from_cluster_attributes(self, "ImportedCluster",
                cluster_name=cluster.cluster_name,
                cluster_security_group_id=cluster.cluster_security_group_id
            )
            
            imported_cluster.connect_auto_scaling_group_capacity(asg)
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster_name": cluster_name,
        }
        if cluster_certificate_authority_data is not None:
            self._values["cluster_certificate_authority_data"] = cluster_certificate_authority_data
        if cluster_encryption_config_key_arn is not None:
            self._values["cluster_encryption_config_key_arn"] = cluster_encryption_config_key_arn
        if cluster_endpoint is not None:
            self._values["cluster_endpoint"] = cluster_endpoint
        if cluster_handler_security_group_id is not None:
            self._values["cluster_handler_security_group_id"] = cluster_handler_security_group_id
        if cluster_security_group_id is not None:
            self._values["cluster_security_group_id"] = cluster_security_group_id
        if kubectl_environment is not None:
            self._values["kubectl_environment"] = kubectl_environment
        if kubectl_lambda_role is not None:
            self._values["kubectl_lambda_role"] = kubectl_lambda_role
        if kubectl_layer is not None:
            self._values["kubectl_layer"] = kubectl_layer
        if kubectl_memory is not None:
            self._values["kubectl_memory"] = kubectl_memory
        if kubectl_private_subnet_ids is not None:
            self._values["kubectl_private_subnet_ids"] = kubectl_private_subnet_ids
        if kubectl_provider is not None:
            self._values["kubectl_provider"] = kubectl_provider
        if kubectl_role_arn is not None:
            self._values["kubectl_role_arn"] = kubectl_role_arn
        if kubectl_security_group_id is not None:
            self._values["kubectl_security_group_id"] = kubectl_security_group_id
        if on_event_layer is not None:
            self._values["on_event_layer"] = on_event_layer
        if open_id_connect_provider is not None:
            self._values["open_id_connect_provider"] = open_id_connect_provider
        if prune is not None:
            self._values["prune"] = prune
        if security_group_ids is not None:
            self._values["security_group_ids"] = security_group_ids
        if vpc is not None:
            self._values["vpc"] = vpc

    @builtins.property
    def cluster_name(self) -> builtins.str:
        '''The physical name of the Cluster.'''
        result = self._values.get("cluster_name")
        assert result is not None, "Required property 'cluster_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def cluster_certificate_authority_data(self) -> typing.Optional[builtins.str]:
        '''The certificate-authority-data for your cluster.

        :default:

        - if not specified ``cluster.clusterCertificateAuthorityData`` will
        throw an error
        '''
        result = self._values.get("cluster_certificate_authority_data")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cluster_encryption_config_key_arn(self) -> typing.Optional[builtins.str]:
        '''Amazon Resource Name (ARN) or alias of the customer master key (CMK).

        :default:

        - if not specified ``cluster.clusterEncryptionConfigKeyArn`` will
        throw an error
        '''
        result = self._values.get("cluster_encryption_config_key_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cluster_endpoint(self) -> typing.Optional[builtins.str]:
        '''The API Server endpoint URL.

        :default: - if not specified ``cluster.clusterEndpoint`` will throw an error.
        '''
        result = self._values.get("cluster_endpoint")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cluster_handler_security_group_id(self) -> typing.Optional[builtins.str]:
        '''A security group id to associate with the Cluster Handler's Lambdas.

        The Cluster Handler's Lambdas are responsible for calling AWS's EKS API.

        :default: - No security group.
        '''
        result = self._values.get("cluster_handler_security_group_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cluster_security_group_id(self) -> typing.Optional[builtins.str]:
        '''The cluster security group that was created by Amazon EKS for the cluster.

        :default:

        - if not specified ``cluster.clusterSecurityGroupId`` will throw an
        error
        '''
        result = self._values.get("cluster_security_group_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kubectl_environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Environment variables to use when running ``kubectl`` against this cluster.

        :default: - no additional variables
        '''
        result = self._values.get("kubectl_environment")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def kubectl_lambda_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''An IAM role that can perform kubectl operations against this cluster.

        The role should be mapped to the ``system:masters`` Kubernetes RBAC role.

        This role is directly passed to the lambda handler that sends Kube Ctl commands
        to the cluster.

        :default:

        - if not specified, the default role created by a lambda function will
        be used.
        '''
        result = self._values.get("kubectl_lambda_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def kubectl_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda Layer which includes ``kubectl``, Helm and the AWS CLI.

        This layer
        is used by the kubectl handler to apply manifests and install helm charts.

        The handler expects the layer to include the following executables::

           helm/helm
           kubectl/kubectl
           awscli/aws

        :default: - a layer bundled with this module.
        '''
        result = self._values.get("kubectl_layer")
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], result)

    @builtins.property
    def kubectl_memory(self) -> typing.Optional[_Size_7b441c34]:
        '''Amount of memory to allocate to the provider's lambda function.

        :default: Size.gibibytes(1)
        '''
        result = self._values.get("kubectl_memory")
        return typing.cast(typing.Optional[_Size_7b441c34], result)

    @builtins.property
    def kubectl_private_subnet_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Subnets to host the ``kubectl`` compute resources.

        If not specified, the k8s
        endpoint is expected to be accessible publicly.

        :default: - k8s endpoint is expected to be accessible publicly
        '''
        result = self._values.get("kubectl_private_subnet_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def kubectl_provider(self) -> typing.Optional["IKubectlProvider"]:
        '''KubectlProvider for issuing kubectl commands.

        :default: - Default CDK provider
        '''
        result = self._values.get("kubectl_provider")
        return typing.cast(typing.Optional["IKubectlProvider"], result)

    @builtins.property
    def kubectl_role_arn(self) -> typing.Optional[builtins.str]:
        '''An IAM role with cluster administrator and "system:masters" permissions.

        :default:

        - if not specified, it not be possible to issue ``kubectl`` commands
        against an imported cluster.
        '''
        result = self._values.get("kubectl_role_arn")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def kubectl_security_group_id(self) -> typing.Optional[builtins.str]:
        '''A security group to use for ``kubectl`` execution.

        If not specified, the k8s
        endpoint is expected to be accessible publicly.

        :default: - k8s endpoint is expected to be accessible publicly
        '''
        result = self._values.get("kubectl_security_group_id")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def on_event_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda Layer which includes the NPM dependency ``proxy-agent``.

        This layer
        is used by the onEvent handler to route AWS SDK requests through a proxy.

        The handler expects the layer to include the following node_modules::

           proxy-agent

        :default: - a layer bundled with this module.
        '''
        result = self._values.get("on_event_layer")
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], result)

    @builtins.property
    def open_id_connect_provider(
        self,
    ) -> typing.Optional[_IOpenIdConnectProvider_203f0793]:
        '''An Open ID Connect provider for this cluster that can be used to configure service accounts.

        You can either import an existing provider using ``iam.OpenIdConnectProvider.fromProviderArn``,
        or create a new provider using ``new eks.OpenIdConnectProvider``

        :default: - if not specified ``cluster.openIdConnectProvider`` and ``cluster.addServiceAccount`` will throw an error.
        '''
        result = self._values.get("open_id_connect_provider")
        return typing.cast(typing.Optional[_IOpenIdConnectProvider_203f0793], result)

    @builtins.property
    def prune(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned.

        When this is enabled (default), prune labels will be
        allocated and injected to each resource. These labels will then be used
        when issuing the ``kubectl apply`` operation with the ``--prune`` switch.

        :default: true
        '''
        result = self._values.get("prune")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def security_group_ids(self) -> typing.Optional[typing.List[builtins.str]]:
        '''Additional security groups associated with this cluster.

        :default:

        - if not specified, no additional security groups will be
        considered in ``cluster.connections``.
        '''
        result = self._values.get("security_group_ids")
        return typing.cast(typing.Optional[typing.List[builtins.str]], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC in which this Cluster was created.

        :default: - if not specified ``cluster.vpc`` will throw an error
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_eks.ClusterLoggingTypes")
class ClusterLoggingTypes(enum.Enum):
    '''EKS cluster logging types.

    :exampleMetadata: infused

    Example::

        cluster = eks.Cluster(self, "Cluster",
            # ...
            version=eks.KubernetesVersion.V1_21,
            cluster_logging=[eks.ClusterLoggingTypes.API, eks.ClusterLoggingTypes.AUTHENTICATOR, eks.ClusterLoggingTypes.SCHEDULER
            ]
        )
    '''

    API = "API"
    '''Logs pertaining to API requests to the cluster.'''
    AUDIT = "AUDIT"
    '''Logs pertaining to cluster access via the Kubernetes API.'''
    AUTHENTICATOR = "AUTHENTICATOR"
    '''Logs pertaining to authentication requests into the cluster.'''
    CONTROLLER_MANAGER = "CONTROLLER_MANAGER"
    '''Logs pertaining to state of cluster controllers.'''
    SCHEDULER = "SCHEDULER"
    '''Logs pertaining to scheduling decisions.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.CommonClusterOptions",
    jsii_struct_bases=[],
    name_mapping={
        "version": "version",
        "cluster_name": "clusterName",
        "output_cluster_name": "outputClusterName",
        "output_config_command": "outputConfigCommand",
        "role": "role",
        "security_group": "securityGroup",
        "vpc": "vpc",
        "vpc_subnets": "vpcSubnets",
    },
)
class CommonClusterOptions:
    def __init__(
        self,
        *,
        version: "KubernetesVersion",
        cluster_name: typing.Optional[builtins.str] = None,
        output_cluster_name: typing.Optional[builtins.bool] = None,
        output_config_command: typing.Optional[builtins.bool] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[typing.Sequence[_SubnetSelection_e57d76df]] = None,
    ) -> None:
        '''Options for configuring an EKS cluster.

        :param version: The Kubernetes version to run in the cluster.
        :param cluster_name: Name for the cluster. Default: - Automatically generated name
        :param output_cluster_name: Determines whether a CloudFormation output with the name of the cluster will be synthesized. Default: false
        :param output_config_command: Determines whether a CloudFormation output with the ``aws eks update-kubeconfig`` command will be synthesized. This command will include the cluster name and, if applicable, the ARN of the masters IAM role. Default: true
        :param role: Role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf. Default: - A role is automatically created for you
        :param security_group: Security Group to use for Control Plane ENIs. Default: - A security group is automatically created
        :param vpc: The VPC in which to create the Cluster. Default: - a VPC with default configuration will be created and can be accessed through ``cluster.vpc``.
        :param vpc_subnets: Where to place EKS Control Plane ENIs. If you want to create public load balancers, this must include public subnets. For example, to only select private subnets, supply the following: ``vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE }]`` Default: - All public and private subnets

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_eks as eks
            from aws_cdk import aws_iam as iam
            
            # kubernetes_version: eks.KubernetesVersion
            # role: iam.Role
            # security_group: ec2.SecurityGroup
            # subnet: ec2.Subnet
            # subnet_filter: ec2.SubnetFilter
            # vpc: ec2.Vpc
            
            common_cluster_options = eks.CommonClusterOptions(
                version=kubernetes_version,
            
                # the properties below are optional
                cluster_name="clusterName",
                output_cluster_name=False,
                output_config_command=False,
                role=role,
                security_group=security_group,
                vpc=vpc,
                vpc_subnets=[ec2.SubnetSelection(
                    availability_zones=["availabilityZones"],
                    one_per_az=False,
                    subnet_filters=[subnet_filter],
                    subnet_group_name="subnetGroupName",
                    subnets=[subnet],
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
                )]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "version": version,
        }
        if cluster_name is not None:
            self._values["cluster_name"] = cluster_name
        if output_cluster_name is not None:
            self._values["output_cluster_name"] = output_cluster_name
        if output_config_command is not None:
            self._values["output_config_command"] = output_config_command
        if role is not None:
            self._values["role"] = role
        if security_group is not None:
            self._values["security_group"] = security_group
        if vpc is not None:
            self._values["vpc"] = vpc
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets

    @builtins.property
    def version(self) -> "KubernetesVersion":
        '''The Kubernetes version to run in the cluster.'''
        result = self._values.get("version")
        assert result is not None, "Required property 'version' is missing"
        return typing.cast("KubernetesVersion", result)

    @builtins.property
    def cluster_name(self) -> typing.Optional[builtins.str]:
        '''Name for the cluster.

        :default: - Automatically generated name
        '''
        result = self._values.get("cluster_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def output_cluster_name(self) -> typing.Optional[builtins.bool]:
        '''Determines whether a CloudFormation output with the name of the cluster will be synthesized.

        :default: false
        '''
        result = self._values.get("output_cluster_name")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def output_config_command(self) -> typing.Optional[builtins.bool]:
        '''Determines whether a CloudFormation output with the ``aws eks update-kubeconfig`` command will be synthesized.

        This command will include
        the cluster name and, if applicable, the ARN of the masters IAM role.

        :default: true
        '''
        result = self._values.get("output_config_command")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''Role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf.

        :default: - A role is automatically created for you
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''Security Group to use for Control Plane ENIs.

        :default: - A security group is automatically created
        '''
        result = self._values.get("security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC in which to create the Cluster.

        :default: - a VPC with default configuration will be created and can be accessed through ``cluster.vpc``.
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[typing.List[_SubnetSelection_e57d76df]]:
        '''Where to place EKS Control Plane ENIs.

        If you want to create public load balancers, this must include public subnets.

        For example, to only select private subnets, supply the following:

        ``vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE }]``

        :default: - All public and private subnets
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[typing.List[_SubnetSelection_e57d76df]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "CommonClusterOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_eks.CoreDnsComputeType")
class CoreDnsComputeType(enum.Enum):
    '''The type of compute resources to use for CoreDNS.'''

    EC2 = "EC2"
    '''Deploy CoreDNS on EC2 instances.'''
    FARGATE = "FARGATE"
    '''Deploy CoreDNS on Fargate-managed instances.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_eks.CpuArch")
class CpuArch(enum.Enum):
    '''CPU architecture.'''

    ARM_64 = "ARM_64"
    '''arm64 CPU type.'''
    X86_64 = "X86_64"
    '''x86_64 CPU type.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_eks.DefaultCapacityType")
class DefaultCapacityType(enum.Enum):
    '''The default capacity type for the cluster.

    :exampleMetadata: infused

    Example::

        cluster = eks.Cluster(self, "HelloEKS",
            version=eks.KubernetesVersion.V1_21,
            default_capacity_type=eks.DefaultCapacityType.EC2
        )
    '''

    NODEGROUP = "NODEGROUP"
    '''managed node group.'''
    EC2 = "EC2"
    '''EC2 autoscaling group.'''


@jsii.implements(_IMachineImage_0e8bd50b)
class EksOptimizedImage(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.EksOptimizedImage",
):
    '''Construct an Amazon Linux 2 image from the latest EKS Optimized AMI published in SSM.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_eks as eks
        
        eks_optimized_image = eks.EksOptimizedImage(
            cpu_arch=eks.CpuArch.ARM_64,
            kubernetes_version="kubernetesVersion",
            node_type=eks.NodeType.STANDARD
        )
    '''

    def __init__(
        self,
        *,
        cpu_arch: typing.Optional[CpuArch] = None,
        kubernetes_version: typing.Optional[builtins.str] = None,
        node_type: typing.Optional["NodeType"] = None,
    ) -> None:
        '''Constructs a new instance of the EcsOptimizedAmi class.

        :param cpu_arch: What cpu architecture to retrieve the image for (arm64 or x86_64). Default: CpuArch.X86_64
        :param kubernetes_version: The Kubernetes version to use. Default: - The latest version
        :param node_type: What instance type to retrieve the image for (standard or GPU-optimized). Default: NodeType.STANDARD
        '''
        props = EksOptimizedImageProps(
            cpu_arch=cpu_arch,
            kubernetes_version=kubernetes_version,
            node_type=node_type,
        )

        jsii.create(self.__class__, self, [props])

    @jsii.member(jsii_name="getImage")
    def get_image(self, scope: constructs.Construct) -> _MachineImageConfig_187edaee:
        '''Return the correct image.

        :param scope: -
        '''
        return typing.cast(_MachineImageConfig_187edaee, jsii.invoke(self, "getImage", [scope]))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.EksOptimizedImageProps",
    jsii_struct_bases=[],
    name_mapping={
        "cpu_arch": "cpuArch",
        "kubernetes_version": "kubernetesVersion",
        "node_type": "nodeType",
    },
)
class EksOptimizedImageProps:
    def __init__(
        self,
        *,
        cpu_arch: typing.Optional[CpuArch] = None,
        kubernetes_version: typing.Optional[builtins.str] = None,
        node_type: typing.Optional["NodeType"] = None,
    ) -> None:
        '''Properties for EksOptimizedImage.

        :param cpu_arch: What cpu architecture to retrieve the image for (arm64 or x86_64). Default: CpuArch.X86_64
        :param kubernetes_version: The Kubernetes version to use. Default: - The latest version
        :param node_type: What instance type to retrieve the image for (standard or GPU-optimized). Default: NodeType.STANDARD

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            eks_optimized_image_props = eks.EksOptimizedImageProps(
                cpu_arch=eks.CpuArch.ARM_64,
                kubernetes_version="kubernetesVersion",
                node_type=eks.NodeType.STANDARD
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if cpu_arch is not None:
            self._values["cpu_arch"] = cpu_arch
        if kubernetes_version is not None:
            self._values["kubernetes_version"] = kubernetes_version
        if node_type is not None:
            self._values["node_type"] = node_type

    @builtins.property
    def cpu_arch(self) -> typing.Optional[CpuArch]:
        '''What cpu architecture to retrieve the image for (arm64 or x86_64).

        :default: CpuArch.X86_64
        '''
        result = self._values.get("cpu_arch")
        return typing.cast(typing.Optional[CpuArch], result)

    @builtins.property
    def kubernetes_version(self) -> typing.Optional[builtins.str]:
        '''The Kubernetes version to use.

        :default: - The latest version
        '''
        result = self._values.get("kubernetes_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def node_type(self) -> typing.Optional["NodeType"]:
        '''What instance type to retrieve the image for (standard or GPU-optimized).

        :default: NodeType.STANDARD
        '''
        result = self._values.get("node_type")
        return typing.cast(typing.Optional["NodeType"], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "EksOptimizedImageProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class EndpointAccess(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.EndpointAccess",
):
    '''Endpoint access characteristics.

    :exampleMetadata: infused

    Example::

        cluster = eks.Cluster(self, "hello-eks",
            version=eks.KubernetesVersion.V1_21,
            endpoint_access=eks.EndpointAccess.PRIVATE
        )
    '''

    @jsii.member(jsii_name="onlyFrom")
    def only_from(self, *cidr: builtins.str) -> "EndpointAccess":
        '''Restrict public access to specific CIDR blocks.

        If public access is disabled, this method will result in an error.

        :param cidr: CIDR blocks.
        '''
        return typing.cast("EndpointAccess", jsii.invoke(self, "onlyFrom", [*cidr]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="PRIVATE")
    def PRIVATE(cls) -> "EndpointAccess":
        '''The cluster endpoint is only accessible through your VPC.

        Worker node traffic to the endpoint will stay within your VPC.
        '''
        return typing.cast("EndpointAccess", jsii.sget(cls, "PRIVATE"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="PUBLIC")
    def PUBLIC(cls) -> "EndpointAccess":
        '''The cluster endpoint is accessible from outside of your VPC.

        Worker node traffic will leave your VPC to connect to the endpoint.

        By default, the endpoint is exposed to all adresses. You can optionally limit the CIDR blocks that can access the public endpoint using the ``PUBLIC.onlyFrom`` method.
        If you limit access to specific CIDR blocks, you must ensure that the CIDR blocks that you
        specify include the addresses that worker nodes and Fargate pods (if you use them)
        access the public endpoint from.
        '''
        return typing.cast("EndpointAccess", jsii.sget(cls, "PUBLIC"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="PUBLIC_AND_PRIVATE")
    def PUBLIC_AND_PRIVATE(cls) -> "EndpointAccess":
        '''The cluster endpoint is accessible from outside of your VPC.

        Worker node traffic to the endpoint will stay within your VPC.

        By default, the endpoint is exposed to all adresses. You can optionally limit the CIDR blocks that can access the public endpoint using the ``PUBLIC_AND_PRIVATE.onlyFrom`` method.
        If you limit access to specific CIDR blocks, you must ensure that the CIDR blocks that you
        specify include the addresses that worker nodes and Fargate pods (if you use them)
        access the public endpoint from.
        '''
        return typing.cast("EndpointAccess", jsii.sget(cls, "PUBLIC_AND_PRIVATE"))


@jsii.implements(_ITaggable_36806126)
class FargateProfile(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.FargateProfile",
):
    '''Fargate profiles allows an administrator to declare which pods run on Fargate.

    This declaration is done through the profile’s selectors. Each
    profile can have up to five selectors that contain a namespace and optional
    labels. You must define a namespace for every selector. The label field
    consists of multiple optional key-value pairs. Pods that match a selector (by
    matching a namespace for the selector and all of the labels specified in the
    selector) are scheduled on Fargate. If a namespace selector is defined
    without any labels, Amazon EKS will attempt to schedule all pods that run in
    that namespace onto Fargate using the profile. If a to-be-scheduled pod
    matches any of the selectors in the Fargate profile, then that pod is
    scheduled on Fargate.

    If a pod matches multiple Fargate profiles, Amazon EKS picks one of the
    matches at random. In this case, you can specify which profile a pod should
    use by adding the following Kubernetes label to the pod specification:
    eks.amazonaws.com/fargate-profile: profile_name. However, the pod must still
    match a selector in that profile in order to be scheduled onto Fargate.

    :exampleMetadata: infused

    Example::

        # cluster: eks.Cluster
        
        eks.FargateProfile(self, "MyProfile",
            cluster=cluster,
            selectors=[eks.Selector(namespace="default")]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster: "Cluster",
        selectors: typing.Sequence["Selector"],
        fargate_profile_name: typing.Optional[builtins.str] = None,
        pod_execution_role: typing.Optional[_IRole_235f5d8e] = None,
        subnet_selection: typing.Optional[_SubnetSelection_e57d76df] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param cluster: The EKS cluster to apply the Fargate profile to. [disable-awslint:ref-via-interface]
        :param selectors: The selectors to match for pods to use this Fargate profile. Each selector must have an associated namespace. Optionally, you can also specify labels for a namespace. At least one selector is required and you may specify up to five selectors.
        :param fargate_profile_name: The name of the Fargate profile. Default: - generated
        :param pod_execution_role: The pod execution role to use for pods that match the selectors in the Fargate profile. The pod execution role allows Fargate infrastructure to register with your cluster as a node, and it provides read access to Amazon ECR image repositories. Default: - a role will be automatically created
        :param subnet_selection: Select which subnets to launch your pods into. At this time, pods running on Fargate are not assigned public IP addresses, so only private subnets (with no direct route to an Internet Gateway) are allowed. You must specify the VPC to customize the subnet selection Default: - all private subnets of the VPC are selected.
        :param vpc: The VPC from which to select subnets to launch your pods into. By default, all private subnets are selected. You can customize this using ``subnetSelection``. Default: - all private subnets used by the EKS cluster
        '''
        props = FargateProfileProps(
            cluster=cluster,
            selectors=selectors,
            fargate_profile_name=fargate_profile_name,
            pod_execution_role=pod_execution_role,
            subnet_selection=subnet_selection,
            vpc=vpc,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fargateProfileArn")
    def fargate_profile_arn(self) -> builtins.str:
        '''The full Amazon Resource Name (ARN) of the Fargate profile.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "fargateProfileArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="fargateProfileName")
    def fargate_profile_name(self) -> builtins.str:
        '''The name of the Fargate profile.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "fargateProfileName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="podExecutionRole")
    def pod_execution_role(self) -> _IRole_235f5d8e:
        '''The pod execution role to use for pods that match the selectors in the Fargate profile.

        The pod execution role allows Fargate infrastructure to
        register with your cluster as a node, and it provides read access to Amazon
        ECR image repositories.
        '''
        return typing.cast(_IRole_235f5d8e, jsii.get(self, "podExecutionRole"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="tags")
    def tags(self) -> _TagManager_0a598cb3:
        '''Resource tags.'''
        return typing.cast(_TagManager_0a598cb3, jsii.get(self, "tags"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.FargateProfileOptions",
    jsii_struct_bases=[],
    name_mapping={
        "selectors": "selectors",
        "fargate_profile_name": "fargateProfileName",
        "pod_execution_role": "podExecutionRole",
        "subnet_selection": "subnetSelection",
        "vpc": "vpc",
    },
)
class FargateProfileOptions:
    def __init__(
        self,
        *,
        selectors: typing.Sequence["Selector"],
        fargate_profile_name: typing.Optional[builtins.str] = None,
        pod_execution_role: typing.Optional[_IRole_235f5d8e] = None,
        subnet_selection: typing.Optional[_SubnetSelection_e57d76df] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> None:
        '''Options for defining EKS Fargate Profiles.

        :param selectors: The selectors to match for pods to use this Fargate profile. Each selector must have an associated namespace. Optionally, you can also specify labels for a namespace. At least one selector is required and you may specify up to five selectors.
        :param fargate_profile_name: The name of the Fargate profile. Default: - generated
        :param pod_execution_role: The pod execution role to use for pods that match the selectors in the Fargate profile. The pod execution role allows Fargate infrastructure to register with your cluster as a node, and it provides read access to Amazon ECR image repositories. Default: - a role will be automatically created
        :param subnet_selection: Select which subnets to launch your pods into. At this time, pods running on Fargate are not assigned public IP addresses, so only private subnets (with no direct route to an Internet Gateway) are allowed. You must specify the VPC to customize the subnet selection Default: - all private subnets of the VPC are selected.
        :param vpc: The VPC from which to select subnets to launch your pods into. By default, all private subnets are selected. You can customize this using ``subnetSelection``. Default: - all private subnets used by the EKS cluster

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            
            cluster.add_fargate_profile("MyProfile",
                selectors=[eks.Selector(namespace="default")]
            )
        '''
        if isinstance(subnet_selection, dict):
            subnet_selection = _SubnetSelection_e57d76df(**subnet_selection)
        self._values: typing.Dict[str, typing.Any] = {
            "selectors": selectors,
        }
        if fargate_profile_name is not None:
            self._values["fargate_profile_name"] = fargate_profile_name
        if pod_execution_role is not None:
            self._values["pod_execution_role"] = pod_execution_role
        if subnet_selection is not None:
            self._values["subnet_selection"] = subnet_selection
        if vpc is not None:
            self._values["vpc"] = vpc

    @builtins.property
    def selectors(self) -> typing.List["Selector"]:
        '''The selectors to match for pods to use this Fargate profile.

        Each selector
        must have an associated namespace. Optionally, you can also specify labels
        for a namespace.

        At least one selector is required and you may specify up to five selectors.
        '''
        result = self._values.get("selectors")
        assert result is not None, "Required property 'selectors' is missing"
        return typing.cast(typing.List["Selector"], result)

    @builtins.property
    def fargate_profile_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Fargate profile.

        :default: - generated
        '''
        result = self._values.get("fargate_profile_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def pod_execution_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The pod execution role to use for pods that match the selectors in the Fargate profile.

        The pod execution role allows Fargate infrastructure to
        register with your cluster as a node, and it provides read access to Amazon
        ECR image repositories.

        :default: - a role will be automatically created

        :see: https://docs.aws.amazon.com/eks/latest/userguide/pod-execution-role.html
        '''
        result = self._values.get("pod_execution_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def subnet_selection(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''Select which subnets to launch your pods into.

        At this time, pods running
        on Fargate are not assigned public IP addresses, so only private subnets
        (with no direct route to an Internet Gateway) are allowed.

        You must specify the VPC to customize the subnet selection

        :default: - all private subnets of the VPC are selected.
        '''
        result = self._values.get("subnet_selection")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC from which to select subnets to launch your pods into.

        By default, all private subnets are selected. You can customize this using
        ``subnetSelection``.

        :default: - all private subnets used by the EKS cluster
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "FargateProfileOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.FargateProfileProps",
    jsii_struct_bases=[FargateProfileOptions],
    name_mapping={
        "selectors": "selectors",
        "fargate_profile_name": "fargateProfileName",
        "pod_execution_role": "podExecutionRole",
        "subnet_selection": "subnetSelection",
        "vpc": "vpc",
        "cluster": "cluster",
    },
)
class FargateProfileProps(FargateProfileOptions):
    def __init__(
        self,
        *,
        selectors: typing.Sequence["Selector"],
        fargate_profile_name: typing.Optional[builtins.str] = None,
        pod_execution_role: typing.Optional[_IRole_235f5d8e] = None,
        subnet_selection: typing.Optional[_SubnetSelection_e57d76df] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        cluster: "Cluster",
    ) -> None:
        '''Configuration props for EKS Fargate Profiles.

        :param selectors: The selectors to match for pods to use this Fargate profile. Each selector must have an associated namespace. Optionally, you can also specify labels for a namespace. At least one selector is required and you may specify up to five selectors.
        :param fargate_profile_name: The name of the Fargate profile. Default: - generated
        :param pod_execution_role: The pod execution role to use for pods that match the selectors in the Fargate profile. The pod execution role allows Fargate infrastructure to register with your cluster as a node, and it provides read access to Amazon ECR image repositories. Default: - a role will be automatically created
        :param subnet_selection: Select which subnets to launch your pods into. At this time, pods running on Fargate are not assigned public IP addresses, so only private subnets (with no direct route to an Internet Gateway) are allowed. You must specify the VPC to customize the subnet selection Default: - all private subnets of the VPC are selected.
        :param vpc: The VPC from which to select subnets to launch your pods into. By default, all private subnets are selected. You can customize this using ``subnetSelection``. Default: - all private subnets used by the EKS cluster
        :param cluster: The EKS cluster to apply the Fargate profile to. [disable-awslint:ref-via-interface]

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            
            eks.FargateProfile(self, "MyProfile",
                cluster=cluster,
                selectors=[eks.Selector(namespace="default")]
            )
        '''
        if isinstance(subnet_selection, dict):
            subnet_selection = _SubnetSelection_e57d76df(**subnet_selection)
        self._values: typing.Dict[str, typing.Any] = {
            "selectors": selectors,
            "cluster": cluster,
        }
        if fargate_profile_name is not None:
            self._values["fargate_profile_name"] = fargate_profile_name
        if pod_execution_role is not None:
            self._values["pod_execution_role"] = pod_execution_role
        if subnet_selection is not None:
            self._values["subnet_selection"] = subnet_selection
        if vpc is not None:
            self._values["vpc"] = vpc

    @builtins.property
    def selectors(self) -> typing.List["Selector"]:
        '''The selectors to match for pods to use this Fargate profile.

        Each selector
        must have an associated namespace. Optionally, you can also specify labels
        for a namespace.

        At least one selector is required and you may specify up to five selectors.
        '''
        result = self._values.get("selectors")
        assert result is not None, "Required property 'selectors' is missing"
        return typing.cast(typing.List["Selector"], result)

    @builtins.property
    def fargate_profile_name(self) -> typing.Optional[builtins.str]:
        '''The name of the Fargate profile.

        :default: - generated
        '''
        result = self._values.get("fargate_profile_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def pod_execution_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The pod execution role to use for pods that match the selectors in the Fargate profile.

        The pod execution role allows Fargate infrastructure to
        register with your cluster as a node, and it provides read access to Amazon
        ECR image repositories.

        :default: - a role will be automatically created

        :see: https://docs.aws.amazon.com/eks/latest/userguide/pod-execution-role.html
        '''
        result = self._values.get("pod_execution_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def subnet_selection(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''Select which subnets to launch your pods into.

        At this time, pods running
        on Fargate are not assigned public IP addresses, so only private subnets
        (with no direct route to an Internet Gateway) are allowed.

        You must specify the VPC to customize the subnet selection

        :default: - all private subnets of the VPC are selected.
        '''
        result = self._values.get("subnet_selection")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC from which to select subnets to launch your pods into.

        By default, all private subnets are selected. You can customize this using
        ``subnetSelection``.

        :default: - all private subnets used by the EKS cluster
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    @builtins.property
    def cluster(self) -> "Cluster":
        '''The EKS cluster to apply the Fargate profile to.

        [disable-awslint:ref-via-interface]
        '''
        result = self._values.get("cluster")
        assert result is not None, "Required property 'cluster' is missing"
        return typing.cast("Cluster", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "FargateProfileProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class HelmChart(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.HelmChart",
):
    '''Represents a helm chart within the Kubernetes system.

    Applies/deletes the resources using ``kubectl`` in sync with the resource.

    :exampleMetadata: infused

    Example::

        # cluster: eks.Cluster
        
        # option 1: use a construct
        eks.HelmChart(self, "NginxIngress",
            cluster=cluster,
            chart="nginx-ingress",
            repository="https://helm.nginx.com/stable",
            namespace="kube-system"
        )
        
        # or, option2: use `addHelmChart`
        cluster.add_helm_chart("NginxIngress",
            chart="nginx-ingress",
            repository="https://helm.nginx.com/stable",
            namespace="kube-system"
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster: "ICluster",
        chart: typing.Optional[builtins.str] = None,
        chart_asset: typing.Optional[_Asset_ac2a7e61] = None,
        create_namespace: typing.Optional[builtins.bool] = None,
        namespace: typing.Optional[builtins.str] = None,
        release: typing.Optional[builtins.str] = None,
        repository: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        version: typing.Optional[builtins.str] = None,
        wait: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param cluster: The EKS cluster to apply this configuration to. [disable-awslint:ref-via-interface]
        :param chart: The name of the chart. Either this or ``chartAsset`` must be specified. Default: - No chart name. Implies ``chartAsset`` is used.
        :param chart_asset: The chart in the form of an asset. Either this or ``chart`` must be specified. Default: - No chart asset. Implies ``chart`` is used.
        :param create_namespace: create namespace if not exist. Default: true
        :param namespace: The Kubernetes namespace scope of the requests. Default: default
        :param release: The name of the release. Default: - If no release name is given, it will use the last 53 characters of the node's unique id.
        :param repository: The repository which contains the chart. For example: https://kubernetes-charts.storage.googleapis.com/ Default: - No repository will be used, which means that the chart needs to be an absolute URL.
        :param timeout: Amount of time to wait for any individual Kubernetes operation. Maximum 15 minutes. Default: Duration.minutes(5)
        :param values: The values to be used by the chart. Default: - No values are provided to the chart.
        :param version: The chart version to install. Default: - If this is not specified, the latest version is installed
        :param wait: Whether or not Helm should wait until all Pods, PVCs, Services, and minimum number of Pods of a Deployment, StatefulSet, or ReplicaSet are in a ready state before marking the release as successful. Default: - Helm will not wait before marking release as successful
        '''
        props = HelmChartProps(
            cluster=cluster,
            chart=chart,
            chart_asset=chart_asset,
            create_namespace=create_namespace,
            namespace=namespace,
            release=release,
            repository=repository,
            timeout=timeout,
            values=values,
            version=version,
            wait=wait,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="RESOURCE_TYPE")
    def RESOURCE_TYPE(cls) -> builtins.str:
        '''The CloudFormation resource type.'''
        return typing.cast(builtins.str, jsii.sget(cls, "RESOURCE_TYPE"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.HelmChartOptions",
    jsii_struct_bases=[],
    name_mapping={
        "chart": "chart",
        "chart_asset": "chartAsset",
        "create_namespace": "createNamespace",
        "namespace": "namespace",
        "release": "release",
        "repository": "repository",
        "timeout": "timeout",
        "values": "values",
        "version": "version",
        "wait": "wait",
    },
)
class HelmChartOptions:
    def __init__(
        self,
        *,
        chart: typing.Optional[builtins.str] = None,
        chart_asset: typing.Optional[_Asset_ac2a7e61] = None,
        create_namespace: typing.Optional[builtins.bool] = None,
        namespace: typing.Optional[builtins.str] = None,
        release: typing.Optional[builtins.str] = None,
        repository: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        version: typing.Optional[builtins.str] = None,
        wait: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Helm Chart options.

        :param chart: The name of the chart. Either this or ``chartAsset`` must be specified. Default: - No chart name. Implies ``chartAsset`` is used.
        :param chart_asset: The chart in the form of an asset. Either this or ``chart`` must be specified. Default: - No chart asset. Implies ``chart`` is used.
        :param create_namespace: create namespace if not exist. Default: true
        :param namespace: The Kubernetes namespace scope of the requests. Default: default
        :param release: The name of the release. Default: - If no release name is given, it will use the last 53 characters of the node's unique id.
        :param repository: The repository which contains the chart. For example: https://kubernetes-charts.storage.googleapis.com/ Default: - No repository will be used, which means that the chart needs to be an absolute URL.
        :param timeout: Amount of time to wait for any individual Kubernetes operation. Maximum 15 minutes. Default: Duration.minutes(5)
        :param values: The values to be used by the chart. Default: - No values are provided to the chart.
        :param version: The chart version to install. Default: - If this is not specified, the latest version is installed
        :param wait: Whether or not Helm should wait until all Pods, PVCs, Services, and minimum number of Pods of a Deployment, StatefulSet, or ReplicaSet are in a ready state before marking the release as successful. Default: - Helm will not wait before marking release as successful

        :exampleMetadata: infused

        Example::

            import aws_cdk.aws_s3_assets as s3_assets
            
            # cluster: eks.Cluster
            
            chart_asset = s3_assets.Asset(self, "ChartAsset",
                path="/path/to/asset"
            )
            
            cluster.add_helm_chart("test-chart",
                chart_asset=chart_asset
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if chart is not None:
            self._values["chart"] = chart
        if chart_asset is not None:
            self._values["chart_asset"] = chart_asset
        if create_namespace is not None:
            self._values["create_namespace"] = create_namespace
        if namespace is not None:
            self._values["namespace"] = namespace
        if release is not None:
            self._values["release"] = release
        if repository is not None:
            self._values["repository"] = repository
        if timeout is not None:
            self._values["timeout"] = timeout
        if values is not None:
            self._values["values"] = values
        if version is not None:
            self._values["version"] = version
        if wait is not None:
            self._values["wait"] = wait

    @builtins.property
    def chart(self) -> typing.Optional[builtins.str]:
        '''The name of the chart.

        Either this or ``chartAsset`` must be specified.

        :default: - No chart name. Implies ``chartAsset`` is used.
        '''
        result = self._values.get("chart")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def chart_asset(self) -> typing.Optional[_Asset_ac2a7e61]:
        '''The chart in the form of an asset.

        Either this or ``chart`` must be specified.

        :default: - No chart asset. Implies ``chart`` is used.
        '''
        result = self._values.get("chart_asset")
        return typing.cast(typing.Optional[_Asset_ac2a7e61], result)

    @builtins.property
    def create_namespace(self) -> typing.Optional[builtins.bool]:
        '''create namespace if not exist.

        :default: true
        '''
        result = self._values.get("create_namespace")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The Kubernetes namespace scope of the requests.

        :default: default
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def release(self) -> typing.Optional[builtins.str]:
        '''The name of the release.

        :default: - If no release name is given, it will use the last 53 characters of the node's unique id.
        '''
        result = self._values.get("release")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def repository(self) -> typing.Optional[builtins.str]:
        '''The repository which contains the chart.

        For example: https://kubernetes-charts.storage.googleapis.com/

        :default: - No repository will be used, which means that the chart needs to be an absolute URL.
        '''
        result = self._values.get("repository")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Amount of time to wait for any individual Kubernetes operation.

        Maximum 15 minutes.

        :default: Duration.minutes(5)
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def values(self) -> typing.Optional[typing.Mapping[builtins.str, typing.Any]]:
        '''The values to be used by the chart.

        :default: - No values are provided to the chart.
        '''
        result = self._values.get("values")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, typing.Any]], result)

    @builtins.property
    def version(self) -> typing.Optional[builtins.str]:
        '''The chart version to install.

        :default: - If this is not specified, the latest version is installed
        '''
        result = self._values.get("version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def wait(self) -> typing.Optional[builtins.bool]:
        '''Whether or not Helm should wait until all Pods, PVCs, Services, and minimum number of Pods of a Deployment, StatefulSet, or ReplicaSet are in a ready state before marking the release as successful.

        :default: - Helm will not wait before marking release as successful
        '''
        result = self._values.get("wait")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "HelmChartOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.HelmChartProps",
    jsii_struct_bases=[HelmChartOptions],
    name_mapping={
        "chart": "chart",
        "chart_asset": "chartAsset",
        "create_namespace": "createNamespace",
        "namespace": "namespace",
        "release": "release",
        "repository": "repository",
        "timeout": "timeout",
        "values": "values",
        "version": "version",
        "wait": "wait",
        "cluster": "cluster",
    },
)
class HelmChartProps(HelmChartOptions):
    def __init__(
        self,
        *,
        chart: typing.Optional[builtins.str] = None,
        chart_asset: typing.Optional[_Asset_ac2a7e61] = None,
        create_namespace: typing.Optional[builtins.bool] = None,
        namespace: typing.Optional[builtins.str] = None,
        release: typing.Optional[builtins.str] = None,
        repository: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        version: typing.Optional[builtins.str] = None,
        wait: typing.Optional[builtins.bool] = None,
        cluster: "ICluster",
    ) -> None:
        '''Helm Chart properties.

        :param chart: The name of the chart. Either this or ``chartAsset`` must be specified. Default: - No chart name. Implies ``chartAsset`` is used.
        :param chart_asset: The chart in the form of an asset. Either this or ``chart`` must be specified. Default: - No chart asset. Implies ``chart`` is used.
        :param create_namespace: create namespace if not exist. Default: true
        :param namespace: The Kubernetes namespace scope of the requests. Default: default
        :param release: The name of the release. Default: - If no release name is given, it will use the last 53 characters of the node's unique id.
        :param repository: The repository which contains the chart. For example: https://kubernetes-charts.storage.googleapis.com/ Default: - No repository will be used, which means that the chart needs to be an absolute URL.
        :param timeout: Amount of time to wait for any individual Kubernetes operation. Maximum 15 minutes. Default: Duration.minutes(5)
        :param values: The values to be used by the chart. Default: - No values are provided to the chart.
        :param version: The chart version to install. Default: - If this is not specified, the latest version is installed
        :param wait: Whether or not Helm should wait until all Pods, PVCs, Services, and minimum number of Pods of a Deployment, StatefulSet, or ReplicaSet are in a ready state before marking the release as successful. Default: - Helm will not wait before marking release as successful
        :param cluster: The EKS cluster to apply this configuration to. [disable-awslint:ref-via-interface]

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            
            # option 1: use a construct
            eks.HelmChart(self, "NginxIngress",
                cluster=cluster,
                chart="nginx-ingress",
                repository="https://helm.nginx.com/stable",
                namespace="kube-system"
            )
            
            # or, option2: use `addHelmChart`
            cluster.add_helm_chart("NginxIngress",
                chart="nginx-ingress",
                repository="https://helm.nginx.com/stable",
                namespace="kube-system"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster": cluster,
        }
        if chart is not None:
            self._values["chart"] = chart
        if chart_asset is not None:
            self._values["chart_asset"] = chart_asset
        if create_namespace is not None:
            self._values["create_namespace"] = create_namespace
        if namespace is not None:
            self._values["namespace"] = namespace
        if release is not None:
            self._values["release"] = release
        if repository is not None:
            self._values["repository"] = repository
        if timeout is not None:
            self._values["timeout"] = timeout
        if values is not None:
            self._values["values"] = values
        if version is not None:
            self._values["version"] = version
        if wait is not None:
            self._values["wait"] = wait

    @builtins.property
    def chart(self) -> typing.Optional[builtins.str]:
        '''The name of the chart.

        Either this or ``chartAsset`` must be specified.

        :default: - No chart name. Implies ``chartAsset`` is used.
        '''
        result = self._values.get("chart")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def chart_asset(self) -> typing.Optional[_Asset_ac2a7e61]:
        '''The chart in the form of an asset.

        Either this or ``chart`` must be specified.

        :default: - No chart asset. Implies ``chart`` is used.
        '''
        result = self._values.get("chart_asset")
        return typing.cast(typing.Optional[_Asset_ac2a7e61], result)

    @builtins.property
    def create_namespace(self) -> typing.Optional[builtins.bool]:
        '''create namespace if not exist.

        :default: true
        '''
        result = self._values.get("create_namespace")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The Kubernetes namespace scope of the requests.

        :default: default
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def release(self) -> typing.Optional[builtins.str]:
        '''The name of the release.

        :default: - If no release name is given, it will use the last 53 characters of the node's unique id.
        '''
        result = self._values.get("release")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def repository(self) -> typing.Optional[builtins.str]:
        '''The repository which contains the chart.

        For example: https://kubernetes-charts.storage.googleapis.com/

        :default: - No repository will be used, which means that the chart needs to be an absolute URL.
        '''
        result = self._values.get("repository")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Amount of time to wait for any individual Kubernetes operation.

        Maximum 15 minutes.

        :default: Duration.minutes(5)
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    @builtins.property
    def values(self) -> typing.Optional[typing.Mapping[builtins.str, typing.Any]]:
        '''The values to be used by the chart.

        :default: - No values are provided to the chart.
        '''
        result = self._values.get("values")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, typing.Any]], result)

    @builtins.property
    def version(self) -> typing.Optional[builtins.str]:
        '''The chart version to install.

        :default: - If this is not specified, the latest version is installed
        '''
        result = self._values.get("version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def wait(self) -> typing.Optional[builtins.bool]:
        '''Whether or not Helm should wait until all Pods, PVCs, Services, and minimum number of Pods of a Deployment, StatefulSet, or ReplicaSet are in a ready state before marking the release as successful.

        :default: - Helm will not wait before marking release as successful
        '''
        result = self._values.get("wait")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def cluster(self) -> "ICluster":
        '''The EKS cluster to apply this configuration to.

        [disable-awslint:ref-via-interface]
        '''
        result = self._values.get("cluster")
        assert result is not None, "Required property 'cluster' is missing"
        return typing.cast("ICluster", result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "HelmChartProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.interface(jsii_type="aws-cdk-lib.aws_eks.ICluster")
class ICluster(_IResource_c80c4260, _IConnectable_10015a05, typing_extensions.Protocol):
    '''An EKS cluster.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterArn")
    def cluster_arn(self) -> builtins.str:
        '''The unique ARN assigned to the service by AWS in the form of arn:aws:eks:.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterCertificateAuthorityData")
    def cluster_certificate_authority_data(self) -> builtins.str:
        '''The certificate-authority-data for your cluster.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterEncryptionConfigKeyArn")
    def cluster_encryption_config_key_arn(self) -> builtins.str:
        '''Amazon Resource Name (ARN) or alias of the customer master key (CMK).

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterEndpoint")
    def cluster_endpoint(self) -> builtins.str:
        '''The API Server endpoint URL.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterName")
    def cluster_name(self) -> builtins.str:
        '''The physical name of the Cluster.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterSecurityGroup")
    def cluster_security_group(self) -> _ISecurityGroup_acf8a799:
        '''The cluster security group that was created by Amazon EKS for the cluster.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterSecurityGroupId")
    def cluster_security_group_id(self) -> builtins.str:
        '''The id of the cluster security group that was created by Amazon EKS for the cluster.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openIdConnectProvider")
    def open_id_connect_provider(self) -> _IOpenIdConnectProvider_203f0793:
        '''The Open ID Connect Provider of the cluster used to configure Service Accounts.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="prune")
    def prune(self) -> builtins.bool:
        '''Indicates whether Kubernetes resources can be automatically pruned.

        When
        this is enabled (default), prune labels will be allocated and injected to
        each resource. These labels will then be used when issuing the ``kubectl apply`` operation with the ``--prune`` switch.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpc")
    def vpc(self) -> _IVpc_f30d5663:
        '''The VPC in which this Cluster was created.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterHandlerSecurityGroup")
    def cluster_handler_security_group(
        self,
    ) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''A security group to associate with the Cluster Handler's Lambdas.

        The Cluster Handler's Lambdas are responsible for calling AWS's EKS API.

        Requires ``placeClusterHandlerInVpc`` to be set to true.

        :default: - No security group.

        :attribute: true
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlEnvironment")
    def kubectl_environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom environment variables when running ``kubectl`` against this cluster.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlLambdaRole")
    def kubectl_lambda_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''An IAM role that can perform kubectl operations against this cluster.

        The role should be mapped to the ``system:masters`` Kubernetes RBAC role.

        This role is directly passed to the lambda handler that sends Kube Ctl commands to the cluster.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlLayer")
    def kubectl_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda layer that includes ``kubectl``, ``helm`` and the ``aws`` CLI.

        If not defined, a default layer will be used.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlMemory")
    def kubectl_memory(self) -> typing.Optional[_Size_7b441c34]:
        '''Amount of memory to allocate to the provider's lambda function.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlPrivateSubnets")
    def kubectl_private_subnets(
        self,
    ) -> typing.Optional[typing.List[_ISubnet_d57d1229]]:
        '''Subnets to host the ``kubectl`` compute resources.

        If this is undefined, the k8s endpoint is expected to be accessible
        publicly.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlProvider")
    def kubectl_provider(self) -> typing.Optional["IKubectlProvider"]:
        '''Kubectl Provider for issuing kubectl commands against it.

        If not defined, a default provider will be used
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlRole")
    def kubectl_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''An IAM role that can perform kubectl operations against this cluster.

        The role should be mapped to the ``system:masters`` Kubernetes RBAC role.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlSecurityGroup")
    def kubectl_security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''A security group to use for ``kubectl`` execution.

        If this is undefined, the k8s endpoint is expected to be accessible
        publicly.
        '''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="onEventLayer")
    def on_event_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda layer that includes the NPM dependency ``proxy-agent``.

        If not defined, a default layer will be used.
        '''
        ...

    @jsii.member(jsii_name="addCdk8sChart")
    def add_cdk8s_chart(
        self,
        id: builtins.str,
        chart: constructs.Construct,
        *,
        ingress_alb: typing.Optional[builtins.bool] = None,
        ingress_alb_scheme: typing.Optional[AlbScheme] = None,
        prune: typing.Optional[builtins.bool] = None,
        skip_validation: typing.Optional[builtins.bool] = None,
    ) -> "KubernetesManifest":
        '''Defines a CDK8s chart in this cluster.

        :param id: logical id of this chart.
        :param chart: the cdk8s chart.
        :param ingress_alb: Automatically detect ``Ingress`` resources in the manifest and annotate them so they are picked up by an ALB Ingress Controller. Default: false
        :param ingress_alb_scheme: Specify the ALB scheme that should be applied to ``Ingress`` resources. Only applicable if ``ingressAlb`` is set to ``true``. Default: AlbScheme.INTERNAL
        :param prune: When a resource is removed from a Kubernetes manifest, it no longer appears in the manifest, and there is no way to know that this resource needs to be deleted. To address this, ``kubectl apply`` has a ``--prune`` option which will query the cluster for all resources with a specific label and will remove all the labeld resources that are not part of the applied manifest. If this option is disabled and a resource is removed, it will become "orphaned" and will not be deleted from the cluster. When this option is enabled (default), the construct will inject a label to all Kubernetes resources included in this manifest which will be used to prune resources when the manifest changes via ``kubectl apply --prune``. The label name will be ``aws.cdk.eks/prune-<ADDR>`` where ``<ADDR>`` is the 42-char unique address of this construct in the construct tree. Value is empty. Default: - based on the prune option of the cluster, which is ``true`` unless otherwise specified.
        :param skip_validation: A flag to signify if the manifest validation should be skipped. Default: false

        :return: a ``KubernetesManifest`` construct representing the chart.
        '''
        ...

    @jsii.member(jsii_name="addHelmChart")
    def add_helm_chart(
        self,
        id: builtins.str,
        *,
        chart: typing.Optional[builtins.str] = None,
        chart_asset: typing.Optional[_Asset_ac2a7e61] = None,
        create_namespace: typing.Optional[builtins.bool] = None,
        namespace: typing.Optional[builtins.str] = None,
        release: typing.Optional[builtins.str] = None,
        repository: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        version: typing.Optional[builtins.str] = None,
        wait: typing.Optional[builtins.bool] = None,
    ) -> HelmChart:
        '''Defines a Helm chart in this cluster.

        :param id: logical id of this chart.
        :param chart: The name of the chart. Either this or ``chartAsset`` must be specified. Default: - No chart name. Implies ``chartAsset`` is used.
        :param chart_asset: The chart in the form of an asset. Either this or ``chart`` must be specified. Default: - No chart asset. Implies ``chart`` is used.
        :param create_namespace: create namespace if not exist. Default: true
        :param namespace: The Kubernetes namespace scope of the requests. Default: default
        :param release: The name of the release. Default: - If no release name is given, it will use the last 53 characters of the node's unique id.
        :param repository: The repository which contains the chart. For example: https://kubernetes-charts.storage.googleapis.com/ Default: - No repository will be used, which means that the chart needs to be an absolute URL.
        :param timeout: Amount of time to wait for any individual Kubernetes operation. Maximum 15 minutes. Default: Duration.minutes(5)
        :param values: The values to be used by the chart. Default: - No values are provided to the chart.
        :param version: The chart version to install. Default: - If this is not specified, the latest version is installed
        :param wait: Whether or not Helm should wait until all Pods, PVCs, Services, and minimum number of Pods of a Deployment, StatefulSet, or ReplicaSet are in a ready state before marking the release as successful. Default: - Helm will not wait before marking release as successful

        :return: a ``HelmChart`` construct
        '''
        ...

    @jsii.member(jsii_name="addManifest")
    def add_manifest(
        self,
        id: builtins.str,
        *manifest: typing.Mapping[builtins.str, typing.Any],
    ) -> "KubernetesManifest":
        '''Defines a Kubernetes resource in this cluster.

        The manifest will be applied/deleted using kubectl as needed.

        :param id: logical id of this manifest.
        :param manifest: a list of Kubernetes resource specifications.

        :return: a ``KubernetesManifest`` object.
        '''
        ...

    @jsii.member(jsii_name="addServiceAccount")
    def add_service_account(
        self,
        id: builtins.str,
        *,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> "ServiceAccount":
        '''Creates a new service account with corresponding IAM Role (IRSA).

        :param id: logical id of service account.
        :param name: The name of the service account. Default: - If no name is given, it will use the id of the resource.
        :param namespace: The namespace of the service account. Default: "default"
        '''
        ...

    @jsii.member(jsii_name="connectAutoScalingGroupCapacity")
    def connect_auto_scaling_group_capacity(
        self,
        auto_scaling_group: _AutoScalingGroup_c547a7b9,
        *,
        bootstrap_enabled: typing.Optional[builtins.bool] = None,
        bootstrap_options: typing.Optional[BootstrapOptions] = None,
        machine_image_type: typing.Optional["MachineImageType"] = None,
        map_role: typing.Optional[builtins.bool] = None,
        spot_interrupt_handler: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Connect capacity in the form of an existing AutoScalingGroup to the EKS cluster.

        The AutoScalingGroup must be running an EKS-optimized AMI containing the
        /etc/eks/bootstrap.sh script. This method will configure Security Groups,
        add the right policies to the instance role, apply the right tags, and add
        the required user data to the instance's launch configuration.

        Spot instances will be labeled ``lifecycle=Ec2Spot`` and tainted with ``PreferNoSchedule``.
        If kubectl is enabled, the
        `spot interrupt handler <https://github.com/awslabs/ec2-spot-labs/tree/master/ec2-spot-eks-solution/spot-termination-handler>`_
        daemon will be installed on all spot instances to handle
        `EC2 Spot Instance Termination Notices <https://aws.amazon.com/blogs/aws/new-ec2-spot-instance-termination-notices/>`_.

        Prefer to use ``addAutoScalingGroupCapacity`` if possible.

        :param auto_scaling_group: [disable-awslint:ref-via-interface].
        :param bootstrap_enabled: Configures the EC2 user-data script for instances in this autoscaling group to bootstrap the node (invoke ``/etc/eks/bootstrap.sh``) and associate it with the EKS cluster. If you wish to provide a custom user data script, set this to ``false`` and manually invoke ``autoscalingGroup.addUserData()``. Default: true
        :param bootstrap_options: Allows options for node bootstrapping through EC2 user data. Default: - default options
        :param machine_image_type: Allow options to specify different machine image type. Default: MachineImageType.AMAZON_LINUX_2
        :param map_role: Will automatically update the aws-auth ConfigMap to map the IAM instance role to RBAC. This cannot be explicitly set to ``true`` if the cluster has kubectl disabled. Default: - true if the cluster has kubectl enabled (which is the default).
        :param spot_interrupt_handler: Installs the AWS spot instance interrupt handler on the cluster if it's not already added. Only relevant if ``spotPrice`` is configured on the auto-scaling group. Default: true

        :see: https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html
        '''
        ...


class _IClusterProxy(
    jsii.proxy_for(_IResource_c80c4260), # type: ignore[misc]
    jsii.proxy_for(_IConnectable_10015a05), # type: ignore[misc]
):
    '''An EKS cluster.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_eks.ICluster"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterArn")
    def cluster_arn(self) -> builtins.str:
        '''The unique ARN assigned to the service by AWS in the form of arn:aws:eks:.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterCertificateAuthorityData")
    def cluster_certificate_authority_data(self) -> builtins.str:
        '''The certificate-authority-data for your cluster.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterCertificateAuthorityData"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterEncryptionConfigKeyArn")
    def cluster_encryption_config_key_arn(self) -> builtins.str:
        '''Amazon Resource Name (ARN) or alias of the customer master key (CMK).

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterEncryptionConfigKeyArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterEndpoint")
    def cluster_endpoint(self) -> builtins.str:
        '''The API Server endpoint URL.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterName")
    def cluster_name(self) -> builtins.str:
        '''The physical name of the Cluster.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterSecurityGroup")
    def cluster_security_group(self) -> _ISecurityGroup_acf8a799:
        '''The cluster security group that was created by Amazon EKS for the cluster.

        :attribute: true
        '''
        return typing.cast(_ISecurityGroup_acf8a799, jsii.get(self, "clusterSecurityGroup"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterSecurityGroupId")
    def cluster_security_group_id(self) -> builtins.str:
        '''The id of the cluster security group that was created by Amazon EKS for the cluster.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterSecurityGroupId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openIdConnectProvider")
    def open_id_connect_provider(self) -> _IOpenIdConnectProvider_203f0793:
        '''The Open ID Connect Provider of the cluster used to configure Service Accounts.'''
        return typing.cast(_IOpenIdConnectProvider_203f0793, jsii.get(self, "openIdConnectProvider"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="prune")
    def prune(self) -> builtins.bool:
        '''Indicates whether Kubernetes resources can be automatically pruned.

        When
        this is enabled (default), prune labels will be allocated and injected to
        each resource. These labels will then be used when issuing the ``kubectl apply`` operation with the ``--prune`` switch.
        '''
        return typing.cast(builtins.bool, jsii.get(self, "prune"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpc")
    def vpc(self) -> _IVpc_f30d5663:
        '''The VPC in which this Cluster was created.'''
        return typing.cast(_IVpc_f30d5663, jsii.get(self, "vpc"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterHandlerSecurityGroup")
    def cluster_handler_security_group(
        self,
    ) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''A security group to associate with the Cluster Handler's Lambdas.

        The Cluster Handler's Lambdas are responsible for calling AWS's EKS API.

        Requires ``placeClusterHandlerInVpc`` to be set to true.

        :default: - No security group.

        :attribute: true
        '''
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], jsii.get(self, "clusterHandlerSecurityGroup"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlEnvironment")
    def kubectl_environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom environment variables when running ``kubectl`` against this cluster.'''
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], jsii.get(self, "kubectlEnvironment"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlLambdaRole")
    def kubectl_lambda_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''An IAM role that can perform kubectl operations against this cluster.

        The role should be mapped to the ``system:masters`` Kubernetes RBAC role.

        This role is directly passed to the lambda handler that sends Kube Ctl commands to the cluster.
        '''
        return typing.cast(typing.Optional[_IRole_235f5d8e], jsii.get(self, "kubectlLambdaRole"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlLayer")
    def kubectl_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda layer that includes ``kubectl``, ``helm`` and the ``aws`` CLI.

        If not defined, a default layer will be used.
        '''
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], jsii.get(self, "kubectlLayer"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlMemory")
    def kubectl_memory(self) -> typing.Optional[_Size_7b441c34]:
        '''Amount of memory to allocate to the provider's lambda function.'''
        return typing.cast(typing.Optional[_Size_7b441c34], jsii.get(self, "kubectlMemory"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlPrivateSubnets")
    def kubectl_private_subnets(
        self,
    ) -> typing.Optional[typing.List[_ISubnet_d57d1229]]:
        '''Subnets to host the ``kubectl`` compute resources.

        If this is undefined, the k8s endpoint is expected to be accessible
        publicly.
        '''
        return typing.cast(typing.Optional[typing.List[_ISubnet_d57d1229]], jsii.get(self, "kubectlPrivateSubnets"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlProvider")
    def kubectl_provider(self) -> typing.Optional["IKubectlProvider"]:
        '''Kubectl Provider for issuing kubectl commands against it.

        If not defined, a default provider will be used
        '''
        return typing.cast(typing.Optional["IKubectlProvider"], jsii.get(self, "kubectlProvider"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlRole")
    def kubectl_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''An IAM role that can perform kubectl operations against this cluster.

        The role should be mapped to the ``system:masters`` Kubernetes RBAC role.
        '''
        return typing.cast(typing.Optional[_IRole_235f5d8e], jsii.get(self, "kubectlRole"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlSecurityGroup")
    def kubectl_security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''A security group to use for ``kubectl`` execution.

        If this is undefined, the k8s endpoint is expected to be accessible
        publicly.
        '''
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], jsii.get(self, "kubectlSecurityGroup"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="onEventLayer")
    def on_event_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda layer that includes the NPM dependency ``proxy-agent``.

        If not defined, a default layer will be used.
        '''
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], jsii.get(self, "onEventLayer"))

    @jsii.member(jsii_name="addCdk8sChart")
    def add_cdk8s_chart(
        self,
        id: builtins.str,
        chart: constructs.Construct,
        *,
        ingress_alb: typing.Optional[builtins.bool] = None,
        ingress_alb_scheme: typing.Optional[AlbScheme] = None,
        prune: typing.Optional[builtins.bool] = None,
        skip_validation: typing.Optional[builtins.bool] = None,
    ) -> "KubernetesManifest":
        '''Defines a CDK8s chart in this cluster.

        :param id: logical id of this chart.
        :param chart: the cdk8s chart.
        :param ingress_alb: Automatically detect ``Ingress`` resources in the manifest and annotate them so they are picked up by an ALB Ingress Controller. Default: false
        :param ingress_alb_scheme: Specify the ALB scheme that should be applied to ``Ingress`` resources. Only applicable if ``ingressAlb`` is set to ``true``. Default: AlbScheme.INTERNAL
        :param prune: When a resource is removed from a Kubernetes manifest, it no longer appears in the manifest, and there is no way to know that this resource needs to be deleted. To address this, ``kubectl apply`` has a ``--prune`` option which will query the cluster for all resources with a specific label and will remove all the labeld resources that are not part of the applied manifest. If this option is disabled and a resource is removed, it will become "orphaned" and will not be deleted from the cluster. When this option is enabled (default), the construct will inject a label to all Kubernetes resources included in this manifest which will be used to prune resources when the manifest changes via ``kubectl apply --prune``. The label name will be ``aws.cdk.eks/prune-<ADDR>`` where ``<ADDR>`` is the 42-char unique address of this construct in the construct tree. Value is empty. Default: - based on the prune option of the cluster, which is ``true`` unless otherwise specified.
        :param skip_validation: A flag to signify if the manifest validation should be skipped. Default: false

        :return: a ``KubernetesManifest`` construct representing the chart.
        '''
        options = KubernetesManifestOptions(
            ingress_alb=ingress_alb,
            ingress_alb_scheme=ingress_alb_scheme,
            prune=prune,
            skip_validation=skip_validation,
        )

        return typing.cast("KubernetesManifest", jsii.invoke(self, "addCdk8sChart", [id, chart, options]))

    @jsii.member(jsii_name="addHelmChart")
    def add_helm_chart(
        self,
        id: builtins.str,
        *,
        chart: typing.Optional[builtins.str] = None,
        chart_asset: typing.Optional[_Asset_ac2a7e61] = None,
        create_namespace: typing.Optional[builtins.bool] = None,
        namespace: typing.Optional[builtins.str] = None,
        release: typing.Optional[builtins.str] = None,
        repository: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        version: typing.Optional[builtins.str] = None,
        wait: typing.Optional[builtins.bool] = None,
    ) -> HelmChart:
        '''Defines a Helm chart in this cluster.

        :param id: logical id of this chart.
        :param chart: The name of the chart. Either this or ``chartAsset`` must be specified. Default: - No chart name. Implies ``chartAsset`` is used.
        :param chart_asset: The chart in the form of an asset. Either this or ``chart`` must be specified. Default: - No chart asset. Implies ``chart`` is used.
        :param create_namespace: create namespace if not exist. Default: true
        :param namespace: The Kubernetes namespace scope of the requests. Default: default
        :param release: The name of the release. Default: - If no release name is given, it will use the last 53 characters of the node's unique id.
        :param repository: The repository which contains the chart. For example: https://kubernetes-charts.storage.googleapis.com/ Default: - No repository will be used, which means that the chart needs to be an absolute URL.
        :param timeout: Amount of time to wait for any individual Kubernetes operation. Maximum 15 minutes. Default: Duration.minutes(5)
        :param values: The values to be used by the chart. Default: - No values are provided to the chart.
        :param version: The chart version to install. Default: - If this is not specified, the latest version is installed
        :param wait: Whether or not Helm should wait until all Pods, PVCs, Services, and minimum number of Pods of a Deployment, StatefulSet, or ReplicaSet are in a ready state before marking the release as successful. Default: - Helm will not wait before marking release as successful

        :return: a ``HelmChart`` construct
        '''
        options = HelmChartOptions(
            chart=chart,
            chart_asset=chart_asset,
            create_namespace=create_namespace,
            namespace=namespace,
            release=release,
            repository=repository,
            timeout=timeout,
            values=values,
            version=version,
            wait=wait,
        )

        return typing.cast(HelmChart, jsii.invoke(self, "addHelmChart", [id, options]))

    @jsii.member(jsii_name="addManifest")
    def add_manifest(
        self,
        id: builtins.str,
        *manifest: typing.Mapping[builtins.str, typing.Any],
    ) -> "KubernetesManifest":
        '''Defines a Kubernetes resource in this cluster.

        The manifest will be applied/deleted using kubectl as needed.

        :param id: logical id of this manifest.
        :param manifest: a list of Kubernetes resource specifications.

        :return: a ``KubernetesManifest`` object.
        '''
        return typing.cast("KubernetesManifest", jsii.invoke(self, "addManifest", [id, *manifest]))

    @jsii.member(jsii_name="addServiceAccount")
    def add_service_account(
        self,
        id: builtins.str,
        *,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> "ServiceAccount":
        '''Creates a new service account with corresponding IAM Role (IRSA).

        :param id: logical id of service account.
        :param name: The name of the service account. Default: - If no name is given, it will use the id of the resource.
        :param namespace: The namespace of the service account. Default: "default"
        '''
        options = ServiceAccountOptions(name=name, namespace=namespace)

        return typing.cast("ServiceAccount", jsii.invoke(self, "addServiceAccount", [id, options]))

    @jsii.member(jsii_name="connectAutoScalingGroupCapacity")
    def connect_auto_scaling_group_capacity(
        self,
        auto_scaling_group: _AutoScalingGroup_c547a7b9,
        *,
        bootstrap_enabled: typing.Optional[builtins.bool] = None,
        bootstrap_options: typing.Optional[BootstrapOptions] = None,
        machine_image_type: typing.Optional["MachineImageType"] = None,
        map_role: typing.Optional[builtins.bool] = None,
        spot_interrupt_handler: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Connect capacity in the form of an existing AutoScalingGroup to the EKS cluster.

        The AutoScalingGroup must be running an EKS-optimized AMI containing the
        /etc/eks/bootstrap.sh script. This method will configure Security Groups,
        add the right policies to the instance role, apply the right tags, and add
        the required user data to the instance's launch configuration.

        Spot instances will be labeled ``lifecycle=Ec2Spot`` and tainted with ``PreferNoSchedule``.
        If kubectl is enabled, the
        `spot interrupt handler <https://github.com/awslabs/ec2-spot-labs/tree/master/ec2-spot-eks-solution/spot-termination-handler>`_
        daemon will be installed on all spot instances to handle
        `EC2 Spot Instance Termination Notices <https://aws.amazon.com/blogs/aws/new-ec2-spot-instance-termination-notices/>`_.

        Prefer to use ``addAutoScalingGroupCapacity`` if possible.

        :param auto_scaling_group: [disable-awslint:ref-via-interface].
        :param bootstrap_enabled: Configures the EC2 user-data script for instances in this autoscaling group to bootstrap the node (invoke ``/etc/eks/bootstrap.sh``) and associate it with the EKS cluster. If you wish to provide a custom user data script, set this to ``false`` and manually invoke ``autoscalingGroup.addUserData()``. Default: true
        :param bootstrap_options: Allows options for node bootstrapping through EC2 user data. Default: - default options
        :param machine_image_type: Allow options to specify different machine image type. Default: MachineImageType.AMAZON_LINUX_2
        :param map_role: Will automatically update the aws-auth ConfigMap to map the IAM instance role to RBAC. This cannot be explicitly set to ``true`` if the cluster has kubectl disabled. Default: - true if the cluster has kubectl enabled (which is the default).
        :param spot_interrupt_handler: Installs the AWS spot instance interrupt handler on the cluster if it's not already added. Only relevant if ``spotPrice`` is configured on the auto-scaling group. Default: true

        :see: https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html
        '''
        options = AutoScalingGroupOptions(
            bootstrap_enabled=bootstrap_enabled,
            bootstrap_options=bootstrap_options,
            machine_image_type=machine_image_type,
            map_role=map_role,
            spot_interrupt_handler=spot_interrupt_handler,
        )

        return typing.cast(None, jsii.invoke(self, "connectAutoScalingGroupCapacity", [auto_scaling_group, options]))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, ICluster).__jsii_proxy_class__ = lambda : _IClusterProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_eks.IKubectlProvider")
class IKubectlProvider(constructs.IConstruct, typing_extensions.Protocol):
    '''Imported KubectlProvider that can be used in place of the default one created by CDK.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="handlerRole")
    def handler_role(self) -> _IRole_235f5d8e:
        '''The IAM execution role of the handler.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''The IAM role to assume in order to perform kubectl operations against this cluster.'''
        ...

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceToken")
    def service_token(self) -> builtins.str:
        '''The custom resource provider's service token.'''
        ...


class _IKubectlProviderProxy(
    jsii.proxy_for(constructs.IConstruct) # type: ignore[misc]
):
    '''Imported KubectlProvider that can be used in place of the default one created by CDK.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_eks.IKubectlProvider"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="handlerRole")
    def handler_role(self) -> _IRole_235f5d8e:
        '''The IAM execution role of the handler.'''
        return typing.cast(_IRole_235f5d8e, jsii.get(self, "handlerRole"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''The IAM role to assume in order to perform kubectl operations against this cluster.'''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceToken")
    def service_token(self) -> builtins.str:
        '''The custom resource provider's service token.'''
        return typing.cast(builtins.str, jsii.get(self, "serviceToken"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, IKubectlProvider).__jsii_proxy_class__ = lambda : _IKubectlProviderProxy


@jsii.interface(jsii_type="aws-cdk-lib.aws_eks.INodegroup")
class INodegroup(_IResource_c80c4260, typing_extensions.Protocol):
    '''NodeGroup interface.'''

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="nodegroupName")
    def nodegroup_name(self) -> builtins.str:
        '''Name of the nodegroup.

        :attribute: true
        '''
        ...


class _INodegroupProxy(
    jsii.proxy_for(_IResource_c80c4260) # type: ignore[misc]
):
    '''NodeGroup interface.'''

    __jsii_type__: typing.ClassVar[str] = "aws-cdk-lib.aws_eks.INodegroup"

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="nodegroupName")
    def nodegroup_name(self) -> builtins.str:
        '''Name of the nodegroup.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "nodegroupName"))

# Adding a "__jsii_proxy_class__(): typing.Type" function to the interface
typing.cast(typing.Any, INodegroup).__jsii_proxy_class__ = lambda : _INodegroupProxy


@jsii.implements(IKubectlProvider)
class KubectlProvider(
    _NestedStack_dd393a45,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.KubectlProvider",
):
    '''Implementation of Kubectl Lambda.

    :exampleMetadata: infused

    Example::

        handler_role = iam.Role.from_role_arn(self, "HandlerRole", "arn:aws:iam::123456789012:role/lambda-role")
        kubectl_provider = eks.KubectlProvider.from_kubectl_provider_attributes(self, "KubectlProvider",
            function_arn="arn:aws:lambda:us-east-2:123456789012:function:my-function:1",
            kubectl_role_arn="arn:aws:iam::123456789012:role/kubectl-role",
            handler_role=handler_role
        )
        
        cluster = eks.Cluster.from_cluster_attributes(self, "Cluster",
            cluster_name="cluster",
            kubectl_provider=kubectl_provider
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster: ICluster,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param cluster: The cluster to control.
        '''
        props = KubectlProviderProps(cluster=cluster)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromKubectlProviderAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_kubectl_provider_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        function_arn: builtins.str,
        handler_role: _IRole_235f5d8e,
        kubectl_role_arn: builtins.str,
    ) -> IKubectlProvider:
        '''Import an existing provider.

        :param scope: Construct.
        :param id: an id of resource.
        :param function_arn: The kubectl provider lambda arn.
        :param handler_role: The IAM execution role of the handler. This role must be able to assume kubectlRoleArn
        :param kubectl_role_arn: The IAM role to assume in order to perform kubectl operations against this cluster.
        '''
        attrs = KubectlProviderAttributes(
            function_arn=function_arn,
            handler_role=handler_role,
            kubectl_role_arn=kubectl_role_arn,
        )

        return typing.cast(IKubectlProvider, jsii.sinvoke(cls, "fromKubectlProviderAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="getOrCreate") # type: ignore[misc]
    @builtins.classmethod
    def get_or_create(
        cls,
        scope: constructs.Construct,
        cluster: ICluster,
    ) -> IKubectlProvider:
        '''Take existing provider or create new based on cluster.

        :param scope: Construct.
        :param cluster: k8s cluster.
        '''
        return typing.cast(IKubectlProvider, jsii.sinvoke(cls, "getOrCreate", [scope, cluster]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="handlerRole")
    def handler_role(self) -> _IRole_235f5d8e:
        '''The IAM execution role of the handler.'''
        return typing.cast(_IRole_235f5d8e, jsii.get(self, "handlerRole"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="roleArn")
    def role_arn(self) -> builtins.str:
        '''The IAM role to assume in order to perform kubectl operations against this cluster.'''
        return typing.cast(builtins.str, jsii.get(self, "roleArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceToken")
    def service_token(self) -> builtins.str:
        '''The custom resource provider's service token.'''
        return typing.cast(builtins.str, jsii.get(self, "serviceToken"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.KubectlProviderAttributes",
    jsii_struct_bases=[],
    name_mapping={
        "function_arn": "functionArn",
        "handler_role": "handlerRole",
        "kubectl_role_arn": "kubectlRoleArn",
    },
)
class KubectlProviderAttributes:
    def __init__(
        self,
        *,
        function_arn: builtins.str,
        handler_role: _IRole_235f5d8e,
        kubectl_role_arn: builtins.str,
    ) -> None:
        '''Kubectl Provider Attributes.

        :param function_arn: The kubectl provider lambda arn.
        :param handler_role: The IAM execution role of the handler. This role must be able to assume kubectlRoleArn
        :param kubectl_role_arn: The IAM role to assume in order to perform kubectl operations against this cluster.

        :exampleMetadata: infused

        Example::

            handler_role = iam.Role.from_role_arn(self, "HandlerRole", "arn:aws:iam::123456789012:role/lambda-role")
            kubectl_provider = eks.KubectlProvider.from_kubectl_provider_attributes(self, "KubectlProvider",
                function_arn="arn:aws:lambda:us-east-2:123456789012:function:my-function:1",
                kubectl_role_arn="arn:aws:iam::123456789012:role/kubectl-role",
                handler_role=handler_role
            )
            
            cluster = eks.Cluster.from_cluster_attributes(self, "Cluster",
                cluster_name="cluster",
                kubectl_provider=kubectl_provider
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "function_arn": function_arn,
            "handler_role": handler_role,
            "kubectl_role_arn": kubectl_role_arn,
        }

    @builtins.property
    def function_arn(self) -> builtins.str:
        '''The kubectl provider lambda arn.'''
        result = self._values.get("function_arn")
        assert result is not None, "Required property 'function_arn' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def handler_role(self) -> _IRole_235f5d8e:
        '''The IAM execution role of the handler.

        This role must be able to assume kubectlRoleArn
        '''
        result = self._values.get("handler_role")
        assert result is not None, "Required property 'handler_role' is missing"
        return typing.cast(_IRole_235f5d8e, result)

    @builtins.property
    def kubectl_role_arn(self) -> builtins.str:
        '''The IAM role to assume in order to perform kubectl operations against this cluster.'''
        result = self._values.get("kubectl_role_arn")
        assert result is not None, "Required property 'kubectl_role_arn' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "KubectlProviderAttributes(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.KubectlProviderProps",
    jsii_struct_bases=[],
    name_mapping={"cluster": "cluster"},
)
class KubectlProviderProps:
    def __init__(self, *, cluster: ICluster) -> None:
        '''Properties for a KubectlProvider.

        :param cluster: The cluster to control.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            # cluster: eks.Cluster
            
            kubectl_provider_props = eks.KubectlProviderProps(
                cluster=cluster
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster": cluster,
        }

    @builtins.property
    def cluster(self) -> ICluster:
        '''The cluster to control.'''
        result = self._values.get("cluster")
        assert result is not None, "Required property 'cluster' is missing"
        return typing.cast(ICluster, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "KubectlProviderProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class KubernetesManifest(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.KubernetesManifest",
):
    '''Represents a manifest within the Kubernetes system.

    Alternatively, you can use ``cluster.addManifest(resource[, resource, ...])``
    to define resources on this cluster.

    Applies/deletes the manifest using ``kubectl``.

    :exampleMetadata: infused

    Example::

        # cluster: eks.Cluster
        
        namespace = cluster.add_manifest("my-namespace", {
            "api_version": "v1",
            "kind": "Namespace",
            "metadata": {"name": "my-app"}
        })
        
        service = cluster.add_manifest("my-service", {
            "metadata": {
                "name": "myservice",
                "namespace": "my-app"
            },
            "spec": {}
        })
        
        service.node.add_dependency(namespace)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster: ICluster,
        manifest: typing.Sequence[typing.Mapping[builtins.str, typing.Any]],
        overwrite: typing.Optional[builtins.bool] = None,
        ingress_alb: typing.Optional[builtins.bool] = None,
        ingress_alb_scheme: typing.Optional[AlbScheme] = None,
        prune: typing.Optional[builtins.bool] = None,
        skip_validation: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param cluster: The EKS cluster to apply this manifest to. [disable-awslint:ref-via-interface]
        :param manifest: The manifest to apply. Consists of any number of child resources. When the resources are created/updated, this manifest will be applied to the cluster through ``kubectl apply`` and when the resources or the stack is deleted, the resources in the manifest will be deleted through ``kubectl delete``.
        :param overwrite: Overwrite any existing resources. If this is set, we will use ``kubectl apply`` instead of ``kubectl create`` when the resource is created. Otherwise, if there is already a resource in the cluster with the same name, the operation will fail. Default: false
        :param ingress_alb: Automatically detect ``Ingress`` resources in the manifest and annotate them so they are picked up by an ALB Ingress Controller. Default: false
        :param ingress_alb_scheme: Specify the ALB scheme that should be applied to ``Ingress`` resources. Only applicable if ``ingressAlb`` is set to ``true``. Default: AlbScheme.INTERNAL
        :param prune: When a resource is removed from a Kubernetes manifest, it no longer appears in the manifest, and there is no way to know that this resource needs to be deleted. To address this, ``kubectl apply`` has a ``--prune`` option which will query the cluster for all resources with a specific label and will remove all the labeld resources that are not part of the applied manifest. If this option is disabled and a resource is removed, it will become "orphaned" and will not be deleted from the cluster. When this option is enabled (default), the construct will inject a label to all Kubernetes resources included in this manifest which will be used to prune resources when the manifest changes via ``kubectl apply --prune``. The label name will be ``aws.cdk.eks/prune-<ADDR>`` where ``<ADDR>`` is the 42-char unique address of this construct in the construct tree. Value is empty. Default: - based on the prune option of the cluster, which is ``true`` unless otherwise specified.
        :param skip_validation: A flag to signify if the manifest validation should be skipped. Default: false
        '''
        props = KubernetesManifestProps(
            cluster=cluster,
            manifest=manifest,
            overwrite=overwrite,
            ingress_alb=ingress_alb,
            ingress_alb_scheme=ingress_alb_scheme,
            prune=prune,
            skip_validation=skip_validation,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="RESOURCE_TYPE")
    def RESOURCE_TYPE(cls) -> builtins.str:
        '''The CloudFormation reosurce type.'''
        return typing.cast(builtins.str, jsii.sget(cls, "RESOURCE_TYPE"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.KubernetesManifestOptions",
    jsii_struct_bases=[],
    name_mapping={
        "ingress_alb": "ingressAlb",
        "ingress_alb_scheme": "ingressAlbScheme",
        "prune": "prune",
        "skip_validation": "skipValidation",
    },
)
class KubernetesManifestOptions:
    def __init__(
        self,
        *,
        ingress_alb: typing.Optional[builtins.bool] = None,
        ingress_alb_scheme: typing.Optional[AlbScheme] = None,
        prune: typing.Optional[builtins.bool] = None,
        skip_validation: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Options for ``KubernetesManifest``.

        :param ingress_alb: Automatically detect ``Ingress`` resources in the manifest and annotate them so they are picked up by an ALB Ingress Controller. Default: false
        :param ingress_alb_scheme: Specify the ALB scheme that should be applied to ``Ingress`` resources. Only applicable if ``ingressAlb`` is set to ``true``. Default: AlbScheme.INTERNAL
        :param prune: When a resource is removed from a Kubernetes manifest, it no longer appears in the manifest, and there is no way to know that this resource needs to be deleted. To address this, ``kubectl apply`` has a ``--prune`` option which will query the cluster for all resources with a specific label and will remove all the labeld resources that are not part of the applied manifest. If this option is disabled and a resource is removed, it will become "orphaned" and will not be deleted from the cluster. When this option is enabled (default), the construct will inject a label to all Kubernetes resources included in this manifest which will be used to prune resources when the manifest changes via ``kubectl apply --prune``. The label name will be ``aws.cdk.eks/prune-<ADDR>`` where ``<ADDR>`` is the 42-char unique address of this construct in the construct tree. Value is empty. Default: - based on the prune option of the cluster, which is ``true`` unless otherwise specified.
        :param skip_validation: A flag to signify if the manifest validation should be skipped. Default: false

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            kubernetes_manifest_options = eks.KubernetesManifestOptions(
                ingress_alb=False,
                ingress_alb_scheme=eks.AlbScheme.INTERNAL,
                prune=False,
                skip_validation=False
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if ingress_alb is not None:
            self._values["ingress_alb"] = ingress_alb
        if ingress_alb_scheme is not None:
            self._values["ingress_alb_scheme"] = ingress_alb_scheme
        if prune is not None:
            self._values["prune"] = prune
        if skip_validation is not None:
            self._values["skip_validation"] = skip_validation

    @builtins.property
    def ingress_alb(self) -> typing.Optional[builtins.bool]:
        '''Automatically detect ``Ingress`` resources in the manifest and annotate them so they are picked up by an ALB Ingress Controller.

        :default: false
        '''
        result = self._values.get("ingress_alb")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def ingress_alb_scheme(self) -> typing.Optional[AlbScheme]:
        '''Specify the ALB scheme that should be applied to ``Ingress`` resources.

        Only applicable if ``ingressAlb`` is set to ``true``.

        :default: AlbScheme.INTERNAL
        '''
        result = self._values.get("ingress_alb_scheme")
        return typing.cast(typing.Optional[AlbScheme], result)

    @builtins.property
    def prune(self) -> typing.Optional[builtins.bool]:
        '''When a resource is removed from a Kubernetes manifest, it no longer appears in the manifest, and there is no way to know that this resource needs to be deleted.

        To address this, ``kubectl apply`` has a ``--prune`` option which will
        query the cluster for all resources with a specific label and will remove
        all the labeld resources that are not part of the applied manifest. If this
        option is disabled and a resource is removed, it will become "orphaned" and
        will not be deleted from the cluster.

        When this option is enabled (default), the construct will inject a label to
        all Kubernetes resources included in this manifest which will be used to
        prune resources when the manifest changes via ``kubectl apply --prune``.

        The label name will be ``aws.cdk.eks/prune-<ADDR>`` where ``<ADDR>`` is the
        42-char unique address of this construct in the construct tree. Value is
        empty.

        :default:

        - based on the prune option of the cluster, which is ``true`` unless
        otherwise specified.

        :see: https://kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/#alternative-kubectl-apply-f-directory-prune-l-your-label
        '''
        result = self._values.get("prune")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def skip_validation(self) -> typing.Optional[builtins.bool]:
        '''A flag to signify if the manifest validation should be skipped.

        :default: false
        '''
        result = self._values.get("skip_validation")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "KubernetesManifestOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.KubernetesManifestProps",
    jsii_struct_bases=[KubernetesManifestOptions],
    name_mapping={
        "ingress_alb": "ingressAlb",
        "ingress_alb_scheme": "ingressAlbScheme",
        "prune": "prune",
        "skip_validation": "skipValidation",
        "cluster": "cluster",
        "manifest": "manifest",
        "overwrite": "overwrite",
    },
)
class KubernetesManifestProps(KubernetesManifestOptions):
    def __init__(
        self,
        *,
        ingress_alb: typing.Optional[builtins.bool] = None,
        ingress_alb_scheme: typing.Optional[AlbScheme] = None,
        prune: typing.Optional[builtins.bool] = None,
        skip_validation: typing.Optional[builtins.bool] = None,
        cluster: ICluster,
        manifest: typing.Sequence[typing.Mapping[builtins.str, typing.Any]],
        overwrite: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Properties for KubernetesManifest.

        :param ingress_alb: Automatically detect ``Ingress`` resources in the manifest and annotate them so they are picked up by an ALB Ingress Controller. Default: false
        :param ingress_alb_scheme: Specify the ALB scheme that should be applied to ``Ingress`` resources. Only applicable if ``ingressAlb`` is set to ``true``. Default: AlbScheme.INTERNAL
        :param prune: When a resource is removed from a Kubernetes manifest, it no longer appears in the manifest, and there is no way to know that this resource needs to be deleted. To address this, ``kubectl apply`` has a ``--prune`` option which will query the cluster for all resources with a specific label and will remove all the labeld resources that are not part of the applied manifest. If this option is disabled and a resource is removed, it will become "orphaned" and will not be deleted from the cluster. When this option is enabled (default), the construct will inject a label to all Kubernetes resources included in this manifest which will be used to prune resources when the manifest changes via ``kubectl apply --prune``. The label name will be ``aws.cdk.eks/prune-<ADDR>`` where ``<ADDR>`` is the 42-char unique address of this construct in the construct tree. Value is empty. Default: - based on the prune option of the cluster, which is ``true`` unless otherwise specified.
        :param skip_validation: A flag to signify if the manifest validation should be skipped. Default: false
        :param cluster: The EKS cluster to apply this manifest to. [disable-awslint:ref-via-interface]
        :param manifest: The manifest to apply. Consists of any number of child resources. When the resources are created/updated, this manifest will be applied to the cluster through ``kubectl apply`` and when the resources or the stack is deleted, the resources in the manifest will be deleted through ``kubectl delete``.
        :param overwrite: Overwrite any existing resources. If this is set, we will use ``kubectl apply`` instead of ``kubectl create`` when the resource is created. Otherwise, if there is already a resource in the cluster with the same name, the operation will fail. Default: false

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            
            app_label = {"app": "hello-kubernetes"}
            
            deployment = {
                "api_version": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "hello-kubernetes"},
                "spec": {
                    "replicas": 3,
                    "selector": {"match_labels": app_label},
                    "template": {
                        "metadata": {"labels": app_label},
                        "spec": {
                            "containers": [{
                                "name": "hello-kubernetes",
                                "image": "paulbouwer/hello-kubernetes:1.5",
                                "ports": [{"container_port": 8080}]
                            }
                            ]
                        }
                    }
                }
            }
            
            service = {
                "api_version": "v1",
                "kind": "Service",
                "metadata": {"name": "hello-kubernetes"},
                "spec": {
                    "type": "LoadBalancer",
                    "ports": [{"port": 80, "target_port": 8080}],
                    "selector": app_label
                }
            }
            
            # option 1: use a construct
            eks.KubernetesManifest(self, "hello-kub",
                cluster=cluster,
                manifest=[deployment, service]
            )
            
            # or, option2: use `addManifest`
            cluster.add_manifest("hello-kub", service, deployment)
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster": cluster,
            "manifest": manifest,
        }
        if ingress_alb is not None:
            self._values["ingress_alb"] = ingress_alb
        if ingress_alb_scheme is not None:
            self._values["ingress_alb_scheme"] = ingress_alb_scheme
        if prune is not None:
            self._values["prune"] = prune
        if skip_validation is not None:
            self._values["skip_validation"] = skip_validation
        if overwrite is not None:
            self._values["overwrite"] = overwrite

    @builtins.property
    def ingress_alb(self) -> typing.Optional[builtins.bool]:
        '''Automatically detect ``Ingress`` resources in the manifest and annotate them so they are picked up by an ALB Ingress Controller.

        :default: false
        '''
        result = self._values.get("ingress_alb")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def ingress_alb_scheme(self) -> typing.Optional[AlbScheme]:
        '''Specify the ALB scheme that should be applied to ``Ingress`` resources.

        Only applicable if ``ingressAlb`` is set to ``true``.

        :default: AlbScheme.INTERNAL
        '''
        result = self._values.get("ingress_alb_scheme")
        return typing.cast(typing.Optional[AlbScheme], result)

    @builtins.property
    def prune(self) -> typing.Optional[builtins.bool]:
        '''When a resource is removed from a Kubernetes manifest, it no longer appears in the manifest, and there is no way to know that this resource needs to be deleted.

        To address this, ``kubectl apply`` has a ``--prune`` option which will
        query the cluster for all resources with a specific label and will remove
        all the labeld resources that are not part of the applied manifest. If this
        option is disabled and a resource is removed, it will become "orphaned" and
        will not be deleted from the cluster.

        When this option is enabled (default), the construct will inject a label to
        all Kubernetes resources included in this manifest which will be used to
        prune resources when the manifest changes via ``kubectl apply --prune``.

        The label name will be ``aws.cdk.eks/prune-<ADDR>`` where ``<ADDR>`` is the
        42-char unique address of this construct in the construct tree. Value is
        empty.

        :default:

        - based on the prune option of the cluster, which is ``true`` unless
        otherwise specified.

        :see: https://kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/#alternative-kubectl-apply-f-directory-prune-l-your-label
        '''
        result = self._values.get("prune")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def skip_validation(self) -> typing.Optional[builtins.bool]:
        '''A flag to signify if the manifest validation should be skipped.

        :default: false
        '''
        result = self._values.get("skip_validation")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def cluster(self) -> ICluster:
        '''The EKS cluster to apply this manifest to.

        [disable-awslint:ref-via-interface]
        '''
        result = self._values.get("cluster")
        assert result is not None, "Required property 'cluster' is missing"
        return typing.cast(ICluster, result)

    @builtins.property
    def manifest(self) -> typing.List[typing.Mapping[builtins.str, typing.Any]]:
        '''The manifest to apply.

        Consists of any number of child resources.

        When the resources are created/updated, this manifest will be applied to the
        cluster through ``kubectl apply`` and when the resources or the stack is
        deleted, the resources in the manifest will be deleted through ``kubectl delete``.

        Example::

            [{
                "api_version": "v1",
                "kind": "Pod",
                "metadata": {"name": "mypod"},
                "spec": {
                    "containers": [{"name": "hello", "image": "paulbouwer/hello-kubernetes:1.5", "ports": [{"container_port": 8080}]}]
                }
            }]
        '''
        result = self._values.get("manifest")
        assert result is not None, "Required property 'manifest' is missing"
        return typing.cast(typing.List[typing.Mapping[builtins.str, typing.Any]], result)

    @builtins.property
    def overwrite(self) -> typing.Optional[builtins.bool]:
        '''Overwrite any existing resources.

        If this is set, we will use ``kubectl apply`` instead of ``kubectl create``
        when the resource is created. Otherwise, if there is already a resource
        in the cluster with the same name, the operation will fail.

        :default: false
        '''
        result = self._values.get("overwrite")
        return typing.cast(typing.Optional[builtins.bool], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "KubernetesManifestProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class KubernetesObjectValue(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.KubernetesObjectValue",
):
    '''Represents a value of a specific object deployed in the cluster.

    Use this to fetch any information available by the ``kubectl get`` command.

    :exampleMetadata: infused

    Example::

        # cluster: eks.Cluster
        
        # query the load balancer address
        my_service_address = eks.KubernetesObjectValue(self, "LoadBalancerAttribute",
            cluster=cluster,
            object_type="service",
            object_name="my-service",
            json_path=".status.loadBalancer.ingress[0].hostname"
        )
        
        # pass the address to a lambda function
        proxy_function = lambda_.Function(self, "ProxyFunction",
            handler="index.handler",
            code=lambda_.Code.from_inline("my-code"),
            runtime=lambda_.Runtime.NODEJS_14_X,
            environment={
                "my_service_address": my_service_address.value
            }
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster: ICluster,
        json_path: builtins.str,
        object_name: builtins.str,
        object_type: builtins.str,
        object_namespace: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param cluster: The EKS cluster to fetch attributes from. [disable-awslint:ref-via-interface]
        :param json_path: JSONPath to the specific value.
        :param object_name: The name of the object to query.
        :param object_type: The object type to query. (e.g 'service', 'pod'...)
        :param object_namespace: The namespace the object belongs to. Default: 'default'
        :param timeout: Timeout for waiting on a value. Default: Duration.minutes(5)
        '''
        props = KubernetesObjectValueProps(
            cluster=cluster,
            json_path=json_path,
            object_name=object_name,
            object_type=object_type,
            object_namespace=object_namespace,
            timeout=timeout,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="RESOURCE_TYPE")
    def RESOURCE_TYPE(cls) -> builtins.str:
        '''The CloudFormation reosurce type.'''
        return typing.cast(builtins.str, jsii.sget(cls, "RESOURCE_TYPE"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="value")
    def value(self) -> builtins.str:
        '''The value as a string token.'''
        return typing.cast(builtins.str, jsii.get(self, "value"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.KubernetesObjectValueProps",
    jsii_struct_bases=[],
    name_mapping={
        "cluster": "cluster",
        "json_path": "jsonPath",
        "object_name": "objectName",
        "object_type": "objectType",
        "object_namespace": "objectNamespace",
        "timeout": "timeout",
    },
)
class KubernetesObjectValueProps:
    def __init__(
        self,
        *,
        cluster: ICluster,
        json_path: builtins.str,
        object_name: builtins.str,
        object_type: builtins.str,
        object_namespace: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Properties for KubernetesObjectValue.

        :param cluster: The EKS cluster to fetch attributes from. [disable-awslint:ref-via-interface]
        :param json_path: JSONPath to the specific value.
        :param object_name: The name of the object to query.
        :param object_type: The object type to query. (e.g 'service', 'pod'...)
        :param object_namespace: The namespace the object belongs to. Default: 'default'
        :param timeout: Timeout for waiting on a value. Default: Duration.minutes(5)

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            
            # query the load balancer address
            my_service_address = eks.KubernetesObjectValue(self, "LoadBalancerAttribute",
                cluster=cluster,
                object_type="service",
                object_name="my-service",
                json_path=".status.loadBalancer.ingress[0].hostname"
            )
            
            # pass the address to a lambda function
            proxy_function = lambda_.Function(self, "ProxyFunction",
                handler="index.handler",
                code=lambda_.Code.from_inline("my-code"),
                runtime=lambda_.Runtime.NODEJS_14_X,
                environment={
                    "my_service_address": my_service_address.value
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster": cluster,
            "json_path": json_path,
            "object_name": object_name,
            "object_type": object_type,
        }
        if object_namespace is not None:
            self._values["object_namespace"] = object_namespace
        if timeout is not None:
            self._values["timeout"] = timeout

    @builtins.property
    def cluster(self) -> ICluster:
        '''The EKS cluster to fetch attributes from.

        [disable-awslint:ref-via-interface]
        '''
        result = self._values.get("cluster")
        assert result is not None, "Required property 'cluster' is missing"
        return typing.cast(ICluster, result)

    @builtins.property
    def json_path(self) -> builtins.str:
        '''JSONPath to the specific value.

        :see: https://kubernetes.io/docs/reference/kubectl/jsonpath/
        '''
        result = self._values.get("json_path")
        assert result is not None, "Required property 'json_path' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def object_name(self) -> builtins.str:
        '''The name of the object to query.'''
        result = self._values.get("object_name")
        assert result is not None, "Required property 'object_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def object_type(self) -> builtins.str:
        '''The object type to query.

        (e.g 'service', 'pod'...)
        '''
        result = self._values.get("object_type")
        assert result is not None, "Required property 'object_type' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def object_namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace the object belongs to.

        :default: 'default'
        '''
        result = self._values.get("object_namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Timeout for waiting on a value.

        :default: Duration.minutes(5)
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "KubernetesObjectValueProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class KubernetesPatch(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.KubernetesPatch",
):
    '''A CloudFormation resource which applies/restores a JSON patch into a Kubernetes resource.

    :see: https://kubernetes.io/docs/tasks/run-application/update-api-object-kubectl-patch/
    :exampleMetadata: infused

    Example::

        # cluster: eks.Cluster
        
        eks.KubernetesPatch(self, "hello-kub-deployment-label",
            cluster=cluster,
            resource_name="deployment/hello-kubernetes",
            apply_patch={"spec": {"replicas": 5}},
            restore_patch={"spec": {"replicas": 3}}
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        apply_patch: typing.Mapping[builtins.str, typing.Any],
        cluster: ICluster,
        resource_name: builtins.str,
        restore_patch: typing.Mapping[builtins.str, typing.Any],
        patch_type: typing.Optional["PatchType"] = None,
        resource_namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param apply_patch: The JSON object to pass to ``kubectl patch`` when the resource is created/updated.
        :param cluster: The cluster to apply the patch to. [disable-awslint:ref-via-interface]
        :param resource_name: The full name of the resource to patch (e.g. ``deployment/coredns``).
        :param restore_patch: The JSON object to pass to ``kubectl patch`` when the resource is removed.
        :param patch_type: The patch type to pass to ``kubectl patch``. The default type used by ``kubectl patch`` is "strategic". Default: PatchType.STRATEGIC
        :param resource_namespace: The kubernetes API namespace. Default: "default"
        '''
        props = KubernetesPatchProps(
            apply_patch=apply_patch,
            cluster=cluster,
            resource_name=resource_name,
            restore_patch=restore_patch,
            patch_type=patch_type,
            resource_namespace=resource_namespace,
        )

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.KubernetesPatchProps",
    jsii_struct_bases=[],
    name_mapping={
        "apply_patch": "applyPatch",
        "cluster": "cluster",
        "resource_name": "resourceName",
        "restore_patch": "restorePatch",
        "patch_type": "patchType",
        "resource_namespace": "resourceNamespace",
    },
)
class KubernetesPatchProps:
    def __init__(
        self,
        *,
        apply_patch: typing.Mapping[builtins.str, typing.Any],
        cluster: ICluster,
        resource_name: builtins.str,
        restore_patch: typing.Mapping[builtins.str, typing.Any],
        patch_type: typing.Optional["PatchType"] = None,
        resource_namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Properties for KubernetesPatch.

        :param apply_patch: The JSON object to pass to ``kubectl patch`` when the resource is created/updated.
        :param cluster: The cluster to apply the patch to. [disable-awslint:ref-via-interface]
        :param resource_name: The full name of the resource to patch (e.g. ``deployment/coredns``).
        :param restore_patch: The JSON object to pass to ``kubectl patch`` when the resource is removed.
        :param patch_type: The patch type to pass to ``kubectl patch``. The default type used by ``kubectl patch`` is "strategic". Default: PatchType.STRATEGIC
        :param resource_namespace: The kubernetes API namespace. Default: "default"

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            
            eks.KubernetesPatch(self, "hello-kub-deployment-label",
                cluster=cluster,
                resource_name="deployment/hello-kubernetes",
                apply_patch={"spec": {"replicas": 5}},
                restore_patch={"spec": {"replicas": 3}}
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "apply_patch": apply_patch,
            "cluster": cluster,
            "resource_name": resource_name,
            "restore_patch": restore_patch,
        }
        if patch_type is not None:
            self._values["patch_type"] = patch_type
        if resource_namespace is not None:
            self._values["resource_namespace"] = resource_namespace

    @builtins.property
    def apply_patch(self) -> typing.Mapping[builtins.str, typing.Any]:
        '''The JSON object to pass to ``kubectl patch`` when the resource is created/updated.'''
        result = self._values.get("apply_patch")
        assert result is not None, "Required property 'apply_patch' is missing"
        return typing.cast(typing.Mapping[builtins.str, typing.Any], result)

    @builtins.property
    def cluster(self) -> ICluster:
        '''The cluster to apply the patch to.

        [disable-awslint:ref-via-interface]
        '''
        result = self._values.get("cluster")
        assert result is not None, "Required property 'cluster' is missing"
        return typing.cast(ICluster, result)

    @builtins.property
    def resource_name(self) -> builtins.str:
        '''The full name of the resource to patch (e.g. ``deployment/coredns``).'''
        result = self._values.get("resource_name")
        assert result is not None, "Required property 'resource_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def restore_patch(self) -> typing.Mapping[builtins.str, typing.Any]:
        '''The JSON object to pass to ``kubectl patch`` when the resource is removed.'''
        result = self._values.get("restore_patch")
        assert result is not None, "Required property 'restore_patch' is missing"
        return typing.cast(typing.Mapping[builtins.str, typing.Any], result)

    @builtins.property
    def patch_type(self) -> typing.Optional["PatchType"]:
        '''The patch type to pass to ``kubectl patch``.

        The default type used by ``kubectl patch`` is "strategic".

        :default: PatchType.STRATEGIC
        '''
        result = self._values.get("patch_type")
        return typing.cast(typing.Optional["PatchType"], result)

    @builtins.property
    def resource_namespace(self) -> typing.Optional[builtins.str]:
        '''The kubernetes API namespace.

        :default: "default"
        '''
        result = self._values.get("resource_namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "KubernetesPatchProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class KubernetesVersion(
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.KubernetesVersion",
):
    '''Kubernetes cluster version.

    :exampleMetadata: infused

    Example::

        cluster = eks.Cluster(self, "HelloEKS",
            version=eks.KubernetesVersion.V1_21,
            default_capacity_type=eks.DefaultCapacityType.EC2
        )
    '''

    @jsii.member(jsii_name="of") # type: ignore[misc]
    @builtins.classmethod
    def of(cls, version: builtins.str) -> "KubernetesVersion":
        '''Custom cluster version.

        :param version: custom version number.
        '''
        return typing.cast("KubernetesVersion", jsii.sinvoke(cls, "of", [version]))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V1_14")
    def V1_14(cls) -> "KubernetesVersion":
        '''(deprecated) Kubernetes version 1.14.

        :deprecated: Use newer version of EKS

        :stability: deprecated
        '''
        return typing.cast("KubernetesVersion", jsii.sget(cls, "V1_14"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V1_15")
    def V1_15(cls) -> "KubernetesVersion":
        '''(deprecated) Kubernetes version 1.15.

        :deprecated: Use newer version of EKS

        :stability: deprecated
        '''
        return typing.cast("KubernetesVersion", jsii.sget(cls, "V1_15"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V1_16")
    def V1_16(cls) -> "KubernetesVersion":
        '''(deprecated) Kubernetes version 1.16.

        :deprecated: Use newer version of EKS

        :stability: deprecated
        '''
        return typing.cast("KubernetesVersion", jsii.sget(cls, "V1_16"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V1_17")
    def V1_17(cls) -> "KubernetesVersion":
        '''(deprecated) Kubernetes version 1.17.

        :deprecated: Use newer version of EKS

        :stability: deprecated
        '''
        return typing.cast("KubernetesVersion", jsii.sget(cls, "V1_17"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V1_18")
    def V1_18(cls) -> "KubernetesVersion":
        '''Kubernetes version 1.18.'''
        return typing.cast("KubernetesVersion", jsii.sget(cls, "V1_18"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V1_19")
    def V1_19(cls) -> "KubernetesVersion":
        '''Kubernetes version 1.19.'''
        return typing.cast("KubernetesVersion", jsii.sget(cls, "V1_19"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V1_20")
    def V1_20(cls) -> "KubernetesVersion":
        '''Kubernetes version 1.20.'''
        return typing.cast("KubernetesVersion", jsii.sget(cls, "V1_20"))

    @jsii.python.classproperty # type: ignore[misc]
    @jsii.member(jsii_name="V1_21")
    def V1_21(cls) -> "KubernetesVersion":
        '''Kubernetes version 1.21.'''
        return typing.cast("KubernetesVersion", jsii.sget(cls, "V1_21"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="version")
    def version(self) -> builtins.str:
        '''cluster version number.'''
        return typing.cast(builtins.str, jsii.get(self, "version"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.LaunchTemplateSpec",
    jsii_struct_bases=[],
    name_mapping={"id": "id", "version": "version"},
)
class LaunchTemplateSpec:
    def __init__(
        self,
        *,
        id: builtins.str,
        version: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Launch template property specification.

        :param id: The Launch template ID.
        :param version: The launch template version to be used (optional). Default: - the default version of the launch template

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            
            
            user_data = """MIME-Version: 1.0
            Content-Type: multipart/mixed; boundary="==MYBOUNDARY=="
            
            --==MYBOUNDARY==
            Content-Type: text/x-shellscript; charset="us-ascii"
            
            #!/bin/bash
            echo "Running custom user data script"
            
            --==MYBOUNDARY==--\\
            """
            lt = ec2.CfnLaunchTemplate(self, "LaunchTemplate",
                launch_template_data=ec2.CfnLaunchTemplate.LaunchTemplateDataProperty(
                    instance_type="t3.small",
                    user_data=Fn.base64(user_data)
                )
            )
            
            cluster.add_nodegroup_capacity("extra-ng",
                launch_template_spec=eks.LaunchTemplateSpec(
                    id=lt.ref,
                    version=lt.attr_latest_version_number
                )
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "id": id,
        }
        if version is not None:
            self._values["version"] = version

    @builtins.property
    def id(self) -> builtins.str:
        '''The Launch template ID.'''
        result = self._values.get("id")
        assert result is not None, "Required property 'id' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def version(self) -> typing.Optional[builtins.str]:
        '''The launch template version to be used (optional).

        :default: - the default version of the launch template
        '''
        result = self._values.get("version")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "LaunchTemplateSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_eks.MachineImageType")
class MachineImageType(enum.Enum):
    '''The machine image type.

    :exampleMetadata: infused

    Example::

        # cluster: eks.Cluster
        
        cluster.add_auto_scaling_group_capacity("BottlerocketNodes",
            instance_type=ec2.InstanceType("t3.small"),
            min_capacity=2,
            machine_image_type=eks.MachineImageType.BOTTLEROCKET
        )
    '''

    AMAZON_LINUX_2 = "AMAZON_LINUX_2"
    '''Amazon EKS-optimized Linux AMI.'''
    BOTTLEROCKET = "BOTTLEROCKET"
    '''Bottlerocket AMI.'''


@jsii.enum(jsii_type="aws-cdk-lib.aws_eks.NodeType")
class NodeType(enum.Enum):
    '''Whether the worker nodes should support GPU or just standard instances.'''

    STANDARD = "STANDARD"
    '''Standard instances.'''
    GPU = "GPU"
    '''GPU instances.'''
    INFERENTIA = "INFERENTIA"
    '''Inferentia instances.'''


@jsii.implements(INodegroup)
class Nodegroup(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.Nodegroup",
):
    '''The Nodegroup resource class.

    :exampleMetadata: fixture=_generated

    Example::

        # The code below shows an example of how to instantiate this type.
        # The values are placeholders you should change.
        from aws_cdk import aws_ec2 as ec2
        from aws_cdk import aws_eks as eks
        from aws_cdk import aws_iam as iam
        
        # cluster: eks.Cluster
        # instance_type: ec2.InstanceType
        # role: iam.Role
        # security_group: ec2.SecurityGroup
        # subnet: ec2.Subnet
        # subnet_filter: ec2.SubnetFilter
        
        nodegroup = eks.Nodegroup(self, "MyNodegroup",
            cluster=cluster,
        
            # the properties below are optional
            ami_type=eks.NodegroupAmiType.AL2_X86_64,
            capacity_type=eks.CapacityType.SPOT,
            desired_size=123,
            disk_size=123,
            force_update=False,
            instance_types=[instance_type],
            labels={
                "labels_key": "labels"
            },
            launch_template_spec=eks.LaunchTemplateSpec(
                id="id",
        
                # the properties below are optional
                version="version"
            ),
            max_size=123,
            min_size=123,
            nodegroup_name="nodegroupName",
            node_role=role,
            release_version="releaseVersion",
            remote_access=eks.NodegroupRemoteAccess(
                ssh_key_name="sshKeyName",
        
                # the properties below are optional
                source_security_groups=[security_group]
            ),
            subnets=ec2.SubnetSelection(
                availability_zones=["availabilityZones"],
                one_per_az=False,
                subnet_filters=[subnet_filter],
                subnet_group_name="subnetGroupName",
                subnets=[subnet],
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
            ),
            tags={
                "tags_key": "tags"
            },
            taints=[eks.TaintSpec(
                effect=eks.TaintEffect.NO_SCHEDULE,
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
        cluster: ICluster,
        ami_type: typing.Optional["NodegroupAmiType"] = None,
        capacity_type: typing.Optional[CapacityType] = None,
        desired_size: typing.Optional[jsii.Number] = None,
        disk_size: typing.Optional[jsii.Number] = None,
        force_update: typing.Optional[builtins.bool] = None,
        instance_types: typing.Optional[typing.Sequence[_InstanceType_f64915b9]] = None,
        labels: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        launch_template_spec: typing.Optional[LaunchTemplateSpec] = None,
        max_size: typing.Optional[jsii.Number] = None,
        min_size: typing.Optional[jsii.Number] = None,
        nodegroup_name: typing.Optional[builtins.str] = None,
        node_role: typing.Optional[_IRole_235f5d8e] = None,
        release_version: typing.Optional[builtins.str] = None,
        remote_access: typing.Optional["NodegroupRemoteAccess"] = None,
        subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        taints: typing.Optional[typing.Sequence["TaintSpec"]] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param cluster: Cluster resource.
        :param ami_type: The AMI type for your node group. If you explicitly specify the launchTemplate with custom AMI, do not specify this property, or the node group deployment will fail. In other cases, you will need to specify correct amiType for the nodegroup. Default: - auto-determined from the instanceTypes property when launchTemplateSpec property is not specified
        :param capacity_type: The capacity type of the nodegroup. Default: - ON_DEMAND
        :param desired_size: The current number of worker nodes that the managed node group should maintain. If not specified, the nodewgroup will initially create ``minSize`` instances. Default: 2
        :param disk_size: The root device disk size (in GiB) for your node group instances. Default: 20
        :param force_update: Force the update if the existing node group's pods are unable to be drained due to a pod disruption budget issue. If an update fails because pods could not be drained, you can force the update after it fails to terminate the old node whether or not any pods are running on the node. Default: true
        :param instance_types: The instance types to use for your node group. Default: t3.medium will be used according to the cloudformation document.
        :param labels: The Kubernetes labels to be applied to the nodes in the node group when they are created. Default: - None
        :param launch_template_spec: Launch template specification used for the nodegroup. Default: - no launch template
        :param max_size: The maximum number of worker nodes that the managed node group can scale out to. Managed node groups can support up to 100 nodes by default. Default: - desiredSize
        :param min_size: The minimum number of worker nodes that the managed node group can scale in to. This number must be greater than or equal to zero. Default: 1
        :param nodegroup_name: Name of the Nodegroup. Default: - resource ID
        :param node_role: The IAM role to associate with your node group. The Amazon EKS worker node kubelet daemon makes calls to AWS APIs on your behalf. Worker nodes receive permissions for these API calls through an IAM instance profile and associated policies. Before you can launch worker nodes and register them into a cluster, you must create an IAM role for those worker nodes to use when they are launched. Default: - None. Auto-generated if not specified.
        :param release_version: The AMI version of the Amazon EKS-optimized AMI to use with your node group (for example, ``1.14.7-YYYYMMDD``). Default: - The latest available AMI version for the node group's current Kubernetes version is used.
        :param remote_access: The remote access (SSH) configuration to use with your node group. Disabled by default, however, if you specify an Amazon EC2 SSH key but do not specify a source security group when you create a managed node group, then port 22 on the worker nodes is opened to the internet (0.0.0.0/0) Default: - disabled
        :param subnets: The subnets to use for the Auto Scaling group that is created for your node group. By specifying the SubnetSelection, the selected subnets will automatically apply required tags i.e. ``kubernetes.io/cluster/CLUSTER_NAME`` with a value of ``shared``, where ``CLUSTER_NAME`` is replaced with the name of your cluster. Default: - private subnets
        :param tags: The metadata to apply to the node group to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Node group tags do not propagate to any other resources associated with the node group, such as the Amazon EC2 instances or subnets. Default: - None
        :param taints: The Kubernetes taints to be applied to the nodes in the node group when they are created. Default: - None
        '''
        props = NodegroupProps(
            cluster=cluster,
            ami_type=ami_type,
            capacity_type=capacity_type,
            desired_size=desired_size,
            disk_size=disk_size,
            force_update=force_update,
            instance_types=instance_types,
            labels=labels,
            launch_template_spec=launch_template_spec,
            max_size=max_size,
            min_size=min_size,
            nodegroup_name=nodegroup_name,
            node_role=node_role,
            release_version=release_version,
            remote_access=remote_access,
            subnets=subnets,
            tags=tags,
            taints=taints,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromNodegroupName") # type: ignore[misc]
    @builtins.classmethod
    def from_nodegroup_name(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        nodegroup_name: builtins.str,
    ) -> INodegroup:
        '''Import the Nodegroup from attributes.

        :param scope: -
        :param id: -
        :param nodegroup_name: -
        '''
        return typing.cast(INodegroup, jsii.sinvoke(cls, "fromNodegroupName", [scope, id, nodegroup_name]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="cluster")
    def cluster(self) -> ICluster:
        '''the Amazon EKS cluster resource.

        :attribute: ClusterName
        '''
        return typing.cast(ICluster, jsii.get(self, "cluster"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="nodegroupArn")
    def nodegroup_arn(self) -> builtins.str:
        '''ARN of the nodegroup.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "nodegroupArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="nodegroupName")
    def nodegroup_name(self) -> builtins.str:
        '''Nodegroup name.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "nodegroupName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> _IRole_235f5d8e:
        '''IAM role of the instance profile for the nodegroup.'''
        return typing.cast(_IRole_235f5d8e, jsii.get(self, "role"))


@jsii.enum(jsii_type="aws-cdk-lib.aws_eks.NodegroupAmiType")
class NodegroupAmiType(enum.Enum):
    '''The AMI type for your node group.

    GPU instance types should use the ``AL2_x86_64_GPU`` AMI type, which uses the
    Amazon EKS-optimized Linux AMI with GPU support. Non-GPU instances should use the ``AL2_x86_64`` AMI type, which
    uses the Amazon EKS-optimized Linux AMI.

    :exampleMetadata: infused

    Example::

        cluster = eks.Cluster(self, "HelloEKS",
            version=eks.KubernetesVersion.V1_21,
            default_capacity=0
        )
        
        cluster.add_nodegroup_capacity("custom-node-group",
            instance_types=[ec2.InstanceType("m5.large")],
            min_size=4,
            disk_size=100,
            ami_type=eks.NodegroupAmiType.AL2_X86_64_GPU
        )
    '''

    AL2_X86_64 = "AL2_X86_64"
    '''Amazon Linux 2 (x86-64).'''
    AL2_X86_64_GPU = "AL2_X86_64_GPU"
    '''Amazon Linux 2 with GPU support.'''
    AL2_ARM_64 = "AL2_ARM_64"
    '''Amazon Linux 2 (ARM-64).'''
    BOTTLEROCKET_ARM_64 = "BOTTLEROCKET_ARM_64"
    '''Bottlerocket Linux(ARM-64).'''
    BOTTLEROCKET_X86_64 = "BOTTLEROCKET_X86_64"
    '''Bottlerocket(x86-64).'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.NodegroupOptions",
    jsii_struct_bases=[],
    name_mapping={
        "ami_type": "amiType",
        "capacity_type": "capacityType",
        "desired_size": "desiredSize",
        "disk_size": "diskSize",
        "force_update": "forceUpdate",
        "instance_types": "instanceTypes",
        "labels": "labels",
        "launch_template_spec": "launchTemplateSpec",
        "max_size": "maxSize",
        "min_size": "minSize",
        "nodegroup_name": "nodegroupName",
        "node_role": "nodeRole",
        "release_version": "releaseVersion",
        "remote_access": "remoteAccess",
        "subnets": "subnets",
        "tags": "tags",
        "taints": "taints",
    },
)
class NodegroupOptions:
    def __init__(
        self,
        *,
        ami_type: typing.Optional[NodegroupAmiType] = None,
        capacity_type: typing.Optional[CapacityType] = None,
        desired_size: typing.Optional[jsii.Number] = None,
        disk_size: typing.Optional[jsii.Number] = None,
        force_update: typing.Optional[builtins.bool] = None,
        instance_types: typing.Optional[typing.Sequence[_InstanceType_f64915b9]] = None,
        labels: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        launch_template_spec: typing.Optional[LaunchTemplateSpec] = None,
        max_size: typing.Optional[jsii.Number] = None,
        min_size: typing.Optional[jsii.Number] = None,
        nodegroup_name: typing.Optional[builtins.str] = None,
        node_role: typing.Optional[_IRole_235f5d8e] = None,
        release_version: typing.Optional[builtins.str] = None,
        remote_access: typing.Optional["NodegroupRemoteAccess"] = None,
        subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        taints: typing.Optional[typing.Sequence["TaintSpec"]] = None,
    ) -> None:
        '''The Nodegroup Options for addNodeGroup() method.

        :param ami_type: The AMI type for your node group. If you explicitly specify the launchTemplate with custom AMI, do not specify this property, or the node group deployment will fail. In other cases, you will need to specify correct amiType for the nodegroup. Default: - auto-determined from the instanceTypes property when launchTemplateSpec property is not specified
        :param capacity_type: The capacity type of the nodegroup. Default: - ON_DEMAND
        :param desired_size: The current number of worker nodes that the managed node group should maintain. If not specified, the nodewgroup will initially create ``minSize`` instances. Default: 2
        :param disk_size: The root device disk size (in GiB) for your node group instances. Default: 20
        :param force_update: Force the update if the existing node group's pods are unable to be drained due to a pod disruption budget issue. If an update fails because pods could not be drained, you can force the update after it fails to terminate the old node whether or not any pods are running on the node. Default: true
        :param instance_types: The instance types to use for your node group. Default: t3.medium will be used according to the cloudformation document.
        :param labels: The Kubernetes labels to be applied to the nodes in the node group when they are created. Default: - None
        :param launch_template_spec: Launch template specification used for the nodegroup. Default: - no launch template
        :param max_size: The maximum number of worker nodes that the managed node group can scale out to. Managed node groups can support up to 100 nodes by default. Default: - desiredSize
        :param min_size: The minimum number of worker nodes that the managed node group can scale in to. This number must be greater than or equal to zero. Default: 1
        :param nodegroup_name: Name of the Nodegroup. Default: - resource ID
        :param node_role: The IAM role to associate with your node group. The Amazon EKS worker node kubelet daemon makes calls to AWS APIs on your behalf. Worker nodes receive permissions for these API calls through an IAM instance profile and associated policies. Before you can launch worker nodes and register them into a cluster, you must create an IAM role for those worker nodes to use when they are launched. Default: - None. Auto-generated if not specified.
        :param release_version: The AMI version of the Amazon EKS-optimized AMI to use with your node group (for example, ``1.14.7-YYYYMMDD``). Default: - The latest available AMI version for the node group's current Kubernetes version is used.
        :param remote_access: The remote access (SSH) configuration to use with your node group. Disabled by default, however, if you specify an Amazon EC2 SSH key but do not specify a source security group when you create a managed node group, then port 22 on the worker nodes is opened to the internet (0.0.0.0/0) Default: - disabled
        :param subnets: The subnets to use for the Auto Scaling group that is created for your node group. By specifying the SubnetSelection, the selected subnets will automatically apply required tags i.e. ``kubernetes.io/cluster/CLUSTER_NAME`` with a value of ``shared``, where ``CLUSTER_NAME`` is replaced with the name of your cluster. Default: - private subnets
        :param tags: The metadata to apply to the node group to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Node group tags do not propagate to any other resources associated with the node group, such as the Amazon EC2 instances or subnets. Default: - None
        :param taints: The Kubernetes taints to be applied to the nodes in the node group when they are created. Default: - None

        :exampleMetadata: infused

        Example::

            # cluster: eks.Cluster
            
            cluster.add_nodegroup_capacity("extra-ng-spot",
                instance_types=[
                    ec2.InstanceType("c5.large"),
                    ec2.InstanceType("c5a.large"),
                    ec2.InstanceType("c5d.large")
                ],
                min_size=3,
                capacity_type=eks.CapacityType.SPOT
            )
        '''
        if isinstance(launch_template_spec, dict):
            launch_template_spec = LaunchTemplateSpec(**launch_template_spec)
        if isinstance(remote_access, dict):
            remote_access = NodegroupRemoteAccess(**remote_access)
        if isinstance(subnets, dict):
            subnets = _SubnetSelection_e57d76df(**subnets)
        self._values: typing.Dict[str, typing.Any] = {}
        if ami_type is not None:
            self._values["ami_type"] = ami_type
        if capacity_type is not None:
            self._values["capacity_type"] = capacity_type
        if desired_size is not None:
            self._values["desired_size"] = desired_size
        if disk_size is not None:
            self._values["disk_size"] = disk_size
        if force_update is not None:
            self._values["force_update"] = force_update
        if instance_types is not None:
            self._values["instance_types"] = instance_types
        if labels is not None:
            self._values["labels"] = labels
        if launch_template_spec is not None:
            self._values["launch_template_spec"] = launch_template_spec
        if max_size is not None:
            self._values["max_size"] = max_size
        if min_size is not None:
            self._values["min_size"] = min_size
        if nodegroup_name is not None:
            self._values["nodegroup_name"] = nodegroup_name
        if node_role is not None:
            self._values["node_role"] = node_role
        if release_version is not None:
            self._values["release_version"] = release_version
        if remote_access is not None:
            self._values["remote_access"] = remote_access
        if subnets is not None:
            self._values["subnets"] = subnets
        if tags is not None:
            self._values["tags"] = tags
        if taints is not None:
            self._values["taints"] = taints

    @builtins.property
    def ami_type(self) -> typing.Optional[NodegroupAmiType]:
        '''The AMI type for your node group.

        If you explicitly specify the launchTemplate with custom AMI, do not specify this property, or
        the node group deployment will fail. In other cases, you will need to specify correct amiType for the nodegroup.

        :default: - auto-determined from the instanceTypes property when launchTemplateSpec property is not specified
        '''
        result = self._values.get("ami_type")
        return typing.cast(typing.Optional[NodegroupAmiType], result)

    @builtins.property
    def capacity_type(self) -> typing.Optional[CapacityType]:
        '''The capacity type of the nodegroup.

        :default: - ON_DEMAND
        '''
        result = self._values.get("capacity_type")
        return typing.cast(typing.Optional[CapacityType], result)

    @builtins.property
    def desired_size(self) -> typing.Optional[jsii.Number]:
        '''The current number of worker nodes that the managed node group should maintain.

        If not specified,
        the nodewgroup will initially create ``minSize`` instances.

        :default: 2
        '''
        result = self._values.get("desired_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def disk_size(self) -> typing.Optional[jsii.Number]:
        '''The root device disk size (in GiB) for your node group instances.

        :default: 20
        '''
        result = self._values.get("disk_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def force_update(self) -> typing.Optional[builtins.bool]:
        '''Force the update if the existing node group's pods are unable to be drained due to a pod disruption budget issue.

        If an update fails because pods could not be drained, you can force the update after it fails to terminate the old
        node whether or not any pods are
        running on the node.

        :default: true
        '''
        result = self._values.get("force_update")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def instance_types(self) -> typing.Optional[typing.List[_InstanceType_f64915b9]]:
        '''The instance types to use for your node group.

        :default: t3.medium will be used according to the cloudformation document.

        :see: - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-instancetypes
        '''
        result = self._values.get("instance_types")
        return typing.cast(typing.Optional[typing.List[_InstanceType_f64915b9]], result)

    @builtins.property
    def labels(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The Kubernetes labels to be applied to the nodes in the node group when they are created.

        :default: - None
        '''
        result = self._values.get("labels")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def launch_template_spec(self) -> typing.Optional[LaunchTemplateSpec]:
        '''Launch template specification used for the nodegroup.

        :default: - no launch template

        :see: - https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html
        '''
        result = self._values.get("launch_template_spec")
        return typing.cast(typing.Optional[LaunchTemplateSpec], result)

    @builtins.property
    def max_size(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of worker nodes that the managed node group can scale out to.

        Managed node groups can support up to 100 nodes by default.

        :default: - desiredSize
        '''
        result = self._values.get("max_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_size(self) -> typing.Optional[jsii.Number]:
        '''The minimum number of worker nodes that the managed node group can scale in to.

        This number must be greater than or equal to zero.

        :default: 1
        '''
        result = self._values.get("min_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def nodegroup_name(self) -> typing.Optional[builtins.str]:
        '''Name of the Nodegroup.

        :default: - resource ID
        '''
        result = self._values.get("nodegroup_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def node_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The IAM role to associate with your node group.

        The Amazon EKS worker node kubelet daemon
        makes calls to AWS APIs on your behalf. Worker nodes receive permissions for these API calls through
        an IAM instance profile and associated policies. Before you can launch worker nodes and register them
        into a cluster, you must create an IAM role for those worker nodes to use when they are launched.

        :default: - None. Auto-generated if not specified.
        '''
        result = self._values.get("node_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def release_version(self) -> typing.Optional[builtins.str]:
        '''The AMI version of the Amazon EKS-optimized AMI to use with your node group (for example, ``1.14.7-YYYYMMDD``).

        :default: - The latest available AMI version for the node group's current Kubernetes version is used.
        '''
        result = self._values.get("release_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def remote_access(self) -> typing.Optional["NodegroupRemoteAccess"]:
        '''The remote access (SSH) configuration to use with your node group.

        Disabled by default, however, if you
        specify an Amazon EC2 SSH key but do not specify a source security group when you create a managed node group,
        then port 22 on the worker nodes is opened to the internet (0.0.0.0/0)

        :default: - disabled
        '''
        result = self._values.get("remote_access")
        return typing.cast(typing.Optional["NodegroupRemoteAccess"], result)

    @builtins.property
    def subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''The subnets to use for the Auto Scaling group that is created for your node group.

        By specifying the
        SubnetSelection, the selected subnets will automatically apply required tags i.e.
        ``kubernetes.io/cluster/CLUSTER_NAME`` with a value of ``shared``, where ``CLUSTER_NAME`` is replaced with
        the name of your cluster.

        :default: - private subnets
        '''
        result = self._values.get("subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The metadata to apply to the node group to assist with categorization and organization.

        Each tag consists of
        a key and an optional value, both of which you define. Node group tags do not propagate to any other resources
        associated with the node group, such as the Amazon EC2 instances or subnets.

        :default: - None
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def taints(self) -> typing.Optional[typing.List["TaintSpec"]]:
        '''The Kubernetes taints to be applied to the nodes in the node group when they are created.

        :default: - None
        '''
        result = self._values.get("taints")
        return typing.cast(typing.Optional[typing.List["TaintSpec"]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NodegroupOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.NodegroupProps",
    jsii_struct_bases=[NodegroupOptions],
    name_mapping={
        "ami_type": "amiType",
        "capacity_type": "capacityType",
        "desired_size": "desiredSize",
        "disk_size": "diskSize",
        "force_update": "forceUpdate",
        "instance_types": "instanceTypes",
        "labels": "labels",
        "launch_template_spec": "launchTemplateSpec",
        "max_size": "maxSize",
        "min_size": "minSize",
        "nodegroup_name": "nodegroupName",
        "node_role": "nodeRole",
        "release_version": "releaseVersion",
        "remote_access": "remoteAccess",
        "subnets": "subnets",
        "tags": "tags",
        "taints": "taints",
        "cluster": "cluster",
    },
)
class NodegroupProps(NodegroupOptions):
    def __init__(
        self,
        *,
        ami_type: typing.Optional[NodegroupAmiType] = None,
        capacity_type: typing.Optional[CapacityType] = None,
        desired_size: typing.Optional[jsii.Number] = None,
        disk_size: typing.Optional[jsii.Number] = None,
        force_update: typing.Optional[builtins.bool] = None,
        instance_types: typing.Optional[typing.Sequence[_InstanceType_f64915b9]] = None,
        labels: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        launch_template_spec: typing.Optional[LaunchTemplateSpec] = None,
        max_size: typing.Optional[jsii.Number] = None,
        min_size: typing.Optional[jsii.Number] = None,
        nodegroup_name: typing.Optional[builtins.str] = None,
        node_role: typing.Optional[_IRole_235f5d8e] = None,
        release_version: typing.Optional[builtins.str] = None,
        remote_access: typing.Optional["NodegroupRemoteAccess"] = None,
        subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        taints: typing.Optional[typing.Sequence["TaintSpec"]] = None,
        cluster: ICluster,
    ) -> None:
        '''NodeGroup properties interface.

        :param ami_type: The AMI type for your node group. If you explicitly specify the launchTemplate with custom AMI, do not specify this property, or the node group deployment will fail. In other cases, you will need to specify correct amiType for the nodegroup. Default: - auto-determined from the instanceTypes property when launchTemplateSpec property is not specified
        :param capacity_type: The capacity type of the nodegroup. Default: - ON_DEMAND
        :param desired_size: The current number of worker nodes that the managed node group should maintain. If not specified, the nodewgroup will initially create ``minSize`` instances. Default: 2
        :param disk_size: The root device disk size (in GiB) for your node group instances. Default: 20
        :param force_update: Force the update if the existing node group's pods are unable to be drained due to a pod disruption budget issue. If an update fails because pods could not be drained, you can force the update after it fails to terminate the old node whether or not any pods are running on the node. Default: true
        :param instance_types: The instance types to use for your node group. Default: t3.medium will be used according to the cloudformation document.
        :param labels: The Kubernetes labels to be applied to the nodes in the node group when they are created. Default: - None
        :param launch_template_spec: Launch template specification used for the nodegroup. Default: - no launch template
        :param max_size: The maximum number of worker nodes that the managed node group can scale out to. Managed node groups can support up to 100 nodes by default. Default: - desiredSize
        :param min_size: The minimum number of worker nodes that the managed node group can scale in to. This number must be greater than or equal to zero. Default: 1
        :param nodegroup_name: Name of the Nodegroup. Default: - resource ID
        :param node_role: The IAM role to associate with your node group. The Amazon EKS worker node kubelet daemon makes calls to AWS APIs on your behalf. Worker nodes receive permissions for these API calls through an IAM instance profile and associated policies. Before you can launch worker nodes and register them into a cluster, you must create an IAM role for those worker nodes to use when they are launched. Default: - None. Auto-generated if not specified.
        :param release_version: The AMI version of the Amazon EKS-optimized AMI to use with your node group (for example, ``1.14.7-YYYYMMDD``). Default: - The latest available AMI version for the node group's current Kubernetes version is used.
        :param remote_access: The remote access (SSH) configuration to use with your node group. Disabled by default, however, if you specify an Amazon EC2 SSH key but do not specify a source security group when you create a managed node group, then port 22 on the worker nodes is opened to the internet (0.0.0.0/0) Default: - disabled
        :param subnets: The subnets to use for the Auto Scaling group that is created for your node group. By specifying the SubnetSelection, the selected subnets will automatically apply required tags i.e. ``kubernetes.io/cluster/CLUSTER_NAME`` with a value of ``shared``, where ``CLUSTER_NAME`` is replaced with the name of your cluster. Default: - private subnets
        :param tags: The metadata to apply to the node group to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Node group tags do not propagate to any other resources associated with the node group, such as the Amazon EC2 instances or subnets. Default: - None
        :param taints: The Kubernetes taints to be applied to the nodes in the node group when they are created. Default: - None
        :param cluster: Cluster resource.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_eks as eks
            from aws_cdk import aws_iam as iam
            
            # cluster: eks.Cluster
            # instance_type: ec2.InstanceType
            # role: iam.Role
            # security_group: ec2.SecurityGroup
            # subnet: ec2.Subnet
            # subnet_filter: ec2.SubnetFilter
            
            nodegroup_props = eks.NodegroupProps(
                cluster=cluster,
            
                # the properties below are optional
                ami_type=eks.NodegroupAmiType.AL2_X86_64,
                capacity_type=eks.CapacityType.SPOT,
                desired_size=123,
                disk_size=123,
                force_update=False,
                instance_types=[instance_type],
                labels={
                    "labels_key": "labels"
                },
                launch_template_spec=eks.LaunchTemplateSpec(
                    id="id",
            
                    # the properties below are optional
                    version="version"
                ),
                max_size=123,
                min_size=123,
                nodegroup_name="nodegroupName",
                node_role=role,
                release_version="releaseVersion",
                remote_access=eks.NodegroupRemoteAccess(
                    ssh_key_name="sshKeyName",
            
                    # the properties below are optional
                    source_security_groups=[security_group]
                ),
                subnets=ec2.SubnetSelection(
                    availability_zones=["availabilityZones"],
                    one_per_az=False,
                    subnet_filters=[subnet_filter],
                    subnet_group_name="subnetGroupName",
                    subnets=[subnet],
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
                ),
                tags={
                    "tags_key": "tags"
                },
                taints=[eks.TaintSpec(
                    effect=eks.TaintEffect.NO_SCHEDULE,
                    key="key",
                    value="value"
                )]
            )
        '''
        if isinstance(launch_template_spec, dict):
            launch_template_spec = LaunchTemplateSpec(**launch_template_spec)
        if isinstance(remote_access, dict):
            remote_access = NodegroupRemoteAccess(**remote_access)
        if isinstance(subnets, dict):
            subnets = _SubnetSelection_e57d76df(**subnets)
        self._values: typing.Dict[str, typing.Any] = {
            "cluster": cluster,
        }
        if ami_type is not None:
            self._values["ami_type"] = ami_type
        if capacity_type is not None:
            self._values["capacity_type"] = capacity_type
        if desired_size is not None:
            self._values["desired_size"] = desired_size
        if disk_size is not None:
            self._values["disk_size"] = disk_size
        if force_update is not None:
            self._values["force_update"] = force_update
        if instance_types is not None:
            self._values["instance_types"] = instance_types
        if labels is not None:
            self._values["labels"] = labels
        if launch_template_spec is not None:
            self._values["launch_template_spec"] = launch_template_spec
        if max_size is not None:
            self._values["max_size"] = max_size
        if min_size is not None:
            self._values["min_size"] = min_size
        if nodegroup_name is not None:
            self._values["nodegroup_name"] = nodegroup_name
        if node_role is not None:
            self._values["node_role"] = node_role
        if release_version is not None:
            self._values["release_version"] = release_version
        if remote_access is not None:
            self._values["remote_access"] = remote_access
        if subnets is not None:
            self._values["subnets"] = subnets
        if tags is not None:
            self._values["tags"] = tags
        if taints is not None:
            self._values["taints"] = taints

    @builtins.property
    def ami_type(self) -> typing.Optional[NodegroupAmiType]:
        '''The AMI type for your node group.

        If you explicitly specify the launchTemplate with custom AMI, do not specify this property, or
        the node group deployment will fail. In other cases, you will need to specify correct amiType for the nodegroup.

        :default: - auto-determined from the instanceTypes property when launchTemplateSpec property is not specified
        '''
        result = self._values.get("ami_type")
        return typing.cast(typing.Optional[NodegroupAmiType], result)

    @builtins.property
    def capacity_type(self) -> typing.Optional[CapacityType]:
        '''The capacity type of the nodegroup.

        :default: - ON_DEMAND
        '''
        result = self._values.get("capacity_type")
        return typing.cast(typing.Optional[CapacityType], result)

    @builtins.property
    def desired_size(self) -> typing.Optional[jsii.Number]:
        '''The current number of worker nodes that the managed node group should maintain.

        If not specified,
        the nodewgroup will initially create ``minSize`` instances.

        :default: 2
        '''
        result = self._values.get("desired_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def disk_size(self) -> typing.Optional[jsii.Number]:
        '''The root device disk size (in GiB) for your node group instances.

        :default: 20
        '''
        result = self._values.get("disk_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def force_update(self) -> typing.Optional[builtins.bool]:
        '''Force the update if the existing node group's pods are unable to be drained due to a pod disruption budget issue.

        If an update fails because pods could not be drained, you can force the update after it fails to terminate the old
        node whether or not any pods are
        running on the node.

        :default: true
        '''
        result = self._values.get("force_update")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def instance_types(self) -> typing.Optional[typing.List[_InstanceType_f64915b9]]:
        '''The instance types to use for your node group.

        :default: t3.medium will be used according to the cloudformation document.

        :see: - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-eks-nodegroup.html#cfn-eks-nodegroup-instancetypes
        '''
        result = self._values.get("instance_types")
        return typing.cast(typing.Optional[typing.List[_InstanceType_f64915b9]], result)

    @builtins.property
    def labels(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The Kubernetes labels to be applied to the nodes in the node group when they are created.

        :default: - None
        '''
        result = self._values.get("labels")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def launch_template_spec(self) -> typing.Optional[LaunchTemplateSpec]:
        '''Launch template specification used for the nodegroup.

        :default: - no launch template

        :see: - https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html
        '''
        result = self._values.get("launch_template_spec")
        return typing.cast(typing.Optional[LaunchTemplateSpec], result)

    @builtins.property
    def max_size(self) -> typing.Optional[jsii.Number]:
        '''The maximum number of worker nodes that the managed node group can scale out to.

        Managed node groups can support up to 100 nodes by default.

        :default: - desiredSize
        '''
        result = self._values.get("max_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def min_size(self) -> typing.Optional[jsii.Number]:
        '''The minimum number of worker nodes that the managed node group can scale in to.

        This number must be greater than or equal to zero.

        :default: 1
        '''
        result = self._values.get("min_size")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def nodegroup_name(self) -> typing.Optional[builtins.str]:
        '''Name of the Nodegroup.

        :default: - resource ID
        '''
        result = self._values.get("nodegroup_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def node_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The IAM role to associate with your node group.

        The Amazon EKS worker node kubelet daemon
        makes calls to AWS APIs on your behalf. Worker nodes receive permissions for these API calls through
        an IAM instance profile and associated policies. Before you can launch worker nodes and register them
        into a cluster, you must create an IAM role for those worker nodes to use when they are launched.

        :default: - None. Auto-generated if not specified.
        '''
        result = self._values.get("node_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def release_version(self) -> typing.Optional[builtins.str]:
        '''The AMI version of the Amazon EKS-optimized AMI to use with your node group (for example, ``1.14.7-YYYYMMDD``).

        :default: - The latest available AMI version for the node group's current Kubernetes version is used.
        '''
        result = self._values.get("release_version")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def remote_access(self) -> typing.Optional["NodegroupRemoteAccess"]:
        '''The remote access (SSH) configuration to use with your node group.

        Disabled by default, however, if you
        specify an Amazon EC2 SSH key but do not specify a source security group when you create a managed node group,
        then port 22 on the worker nodes is opened to the internet (0.0.0.0/0)

        :default: - disabled
        '''
        result = self._values.get("remote_access")
        return typing.cast(typing.Optional["NodegroupRemoteAccess"], result)

    @builtins.property
    def subnets(self) -> typing.Optional[_SubnetSelection_e57d76df]:
        '''The subnets to use for the Auto Scaling group that is created for your node group.

        By specifying the
        SubnetSelection, the selected subnets will automatically apply required tags i.e.
        ``kubernetes.io/cluster/CLUSTER_NAME`` with a value of ``shared``, where ``CLUSTER_NAME`` is replaced with
        the name of your cluster.

        :default: - private subnets
        '''
        result = self._values.get("subnets")
        return typing.cast(typing.Optional[_SubnetSelection_e57d76df], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The metadata to apply to the node group to assist with categorization and organization.

        Each tag consists of
        a key and an optional value, both of which you define. Node group tags do not propagate to any other resources
        associated with the node group, such as the Amazon EC2 instances or subnets.

        :default: - None
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def taints(self) -> typing.Optional[typing.List["TaintSpec"]]:
        '''The Kubernetes taints to be applied to the nodes in the node group when they are created.

        :default: - None
        '''
        result = self._values.get("taints")
        return typing.cast(typing.Optional[typing.List["TaintSpec"]], result)

    @builtins.property
    def cluster(self) -> ICluster:
        '''Cluster resource.'''
        result = self._values.get("cluster")
        assert result is not None, "Required property 'cluster' is missing"
        return typing.cast(ICluster, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NodegroupProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.NodegroupRemoteAccess",
    jsii_struct_bases=[],
    name_mapping={
        "ssh_key_name": "sshKeyName",
        "source_security_groups": "sourceSecurityGroups",
    },
)
class NodegroupRemoteAccess:
    def __init__(
        self,
        *,
        ssh_key_name: builtins.str,
        source_security_groups: typing.Optional[typing.Sequence[_ISecurityGroup_acf8a799]] = None,
    ) -> None:
        '''The remote access (SSH) configuration to use with your node group.

        :param ssh_key_name: The Amazon EC2 SSH key that provides access for SSH communication with the worker nodes in the managed node group.
        :param source_security_groups: The security groups that are allowed SSH access (port 22) to the worker nodes. If you specify an Amazon EC2 SSH key but do not specify a source security group when you create a managed node group, then port 22 on the worker nodes is opened to the internet (0.0.0.0/0). Default: - port 22 on the worker nodes is opened to the internet (0.0.0.0/0)

        :see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-eks-nodegroup-remoteaccess.html
        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_eks as eks
            
            # security_group: ec2.SecurityGroup
            
            nodegroup_remote_access = eks.NodegroupRemoteAccess(
                ssh_key_name="sshKeyName",
            
                # the properties below are optional
                source_security_groups=[security_group]
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "ssh_key_name": ssh_key_name,
        }
        if source_security_groups is not None:
            self._values["source_security_groups"] = source_security_groups

    @builtins.property
    def ssh_key_name(self) -> builtins.str:
        '''The Amazon EC2 SSH key that provides access for SSH communication with the worker nodes in the managed node group.'''
        result = self._values.get("ssh_key_name")
        assert result is not None, "Required property 'ssh_key_name' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def source_security_groups(
        self,
    ) -> typing.Optional[typing.List[_ISecurityGroup_acf8a799]]:
        '''The security groups that are allowed SSH access (port 22) to the worker nodes.

        If you specify an Amazon EC2 SSH
        key but do not specify a source security group when you create a managed node group, then port 22 on the worker
        nodes is opened to the internet (0.0.0.0/0).

        :default: - port 22 on the worker nodes is opened to the internet (0.0.0.0/0)
        '''
        result = self._values.get("source_security_groups")
        return typing.cast(typing.Optional[typing.List[_ISecurityGroup_acf8a799]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "NodegroupRemoteAccess(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class OpenIdConnectProvider(
    _OpenIdConnectProvider_5cb7bc9f,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.OpenIdConnectProvider",
):
    '''IAM OIDC identity providers are entities in IAM that describe an external identity provider (IdP) service that supports the OpenID Connect (OIDC) standard, such as Google or Salesforce.

    You use an IAM OIDC identity provider
    when you want to establish trust between an OIDC-compatible IdP and your AWS
    account.

    This implementation has default values for thumbprints and clientIds props
    that will be compatible with the eks cluster

    :see: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
    :exampleMetadata: infused
    :resource: AWS::CloudFormation::CustomResource

    Example::

        # or create a new one using an existing issuer url
        # issuer_url: str
        # you can import an existing provider
        provider = eks.OpenIdConnectProvider.from_open_id_connect_provider_arn(self, "Provider", "arn:aws:iam::123456:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/AB123456ABC")
        provider2 = eks.OpenIdConnectProvider(self, "Provider",
            url=issuer_url
        )
        
        cluster = eks.Cluster.from_cluster_attributes(self, "MyCluster",
            cluster_name="Cluster",
            open_id_connect_provider=provider,
            kubectl_role_arn="arn:aws:iam::123456:role/service-role/k8sservicerole"
        )
        
        service_account = cluster.add_service_account("MyServiceAccount")
        
        bucket = s3.Bucket(self, "Bucket")
        bucket.grant_read_write(service_account)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        url: builtins.str,
    ) -> None:
        '''Defines an OpenID Connect provider.

        :param scope: The definition scope.
        :param id: Construct ID.
        :param url: The URL of the identity provider. The URL must begin with https:// and should correspond to the iss claim in the provider's OpenID Connect ID tokens. Per the OIDC standard, path components are allowed but query parameters are not. Typically the URL consists of only a hostname, like https://server.example.org or https://example.com. You can find your OIDC Issuer URL by: aws eks describe-cluster --name %cluster_name% --query "cluster.identity.oidc.issuer" --output text
        '''
        props = OpenIdConnectProviderProps(url=url)

        jsii.create(self.__class__, self, [scope, id, props])


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.OpenIdConnectProviderProps",
    jsii_struct_bases=[],
    name_mapping={"url": "url"},
)
class OpenIdConnectProviderProps:
    def __init__(self, *, url: builtins.str) -> None:
        '''Initialization properties for ``OpenIdConnectProvider``.

        :param url: The URL of the identity provider. The URL must begin with https:// and should correspond to the iss claim in the provider's OpenID Connect ID tokens. Per the OIDC standard, path components are allowed but query parameters are not. Typically the URL consists of only a hostname, like https://server.example.org or https://example.com. You can find your OIDC Issuer URL by: aws eks describe-cluster --name %cluster_name% --query "cluster.identity.oidc.issuer" --output text

        :exampleMetadata: infused

        Example::

            # or create a new one using an existing issuer url
            # issuer_url: str
            # you can import an existing provider
            provider = eks.OpenIdConnectProvider.from_open_id_connect_provider_arn(self, "Provider", "arn:aws:iam::123456:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/AB123456ABC")
            provider2 = eks.OpenIdConnectProvider(self, "Provider",
                url=issuer_url
            )
            
            cluster = eks.Cluster.from_cluster_attributes(self, "MyCluster",
                cluster_name="Cluster",
                open_id_connect_provider=provider,
                kubectl_role_arn="arn:aws:iam::123456:role/service-role/k8sservicerole"
            )
            
            service_account = cluster.add_service_account("MyServiceAccount")
            
            bucket = s3.Bucket(self, "Bucket")
            bucket.grant_read_write(service_account)
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "url": url,
        }

    @builtins.property
    def url(self) -> builtins.str:
        '''The URL of the identity provider.

        The URL must begin with https:// and
        should correspond to the iss claim in the provider's OpenID Connect ID
        tokens. Per the OIDC standard, path components are allowed but query
        parameters are not. Typically the URL consists of only a hostname, like
        https://server.example.org or https://example.com.

        You can find your OIDC Issuer URL by:
        aws eks describe-cluster --name %cluster_name% --query "cluster.identity.oidc.issuer" --output text
        '''
        result = self._values.get("url")
        assert result is not None, "Required property 'url' is missing"
        return typing.cast(builtins.str, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "OpenIdConnectProviderProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_eks.PatchType")
class PatchType(enum.Enum):
    '''Values for ``kubectl patch`` --type argument.'''

    JSON = "JSON"
    '''JSON Patch, RFC 6902.'''
    MERGE = "MERGE"
    '''JSON Merge patch.'''
    STRATEGIC = "STRATEGIC"
    '''Strategic merge patch.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.Selector",
    jsii_struct_bases=[],
    name_mapping={"namespace": "namespace", "labels": "labels"},
)
class Selector:
    def __init__(
        self,
        *,
        namespace: builtins.str,
        labels: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Fargate profile selector.

        :param namespace: The Kubernetes namespace that the selector should match. You must specify a namespace for a selector. The selector only matches pods that are created in this namespace, but you can create multiple selectors to target multiple namespaces.
        :param labels: The Kubernetes labels that the selector should match. A pod must contain all of the labels that are specified in the selector for it to be considered a match. Default: - all pods within the namespace will be selected.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            selector = eks.Selector(
                namespace="namespace",
            
                # the properties below are optional
                labels={
                    "labels_key": "labels"
                }
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "namespace": namespace,
        }
        if labels is not None:
            self._values["labels"] = labels

    @builtins.property
    def namespace(self) -> builtins.str:
        '''The Kubernetes namespace that the selector should match.

        You must specify a namespace for a selector. The selector only matches pods
        that are created in this namespace, but you can create multiple selectors
        to target multiple namespaces.
        '''
        result = self._values.get("namespace")
        assert result is not None, "Required property 'namespace' is missing"
        return typing.cast(builtins.str, result)

    @builtins.property
    def labels(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The Kubernetes labels that the selector should match.

        A pod must contain
        all of the labels that are specified in the selector for it to be
        considered a match.

        :default: - all pods within the namespace will be selected.
        '''
        result = self._values.get("labels")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "Selector(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(_IPrincipal_539bb2fd)
class ServiceAccount(
    constructs.Construct,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.ServiceAccount",
):
    '''Service Account.

    :exampleMetadata: infused

    Example::

        # cluster: eks.Cluster
        
        # add service account
        service_account = cluster.add_service_account("MyServiceAccount")
        
        bucket = s3.Bucket(self, "Bucket")
        bucket.grant_read_write(service_account)
        
        mypod = cluster.add_manifest("mypod", {
            "api_version": "v1",
            "kind": "Pod",
            "metadata": {"name": "mypod"},
            "spec": {
                "service_account_name": service_account.service_account_name,
                "containers": [{
                    "name": "hello",
                    "image": "paulbouwer/hello-kubernetes:1.5",
                    "ports": [{"container_port": 8080}]
                }
                ]
            }
        })
        
        # create the resource after the service account.
        mypod.node.add_dependency(service_account)
        
        # print the IAM role arn for this service account
        CfnOutput(self, "ServiceAccountIamRole", value=service_account.role.role_arn)
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster: ICluster,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param cluster: The cluster to apply the patch to.
        :param name: The name of the service account. Default: - If no name is given, it will use the id of the resource.
        :param namespace: The namespace of the service account. Default: "default"
        '''
        props = ServiceAccountProps(cluster=cluster, name=name, namespace=namespace)

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="addToPrincipalPolicy")
    def add_to_principal_policy(
        self,
        statement: _PolicyStatement_0fe33853,
    ) -> _AddToPrincipalPolicyResult_946c9561:
        '''Add to the policy of this principal.

        :param statement: -
        '''
        return typing.cast(_AddToPrincipalPolicyResult_946c9561, jsii.invoke(self, "addToPrincipalPolicy", [statement]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="assumeRoleAction")
    def assume_role_action(self) -> builtins.str:
        '''When this Principal is used in an AssumeRole policy, the action to use.'''
        return typing.cast(builtins.str, jsii.get(self, "assumeRoleAction"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="grantPrincipal")
    def grant_principal(self) -> _IPrincipal_539bb2fd:
        '''The principal to grant permissions to.'''
        return typing.cast(_IPrincipal_539bb2fd, jsii.get(self, "grantPrincipal"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="policyFragment")
    def policy_fragment(self) -> _PrincipalPolicyFragment_6a855d11:
        '''Return the policy fragment that identifies this principal in a Policy.'''
        return typing.cast(_PrincipalPolicyFragment_6a855d11, jsii.get(self, "policyFragment"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> _IRole_235f5d8e:
        '''The role which is linked to the service account.'''
        return typing.cast(_IRole_235f5d8e, jsii.get(self, "role"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceAccountName")
    def service_account_name(self) -> builtins.str:
        '''The name of the service account.'''
        return typing.cast(builtins.str, jsii.get(self, "serviceAccountName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="serviceAccountNamespace")
    def service_account_namespace(self) -> builtins.str:
        '''The namespace where the service account is located in.'''
        return typing.cast(builtins.str, jsii.get(self, "serviceAccountNamespace"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.ServiceAccountOptions",
    jsii_struct_bases=[],
    name_mapping={"name": "name", "namespace": "namespace"},
)
class ServiceAccountOptions:
    def __init__(
        self,
        *,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Options for ``ServiceAccount``.

        :param name: The name of the service account. Default: - If no name is given, it will use the id of the resource.
        :param namespace: The namespace of the service account. Default: "default"

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            service_account_options = eks.ServiceAccountOptions(
                name="name",
                namespace="namespace"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the service account.

        :default: - If no name is given, it will use the id of the resource.
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the service account.

        :default: "default"
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ServiceAccountOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.ServiceAccountProps",
    jsii_struct_bases=[ServiceAccountOptions],
    name_mapping={"name": "name", "namespace": "namespace", "cluster": "cluster"},
)
class ServiceAccountProps(ServiceAccountOptions):
    def __init__(
        self,
        *,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
        cluster: ICluster,
    ) -> None:
        '''Properties for defining service accounts.

        :param name: The name of the service account. Default: - If no name is given, it will use the id of the resource.
        :param namespace: The namespace of the service account. Default: "default"
        :param cluster: The cluster to apply the patch to.

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            # cluster: eks.Cluster
            
            service_account_props = eks.ServiceAccountProps(
                cluster=cluster,
            
                # the properties below are optional
                name="name",
                namespace="namespace"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {
            "cluster": cluster,
        }
        if name is not None:
            self._values["name"] = name
        if namespace is not None:
            self._values["namespace"] = namespace

    @builtins.property
    def name(self) -> typing.Optional[builtins.str]:
        '''The name of the service account.

        :default: - If no name is given, it will use the id of the resource.
        '''
        result = self._values.get("name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace of the service account.

        :default: "default"
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cluster(self) -> ICluster:
        '''The cluster to apply the patch to.'''
        result = self._values.get("cluster")
        assert result is not None, "Required property 'cluster' is missing"
        return typing.cast(ICluster, result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ServiceAccountProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.ServiceLoadBalancerAddressOptions",
    jsii_struct_bases=[],
    name_mapping={"namespace": "namespace", "timeout": "timeout"},
)
class ServiceLoadBalancerAddressOptions:
    def __init__(
        self,
        *,
        namespace: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Options for fetching a ServiceLoadBalancerAddress.

        :param namespace: The namespace the service belongs to. Default: 'default'
        :param timeout: Timeout for waiting on the load balancer address. Default: Duration.minutes(5)

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_eks as eks
            
            service_load_balancer_address_options = eks.ServiceLoadBalancerAddressOptions(
                namespace="namespace",
                timeout=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if namespace is not None:
            self._values["namespace"] = namespace
        if timeout is not None:
            self._values["timeout"] = timeout

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace the service belongs to.

        :default: 'default'
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Timeout for waiting on the load balancer address.

        :default: Duration.minutes(5)
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ServiceLoadBalancerAddressOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.enum(jsii_type="aws-cdk-lib.aws_eks.TaintEffect")
class TaintEffect(enum.Enum):
    '''Effect types of kubernetes node taint.

    :exampleMetadata: infused

    Example::

        # cluster: eks.Cluster
        
        cluster.add_nodegroup_capacity("custom-node-group",
            instance_types=[ec2.InstanceType("m5.large")],
            taints=[eks.TaintSpec(
                effect=eks.TaintEffect.NO_SCHEDULE,
                key="foo",
                value="bar"
            )
            ]
        )
    '''

    NO_SCHEDULE = "NO_SCHEDULE"
    '''NoSchedule.'''
    PREFER_NO_SCHEDULE = "PREFER_NO_SCHEDULE"
    '''PreferNoSchedule.'''
    NO_EXECUTE = "NO_EXECUTE"
    '''NoExecute.'''


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.TaintSpec",
    jsii_struct_bases=[],
    name_mapping={"effect": "effect", "key": "key", "value": "value"},
)
class TaintSpec:
    def __init__(
        self,
        *,
        effect: typing.Optional[TaintEffect] = None,
        key: typing.Optional[builtins.str] = None,
        value: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Taint interface.

        :param effect: Effect type. Default: - None
        :param key: Taint key. Default: - None
        :param value: Taint value. Default: - None

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            from aws_cdk import aws_eks as eks
            
            taint_spec = eks.TaintSpec(
                effect=eks.TaintEffect.NO_SCHEDULE,
                key="key",
                value="value"
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if effect is not None:
            self._values["effect"] = effect
        if key is not None:
            self._values["key"] = key
        if value is not None:
            self._values["value"] = value

    @builtins.property
    def effect(self) -> typing.Optional[TaintEffect]:
        '''Effect type.

        :default: - None
        '''
        result = self._values.get("effect")
        return typing.cast(typing.Optional[TaintEffect], result)

    @builtins.property
    def key(self) -> typing.Optional[builtins.str]:
        '''Taint key.

        :default: - None
        '''
        result = self._values.get("key")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def value(self) -> typing.Optional[builtins.str]:
        '''Taint value.

        :default: - None
        '''
        result = self._values.get("value")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "TaintSpec(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.implements(ICluster)
class Cluster(
    _Resource_45bc6135,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.Cluster",
):
    '''A Cluster represents a managed Kubernetes Service (EKS).

    This is a fully managed cluster of API Servers (control-plane)
    The user is still required to create the worker nodes.

    :exampleMetadata: infused

    Example::

        # vpc: ec2.Vpc
        
        
        eks.Cluster(self, "HelloEKS",
            version=eks.KubernetesVersion.V1_21,
            vpc=vpc,
            vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE)]
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster_logging: typing.Optional[typing.Sequence[ClusterLoggingTypes]] = None,
        default_capacity: typing.Optional[jsii.Number] = None,
        default_capacity_instance: typing.Optional[_InstanceType_f64915b9] = None,
        default_capacity_type: typing.Optional[DefaultCapacityType] = None,
        kubectl_lambda_role: typing.Optional[_IRole_235f5d8e] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        alb_controller: typing.Optional[AlbControllerOptions] = None,
        cluster_handler_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        cluster_handler_security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        core_dns_compute_type: typing.Optional[CoreDnsComputeType] = None,
        endpoint_access: typing.Optional[EndpointAccess] = None,
        kubectl_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        kubectl_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        kubectl_memory: typing.Optional[_Size_7b441c34] = None,
        masters_role: typing.Optional[_IRole_235f5d8e] = None,
        on_event_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        output_masters_role_arn: typing.Optional[builtins.bool] = None,
        place_cluster_handler_in_vpc: typing.Optional[builtins.bool] = None,
        prune: typing.Optional[builtins.bool] = None,
        secrets_encryption_key: typing.Optional[_IKey_5f11635f] = None,
        service_ipv4_cidr: typing.Optional[builtins.str] = None,
        version: KubernetesVersion,
        cluster_name: typing.Optional[builtins.str] = None,
        output_cluster_name: typing.Optional[builtins.bool] = None,
        output_config_command: typing.Optional[builtins.bool] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[typing.Sequence[_SubnetSelection_e57d76df]] = None,
    ) -> None:
        '''Initiates an EKS Cluster with the supplied arguments.

        :param scope: a Construct, most likely a cdk.Stack created.
        :param id: the id of the Construct to create.
        :param cluster_logging: The cluster log types which you want to enable. Default: - none
        :param default_capacity: Number of instances to allocate as an initial capacity for this cluster. Instance type can be configured through ``defaultCapacityInstanceType``, which defaults to ``m5.large``. Use ``cluster.addAutoScalingGroupCapacity`` to add additional customized capacity. Set this to ``0`` is you wish to avoid the initial capacity allocation. Default: 2
        :param default_capacity_instance: The instance type to use for the default capacity. This will only be taken into account if ``defaultCapacity`` is > 0. Default: m5.large
        :param default_capacity_type: The default capacity type for the cluster. Default: NODEGROUP
        :param kubectl_lambda_role: The IAM role to pass to the Kubectl Lambda Handler. Default: - Default Lambda IAM Execution Role
        :param tags: The tags assigned to the EKS cluster. Default: - none
        :param alb_controller: Install the AWS Load Balancer Controller onto the cluster. Default: - The controller is not installed.
        :param cluster_handler_environment: Custom environment variables when interacting with the EKS endpoint to manage the cluster lifecycle. Default: - No environment variables.
        :param cluster_handler_security_group: A security group to associate with the Cluster Handler's Lambdas. The Cluster Handler's Lambdas are responsible for calling AWS's EKS API. Requires ``placeClusterHandlerInVpc`` to be set to true. Default: - No security group.
        :param core_dns_compute_type: Controls the "eks.amazonaws.com/compute-type" annotation in the CoreDNS configuration on your cluster to determine which compute type to use for CoreDNS. Default: CoreDnsComputeType.EC2 (for ``FargateCluster`` the default is FARGATE)
        :param endpoint_access: Configure access to the Kubernetes API server endpoint.. Default: EndpointAccess.PUBLIC_AND_PRIVATE
        :param kubectl_environment: Environment variables for the kubectl execution. Only relevant for kubectl enabled clusters. Default: - No environment variables.
        :param kubectl_layer: An AWS Lambda Layer which includes ``kubectl``, Helm and the AWS CLI. By default, the provider will use the layer included in the "aws-lambda-layer-kubectl" SAR application which is available in all commercial regions. To deploy the layer locally, visit https://github.com/aws-samples/aws-lambda-layer-kubectl/blob/master/cdk/README.md for instructions on how to prepare the .zip file and then define it in your app as follows:: const layer = new lambda.LayerVersion(this, 'kubectl-layer', { code: lambda.Code.fromAsset(`${__dirname}/layer.zip`), compatibleRuntimes: [lambda.Runtime.PROVIDED], }); Default: - the layer provided by the ``aws-lambda-layer-kubectl`` SAR app.
        :param kubectl_memory: Amount of memory to allocate to the provider's lambda function. Default: Size.gibibytes(1)
        :param masters_role: An IAM role that will be added to the ``system:masters`` Kubernetes RBAC group. Default: - a role that assumable by anyone with permissions in the same account will automatically be defined
        :param on_event_layer: An AWS Lambda Layer which includes the NPM dependency ``proxy-agent``. This layer is used by the onEvent handler to route AWS SDK requests through a proxy. By default, the provider will use the layer included in the "aws-lambda-layer-node-proxy-agent" SAR application which is available in all commercial regions. To deploy the layer locally define it in your app as follows:: const layer = new lambda.LayerVersion(this, 'proxy-agent-layer', { code: lambda.Code.fromAsset(`${__dirname}/layer.zip`), compatibleRuntimes: [lambda.Runtime.NODEJS_12_X], }); Default: - a layer bundled with this module.
        :param output_masters_role_arn: Determines whether a CloudFormation output with the ARN of the "masters" IAM role will be synthesized (if ``mastersRole`` is specified). Default: false
        :param place_cluster_handler_in_vpc: If set to true, the cluster handler functions will be placed in the private subnets of the cluster vpc, subject to the ``vpcSubnets`` selection strategy. Default: false
        :param prune: Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned. When this is enabled (default), prune labels will be allocated and injected to each resource. These labels will then be used when issuing the ``kubectl apply`` operation with the ``--prune`` switch. Default: true
        :param secrets_encryption_key: KMS secret for envelope encryption for Kubernetes secrets. Default: - By default, Kubernetes stores all secret object data within etcd and all etcd volumes used by Amazon EKS are encrypted at the disk-level using AWS-Managed encryption keys.
        :param service_ipv4_cidr: The CIDR block to assign Kubernetes service IP addresses from. Default: - Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks
        :param version: The Kubernetes version to run in the cluster.
        :param cluster_name: Name for the cluster. Default: - Automatically generated name
        :param output_cluster_name: Determines whether a CloudFormation output with the name of the cluster will be synthesized. Default: false
        :param output_config_command: Determines whether a CloudFormation output with the ``aws eks update-kubeconfig`` command will be synthesized. This command will include the cluster name and, if applicable, the ARN of the masters IAM role. Default: true
        :param role: Role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf. Default: - A role is automatically created for you
        :param security_group: Security Group to use for Control Plane ENIs. Default: - A security group is automatically created
        :param vpc: The VPC in which to create the Cluster. Default: - a VPC with default configuration will be created and can be accessed through ``cluster.vpc``.
        :param vpc_subnets: Where to place EKS Control Plane ENIs. If you want to create public load balancers, this must include public subnets. For example, to only select private subnets, supply the following: ``vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE }]`` Default: - All public and private subnets
        '''
        props = ClusterProps(
            cluster_logging=cluster_logging,
            default_capacity=default_capacity,
            default_capacity_instance=default_capacity_instance,
            default_capacity_type=default_capacity_type,
            kubectl_lambda_role=kubectl_lambda_role,
            tags=tags,
            alb_controller=alb_controller,
            cluster_handler_environment=cluster_handler_environment,
            cluster_handler_security_group=cluster_handler_security_group,
            core_dns_compute_type=core_dns_compute_type,
            endpoint_access=endpoint_access,
            kubectl_environment=kubectl_environment,
            kubectl_layer=kubectl_layer,
            kubectl_memory=kubectl_memory,
            masters_role=masters_role,
            on_event_layer=on_event_layer,
            output_masters_role_arn=output_masters_role_arn,
            place_cluster_handler_in_vpc=place_cluster_handler_in_vpc,
            prune=prune,
            secrets_encryption_key=secrets_encryption_key,
            service_ipv4_cidr=service_ipv4_cidr,
            version=version,
            cluster_name=cluster_name,
            output_cluster_name=output_cluster_name,
            output_config_command=output_config_command,
            role=role,
            security_group=security_group,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @jsii.member(jsii_name="fromClusterAttributes") # type: ignore[misc]
    @builtins.classmethod
    def from_cluster_attributes(
        cls,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        cluster_name: builtins.str,
        cluster_certificate_authority_data: typing.Optional[builtins.str] = None,
        cluster_encryption_config_key_arn: typing.Optional[builtins.str] = None,
        cluster_endpoint: typing.Optional[builtins.str] = None,
        cluster_handler_security_group_id: typing.Optional[builtins.str] = None,
        cluster_security_group_id: typing.Optional[builtins.str] = None,
        kubectl_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        kubectl_lambda_role: typing.Optional[_IRole_235f5d8e] = None,
        kubectl_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        kubectl_memory: typing.Optional[_Size_7b441c34] = None,
        kubectl_private_subnet_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        kubectl_provider: typing.Optional[IKubectlProvider] = None,
        kubectl_role_arn: typing.Optional[builtins.str] = None,
        kubectl_security_group_id: typing.Optional[builtins.str] = None,
        on_event_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        open_id_connect_provider: typing.Optional[_IOpenIdConnectProvider_203f0793] = None,
        prune: typing.Optional[builtins.bool] = None,
        security_group_ids: typing.Optional[typing.Sequence[builtins.str]] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> ICluster:
        '''Import an existing cluster.

        :param scope: the construct scope, in most cases 'this'.
        :param id: the id or name to import as.
        :param cluster_name: The physical name of the Cluster.
        :param cluster_certificate_authority_data: The certificate-authority-data for your cluster. Default: - if not specified ``cluster.clusterCertificateAuthorityData`` will throw an error
        :param cluster_encryption_config_key_arn: Amazon Resource Name (ARN) or alias of the customer master key (CMK). Default: - if not specified ``cluster.clusterEncryptionConfigKeyArn`` will throw an error
        :param cluster_endpoint: The API Server endpoint URL. Default: - if not specified ``cluster.clusterEndpoint`` will throw an error.
        :param cluster_handler_security_group_id: A security group id to associate with the Cluster Handler's Lambdas. The Cluster Handler's Lambdas are responsible for calling AWS's EKS API. Default: - No security group.
        :param cluster_security_group_id: The cluster security group that was created by Amazon EKS for the cluster. Default: - if not specified ``cluster.clusterSecurityGroupId`` will throw an error
        :param kubectl_environment: Environment variables to use when running ``kubectl`` against this cluster. Default: - no additional variables
        :param kubectl_lambda_role: An IAM role that can perform kubectl operations against this cluster. The role should be mapped to the ``system:masters`` Kubernetes RBAC role. This role is directly passed to the lambda handler that sends Kube Ctl commands to the cluster. Default: - if not specified, the default role created by a lambda function will be used.
        :param kubectl_layer: An AWS Lambda Layer which includes ``kubectl``, Helm and the AWS CLI. This layer is used by the kubectl handler to apply manifests and install helm charts. The handler expects the layer to include the following executables:: helm/helm kubectl/kubectl awscli/aws Default: - a layer bundled with this module.
        :param kubectl_memory: Amount of memory to allocate to the provider's lambda function. Default: Size.gibibytes(1)
        :param kubectl_private_subnet_ids: Subnets to host the ``kubectl`` compute resources. If not specified, the k8s endpoint is expected to be accessible publicly. Default: - k8s endpoint is expected to be accessible publicly
        :param kubectl_provider: KubectlProvider for issuing kubectl commands. Default: - Default CDK provider
        :param kubectl_role_arn: An IAM role with cluster administrator and "system:masters" permissions. Default: - if not specified, it not be possible to issue ``kubectl`` commands against an imported cluster.
        :param kubectl_security_group_id: A security group to use for ``kubectl`` execution. If not specified, the k8s endpoint is expected to be accessible publicly. Default: - k8s endpoint is expected to be accessible publicly
        :param on_event_layer: An AWS Lambda Layer which includes the NPM dependency ``proxy-agent``. This layer is used by the onEvent handler to route AWS SDK requests through a proxy. The handler expects the layer to include the following node_modules:: proxy-agent Default: - a layer bundled with this module.
        :param open_id_connect_provider: An Open ID Connect provider for this cluster that can be used to configure service accounts. You can either import an existing provider using ``iam.OpenIdConnectProvider.fromProviderArn``, or create a new provider using ``new eks.OpenIdConnectProvider`` Default: - if not specified ``cluster.openIdConnectProvider`` and ``cluster.addServiceAccount`` will throw an error.
        :param prune: Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned. When this is enabled (default), prune labels will be allocated and injected to each resource. These labels will then be used when issuing the ``kubectl apply`` operation with the ``--prune`` switch. Default: true
        :param security_group_ids: Additional security groups associated with this cluster. Default: - if not specified, no additional security groups will be considered in ``cluster.connections``.
        :param vpc: The VPC in which this Cluster was created. Default: - if not specified ``cluster.vpc`` will throw an error
        '''
        attrs = ClusterAttributes(
            cluster_name=cluster_name,
            cluster_certificate_authority_data=cluster_certificate_authority_data,
            cluster_encryption_config_key_arn=cluster_encryption_config_key_arn,
            cluster_endpoint=cluster_endpoint,
            cluster_handler_security_group_id=cluster_handler_security_group_id,
            cluster_security_group_id=cluster_security_group_id,
            kubectl_environment=kubectl_environment,
            kubectl_lambda_role=kubectl_lambda_role,
            kubectl_layer=kubectl_layer,
            kubectl_memory=kubectl_memory,
            kubectl_private_subnet_ids=kubectl_private_subnet_ids,
            kubectl_provider=kubectl_provider,
            kubectl_role_arn=kubectl_role_arn,
            kubectl_security_group_id=kubectl_security_group_id,
            on_event_layer=on_event_layer,
            open_id_connect_provider=open_id_connect_provider,
            prune=prune,
            security_group_ids=security_group_ids,
            vpc=vpc,
        )

        return typing.cast(ICluster, jsii.sinvoke(cls, "fromClusterAttributes", [scope, id, attrs]))

    @jsii.member(jsii_name="addAutoScalingGroupCapacity")
    def add_auto_scaling_group_capacity(
        self,
        id: builtins.str,
        *,
        instance_type: _InstanceType_f64915b9,
        bootstrap_enabled: typing.Optional[builtins.bool] = None,
        bootstrap_options: typing.Optional[BootstrapOptions] = None,
        machine_image_type: typing.Optional[MachineImageType] = None,
        map_role: typing.Optional[builtins.bool] = None,
        spot_interrupt_handler: typing.Optional[builtins.bool] = None,
        allow_all_outbound: typing.Optional[builtins.bool] = None,
        associate_public_ip_address: typing.Optional[builtins.bool] = None,
        auto_scaling_group_name: typing.Optional[builtins.str] = None,
        block_devices: typing.Optional[typing.Sequence[_BlockDevice_0cfc0568]] = None,
        cooldown: typing.Optional[_Duration_4839e8c3] = None,
        desired_capacity: typing.Optional[jsii.Number] = None,
        group_metrics: typing.Optional[typing.Sequence[_GroupMetrics_7cdf729b]] = None,
        health_check: typing.Optional[_HealthCheck_03a4bd5a] = None,
        ignore_unmodified_size_properties: typing.Optional[builtins.bool] = None,
        instance_monitoring: typing.Optional[_Monitoring_50020f91] = None,
        key_name: typing.Optional[builtins.str] = None,
        max_capacity: typing.Optional[jsii.Number] = None,
        max_instance_lifetime: typing.Optional[_Duration_4839e8c3] = None,
        min_capacity: typing.Optional[jsii.Number] = None,
        new_instances_protected_from_scale_in: typing.Optional[builtins.bool] = None,
        notifications: typing.Optional[typing.Sequence[_NotificationConfiguration_d5911670]] = None,
        signals: typing.Optional[_Signals_69fbeb6e] = None,
        spot_price: typing.Optional[builtins.str] = None,
        termination_policies: typing.Optional[typing.Sequence[_TerminationPolicy_89633c56]] = None,
        update_policy: typing.Optional[_UpdatePolicy_6dffc7ca] = None,
        vpc_subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
    ) -> _AutoScalingGroup_c547a7b9:
        '''Add nodes to this EKS cluster.

        The nodes will automatically be configured with the right VPC and AMI
        for the instance type and Kubernetes version.

        Note that if you specify ``updateType: RollingUpdate`` or ``updateType: ReplacingUpdate``, your nodes might be replaced at deploy
        time without notice in case the recommended AMI for your machine image type has been updated by AWS.
        The default behavior for ``updateType`` is ``None``, which means only new instances will be launched using the new AMI.

        Spot instances will be labeled ``lifecycle=Ec2Spot`` and tainted with ``PreferNoSchedule``.
        In addition, the `spot interrupt handler <https://github.com/awslabs/ec2-spot-labs/tree/master/ec2-spot-eks-solution/spot-termination-handler>`_
        daemon will be installed on all spot instances to handle
        `EC2 Spot Instance Termination Notices <https://aws.amazon.com/blogs/aws/new-ec2-spot-instance-termination-notices/>`_.

        :param id: -
        :param instance_type: Instance type of the instances to start.
        :param bootstrap_enabled: Configures the EC2 user-data script for instances in this autoscaling group to bootstrap the node (invoke ``/etc/eks/bootstrap.sh``) and associate it with the EKS cluster. If you wish to provide a custom user data script, set this to ``false`` and manually invoke ``autoscalingGroup.addUserData()``. Default: true
        :param bootstrap_options: EKS node bootstrapping options. Default: - none
        :param machine_image_type: Machine image type. Default: MachineImageType.AMAZON_LINUX_2
        :param map_role: Will automatically update the aws-auth ConfigMap to map the IAM instance role to RBAC. This cannot be explicitly set to ``true`` if the cluster has kubectl disabled. Default: - true if the cluster has kubectl enabled (which is the default).
        :param spot_interrupt_handler: Installs the AWS spot instance interrupt handler on the cluster if it's not already added. Only relevant if ``spotPrice`` is used. Default: true
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
        options = AutoScalingGroupCapacityOptions(
            instance_type=instance_type,
            bootstrap_enabled=bootstrap_enabled,
            bootstrap_options=bootstrap_options,
            machine_image_type=machine_image_type,
            map_role=map_role,
            spot_interrupt_handler=spot_interrupt_handler,
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

        return typing.cast(_AutoScalingGroup_c547a7b9, jsii.invoke(self, "addAutoScalingGroupCapacity", [id, options]))

    @jsii.member(jsii_name="addCdk8sChart")
    def add_cdk8s_chart(
        self,
        id: builtins.str,
        chart: constructs.Construct,
        *,
        ingress_alb: typing.Optional[builtins.bool] = None,
        ingress_alb_scheme: typing.Optional[AlbScheme] = None,
        prune: typing.Optional[builtins.bool] = None,
        skip_validation: typing.Optional[builtins.bool] = None,
    ) -> KubernetesManifest:
        '''Defines a CDK8s chart in this cluster.

        :param id: logical id of this chart.
        :param chart: the cdk8s chart.
        :param ingress_alb: Automatically detect ``Ingress`` resources in the manifest and annotate them so they are picked up by an ALB Ingress Controller. Default: false
        :param ingress_alb_scheme: Specify the ALB scheme that should be applied to ``Ingress`` resources. Only applicable if ``ingressAlb`` is set to ``true``. Default: AlbScheme.INTERNAL
        :param prune: When a resource is removed from a Kubernetes manifest, it no longer appears in the manifest, and there is no way to know that this resource needs to be deleted. To address this, ``kubectl apply`` has a ``--prune`` option which will query the cluster for all resources with a specific label and will remove all the labeld resources that are not part of the applied manifest. If this option is disabled and a resource is removed, it will become "orphaned" and will not be deleted from the cluster. When this option is enabled (default), the construct will inject a label to all Kubernetes resources included in this manifest which will be used to prune resources when the manifest changes via ``kubectl apply --prune``. The label name will be ``aws.cdk.eks/prune-<ADDR>`` where ``<ADDR>`` is the 42-char unique address of this construct in the construct tree. Value is empty. Default: - based on the prune option of the cluster, which is ``true`` unless otherwise specified.
        :param skip_validation: A flag to signify if the manifest validation should be skipped. Default: false

        :return: a ``KubernetesManifest`` construct representing the chart.
        '''
        options = KubernetesManifestOptions(
            ingress_alb=ingress_alb,
            ingress_alb_scheme=ingress_alb_scheme,
            prune=prune,
            skip_validation=skip_validation,
        )

        return typing.cast(KubernetesManifest, jsii.invoke(self, "addCdk8sChart", [id, chart, options]))

    @jsii.member(jsii_name="addFargateProfile")
    def add_fargate_profile(
        self,
        id: builtins.str,
        *,
        selectors: typing.Sequence[Selector],
        fargate_profile_name: typing.Optional[builtins.str] = None,
        pod_execution_role: typing.Optional[_IRole_235f5d8e] = None,
        subnet_selection: typing.Optional[_SubnetSelection_e57d76df] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
    ) -> FargateProfile:
        '''Adds a Fargate profile to this cluster.

        :param id: the id of this profile.
        :param selectors: The selectors to match for pods to use this Fargate profile. Each selector must have an associated namespace. Optionally, you can also specify labels for a namespace. At least one selector is required and you may specify up to five selectors.
        :param fargate_profile_name: The name of the Fargate profile. Default: - generated
        :param pod_execution_role: The pod execution role to use for pods that match the selectors in the Fargate profile. The pod execution role allows Fargate infrastructure to register with your cluster as a node, and it provides read access to Amazon ECR image repositories. Default: - a role will be automatically created
        :param subnet_selection: Select which subnets to launch your pods into. At this time, pods running on Fargate are not assigned public IP addresses, so only private subnets (with no direct route to an Internet Gateway) are allowed. You must specify the VPC to customize the subnet selection Default: - all private subnets of the VPC are selected.
        :param vpc: The VPC from which to select subnets to launch your pods into. By default, all private subnets are selected. You can customize this using ``subnetSelection``. Default: - all private subnets used by the EKS cluster

        :see: https://docs.aws.amazon.com/eks/latest/userguide/fargate-profile.html
        '''
        options = FargateProfileOptions(
            selectors=selectors,
            fargate_profile_name=fargate_profile_name,
            pod_execution_role=pod_execution_role,
            subnet_selection=subnet_selection,
            vpc=vpc,
        )

        return typing.cast(FargateProfile, jsii.invoke(self, "addFargateProfile", [id, options]))

    @jsii.member(jsii_name="addHelmChart")
    def add_helm_chart(
        self,
        id: builtins.str,
        *,
        chart: typing.Optional[builtins.str] = None,
        chart_asset: typing.Optional[_Asset_ac2a7e61] = None,
        create_namespace: typing.Optional[builtins.bool] = None,
        namespace: typing.Optional[builtins.str] = None,
        release: typing.Optional[builtins.str] = None,
        repository: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
        values: typing.Optional[typing.Mapping[builtins.str, typing.Any]] = None,
        version: typing.Optional[builtins.str] = None,
        wait: typing.Optional[builtins.bool] = None,
    ) -> HelmChart:
        '''Defines a Helm chart in this cluster.

        :param id: logical id of this chart.
        :param chart: The name of the chart. Either this or ``chartAsset`` must be specified. Default: - No chart name. Implies ``chartAsset`` is used.
        :param chart_asset: The chart in the form of an asset. Either this or ``chart`` must be specified. Default: - No chart asset. Implies ``chart`` is used.
        :param create_namespace: create namespace if not exist. Default: true
        :param namespace: The Kubernetes namespace scope of the requests. Default: default
        :param release: The name of the release. Default: - If no release name is given, it will use the last 53 characters of the node's unique id.
        :param repository: The repository which contains the chart. For example: https://kubernetes-charts.storage.googleapis.com/ Default: - No repository will be used, which means that the chart needs to be an absolute URL.
        :param timeout: Amount of time to wait for any individual Kubernetes operation. Maximum 15 minutes. Default: Duration.minutes(5)
        :param values: The values to be used by the chart. Default: - No values are provided to the chart.
        :param version: The chart version to install. Default: - If this is not specified, the latest version is installed
        :param wait: Whether or not Helm should wait until all Pods, PVCs, Services, and minimum number of Pods of a Deployment, StatefulSet, or ReplicaSet are in a ready state before marking the release as successful. Default: - Helm will not wait before marking release as successful

        :return: a ``HelmChart`` construct
        '''
        options = HelmChartOptions(
            chart=chart,
            chart_asset=chart_asset,
            create_namespace=create_namespace,
            namespace=namespace,
            release=release,
            repository=repository,
            timeout=timeout,
            values=values,
            version=version,
            wait=wait,
        )

        return typing.cast(HelmChart, jsii.invoke(self, "addHelmChart", [id, options]))

    @jsii.member(jsii_name="addManifest")
    def add_manifest(
        self,
        id: builtins.str,
        *manifest: typing.Mapping[builtins.str, typing.Any],
    ) -> KubernetesManifest:
        '''Defines a Kubernetes resource in this cluster.

        The manifest will be applied/deleted using kubectl as needed.

        :param id: logical id of this manifest.
        :param manifest: a list of Kubernetes resource specifications.

        :return: a ``KubernetesResource`` object.
        '''
        return typing.cast(KubernetesManifest, jsii.invoke(self, "addManifest", [id, *manifest]))

    @jsii.member(jsii_name="addNodegroupCapacity")
    def add_nodegroup_capacity(
        self,
        id: builtins.str,
        *,
        ami_type: typing.Optional[NodegroupAmiType] = None,
        capacity_type: typing.Optional[CapacityType] = None,
        desired_size: typing.Optional[jsii.Number] = None,
        disk_size: typing.Optional[jsii.Number] = None,
        force_update: typing.Optional[builtins.bool] = None,
        instance_types: typing.Optional[typing.Sequence[_InstanceType_f64915b9]] = None,
        labels: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        launch_template_spec: typing.Optional[LaunchTemplateSpec] = None,
        max_size: typing.Optional[jsii.Number] = None,
        min_size: typing.Optional[jsii.Number] = None,
        nodegroup_name: typing.Optional[builtins.str] = None,
        node_role: typing.Optional[_IRole_235f5d8e] = None,
        release_version: typing.Optional[builtins.str] = None,
        remote_access: typing.Optional[NodegroupRemoteAccess] = None,
        subnets: typing.Optional[_SubnetSelection_e57d76df] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        taints: typing.Optional[typing.Sequence[TaintSpec]] = None,
    ) -> Nodegroup:
        '''Add managed nodegroup to this Amazon EKS cluster.

        This method will create a new managed nodegroup and add into the capacity.

        :param id: The ID of the nodegroup.
        :param ami_type: The AMI type for your node group. If you explicitly specify the launchTemplate with custom AMI, do not specify this property, or the node group deployment will fail. In other cases, you will need to specify correct amiType for the nodegroup. Default: - auto-determined from the instanceTypes property when launchTemplateSpec property is not specified
        :param capacity_type: The capacity type of the nodegroup. Default: - ON_DEMAND
        :param desired_size: The current number of worker nodes that the managed node group should maintain. If not specified, the nodewgroup will initially create ``minSize`` instances. Default: 2
        :param disk_size: The root device disk size (in GiB) for your node group instances. Default: 20
        :param force_update: Force the update if the existing node group's pods are unable to be drained due to a pod disruption budget issue. If an update fails because pods could not be drained, you can force the update after it fails to terminate the old node whether or not any pods are running on the node. Default: true
        :param instance_types: The instance types to use for your node group. Default: t3.medium will be used according to the cloudformation document.
        :param labels: The Kubernetes labels to be applied to the nodes in the node group when they are created. Default: - None
        :param launch_template_spec: Launch template specification used for the nodegroup. Default: - no launch template
        :param max_size: The maximum number of worker nodes that the managed node group can scale out to. Managed node groups can support up to 100 nodes by default. Default: - desiredSize
        :param min_size: The minimum number of worker nodes that the managed node group can scale in to. This number must be greater than or equal to zero. Default: 1
        :param nodegroup_name: Name of the Nodegroup. Default: - resource ID
        :param node_role: The IAM role to associate with your node group. The Amazon EKS worker node kubelet daemon makes calls to AWS APIs on your behalf. Worker nodes receive permissions for these API calls through an IAM instance profile and associated policies. Before you can launch worker nodes and register them into a cluster, you must create an IAM role for those worker nodes to use when they are launched. Default: - None. Auto-generated if not specified.
        :param release_version: The AMI version of the Amazon EKS-optimized AMI to use with your node group (for example, ``1.14.7-YYYYMMDD``). Default: - The latest available AMI version for the node group's current Kubernetes version is used.
        :param remote_access: The remote access (SSH) configuration to use with your node group. Disabled by default, however, if you specify an Amazon EC2 SSH key but do not specify a source security group when you create a managed node group, then port 22 on the worker nodes is opened to the internet (0.0.0.0/0) Default: - disabled
        :param subnets: The subnets to use for the Auto Scaling group that is created for your node group. By specifying the SubnetSelection, the selected subnets will automatically apply required tags i.e. ``kubernetes.io/cluster/CLUSTER_NAME`` with a value of ``shared``, where ``CLUSTER_NAME`` is replaced with the name of your cluster. Default: - private subnets
        :param tags: The metadata to apply to the node group to assist with categorization and organization. Each tag consists of a key and an optional value, both of which you define. Node group tags do not propagate to any other resources associated with the node group, such as the Amazon EC2 instances or subnets. Default: - None
        :param taints: The Kubernetes taints to be applied to the nodes in the node group when they are created. Default: - None

        :see: https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html
        '''
        options = NodegroupOptions(
            ami_type=ami_type,
            capacity_type=capacity_type,
            desired_size=desired_size,
            disk_size=disk_size,
            force_update=force_update,
            instance_types=instance_types,
            labels=labels,
            launch_template_spec=launch_template_spec,
            max_size=max_size,
            min_size=min_size,
            nodegroup_name=nodegroup_name,
            node_role=node_role,
            release_version=release_version,
            remote_access=remote_access,
            subnets=subnets,
            tags=tags,
            taints=taints,
        )

        return typing.cast(Nodegroup, jsii.invoke(self, "addNodegroupCapacity", [id, options]))

    @jsii.member(jsii_name="addServiceAccount")
    def add_service_account(
        self,
        id: builtins.str,
        *,
        name: typing.Optional[builtins.str] = None,
        namespace: typing.Optional[builtins.str] = None,
    ) -> ServiceAccount:
        '''Creates a new service account with corresponding IAM Role (IRSA).

        :param id: -
        :param name: The name of the service account. Default: - If no name is given, it will use the id of the resource.
        :param namespace: The namespace of the service account. Default: "default"
        '''
        options = ServiceAccountOptions(name=name, namespace=namespace)

        return typing.cast(ServiceAccount, jsii.invoke(self, "addServiceAccount", [id, options]))

    @jsii.member(jsii_name="connectAutoScalingGroupCapacity")
    def connect_auto_scaling_group_capacity(
        self,
        auto_scaling_group: _AutoScalingGroup_c547a7b9,
        *,
        bootstrap_enabled: typing.Optional[builtins.bool] = None,
        bootstrap_options: typing.Optional[BootstrapOptions] = None,
        machine_image_type: typing.Optional[MachineImageType] = None,
        map_role: typing.Optional[builtins.bool] = None,
        spot_interrupt_handler: typing.Optional[builtins.bool] = None,
    ) -> None:
        '''Connect capacity in the form of an existing AutoScalingGroup to the EKS cluster.

        The AutoScalingGroup must be running an EKS-optimized AMI containing the
        /etc/eks/bootstrap.sh script. This method will configure Security Groups,
        add the right policies to the instance role, apply the right tags, and add
        the required user data to the instance's launch configuration.

        Spot instances will be labeled ``lifecycle=Ec2Spot`` and tainted with ``PreferNoSchedule``.
        If kubectl is enabled, the
        `spot interrupt handler <https://github.com/awslabs/ec2-spot-labs/tree/master/ec2-spot-eks-solution/spot-termination-handler>`_
        daemon will be installed on all spot instances to handle
        `EC2 Spot Instance Termination Notices <https://aws.amazon.com/blogs/aws/new-ec2-spot-instance-termination-notices/>`_.

        Prefer to use ``addAutoScalingGroupCapacity`` if possible.

        :param auto_scaling_group: [disable-awslint:ref-via-interface].
        :param bootstrap_enabled: Configures the EC2 user-data script for instances in this autoscaling group to bootstrap the node (invoke ``/etc/eks/bootstrap.sh``) and associate it with the EKS cluster. If you wish to provide a custom user data script, set this to ``false`` and manually invoke ``autoscalingGroup.addUserData()``. Default: true
        :param bootstrap_options: Allows options for node bootstrapping through EC2 user data. Default: - default options
        :param machine_image_type: Allow options to specify different machine image type. Default: MachineImageType.AMAZON_LINUX_2
        :param map_role: Will automatically update the aws-auth ConfigMap to map the IAM instance role to RBAC. This cannot be explicitly set to ``true`` if the cluster has kubectl disabled. Default: - true if the cluster has kubectl enabled (which is the default).
        :param spot_interrupt_handler: Installs the AWS spot instance interrupt handler on the cluster if it's not already added. Only relevant if ``spotPrice`` is configured on the auto-scaling group. Default: true

        :see: https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html
        '''
        options = AutoScalingGroupOptions(
            bootstrap_enabled=bootstrap_enabled,
            bootstrap_options=bootstrap_options,
            machine_image_type=machine_image_type,
            map_role=map_role,
            spot_interrupt_handler=spot_interrupt_handler,
        )

        return typing.cast(None, jsii.invoke(self, "connectAutoScalingGroupCapacity", [auto_scaling_group, options]))

    @jsii.member(jsii_name="getIngressLoadBalancerAddress")
    def get_ingress_load_balancer_address(
        self,
        ingress_name: builtins.str,
        *,
        namespace: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> builtins.str:
        '''Fetch the load balancer address of an ingress backed by a load balancer.

        :param ingress_name: The name of the ingress.
        :param namespace: The namespace the service belongs to. Default: 'default'
        :param timeout: Timeout for waiting on the load balancer address. Default: Duration.minutes(5)
        '''
        options = IngressLoadBalancerAddressOptions(
            namespace=namespace, timeout=timeout
        )

        return typing.cast(builtins.str, jsii.invoke(self, "getIngressLoadBalancerAddress", [ingress_name, options]))

    @jsii.member(jsii_name="getServiceLoadBalancerAddress")
    def get_service_load_balancer_address(
        self,
        service_name: builtins.str,
        *,
        namespace: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> builtins.str:
        '''Fetch the load balancer address of a service of type 'LoadBalancer'.

        :param service_name: The name of the service.
        :param namespace: The namespace the service belongs to. Default: 'default'
        :param timeout: Timeout for waiting on the load balancer address. Default: Duration.minutes(5)
        '''
        options = ServiceLoadBalancerAddressOptions(
            namespace=namespace, timeout=timeout
        )

        return typing.cast(builtins.str, jsii.invoke(self, "getServiceLoadBalancerAddress", [service_name, options]))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="adminRole")
    def admin_role(self) -> _Role_e8c6e11f:
        '''An IAM role with administrative permissions to create or update the cluster.

        This role also has ``systems:master`` permissions.
        '''
        return typing.cast(_Role_e8c6e11f, jsii.get(self, "adminRole"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="awsAuth")
    def aws_auth(self) -> AwsAuth:
        '''Lazily creates the AwsAuth resource, which manages AWS authentication mapping.'''
        return typing.cast(AwsAuth, jsii.get(self, "awsAuth"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterArn")
    def cluster_arn(self) -> builtins.str:
        '''The AWS generated ARN for the Cluster resource.

        For example, ``arn:aws:eks:us-west-2:666666666666:cluster/prod``
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterCertificateAuthorityData")
    def cluster_certificate_authority_data(self) -> builtins.str:
        '''The certificate-authority-data for your cluster.'''
        return typing.cast(builtins.str, jsii.get(self, "clusterCertificateAuthorityData"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterEncryptionConfigKeyArn")
    def cluster_encryption_config_key_arn(self) -> builtins.str:
        '''Amazon Resource Name (ARN) or alias of the customer master key (CMK).'''
        return typing.cast(builtins.str, jsii.get(self, "clusterEncryptionConfigKeyArn"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterEndpoint")
    def cluster_endpoint(self) -> builtins.str:
        '''The endpoint URL for the Cluster.

        This is the URL inside the kubeconfig file to use with kubectl

        For example, ``https://5E1D0CEXAMPLEA591B746AFC5AB30262.yl4.us-west-2.eks.amazonaws.com``
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterEndpoint"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterName")
    def cluster_name(self) -> builtins.str:
        '''The Name of the created EKS Cluster.'''
        return typing.cast(builtins.str, jsii.get(self, "clusterName"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterOpenIdConnectIssuer")
    def cluster_open_id_connect_issuer(self) -> builtins.str:
        '''If this cluster is kubectl-enabled, returns the OpenID Connect issuer.

        This is because the values is only be retrieved by the API and not exposed
        by CloudFormation. If this cluster is not kubectl-enabled (i.e. uses the
        stock ``CfnCluster``), this is ``undefined``.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterOpenIdConnectIssuer"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterOpenIdConnectIssuerUrl")
    def cluster_open_id_connect_issuer_url(self) -> builtins.str:
        '''If this cluster is kubectl-enabled, returns the OpenID Connect issuer url.

        This is because the values is only be retrieved by the API and not exposed
        by CloudFormation. If this cluster is not kubectl-enabled (i.e. uses the
        stock ``CfnCluster``), this is ``undefined``.

        :attribute: true
        '''
        return typing.cast(builtins.str, jsii.get(self, "clusterOpenIdConnectIssuerUrl"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterSecurityGroup")
    def cluster_security_group(self) -> _ISecurityGroup_acf8a799:
        '''The cluster security group that was created by Amazon EKS for the cluster.'''
        return typing.cast(_ISecurityGroup_acf8a799, jsii.get(self, "clusterSecurityGroup"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterSecurityGroupId")
    def cluster_security_group_id(self) -> builtins.str:
        '''The id of the cluster security group that was created by Amazon EKS for the cluster.'''
        return typing.cast(builtins.str, jsii.get(self, "clusterSecurityGroupId"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="connections")
    def connections(self) -> _Connections_0f31fce8:
        '''Manages connection rules (Security Group Rules) for the cluster.

        :memberof: Cluster
        :type: {ec2.Connections}
        '''
        return typing.cast(_Connections_0f31fce8, jsii.get(self, "connections"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="openIdConnectProvider")
    def open_id_connect_provider(self) -> _IOpenIdConnectProvider_203f0793:
        '''An ``OpenIdConnectProvider`` resource associated with this cluster, and which can be used to link this cluster to AWS IAM.

        A provider will only be defined if this property is accessed (lazy initialization).
        '''
        return typing.cast(_IOpenIdConnectProvider_203f0793, jsii.get(self, "openIdConnectProvider"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="prune")
    def prune(self) -> builtins.bool:
        '''Determines if Kubernetes resources can be pruned automatically.'''
        return typing.cast(builtins.bool, jsii.get(self, "prune"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="role")
    def role(self) -> _IRole_235f5d8e:
        '''IAM role assumed by the EKS Control Plane.'''
        return typing.cast(_IRole_235f5d8e, jsii.get(self, "role"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="vpc")
    def vpc(self) -> _IVpc_f30d5663:
        '''The VPC in which this Cluster was created.'''
        return typing.cast(_IVpc_f30d5663, jsii.get(self, "vpc"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="albController")
    def alb_controller(self) -> typing.Optional[AlbController]:
        '''The ALB Controller construct defined for this cluster.

        Will be undefined if ``albController`` wasn't configured.
        '''
        return typing.cast(typing.Optional[AlbController], jsii.get(self, "albController"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="clusterHandlerSecurityGroup")
    def cluster_handler_security_group(
        self,
    ) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''A security group to associate with the Cluster Handler's Lambdas.

        The Cluster Handler's Lambdas are responsible for calling AWS's EKS API.

        Requires ``placeClusterHandlerInVpc`` to be set to true.

        :default: - No security group.
        '''
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], jsii.get(self, "clusterHandlerSecurityGroup"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultCapacity")
    def default_capacity(self) -> typing.Optional[_AutoScalingGroup_c547a7b9]:
        '''The auto scaling group that hosts the default capacity for this cluster.

        This will be ``undefined`` if the ``defaultCapacityType`` is not ``EC2`` or
        ``defaultCapacityType`` is ``EC2`` but default capacity is set to 0.
        '''
        return typing.cast(typing.Optional[_AutoScalingGroup_c547a7b9], jsii.get(self, "defaultCapacity"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultNodegroup")
    def default_nodegroup(self) -> typing.Optional[Nodegroup]:
        '''The node group that hosts the default capacity for this cluster.

        This will be ``undefined`` if the ``defaultCapacityType`` is ``EC2`` or
        ``defaultCapacityType`` is ``NODEGROUP`` but default capacity is set to 0.
        '''
        return typing.cast(typing.Optional[Nodegroup], jsii.get(self, "defaultNodegroup"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlEnvironment")
    def kubectl_environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom environment variables when running ``kubectl`` against this cluster.'''
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], jsii.get(self, "kubectlEnvironment"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlLambdaRole")
    def kubectl_lambda_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''An IAM role that can perform kubectl operations against this cluster.

        The role should be mapped to the ``system:masters`` Kubernetes RBAC role.

        This role is directly passed to the lambda handler that sends Kube Ctl commands to the cluster.

        :default:

        - if not specified, the default role created by a lambda function will
        be used.
        '''
        return typing.cast(typing.Optional[_IRole_235f5d8e], jsii.get(self, "kubectlLambdaRole"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlLayer")
    def kubectl_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''The AWS Lambda layer that contains ``kubectl``, ``helm`` and the AWS CLI.

        If
        undefined, a SAR app that contains this layer will be used.
        '''
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], jsii.get(self, "kubectlLayer"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlMemory")
    def kubectl_memory(self) -> typing.Optional[_Size_7b441c34]:
        '''The amount of memory allocated to the kubectl provider's lambda function.'''
        return typing.cast(typing.Optional[_Size_7b441c34], jsii.get(self, "kubectlMemory"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlPrivateSubnets")
    def kubectl_private_subnets(
        self,
    ) -> typing.Optional[typing.List[_ISubnet_d57d1229]]:
        '''Subnets to host the ``kubectl`` compute resources.

        :default:

        - If not specified, the k8s endpoint is expected to be accessible
        publicly.
        '''
        return typing.cast(typing.Optional[typing.List[_ISubnet_d57d1229]], jsii.get(self, "kubectlPrivateSubnets"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlRole")
    def kubectl_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''An IAM role that can perform kubectl operations against this cluster.

        The role should be mapped to the ``system:masters`` Kubernetes RBAC role.
        '''
        return typing.cast(typing.Optional[_IRole_235f5d8e], jsii.get(self, "kubectlRole"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="kubectlSecurityGroup")
    def kubectl_security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''A security group to use for ``kubectl`` execution.

        :default:

        - If not specified, the k8s endpoint is expected to be accessible
        publicly.
        '''
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], jsii.get(self, "kubectlSecurityGroup"))

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="onEventLayer")
    def on_event_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''The AWS Lambda layer that contains the NPM dependency ``proxy-agent``.

        If
        undefined, a SAR app that contains this layer will be used.
        '''
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], jsii.get(self, "onEventLayer"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.ClusterOptions",
    jsii_struct_bases=[CommonClusterOptions],
    name_mapping={
        "version": "version",
        "cluster_name": "clusterName",
        "output_cluster_name": "outputClusterName",
        "output_config_command": "outputConfigCommand",
        "role": "role",
        "security_group": "securityGroup",
        "vpc": "vpc",
        "vpc_subnets": "vpcSubnets",
        "alb_controller": "albController",
        "cluster_handler_environment": "clusterHandlerEnvironment",
        "cluster_handler_security_group": "clusterHandlerSecurityGroup",
        "core_dns_compute_type": "coreDnsComputeType",
        "endpoint_access": "endpointAccess",
        "kubectl_environment": "kubectlEnvironment",
        "kubectl_layer": "kubectlLayer",
        "kubectl_memory": "kubectlMemory",
        "masters_role": "mastersRole",
        "on_event_layer": "onEventLayer",
        "output_masters_role_arn": "outputMastersRoleArn",
        "place_cluster_handler_in_vpc": "placeClusterHandlerInVpc",
        "prune": "prune",
        "secrets_encryption_key": "secretsEncryptionKey",
        "service_ipv4_cidr": "serviceIpv4Cidr",
    },
)
class ClusterOptions(CommonClusterOptions):
    def __init__(
        self,
        *,
        version: KubernetesVersion,
        cluster_name: typing.Optional[builtins.str] = None,
        output_cluster_name: typing.Optional[builtins.bool] = None,
        output_config_command: typing.Optional[builtins.bool] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[typing.Sequence[_SubnetSelection_e57d76df]] = None,
        alb_controller: typing.Optional[AlbControllerOptions] = None,
        cluster_handler_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        cluster_handler_security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        core_dns_compute_type: typing.Optional[CoreDnsComputeType] = None,
        endpoint_access: typing.Optional[EndpointAccess] = None,
        kubectl_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        kubectl_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        kubectl_memory: typing.Optional[_Size_7b441c34] = None,
        masters_role: typing.Optional[_IRole_235f5d8e] = None,
        on_event_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        output_masters_role_arn: typing.Optional[builtins.bool] = None,
        place_cluster_handler_in_vpc: typing.Optional[builtins.bool] = None,
        prune: typing.Optional[builtins.bool] = None,
        secrets_encryption_key: typing.Optional[_IKey_5f11635f] = None,
        service_ipv4_cidr: typing.Optional[builtins.str] = None,
    ) -> None:
        '''Options for EKS clusters.

        :param version: The Kubernetes version to run in the cluster.
        :param cluster_name: Name for the cluster. Default: - Automatically generated name
        :param output_cluster_name: Determines whether a CloudFormation output with the name of the cluster will be synthesized. Default: false
        :param output_config_command: Determines whether a CloudFormation output with the ``aws eks update-kubeconfig`` command will be synthesized. This command will include the cluster name and, if applicable, the ARN of the masters IAM role. Default: true
        :param role: Role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf. Default: - A role is automatically created for you
        :param security_group: Security Group to use for Control Plane ENIs. Default: - A security group is automatically created
        :param vpc: The VPC in which to create the Cluster. Default: - a VPC with default configuration will be created and can be accessed through ``cluster.vpc``.
        :param vpc_subnets: Where to place EKS Control Plane ENIs. If you want to create public load balancers, this must include public subnets. For example, to only select private subnets, supply the following: ``vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE }]`` Default: - All public and private subnets
        :param alb_controller: Install the AWS Load Balancer Controller onto the cluster. Default: - The controller is not installed.
        :param cluster_handler_environment: Custom environment variables when interacting with the EKS endpoint to manage the cluster lifecycle. Default: - No environment variables.
        :param cluster_handler_security_group: A security group to associate with the Cluster Handler's Lambdas. The Cluster Handler's Lambdas are responsible for calling AWS's EKS API. Requires ``placeClusterHandlerInVpc`` to be set to true. Default: - No security group.
        :param core_dns_compute_type: Controls the "eks.amazonaws.com/compute-type" annotation in the CoreDNS configuration on your cluster to determine which compute type to use for CoreDNS. Default: CoreDnsComputeType.EC2 (for ``FargateCluster`` the default is FARGATE)
        :param endpoint_access: Configure access to the Kubernetes API server endpoint.. Default: EndpointAccess.PUBLIC_AND_PRIVATE
        :param kubectl_environment: Environment variables for the kubectl execution. Only relevant for kubectl enabled clusters. Default: - No environment variables.
        :param kubectl_layer: An AWS Lambda Layer which includes ``kubectl``, Helm and the AWS CLI. By default, the provider will use the layer included in the "aws-lambda-layer-kubectl" SAR application which is available in all commercial regions. To deploy the layer locally, visit https://github.com/aws-samples/aws-lambda-layer-kubectl/blob/master/cdk/README.md for instructions on how to prepare the .zip file and then define it in your app as follows:: const layer = new lambda.LayerVersion(this, 'kubectl-layer', { code: lambda.Code.fromAsset(`${__dirname}/layer.zip`), compatibleRuntimes: [lambda.Runtime.PROVIDED], }); Default: - the layer provided by the ``aws-lambda-layer-kubectl`` SAR app.
        :param kubectl_memory: Amount of memory to allocate to the provider's lambda function. Default: Size.gibibytes(1)
        :param masters_role: An IAM role that will be added to the ``system:masters`` Kubernetes RBAC group. Default: - a role that assumable by anyone with permissions in the same account will automatically be defined
        :param on_event_layer: An AWS Lambda Layer which includes the NPM dependency ``proxy-agent``. This layer is used by the onEvent handler to route AWS SDK requests through a proxy. By default, the provider will use the layer included in the "aws-lambda-layer-node-proxy-agent" SAR application which is available in all commercial regions. To deploy the layer locally define it in your app as follows:: const layer = new lambda.LayerVersion(this, 'proxy-agent-layer', { code: lambda.Code.fromAsset(`${__dirname}/layer.zip`), compatibleRuntimes: [lambda.Runtime.NODEJS_12_X], }); Default: - a layer bundled with this module.
        :param output_masters_role_arn: Determines whether a CloudFormation output with the ARN of the "masters" IAM role will be synthesized (if ``mastersRole`` is specified). Default: false
        :param place_cluster_handler_in_vpc: If set to true, the cluster handler functions will be placed in the private subnets of the cluster vpc, subject to the ``vpcSubnets`` selection strategy. Default: false
        :param prune: Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned. When this is enabled (default), prune labels will be allocated and injected to each resource. These labels will then be used when issuing the ``kubectl apply`` operation with the ``--prune`` switch. Default: true
        :param secrets_encryption_key: KMS secret for envelope encryption for Kubernetes secrets. Default: - By default, Kubernetes stores all secret object data within etcd and all etcd volumes used by Amazon EKS are encrypted at the disk-level using AWS-Managed encryption keys.
        :param service_ipv4_cidr: The CIDR block to assign Kubernetes service IP addresses from. Default: - Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_ec2 as ec2
            from aws_cdk import aws_eks as eks
            from aws_cdk import aws_iam as iam
            from aws_cdk import aws_kms as kms
            from aws_cdk import aws_lambda as lambda_
            
            # alb_controller_version: eks.AlbControllerVersion
            # endpoint_access: eks.EndpointAccess
            # key: kms.Key
            # kubernetes_version: eks.KubernetesVersion
            # layer_version: lambda.LayerVersion
            # policy: Any
            # role: iam.Role
            # security_group: ec2.SecurityGroup
            # size: cdk.Size
            # subnet: ec2.Subnet
            # subnet_filter: ec2.SubnetFilter
            # vpc: ec2.Vpc
            
            cluster_options = eks.ClusterOptions(
                version=kubernetes_version,
            
                # the properties below are optional
                alb_controller=eks.AlbControllerOptions(
                    version=alb_controller_version,
            
                    # the properties below are optional
                    policy=policy,
                    repository="repository"
                ),
                cluster_handler_environment={
                    "cluster_handler_environment_key": "clusterHandlerEnvironment"
                },
                cluster_handler_security_group=security_group,
                cluster_name="clusterName",
                core_dns_compute_type=eks.CoreDnsComputeType.EC2,
                endpoint_access=endpoint_access,
                kubectl_environment={
                    "kubectl_environment_key": "kubectlEnvironment"
                },
                kubectl_layer=layer_version,
                kubectl_memory=size,
                masters_role=role,
                on_event_layer=layer_version,
                output_cluster_name=False,
                output_config_command=False,
                output_masters_role_arn=False,
                place_cluster_handler_in_vpc=False,
                prune=False,
                role=role,
                secrets_encryption_key=key,
                security_group=security_group,
                service_ipv4_cidr="serviceIpv4Cidr",
                vpc=vpc,
                vpc_subnets=[ec2.SubnetSelection(
                    availability_zones=["availabilityZones"],
                    one_per_az=False,
                    subnet_filters=[subnet_filter],
                    subnet_group_name="subnetGroupName",
                    subnets=[subnet],
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
                )]
            )
        '''
        if isinstance(alb_controller, dict):
            alb_controller = AlbControllerOptions(**alb_controller)
        self._values: typing.Dict[str, typing.Any] = {
            "version": version,
        }
        if cluster_name is not None:
            self._values["cluster_name"] = cluster_name
        if output_cluster_name is not None:
            self._values["output_cluster_name"] = output_cluster_name
        if output_config_command is not None:
            self._values["output_config_command"] = output_config_command
        if role is not None:
            self._values["role"] = role
        if security_group is not None:
            self._values["security_group"] = security_group
        if vpc is not None:
            self._values["vpc"] = vpc
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets
        if alb_controller is not None:
            self._values["alb_controller"] = alb_controller
        if cluster_handler_environment is not None:
            self._values["cluster_handler_environment"] = cluster_handler_environment
        if cluster_handler_security_group is not None:
            self._values["cluster_handler_security_group"] = cluster_handler_security_group
        if core_dns_compute_type is not None:
            self._values["core_dns_compute_type"] = core_dns_compute_type
        if endpoint_access is not None:
            self._values["endpoint_access"] = endpoint_access
        if kubectl_environment is not None:
            self._values["kubectl_environment"] = kubectl_environment
        if kubectl_layer is not None:
            self._values["kubectl_layer"] = kubectl_layer
        if kubectl_memory is not None:
            self._values["kubectl_memory"] = kubectl_memory
        if masters_role is not None:
            self._values["masters_role"] = masters_role
        if on_event_layer is not None:
            self._values["on_event_layer"] = on_event_layer
        if output_masters_role_arn is not None:
            self._values["output_masters_role_arn"] = output_masters_role_arn
        if place_cluster_handler_in_vpc is not None:
            self._values["place_cluster_handler_in_vpc"] = place_cluster_handler_in_vpc
        if prune is not None:
            self._values["prune"] = prune
        if secrets_encryption_key is not None:
            self._values["secrets_encryption_key"] = secrets_encryption_key
        if service_ipv4_cidr is not None:
            self._values["service_ipv4_cidr"] = service_ipv4_cidr

    @builtins.property
    def version(self) -> KubernetesVersion:
        '''The Kubernetes version to run in the cluster.'''
        result = self._values.get("version")
        assert result is not None, "Required property 'version' is missing"
        return typing.cast(KubernetesVersion, result)

    @builtins.property
    def cluster_name(self) -> typing.Optional[builtins.str]:
        '''Name for the cluster.

        :default: - Automatically generated name
        '''
        result = self._values.get("cluster_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def output_cluster_name(self) -> typing.Optional[builtins.bool]:
        '''Determines whether a CloudFormation output with the name of the cluster will be synthesized.

        :default: false
        '''
        result = self._values.get("output_cluster_name")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def output_config_command(self) -> typing.Optional[builtins.bool]:
        '''Determines whether a CloudFormation output with the ``aws eks update-kubeconfig`` command will be synthesized.

        This command will include
        the cluster name and, if applicable, the ARN of the masters IAM role.

        :default: true
        '''
        result = self._values.get("output_config_command")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''Role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf.

        :default: - A role is automatically created for you
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''Security Group to use for Control Plane ENIs.

        :default: - A security group is automatically created
        '''
        result = self._values.get("security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC in which to create the Cluster.

        :default: - a VPC with default configuration will be created and can be accessed through ``cluster.vpc``.
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[typing.List[_SubnetSelection_e57d76df]]:
        '''Where to place EKS Control Plane ENIs.

        If you want to create public load balancers, this must include public subnets.

        For example, to only select private subnets, supply the following:

        ``vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE }]``

        :default: - All public and private subnets
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[typing.List[_SubnetSelection_e57d76df]], result)

    @builtins.property
    def alb_controller(self) -> typing.Optional[AlbControllerOptions]:
        '''Install the AWS Load Balancer Controller onto the cluster.

        :default: - The controller is not installed.

        :see: https://kubernetes-sigs.github.io/aws-load-balancer-controller
        '''
        result = self._values.get("alb_controller")
        return typing.cast(typing.Optional[AlbControllerOptions], result)

    @builtins.property
    def cluster_handler_environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom environment variables when interacting with the EKS endpoint to manage the cluster lifecycle.

        :default: - No environment variables.
        '''
        result = self._values.get("cluster_handler_environment")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def cluster_handler_security_group(
        self,
    ) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''A security group to associate with the Cluster Handler's Lambdas.

        The Cluster Handler's Lambdas are responsible for calling AWS's EKS API.

        Requires ``placeClusterHandlerInVpc`` to be set to true.

        :default: - No security group.
        '''
        result = self._values.get("cluster_handler_security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    @builtins.property
    def core_dns_compute_type(self) -> typing.Optional[CoreDnsComputeType]:
        '''Controls the "eks.amazonaws.com/compute-type" annotation in the CoreDNS configuration on your cluster to determine which compute type to use for CoreDNS.

        :default: CoreDnsComputeType.EC2 (for ``FargateCluster`` the default is FARGATE)
        '''
        result = self._values.get("core_dns_compute_type")
        return typing.cast(typing.Optional[CoreDnsComputeType], result)

    @builtins.property
    def endpoint_access(self) -> typing.Optional[EndpointAccess]:
        '''Configure access to the Kubernetes API server endpoint..

        :default: EndpointAccess.PUBLIC_AND_PRIVATE

        :see: https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html
        '''
        result = self._values.get("endpoint_access")
        return typing.cast(typing.Optional[EndpointAccess], result)

    @builtins.property
    def kubectl_environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Environment variables for the kubectl execution.

        Only relevant for kubectl enabled clusters.

        :default: - No environment variables.
        '''
        result = self._values.get("kubectl_environment")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def kubectl_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda Layer which includes ``kubectl``, Helm and the AWS CLI.

        By default, the provider will use the layer included in the
        "aws-lambda-layer-kubectl" SAR application which is available in all
        commercial regions.

        To deploy the layer locally, visit
        https://github.com/aws-samples/aws-lambda-layer-kubectl/blob/master/cdk/README.md
        for instructions on how to prepare the .zip file and then define it in your
        app as follows::

           layer = lambda_.LayerVersion(self, "kubectl-layer",
               code=lambda_.Code.from_asset(f"{__dirname}/layer.zip"),
               compatible_runtimes=[lambda_.Runtime.PROVIDED]
           )

        :default: - the layer provided by the ``aws-lambda-layer-kubectl`` SAR app.

        :see: https://github.com/aws-samples/aws-lambda-layer-kubectl
        '''
        result = self._values.get("kubectl_layer")
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], result)

    @builtins.property
    def kubectl_memory(self) -> typing.Optional[_Size_7b441c34]:
        '''Amount of memory to allocate to the provider's lambda function.

        :default: Size.gibibytes(1)
        '''
        result = self._values.get("kubectl_memory")
        return typing.cast(typing.Optional[_Size_7b441c34], result)

    @builtins.property
    def masters_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''An IAM role that will be added to the ``system:masters`` Kubernetes RBAC group.

        :default:

        - a role that assumable by anyone with permissions in the same
        account will automatically be defined

        :see: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings
        '''
        result = self._values.get("masters_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def on_event_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda Layer which includes the NPM dependency ``proxy-agent``.

        This layer
        is used by the onEvent handler to route AWS SDK requests through a proxy.

        By default, the provider will use the layer included in the
        "aws-lambda-layer-node-proxy-agent" SAR application which is available in all
        commercial regions.

        To deploy the layer locally define it in your app as follows::

           layer = lambda_.LayerVersion(self, "proxy-agent-layer",
               code=lambda_.Code.from_asset(f"{__dirname}/layer.zip"),
               compatible_runtimes=[lambda_.Runtime.NODEJS_12_X]
           )

        :default: - a layer bundled with this module.
        '''
        result = self._values.get("on_event_layer")
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], result)

    @builtins.property
    def output_masters_role_arn(self) -> typing.Optional[builtins.bool]:
        '''Determines whether a CloudFormation output with the ARN of the "masters" IAM role will be synthesized (if ``mastersRole`` is specified).

        :default: false
        '''
        result = self._values.get("output_masters_role_arn")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def place_cluster_handler_in_vpc(self) -> typing.Optional[builtins.bool]:
        '''If set to true, the cluster handler functions will be placed in the private subnets of the cluster vpc, subject to the ``vpcSubnets`` selection strategy.

        :default: false
        '''
        result = self._values.get("place_cluster_handler_in_vpc")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def prune(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned.

        When this is enabled (default), prune labels will be
        allocated and injected to each resource. These labels will then be used
        when issuing the ``kubectl apply`` operation with the ``--prune`` switch.

        :default: true
        '''
        result = self._values.get("prune")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def secrets_encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''KMS secret for envelope encryption for Kubernetes secrets.

        :default:

        - By default, Kubernetes stores all secret object data within etcd and
        all etcd volumes used by Amazon EKS are encrypted at the disk-level
        using AWS-Managed encryption keys.
        '''
        result = self._values.get("secrets_encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def service_ipv4_cidr(self) -> typing.Optional[builtins.str]:
        '''The CIDR block to assign Kubernetes service IP addresses from.

        :default:

        - Kubernetes assigns addresses from either the
        10.100.0.0/16 or 172.20.0.0/16 CIDR blocks

        :see: https://docs.aws.amazon.com/eks/latest/APIReference/API_KubernetesNetworkConfigRequest.html#AmazonEKS-Type-KubernetesNetworkConfigRequest-serviceIpv4Cidr
        '''
        result = self._values.get("service_ipv4_cidr")
        return typing.cast(typing.Optional[builtins.str], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.ClusterProps",
    jsii_struct_bases=[ClusterOptions],
    name_mapping={
        "version": "version",
        "cluster_name": "clusterName",
        "output_cluster_name": "outputClusterName",
        "output_config_command": "outputConfigCommand",
        "role": "role",
        "security_group": "securityGroup",
        "vpc": "vpc",
        "vpc_subnets": "vpcSubnets",
        "alb_controller": "albController",
        "cluster_handler_environment": "clusterHandlerEnvironment",
        "cluster_handler_security_group": "clusterHandlerSecurityGroup",
        "core_dns_compute_type": "coreDnsComputeType",
        "endpoint_access": "endpointAccess",
        "kubectl_environment": "kubectlEnvironment",
        "kubectl_layer": "kubectlLayer",
        "kubectl_memory": "kubectlMemory",
        "masters_role": "mastersRole",
        "on_event_layer": "onEventLayer",
        "output_masters_role_arn": "outputMastersRoleArn",
        "place_cluster_handler_in_vpc": "placeClusterHandlerInVpc",
        "prune": "prune",
        "secrets_encryption_key": "secretsEncryptionKey",
        "service_ipv4_cidr": "serviceIpv4Cidr",
        "cluster_logging": "clusterLogging",
        "default_capacity": "defaultCapacity",
        "default_capacity_instance": "defaultCapacityInstance",
        "default_capacity_type": "defaultCapacityType",
        "kubectl_lambda_role": "kubectlLambdaRole",
        "tags": "tags",
    },
)
class ClusterProps(ClusterOptions):
    def __init__(
        self,
        *,
        version: KubernetesVersion,
        cluster_name: typing.Optional[builtins.str] = None,
        output_cluster_name: typing.Optional[builtins.bool] = None,
        output_config_command: typing.Optional[builtins.bool] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[typing.Sequence[_SubnetSelection_e57d76df]] = None,
        alb_controller: typing.Optional[AlbControllerOptions] = None,
        cluster_handler_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        cluster_handler_security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        core_dns_compute_type: typing.Optional[CoreDnsComputeType] = None,
        endpoint_access: typing.Optional[EndpointAccess] = None,
        kubectl_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        kubectl_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        kubectl_memory: typing.Optional[_Size_7b441c34] = None,
        masters_role: typing.Optional[_IRole_235f5d8e] = None,
        on_event_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        output_masters_role_arn: typing.Optional[builtins.bool] = None,
        place_cluster_handler_in_vpc: typing.Optional[builtins.bool] = None,
        prune: typing.Optional[builtins.bool] = None,
        secrets_encryption_key: typing.Optional[_IKey_5f11635f] = None,
        service_ipv4_cidr: typing.Optional[builtins.str] = None,
        cluster_logging: typing.Optional[typing.Sequence[ClusterLoggingTypes]] = None,
        default_capacity: typing.Optional[jsii.Number] = None,
        default_capacity_instance: typing.Optional[_InstanceType_f64915b9] = None,
        default_capacity_type: typing.Optional[DefaultCapacityType] = None,
        kubectl_lambda_role: typing.Optional[_IRole_235f5d8e] = None,
        tags: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
    ) -> None:
        '''Common configuration props for EKS clusters.

        :param version: The Kubernetes version to run in the cluster.
        :param cluster_name: Name for the cluster. Default: - Automatically generated name
        :param output_cluster_name: Determines whether a CloudFormation output with the name of the cluster will be synthesized. Default: false
        :param output_config_command: Determines whether a CloudFormation output with the ``aws eks update-kubeconfig`` command will be synthesized. This command will include the cluster name and, if applicable, the ARN of the masters IAM role. Default: true
        :param role: Role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf. Default: - A role is automatically created for you
        :param security_group: Security Group to use for Control Plane ENIs. Default: - A security group is automatically created
        :param vpc: The VPC in which to create the Cluster. Default: - a VPC with default configuration will be created and can be accessed through ``cluster.vpc``.
        :param vpc_subnets: Where to place EKS Control Plane ENIs. If you want to create public load balancers, this must include public subnets. For example, to only select private subnets, supply the following: ``vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE }]`` Default: - All public and private subnets
        :param alb_controller: Install the AWS Load Balancer Controller onto the cluster. Default: - The controller is not installed.
        :param cluster_handler_environment: Custom environment variables when interacting with the EKS endpoint to manage the cluster lifecycle. Default: - No environment variables.
        :param cluster_handler_security_group: A security group to associate with the Cluster Handler's Lambdas. The Cluster Handler's Lambdas are responsible for calling AWS's EKS API. Requires ``placeClusterHandlerInVpc`` to be set to true. Default: - No security group.
        :param core_dns_compute_type: Controls the "eks.amazonaws.com/compute-type" annotation in the CoreDNS configuration on your cluster to determine which compute type to use for CoreDNS. Default: CoreDnsComputeType.EC2 (for ``FargateCluster`` the default is FARGATE)
        :param endpoint_access: Configure access to the Kubernetes API server endpoint.. Default: EndpointAccess.PUBLIC_AND_PRIVATE
        :param kubectl_environment: Environment variables for the kubectl execution. Only relevant for kubectl enabled clusters. Default: - No environment variables.
        :param kubectl_layer: An AWS Lambda Layer which includes ``kubectl``, Helm and the AWS CLI. By default, the provider will use the layer included in the "aws-lambda-layer-kubectl" SAR application which is available in all commercial regions. To deploy the layer locally, visit https://github.com/aws-samples/aws-lambda-layer-kubectl/blob/master/cdk/README.md for instructions on how to prepare the .zip file and then define it in your app as follows:: const layer = new lambda.LayerVersion(this, 'kubectl-layer', { code: lambda.Code.fromAsset(`${__dirname}/layer.zip`), compatibleRuntimes: [lambda.Runtime.PROVIDED], }); Default: - the layer provided by the ``aws-lambda-layer-kubectl`` SAR app.
        :param kubectl_memory: Amount of memory to allocate to the provider's lambda function. Default: Size.gibibytes(1)
        :param masters_role: An IAM role that will be added to the ``system:masters`` Kubernetes RBAC group. Default: - a role that assumable by anyone with permissions in the same account will automatically be defined
        :param on_event_layer: An AWS Lambda Layer which includes the NPM dependency ``proxy-agent``. This layer is used by the onEvent handler to route AWS SDK requests through a proxy. By default, the provider will use the layer included in the "aws-lambda-layer-node-proxy-agent" SAR application which is available in all commercial regions. To deploy the layer locally define it in your app as follows:: const layer = new lambda.LayerVersion(this, 'proxy-agent-layer', { code: lambda.Code.fromAsset(`${__dirname}/layer.zip`), compatibleRuntimes: [lambda.Runtime.NODEJS_12_X], }); Default: - a layer bundled with this module.
        :param output_masters_role_arn: Determines whether a CloudFormation output with the ARN of the "masters" IAM role will be synthesized (if ``mastersRole`` is specified). Default: false
        :param place_cluster_handler_in_vpc: If set to true, the cluster handler functions will be placed in the private subnets of the cluster vpc, subject to the ``vpcSubnets`` selection strategy. Default: false
        :param prune: Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned. When this is enabled (default), prune labels will be allocated and injected to each resource. These labels will then be used when issuing the ``kubectl apply`` operation with the ``--prune`` switch. Default: true
        :param secrets_encryption_key: KMS secret for envelope encryption for Kubernetes secrets. Default: - By default, Kubernetes stores all secret object data within etcd and all etcd volumes used by Amazon EKS are encrypted at the disk-level using AWS-Managed encryption keys.
        :param service_ipv4_cidr: The CIDR block to assign Kubernetes service IP addresses from. Default: - Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks
        :param cluster_logging: The cluster log types which you want to enable. Default: - none
        :param default_capacity: Number of instances to allocate as an initial capacity for this cluster. Instance type can be configured through ``defaultCapacityInstanceType``, which defaults to ``m5.large``. Use ``cluster.addAutoScalingGroupCapacity`` to add additional customized capacity. Set this to ``0`` is you wish to avoid the initial capacity allocation. Default: 2
        :param default_capacity_instance: The instance type to use for the default capacity. This will only be taken into account if ``defaultCapacity`` is > 0. Default: m5.large
        :param default_capacity_type: The default capacity type for the cluster. Default: NODEGROUP
        :param kubectl_lambda_role: The IAM role to pass to the Kubectl Lambda Handler. Default: - Default Lambda IAM Execution Role
        :param tags: The tags assigned to the EKS cluster. Default: - none

        :exampleMetadata: infused

        Example::

            # vpc: ec2.Vpc
            
            
            eks.Cluster(self, "HelloEKS",
                version=eks.KubernetesVersion.V1_21,
                vpc=vpc,
                vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE)]
            )
        '''
        if isinstance(alb_controller, dict):
            alb_controller = AlbControllerOptions(**alb_controller)
        self._values: typing.Dict[str, typing.Any] = {
            "version": version,
        }
        if cluster_name is not None:
            self._values["cluster_name"] = cluster_name
        if output_cluster_name is not None:
            self._values["output_cluster_name"] = output_cluster_name
        if output_config_command is not None:
            self._values["output_config_command"] = output_config_command
        if role is not None:
            self._values["role"] = role
        if security_group is not None:
            self._values["security_group"] = security_group
        if vpc is not None:
            self._values["vpc"] = vpc
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets
        if alb_controller is not None:
            self._values["alb_controller"] = alb_controller
        if cluster_handler_environment is not None:
            self._values["cluster_handler_environment"] = cluster_handler_environment
        if cluster_handler_security_group is not None:
            self._values["cluster_handler_security_group"] = cluster_handler_security_group
        if core_dns_compute_type is not None:
            self._values["core_dns_compute_type"] = core_dns_compute_type
        if endpoint_access is not None:
            self._values["endpoint_access"] = endpoint_access
        if kubectl_environment is not None:
            self._values["kubectl_environment"] = kubectl_environment
        if kubectl_layer is not None:
            self._values["kubectl_layer"] = kubectl_layer
        if kubectl_memory is not None:
            self._values["kubectl_memory"] = kubectl_memory
        if masters_role is not None:
            self._values["masters_role"] = masters_role
        if on_event_layer is not None:
            self._values["on_event_layer"] = on_event_layer
        if output_masters_role_arn is not None:
            self._values["output_masters_role_arn"] = output_masters_role_arn
        if place_cluster_handler_in_vpc is not None:
            self._values["place_cluster_handler_in_vpc"] = place_cluster_handler_in_vpc
        if prune is not None:
            self._values["prune"] = prune
        if secrets_encryption_key is not None:
            self._values["secrets_encryption_key"] = secrets_encryption_key
        if service_ipv4_cidr is not None:
            self._values["service_ipv4_cidr"] = service_ipv4_cidr
        if cluster_logging is not None:
            self._values["cluster_logging"] = cluster_logging
        if default_capacity is not None:
            self._values["default_capacity"] = default_capacity
        if default_capacity_instance is not None:
            self._values["default_capacity_instance"] = default_capacity_instance
        if default_capacity_type is not None:
            self._values["default_capacity_type"] = default_capacity_type
        if kubectl_lambda_role is not None:
            self._values["kubectl_lambda_role"] = kubectl_lambda_role
        if tags is not None:
            self._values["tags"] = tags

    @builtins.property
    def version(self) -> KubernetesVersion:
        '''The Kubernetes version to run in the cluster.'''
        result = self._values.get("version")
        assert result is not None, "Required property 'version' is missing"
        return typing.cast(KubernetesVersion, result)

    @builtins.property
    def cluster_name(self) -> typing.Optional[builtins.str]:
        '''Name for the cluster.

        :default: - Automatically generated name
        '''
        result = self._values.get("cluster_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def output_cluster_name(self) -> typing.Optional[builtins.bool]:
        '''Determines whether a CloudFormation output with the name of the cluster will be synthesized.

        :default: false
        '''
        result = self._values.get("output_cluster_name")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def output_config_command(self) -> typing.Optional[builtins.bool]:
        '''Determines whether a CloudFormation output with the ``aws eks update-kubeconfig`` command will be synthesized.

        This command will include
        the cluster name and, if applicable, the ARN of the masters IAM role.

        :default: true
        '''
        result = self._values.get("output_config_command")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''Role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf.

        :default: - A role is automatically created for you
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''Security Group to use for Control Plane ENIs.

        :default: - A security group is automatically created
        '''
        result = self._values.get("security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC in which to create the Cluster.

        :default: - a VPC with default configuration will be created and can be accessed through ``cluster.vpc``.
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[typing.List[_SubnetSelection_e57d76df]]:
        '''Where to place EKS Control Plane ENIs.

        If you want to create public load balancers, this must include public subnets.

        For example, to only select private subnets, supply the following:

        ``vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE }]``

        :default: - All public and private subnets
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[typing.List[_SubnetSelection_e57d76df]], result)

    @builtins.property
    def alb_controller(self) -> typing.Optional[AlbControllerOptions]:
        '''Install the AWS Load Balancer Controller onto the cluster.

        :default: - The controller is not installed.

        :see: https://kubernetes-sigs.github.io/aws-load-balancer-controller
        '''
        result = self._values.get("alb_controller")
        return typing.cast(typing.Optional[AlbControllerOptions], result)

    @builtins.property
    def cluster_handler_environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom environment variables when interacting with the EKS endpoint to manage the cluster lifecycle.

        :default: - No environment variables.
        '''
        result = self._values.get("cluster_handler_environment")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def cluster_handler_security_group(
        self,
    ) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''A security group to associate with the Cluster Handler's Lambdas.

        The Cluster Handler's Lambdas are responsible for calling AWS's EKS API.

        Requires ``placeClusterHandlerInVpc`` to be set to true.

        :default: - No security group.
        '''
        result = self._values.get("cluster_handler_security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    @builtins.property
    def core_dns_compute_type(self) -> typing.Optional[CoreDnsComputeType]:
        '''Controls the "eks.amazonaws.com/compute-type" annotation in the CoreDNS configuration on your cluster to determine which compute type to use for CoreDNS.

        :default: CoreDnsComputeType.EC2 (for ``FargateCluster`` the default is FARGATE)
        '''
        result = self._values.get("core_dns_compute_type")
        return typing.cast(typing.Optional[CoreDnsComputeType], result)

    @builtins.property
    def endpoint_access(self) -> typing.Optional[EndpointAccess]:
        '''Configure access to the Kubernetes API server endpoint..

        :default: EndpointAccess.PUBLIC_AND_PRIVATE

        :see: https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html
        '''
        result = self._values.get("endpoint_access")
        return typing.cast(typing.Optional[EndpointAccess], result)

    @builtins.property
    def kubectl_environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Environment variables for the kubectl execution.

        Only relevant for kubectl enabled clusters.

        :default: - No environment variables.
        '''
        result = self._values.get("kubectl_environment")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def kubectl_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda Layer which includes ``kubectl``, Helm and the AWS CLI.

        By default, the provider will use the layer included in the
        "aws-lambda-layer-kubectl" SAR application which is available in all
        commercial regions.

        To deploy the layer locally, visit
        https://github.com/aws-samples/aws-lambda-layer-kubectl/blob/master/cdk/README.md
        for instructions on how to prepare the .zip file and then define it in your
        app as follows::

           layer = lambda_.LayerVersion(self, "kubectl-layer",
               code=lambda_.Code.from_asset(f"{__dirname}/layer.zip"),
               compatible_runtimes=[lambda_.Runtime.PROVIDED]
           )

        :default: - the layer provided by the ``aws-lambda-layer-kubectl`` SAR app.

        :see: https://github.com/aws-samples/aws-lambda-layer-kubectl
        '''
        result = self._values.get("kubectl_layer")
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], result)

    @builtins.property
    def kubectl_memory(self) -> typing.Optional[_Size_7b441c34]:
        '''Amount of memory to allocate to the provider's lambda function.

        :default: Size.gibibytes(1)
        '''
        result = self._values.get("kubectl_memory")
        return typing.cast(typing.Optional[_Size_7b441c34], result)

    @builtins.property
    def masters_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''An IAM role that will be added to the ``system:masters`` Kubernetes RBAC group.

        :default:

        - a role that assumable by anyone with permissions in the same
        account will automatically be defined

        :see: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings
        '''
        result = self._values.get("masters_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def on_event_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda Layer which includes the NPM dependency ``proxy-agent``.

        This layer
        is used by the onEvent handler to route AWS SDK requests through a proxy.

        By default, the provider will use the layer included in the
        "aws-lambda-layer-node-proxy-agent" SAR application which is available in all
        commercial regions.

        To deploy the layer locally define it in your app as follows::

           layer = lambda_.LayerVersion(self, "proxy-agent-layer",
               code=lambda_.Code.from_asset(f"{__dirname}/layer.zip"),
               compatible_runtimes=[lambda_.Runtime.NODEJS_12_X]
           )

        :default: - a layer bundled with this module.
        '''
        result = self._values.get("on_event_layer")
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], result)

    @builtins.property
    def output_masters_role_arn(self) -> typing.Optional[builtins.bool]:
        '''Determines whether a CloudFormation output with the ARN of the "masters" IAM role will be synthesized (if ``mastersRole`` is specified).

        :default: false
        '''
        result = self._values.get("output_masters_role_arn")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def place_cluster_handler_in_vpc(self) -> typing.Optional[builtins.bool]:
        '''If set to true, the cluster handler functions will be placed in the private subnets of the cluster vpc, subject to the ``vpcSubnets`` selection strategy.

        :default: false
        '''
        result = self._values.get("place_cluster_handler_in_vpc")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def prune(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned.

        When this is enabled (default), prune labels will be
        allocated and injected to each resource. These labels will then be used
        when issuing the ``kubectl apply`` operation with the ``--prune`` switch.

        :default: true
        '''
        result = self._values.get("prune")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def secrets_encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''KMS secret for envelope encryption for Kubernetes secrets.

        :default:

        - By default, Kubernetes stores all secret object data within etcd and
        all etcd volumes used by Amazon EKS are encrypted at the disk-level
        using AWS-Managed encryption keys.
        '''
        result = self._values.get("secrets_encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def service_ipv4_cidr(self) -> typing.Optional[builtins.str]:
        '''The CIDR block to assign Kubernetes service IP addresses from.

        :default:

        - Kubernetes assigns addresses from either the
        10.100.0.0/16 or 172.20.0.0/16 CIDR blocks

        :see: https://docs.aws.amazon.com/eks/latest/APIReference/API_KubernetesNetworkConfigRequest.html#AmazonEKS-Type-KubernetesNetworkConfigRequest-serviceIpv4Cidr
        '''
        result = self._values.get("service_ipv4_cidr")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def cluster_logging(self) -> typing.Optional[typing.List[ClusterLoggingTypes]]:
        '''The cluster log types which you want to enable.

        :default: - none
        '''
        result = self._values.get("cluster_logging")
        return typing.cast(typing.Optional[typing.List[ClusterLoggingTypes]], result)

    @builtins.property
    def default_capacity(self) -> typing.Optional[jsii.Number]:
        '''Number of instances to allocate as an initial capacity for this cluster.

        Instance type can be configured through ``defaultCapacityInstanceType``,
        which defaults to ``m5.large``.

        Use ``cluster.addAutoScalingGroupCapacity`` to add additional customized capacity. Set this
        to ``0`` is you wish to avoid the initial capacity allocation.

        :default: 2
        '''
        result = self._values.get("default_capacity")
        return typing.cast(typing.Optional[jsii.Number], result)

    @builtins.property
    def default_capacity_instance(self) -> typing.Optional[_InstanceType_f64915b9]:
        '''The instance type to use for the default capacity.

        This will only be taken
        into account if ``defaultCapacity`` is > 0.

        :default: m5.large
        '''
        result = self._values.get("default_capacity_instance")
        return typing.cast(typing.Optional[_InstanceType_f64915b9], result)

    @builtins.property
    def default_capacity_type(self) -> typing.Optional[DefaultCapacityType]:
        '''The default capacity type for the cluster.

        :default: NODEGROUP
        '''
        result = self._values.get("default_capacity_type")
        return typing.cast(typing.Optional[DefaultCapacityType], result)

    @builtins.property
    def kubectl_lambda_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''The IAM role to pass to the Kubectl Lambda Handler.

        :default: - Default Lambda IAM Execution Role
        '''
        result = self._values.get("kubectl_lambda_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def tags(self) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''The tags assigned to the EKS cluster.

        :default: - none
        '''
        result = self._values.get("tags")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "ClusterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


class FargateCluster(
    Cluster,
    metaclass=jsii.JSIIMeta,
    jsii_type="aws-cdk-lib.aws_eks.FargateCluster",
):
    '''Defines an EKS cluster that runs entirely on AWS Fargate.

    The cluster is created with a default Fargate Profile that matches the
    "default" and "kube-system" namespaces. You can add additional profiles using
    ``addFargateProfile``.

    :exampleMetadata: infused

    Example::

        cluster = eks.FargateCluster(self, "MyCluster",
            version=eks.KubernetesVersion.V1_21
        )
    '''

    def __init__(
        self,
        scope: constructs.Construct,
        id: builtins.str,
        *,
        default_profile: typing.Optional[FargateProfileOptions] = None,
        alb_controller: typing.Optional[AlbControllerOptions] = None,
        cluster_handler_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        cluster_handler_security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        core_dns_compute_type: typing.Optional[CoreDnsComputeType] = None,
        endpoint_access: typing.Optional[EndpointAccess] = None,
        kubectl_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        kubectl_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        kubectl_memory: typing.Optional[_Size_7b441c34] = None,
        masters_role: typing.Optional[_IRole_235f5d8e] = None,
        on_event_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        output_masters_role_arn: typing.Optional[builtins.bool] = None,
        place_cluster_handler_in_vpc: typing.Optional[builtins.bool] = None,
        prune: typing.Optional[builtins.bool] = None,
        secrets_encryption_key: typing.Optional[_IKey_5f11635f] = None,
        service_ipv4_cidr: typing.Optional[builtins.str] = None,
        version: KubernetesVersion,
        cluster_name: typing.Optional[builtins.str] = None,
        output_cluster_name: typing.Optional[builtins.bool] = None,
        output_config_command: typing.Optional[builtins.bool] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[typing.Sequence[_SubnetSelection_e57d76df]] = None,
    ) -> None:
        '''
        :param scope: -
        :param id: -
        :param default_profile: Fargate Profile to create along with the cluster. Default: - A profile called "default" with 'default' and 'kube-system' selectors will be created if this is left undefined.
        :param alb_controller: Install the AWS Load Balancer Controller onto the cluster. Default: - The controller is not installed.
        :param cluster_handler_environment: Custom environment variables when interacting with the EKS endpoint to manage the cluster lifecycle. Default: - No environment variables.
        :param cluster_handler_security_group: A security group to associate with the Cluster Handler's Lambdas. The Cluster Handler's Lambdas are responsible for calling AWS's EKS API. Requires ``placeClusterHandlerInVpc`` to be set to true. Default: - No security group.
        :param core_dns_compute_type: Controls the "eks.amazonaws.com/compute-type" annotation in the CoreDNS configuration on your cluster to determine which compute type to use for CoreDNS. Default: CoreDnsComputeType.EC2 (for ``FargateCluster`` the default is FARGATE)
        :param endpoint_access: Configure access to the Kubernetes API server endpoint.. Default: EndpointAccess.PUBLIC_AND_PRIVATE
        :param kubectl_environment: Environment variables for the kubectl execution. Only relevant for kubectl enabled clusters. Default: - No environment variables.
        :param kubectl_layer: An AWS Lambda Layer which includes ``kubectl``, Helm and the AWS CLI. By default, the provider will use the layer included in the "aws-lambda-layer-kubectl" SAR application which is available in all commercial regions. To deploy the layer locally, visit https://github.com/aws-samples/aws-lambda-layer-kubectl/blob/master/cdk/README.md for instructions on how to prepare the .zip file and then define it in your app as follows:: const layer = new lambda.LayerVersion(this, 'kubectl-layer', { code: lambda.Code.fromAsset(`${__dirname}/layer.zip`), compatibleRuntimes: [lambda.Runtime.PROVIDED], }); Default: - the layer provided by the ``aws-lambda-layer-kubectl`` SAR app.
        :param kubectl_memory: Amount of memory to allocate to the provider's lambda function. Default: Size.gibibytes(1)
        :param masters_role: An IAM role that will be added to the ``system:masters`` Kubernetes RBAC group. Default: - a role that assumable by anyone with permissions in the same account will automatically be defined
        :param on_event_layer: An AWS Lambda Layer which includes the NPM dependency ``proxy-agent``. This layer is used by the onEvent handler to route AWS SDK requests through a proxy. By default, the provider will use the layer included in the "aws-lambda-layer-node-proxy-agent" SAR application which is available in all commercial regions. To deploy the layer locally define it in your app as follows:: const layer = new lambda.LayerVersion(this, 'proxy-agent-layer', { code: lambda.Code.fromAsset(`${__dirname}/layer.zip`), compatibleRuntimes: [lambda.Runtime.NODEJS_12_X], }); Default: - a layer bundled with this module.
        :param output_masters_role_arn: Determines whether a CloudFormation output with the ARN of the "masters" IAM role will be synthesized (if ``mastersRole`` is specified). Default: false
        :param place_cluster_handler_in_vpc: If set to true, the cluster handler functions will be placed in the private subnets of the cluster vpc, subject to the ``vpcSubnets`` selection strategy. Default: false
        :param prune: Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned. When this is enabled (default), prune labels will be allocated and injected to each resource. These labels will then be used when issuing the ``kubectl apply`` operation with the ``--prune`` switch. Default: true
        :param secrets_encryption_key: KMS secret for envelope encryption for Kubernetes secrets. Default: - By default, Kubernetes stores all secret object data within etcd and all etcd volumes used by Amazon EKS are encrypted at the disk-level using AWS-Managed encryption keys.
        :param service_ipv4_cidr: The CIDR block to assign Kubernetes service IP addresses from. Default: - Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks
        :param version: The Kubernetes version to run in the cluster.
        :param cluster_name: Name for the cluster. Default: - Automatically generated name
        :param output_cluster_name: Determines whether a CloudFormation output with the name of the cluster will be synthesized. Default: false
        :param output_config_command: Determines whether a CloudFormation output with the ``aws eks update-kubeconfig`` command will be synthesized. This command will include the cluster name and, if applicable, the ARN of the masters IAM role. Default: true
        :param role: Role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf. Default: - A role is automatically created for you
        :param security_group: Security Group to use for Control Plane ENIs. Default: - A security group is automatically created
        :param vpc: The VPC in which to create the Cluster. Default: - a VPC with default configuration will be created and can be accessed through ``cluster.vpc``.
        :param vpc_subnets: Where to place EKS Control Plane ENIs. If you want to create public load balancers, this must include public subnets. For example, to only select private subnets, supply the following: ``vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE }]`` Default: - All public and private subnets
        '''
        props = FargateClusterProps(
            default_profile=default_profile,
            alb_controller=alb_controller,
            cluster_handler_environment=cluster_handler_environment,
            cluster_handler_security_group=cluster_handler_security_group,
            core_dns_compute_type=core_dns_compute_type,
            endpoint_access=endpoint_access,
            kubectl_environment=kubectl_environment,
            kubectl_layer=kubectl_layer,
            kubectl_memory=kubectl_memory,
            masters_role=masters_role,
            on_event_layer=on_event_layer,
            output_masters_role_arn=output_masters_role_arn,
            place_cluster_handler_in_vpc=place_cluster_handler_in_vpc,
            prune=prune,
            secrets_encryption_key=secrets_encryption_key,
            service_ipv4_cidr=service_ipv4_cidr,
            version=version,
            cluster_name=cluster_name,
            output_cluster_name=output_cluster_name,
            output_config_command=output_config_command,
            role=role,
            security_group=security_group,
            vpc=vpc,
            vpc_subnets=vpc_subnets,
        )

        jsii.create(self.__class__, self, [scope, id, props])

    @builtins.property # type: ignore[misc]
    @jsii.member(jsii_name="defaultProfile")
    def default_profile(self) -> FargateProfile:
        '''Fargate Profile that was created with the cluster.'''
        return typing.cast(FargateProfile, jsii.get(self, "defaultProfile"))


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.FargateClusterProps",
    jsii_struct_bases=[ClusterOptions],
    name_mapping={
        "version": "version",
        "cluster_name": "clusterName",
        "output_cluster_name": "outputClusterName",
        "output_config_command": "outputConfigCommand",
        "role": "role",
        "security_group": "securityGroup",
        "vpc": "vpc",
        "vpc_subnets": "vpcSubnets",
        "alb_controller": "albController",
        "cluster_handler_environment": "clusterHandlerEnvironment",
        "cluster_handler_security_group": "clusterHandlerSecurityGroup",
        "core_dns_compute_type": "coreDnsComputeType",
        "endpoint_access": "endpointAccess",
        "kubectl_environment": "kubectlEnvironment",
        "kubectl_layer": "kubectlLayer",
        "kubectl_memory": "kubectlMemory",
        "masters_role": "mastersRole",
        "on_event_layer": "onEventLayer",
        "output_masters_role_arn": "outputMastersRoleArn",
        "place_cluster_handler_in_vpc": "placeClusterHandlerInVpc",
        "prune": "prune",
        "secrets_encryption_key": "secretsEncryptionKey",
        "service_ipv4_cidr": "serviceIpv4Cidr",
        "default_profile": "defaultProfile",
    },
)
class FargateClusterProps(ClusterOptions):
    def __init__(
        self,
        *,
        version: KubernetesVersion,
        cluster_name: typing.Optional[builtins.str] = None,
        output_cluster_name: typing.Optional[builtins.bool] = None,
        output_config_command: typing.Optional[builtins.bool] = None,
        role: typing.Optional[_IRole_235f5d8e] = None,
        security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        vpc: typing.Optional[_IVpc_f30d5663] = None,
        vpc_subnets: typing.Optional[typing.Sequence[_SubnetSelection_e57d76df]] = None,
        alb_controller: typing.Optional[AlbControllerOptions] = None,
        cluster_handler_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        cluster_handler_security_group: typing.Optional[_ISecurityGroup_acf8a799] = None,
        core_dns_compute_type: typing.Optional[CoreDnsComputeType] = None,
        endpoint_access: typing.Optional[EndpointAccess] = None,
        kubectl_environment: typing.Optional[typing.Mapping[builtins.str, builtins.str]] = None,
        kubectl_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        kubectl_memory: typing.Optional[_Size_7b441c34] = None,
        masters_role: typing.Optional[_IRole_235f5d8e] = None,
        on_event_layer: typing.Optional[_ILayerVersion_5ac127c8] = None,
        output_masters_role_arn: typing.Optional[builtins.bool] = None,
        place_cluster_handler_in_vpc: typing.Optional[builtins.bool] = None,
        prune: typing.Optional[builtins.bool] = None,
        secrets_encryption_key: typing.Optional[_IKey_5f11635f] = None,
        service_ipv4_cidr: typing.Optional[builtins.str] = None,
        default_profile: typing.Optional[FargateProfileOptions] = None,
    ) -> None:
        '''Configuration props for EKS Fargate.

        :param version: The Kubernetes version to run in the cluster.
        :param cluster_name: Name for the cluster. Default: - Automatically generated name
        :param output_cluster_name: Determines whether a CloudFormation output with the name of the cluster will be synthesized. Default: false
        :param output_config_command: Determines whether a CloudFormation output with the ``aws eks update-kubeconfig`` command will be synthesized. This command will include the cluster name and, if applicable, the ARN of the masters IAM role. Default: true
        :param role: Role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf. Default: - A role is automatically created for you
        :param security_group: Security Group to use for Control Plane ENIs. Default: - A security group is automatically created
        :param vpc: The VPC in which to create the Cluster. Default: - a VPC with default configuration will be created and can be accessed through ``cluster.vpc``.
        :param vpc_subnets: Where to place EKS Control Plane ENIs. If you want to create public load balancers, this must include public subnets. For example, to only select private subnets, supply the following: ``vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE }]`` Default: - All public and private subnets
        :param alb_controller: Install the AWS Load Balancer Controller onto the cluster. Default: - The controller is not installed.
        :param cluster_handler_environment: Custom environment variables when interacting with the EKS endpoint to manage the cluster lifecycle. Default: - No environment variables.
        :param cluster_handler_security_group: A security group to associate with the Cluster Handler's Lambdas. The Cluster Handler's Lambdas are responsible for calling AWS's EKS API. Requires ``placeClusterHandlerInVpc`` to be set to true. Default: - No security group.
        :param core_dns_compute_type: Controls the "eks.amazonaws.com/compute-type" annotation in the CoreDNS configuration on your cluster to determine which compute type to use for CoreDNS. Default: CoreDnsComputeType.EC2 (for ``FargateCluster`` the default is FARGATE)
        :param endpoint_access: Configure access to the Kubernetes API server endpoint.. Default: EndpointAccess.PUBLIC_AND_PRIVATE
        :param kubectl_environment: Environment variables for the kubectl execution. Only relevant for kubectl enabled clusters. Default: - No environment variables.
        :param kubectl_layer: An AWS Lambda Layer which includes ``kubectl``, Helm and the AWS CLI. By default, the provider will use the layer included in the "aws-lambda-layer-kubectl" SAR application which is available in all commercial regions. To deploy the layer locally, visit https://github.com/aws-samples/aws-lambda-layer-kubectl/blob/master/cdk/README.md for instructions on how to prepare the .zip file and then define it in your app as follows:: const layer = new lambda.LayerVersion(this, 'kubectl-layer', { code: lambda.Code.fromAsset(`${__dirname}/layer.zip`), compatibleRuntimes: [lambda.Runtime.PROVIDED], }); Default: - the layer provided by the ``aws-lambda-layer-kubectl`` SAR app.
        :param kubectl_memory: Amount of memory to allocate to the provider's lambda function. Default: Size.gibibytes(1)
        :param masters_role: An IAM role that will be added to the ``system:masters`` Kubernetes RBAC group. Default: - a role that assumable by anyone with permissions in the same account will automatically be defined
        :param on_event_layer: An AWS Lambda Layer which includes the NPM dependency ``proxy-agent``. This layer is used by the onEvent handler to route AWS SDK requests through a proxy. By default, the provider will use the layer included in the "aws-lambda-layer-node-proxy-agent" SAR application which is available in all commercial regions. To deploy the layer locally define it in your app as follows:: const layer = new lambda.LayerVersion(this, 'proxy-agent-layer', { code: lambda.Code.fromAsset(`${__dirname}/layer.zip`), compatibleRuntimes: [lambda.Runtime.NODEJS_12_X], }); Default: - a layer bundled with this module.
        :param output_masters_role_arn: Determines whether a CloudFormation output with the ARN of the "masters" IAM role will be synthesized (if ``mastersRole`` is specified). Default: false
        :param place_cluster_handler_in_vpc: If set to true, the cluster handler functions will be placed in the private subnets of the cluster vpc, subject to the ``vpcSubnets`` selection strategy. Default: false
        :param prune: Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned. When this is enabled (default), prune labels will be allocated and injected to each resource. These labels will then be used when issuing the ``kubectl apply`` operation with the ``--prune`` switch. Default: true
        :param secrets_encryption_key: KMS secret for envelope encryption for Kubernetes secrets. Default: - By default, Kubernetes stores all secret object data within etcd and all etcd volumes used by Amazon EKS are encrypted at the disk-level using AWS-Managed encryption keys.
        :param service_ipv4_cidr: The CIDR block to assign Kubernetes service IP addresses from. Default: - Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks
        :param default_profile: Fargate Profile to create along with the cluster. Default: - A profile called "default" with 'default' and 'kube-system' selectors will be created if this is left undefined.

        :exampleMetadata: infused

        Example::

            cluster = eks.FargateCluster(self, "MyCluster",
                version=eks.KubernetesVersion.V1_21
            )
        '''
        if isinstance(alb_controller, dict):
            alb_controller = AlbControllerOptions(**alb_controller)
        if isinstance(default_profile, dict):
            default_profile = FargateProfileOptions(**default_profile)
        self._values: typing.Dict[str, typing.Any] = {
            "version": version,
        }
        if cluster_name is not None:
            self._values["cluster_name"] = cluster_name
        if output_cluster_name is not None:
            self._values["output_cluster_name"] = output_cluster_name
        if output_config_command is not None:
            self._values["output_config_command"] = output_config_command
        if role is not None:
            self._values["role"] = role
        if security_group is not None:
            self._values["security_group"] = security_group
        if vpc is not None:
            self._values["vpc"] = vpc
        if vpc_subnets is not None:
            self._values["vpc_subnets"] = vpc_subnets
        if alb_controller is not None:
            self._values["alb_controller"] = alb_controller
        if cluster_handler_environment is not None:
            self._values["cluster_handler_environment"] = cluster_handler_environment
        if cluster_handler_security_group is not None:
            self._values["cluster_handler_security_group"] = cluster_handler_security_group
        if core_dns_compute_type is not None:
            self._values["core_dns_compute_type"] = core_dns_compute_type
        if endpoint_access is not None:
            self._values["endpoint_access"] = endpoint_access
        if kubectl_environment is not None:
            self._values["kubectl_environment"] = kubectl_environment
        if kubectl_layer is not None:
            self._values["kubectl_layer"] = kubectl_layer
        if kubectl_memory is not None:
            self._values["kubectl_memory"] = kubectl_memory
        if masters_role is not None:
            self._values["masters_role"] = masters_role
        if on_event_layer is not None:
            self._values["on_event_layer"] = on_event_layer
        if output_masters_role_arn is not None:
            self._values["output_masters_role_arn"] = output_masters_role_arn
        if place_cluster_handler_in_vpc is not None:
            self._values["place_cluster_handler_in_vpc"] = place_cluster_handler_in_vpc
        if prune is not None:
            self._values["prune"] = prune
        if secrets_encryption_key is not None:
            self._values["secrets_encryption_key"] = secrets_encryption_key
        if service_ipv4_cidr is not None:
            self._values["service_ipv4_cidr"] = service_ipv4_cidr
        if default_profile is not None:
            self._values["default_profile"] = default_profile

    @builtins.property
    def version(self) -> KubernetesVersion:
        '''The Kubernetes version to run in the cluster.'''
        result = self._values.get("version")
        assert result is not None, "Required property 'version' is missing"
        return typing.cast(KubernetesVersion, result)

    @builtins.property
    def cluster_name(self) -> typing.Optional[builtins.str]:
        '''Name for the cluster.

        :default: - Automatically generated name
        '''
        result = self._values.get("cluster_name")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def output_cluster_name(self) -> typing.Optional[builtins.bool]:
        '''Determines whether a CloudFormation output with the name of the cluster will be synthesized.

        :default: false
        '''
        result = self._values.get("output_cluster_name")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def output_config_command(self) -> typing.Optional[builtins.bool]:
        '''Determines whether a CloudFormation output with the ``aws eks update-kubeconfig`` command will be synthesized.

        This command will include
        the cluster name and, if applicable, the ARN of the masters IAM role.

        :default: true
        '''
        result = self._values.get("output_config_command")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''Role that provides permissions for the Kubernetes control plane to make calls to AWS API operations on your behalf.

        :default: - A role is automatically created for you
        '''
        result = self._values.get("role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def security_group(self) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''Security Group to use for Control Plane ENIs.

        :default: - A security group is automatically created
        '''
        result = self._values.get("security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    @builtins.property
    def vpc(self) -> typing.Optional[_IVpc_f30d5663]:
        '''The VPC in which to create the Cluster.

        :default: - a VPC with default configuration will be created and can be accessed through ``cluster.vpc``.
        '''
        result = self._values.get("vpc")
        return typing.cast(typing.Optional[_IVpc_f30d5663], result)

    @builtins.property
    def vpc_subnets(self) -> typing.Optional[typing.List[_SubnetSelection_e57d76df]]:
        '''Where to place EKS Control Plane ENIs.

        If you want to create public load balancers, this must include public subnets.

        For example, to only select private subnets, supply the following:

        ``vpcSubnets: [{ subnetType: ec2.SubnetType.PRIVATE }]``

        :default: - All public and private subnets
        '''
        result = self._values.get("vpc_subnets")
        return typing.cast(typing.Optional[typing.List[_SubnetSelection_e57d76df]], result)

    @builtins.property
    def alb_controller(self) -> typing.Optional[AlbControllerOptions]:
        '''Install the AWS Load Balancer Controller onto the cluster.

        :default: - The controller is not installed.

        :see: https://kubernetes-sigs.github.io/aws-load-balancer-controller
        '''
        result = self._values.get("alb_controller")
        return typing.cast(typing.Optional[AlbControllerOptions], result)

    @builtins.property
    def cluster_handler_environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Custom environment variables when interacting with the EKS endpoint to manage the cluster lifecycle.

        :default: - No environment variables.
        '''
        result = self._values.get("cluster_handler_environment")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def cluster_handler_security_group(
        self,
    ) -> typing.Optional[_ISecurityGroup_acf8a799]:
        '''A security group to associate with the Cluster Handler's Lambdas.

        The Cluster Handler's Lambdas are responsible for calling AWS's EKS API.

        Requires ``placeClusterHandlerInVpc`` to be set to true.

        :default: - No security group.
        '''
        result = self._values.get("cluster_handler_security_group")
        return typing.cast(typing.Optional[_ISecurityGroup_acf8a799], result)

    @builtins.property
    def core_dns_compute_type(self) -> typing.Optional[CoreDnsComputeType]:
        '''Controls the "eks.amazonaws.com/compute-type" annotation in the CoreDNS configuration on your cluster to determine which compute type to use for CoreDNS.

        :default: CoreDnsComputeType.EC2 (for ``FargateCluster`` the default is FARGATE)
        '''
        result = self._values.get("core_dns_compute_type")
        return typing.cast(typing.Optional[CoreDnsComputeType], result)

    @builtins.property
    def endpoint_access(self) -> typing.Optional[EndpointAccess]:
        '''Configure access to the Kubernetes API server endpoint..

        :default: EndpointAccess.PUBLIC_AND_PRIVATE

        :see: https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html
        '''
        result = self._values.get("endpoint_access")
        return typing.cast(typing.Optional[EndpointAccess], result)

    @builtins.property
    def kubectl_environment(
        self,
    ) -> typing.Optional[typing.Mapping[builtins.str, builtins.str]]:
        '''Environment variables for the kubectl execution.

        Only relevant for kubectl enabled clusters.

        :default: - No environment variables.
        '''
        result = self._values.get("kubectl_environment")
        return typing.cast(typing.Optional[typing.Mapping[builtins.str, builtins.str]], result)

    @builtins.property
    def kubectl_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda Layer which includes ``kubectl``, Helm and the AWS CLI.

        By default, the provider will use the layer included in the
        "aws-lambda-layer-kubectl" SAR application which is available in all
        commercial regions.

        To deploy the layer locally, visit
        https://github.com/aws-samples/aws-lambda-layer-kubectl/blob/master/cdk/README.md
        for instructions on how to prepare the .zip file and then define it in your
        app as follows::

           layer = lambda_.LayerVersion(self, "kubectl-layer",
               code=lambda_.Code.from_asset(f"{__dirname}/layer.zip"),
               compatible_runtimes=[lambda_.Runtime.PROVIDED]
           )

        :default: - the layer provided by the ``aws-lambda-layer-kubectl`` SAR app.

        :see: https://github.com/aws-samples/aws-lambda-layer-kubectl
        '''
        result = self._values.get("kubectl_layer")
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], result)

    @builtins.property
    def kubectl_memory(self) -> typing.Optional[_Size_7b441c34]:
        '''Amount of memory to allocate to the provider's lambda function.

        :default: Size.gibibytes(1)
        '''
        result = self._values.get("kubectl_memory")
        return typing.cast(typing.Optional[_Size_7b441c34], result)

    @builtins.property
    def masters_role(self) -> typing.Optional[_IRole_235f5d8e]:
        '''An IAM role that will be added to the ``system:masters`` Kubernetes RBAC group.

        :default:

        - a role that assumable by anyone with permissions in the same
        account will automatically be defined

        :see: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#default-roles-and-role-bindings
        '''
        result = self._values.get("masters_role")
        return typing.cast(typing.Optional[_IRole_235f5d8e], result)

    @builtins.property
    def on_event_layer(self) -> typing.Optional[_ILayerVersion_5ac127c8]:
        '''An AWS Lambda Layer which includes the NPM dependency ``proxy-agent``.

        This layer
        is used by the onEvent handler to route AWS SDK requests through a proxy.

        By default, the provider will use the layer included in the
        "aws-lambda-layer-node-proxy-agent" SAR application which is available in all
        commercial regions.

        To deploy the layer locally define it in your app as follows::

           layer = lambda_.LayerVersion(self, "proxy-agent-layer",
               code=lambda_.Code.from_asset(f"{__dirname}/layer.zip"),
               compatible_runtimes=[lambda_.Runtime.NODEJS_12_X]
           )

        :default: - a layer bundled with this module.
        '''
        result = self._values.get("on_event_layer")
        return typing.cast(typing.Optional[_ILayerVersion_5ac127c8], result)

    @builtins.property
    def output_masters_role_arn(self) -> typing.Optional[builtins.bool]:
        '''Determines whether a CloudFormation output with the ARN of the "masters" IAM role will be synthesized (if ``mastersRole`` is specified).

        :default: false
        '''
        result = self._values.get("output_masters_role_arn")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def place_cluster_handler_in_vpc(self) -> typing.Optional[builtins.bool]:
        '''If set to true, the cluster handler functions will be placed in the private subnets of the cluster vpc, subject to the ``vpcSubnets`` selection strategy.

        :default: false
        '''
        result = self._values.get("place_cluster_handler_in_vpc")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def prune(self) -> typing.Optional[builtins.bool]:
        '''Indicates whether Kubernetes resources added through ``addManifest()`` can be automatically pruned.

        When this is enabled (default), prune labels will be
        allocated and injected to each resource. These labels will then be used
        when issuing the ``kubectl apply`` operation with the ``--prune`` switch.

        :default: true
        '''
        result = self._values.get("prune")
        return typing.cast(typing.Optional[builtins.bool], result)

    @builtins.property
    def secrets_encryption_key(self) -> typing.Optional[_IKey_5f11635f]:
        '''KMS secret for envelope encryption for Kubernetes secrets.

        :default:

        - By default, Kubernetes stores all secret object data within etcd and
        all etcd volumes used by Amazon EKS are encrypted at the disk-level
        using AWS-Managed encryption keys.
        '''
        result = self._values.get("secrets_encryption_key")
        return typing.cast(typing.Optional[_IKey_5f11635f], result)

    @builtins.property
    def service_ipv4_cidr(self) -> typing.Optional[builtins.str]:
        '''The CIDR block to assign Kubernetes service IP addresses from.

        :default:

        - Kubernetes assigns addresses from either the
        10.100.0.0/16 or 172.20.0.0/16 CIDR blocks

        :see: https://docs.aws.amazon.com/eks/latest/APIReference/API_KubernetesNetworkConfigRequest.html#AmazonEKS-Type-KubernetesNetworkConfigRequest-serviceIpv4Cidr
        '''
        result = self._values.get("service_ipv4_cidr")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def default_profile(self) -> typing.Optional[FargateProfileOptions]:
        '''Fargate Profile to create along with the cluster.

        :default:

        - A profile called "default" with 'default' and 'kube-system'
        selectors will be created if this is left undefined.
        '''
        result = self._values.get("default_profile")
        return typing.cast(typing.Optional[FargateProfileOptions], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "FargateClusterProps(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


@jsii.data_type(
    jsii_type="aws-cdk-lib.aws_eks.IngressLoadBalancerAddressOptions",
    jsii_struct_bases=[ServiceLoadBalancerAddressOptions],
    name_mapping={"namespace": "namespace", "timeout": "timeout"},
)
class IngressLoadBalancerAddressOptions(ServiceLoadBalancerAddressOptions):
    def __init__(
        self,
        *,
        namespace: typing.Optional[builtins.str] = None,
        timeout: typing.Optional[_Duration_4839e8c3] = None,
    ) -> None:
        '''Options for fetching an IngressLoadBalancerAddress.

        :param namespace: The namespace the service belongs to. Default: 'default'
        :param timeout: Timeout for waiting on the load balancer address. Default: Duration.minutes(5)

        :exampleMetadata: fixture=_generated

        Example::

            # The code below shows an example of how to instantiate this type.
            # The values are placeholders you should change.
            import aws_cdk as cdk
            from aws_cdk import aws_eks as eks
            
            ingress_load_balancer_address_options = eks.IngressLoadBalancerAddressOptions(
                namespace="namespace",
                timeout=cdk.Duration.minutes(30)
            )
        '''
        self._values: typing.Dict[str, typing.Any] = {}
        if namespace is not None:
            self._values["namespace"] = namespace
        if timeout is not None:
            self._values["timeout"] = timeout

    @builtins.property
    def namespace(self) -> typing.Optional[builtins.str]:
        '''The namespace the service belongs to.

        :default: 'default'
        '''
        result = self._values.get("namespace")
        return typing.cast(typing.Optional[builtins.str], result)

    @builtins.property
    def timeout(self) -> typing.Optional[_Duration_4839e8c3]:
        '''Timeout for waiting on the load balancer address.

        :default: Duration.minutes(5)
        '''
        result = self._values.get("timeout")
        return typing.cast(typing.Optional[_Duration_4839e8c3], result)

    def __eq__(self, rhs: typing.Any) -> builtins.bool:
        return isinstance(rhs, self.__class__) and rhs._values == self._values

    def __ne__(self, rhs: typing.Any) -> builtins.bool:
        return not (rhs == self)

    def __repr__(self) -> str:
        return "IngressLoadBalancerAddressOptions(%s)" % ", ".join(
            k + "=" + repr(v) for k, v in self._values.items()
        )


__all__ = [
    "AlbController",
    "AlbControllerOptions",
    "AlbControllerProps",
    "AlbControllerVersion",
    "AlbScheme",
    "AutoScalingGroupCapacityOptions",
    "AutoScalingGroupOptions",
    "AwsAuth",
    "AwsAuthMapping",
    "AwsAuthProps",
    "BootstrapOptions",
    "CapacityType",
    "CfnAddon",
    "CfnAddonProps",
    "CfnCluster",
    "CfnClusterProps",
    "CfnFargateProfile",
    "CfnFargateProfileProps",
    "CfnNodegroup",
    "CfnNodegroupProps",
    "Cluster",
    "ClusterAttributes",
    "ClusterLoggingTypes",
    "ClusterOptions",
    "ClusterProps",
    "CommonClusterOptions",
    "CoreDnsComputeType",
    "CpuArch",
    "DefaultCapacityType",
    "EksOptimizedImage",
    "EksOptimizedImageProps",
    "EndpointAccess",
    "FargateCluster",
    "FargateClusterProps",
    "FargateProfile",
    "FargateProfileOptions",
    "FargateProfileProps",
    "HelmChart",
    "HelmChartOptions",
    "HelmChartProps",
    "ICluster",
    "IKubectlProvider",
    "INodegroup",
    "IngressLoadBalancerAddressOptions",
    "KubectlProvider",
    "KubectlProviderAttributes",
    "KubectlProviderProps",
    "KubernetesManifest",
    "KubernetesManifestOptions",
    "KubernetesManifestProps",
    "KubernetesObjectValue",
    "KubernetesObjectValueProps",
    "KubernetesPatch",
    "KubernetesPatchProps",
    "KubernetesVersion",
    "LaunchTemplateSpec",
    "MachineImageType",
    "NodeType",
    "Nodegroup",
    "NodegroupAmiType",
    "NodegroupOptions",
    "NodegroupProps",
    "NodegroupRemoteAccess",
    "OpenIdConnectProvider",
    "OpenIdConnectProviderProps",
    "PatchType",
    "Selector",
    "ServiceAccount",
    "ServiceAccountOptions",
    "ServiceAccountProps",
    "ServiceLoadBalancerAddressOptions",
    "TaintEffect",
    "TaintSpec",
]

publication.publish()
