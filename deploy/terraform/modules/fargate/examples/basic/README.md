# Example: ASH over MCP on Fargate behind an internal ALB

Builds a VPC with the aws-ia VPC module, builds the ASH image, and runs the MCP
server as a Fargate service behind an internal Application Load Balancer.

## Run it

```console
terraform init
terraform plan
terraform apply
```

Then run the first image build, which the service cannot start without:

```console
terraform output -raw run_the_first_build
```

Run the printed command, wait for it to succeed, then force a new deployment so
the service pulls the now-existing image:

```console
aws ecs update-service --cluster ash-mcp --service ash-mcp --force-new-deployment
```

## Reaching it

The load balancer is internal and admits only `10.0.0.0/16`, so requests have to
originate inside the VPC. `terraform output mcp_endpoint_url` gives the URL to
POST to.

`terraform output allowed_hosts` lists the `Host` header values ASH accepts. A
client that dials some other name is rejected by the MCP SDK's DNS-rebinding
protection, which this deployment leaves **on** rather than disabling.

## What aws-ia provides here

`aws-ia/vpc/aws ~> 4.9` builds the VPC, its subnets, the NAT gateway, and the
routing. `natgw_subnet_ids` is the flat list of private subnets that actually
have a route to the NAT gateway, which is what the tasks need to reach ECR.

Everything else — the cluster, service, task definition, load balancer, target
group, listener, security groups, and roles — is first-party. See the module
README for why no aws-ia ECS module is used.

## Going to production from here

- Set `certificate_arn` and reach the service over HTTPS. Required if you also
  set `mcp_auth_header_value`.
- Replace the NAT gateway with interface endpoints for ECR, CloudWatch Logs, SSM,
  and Secrets Manager, then narrow the task security group's egress.
- Raise `desired_count` above 1. Safe as long as `mcp_stateless_http` stays true.
