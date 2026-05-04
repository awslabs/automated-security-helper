# Offline test infrastructure

CDK stack that provisions an air-gapped VPC for validating ASH offline mode.

## What gets created

| Resource | Purpose |
|----------|---------|
| VPC (isolated subnets, no NAT/IGW) | Network with zero internet access |
| S3 gateway endpoint | Lets CodeBuild read/write artifacts without leaving the VPC |
| EC2 instance (Amazon Linux 2023) | Manual testing host reachable via SSM Session Manager |
| CodeBuild project | Automated ASH scan runner inside the isolated VPC |
| S3 bucket | Stores ASH bundle and scan artifacts |

## Prerequisites

- Python 3.10+
- AWS CDK CLI (`npm install -g aws-cdk`)
- AWS credentials configured (`aws configure` or environment variables)
- ASH project dependencies installed (`pip install -e '.[dev]'` from repo root)

## Deploy the stack

```bash
cd tests/infrastructure

# Synthesize the CloudFormation template (no AWS calls)
cdk synth

# Deploy with default parameters
cdk deploy

# Deploy with custom parameters
cdk deploy \
  --context vpc_cidr=10.1.0.0/16 \
  --context instance_type=m5.large \
  --context ash_version=3.4.0
```

## Parameters

| Name | Default | Description |
|------|---------|-------------|
| `vpc_cidr` | `10.0.0.0/16` | CIDR block for the isolated VPC |
| `instance_type` | `t3.medium` | EC2 instance type for the test host |
| `ash_version` | `latest` | ASH version tag written to the host environment |

Pass parameters via `--context key=value` on the `cdk` command line.

## Run offline tests

### Option A -- EC2 instance (interactive)

1. Connect via SSM Session Manager (the instance has no public IP):
   ```bash
   aws ssm start-session --target <instance-id>
   ```
2. Upload an ASH bundle to the S3 artifact bucket, then pull it
   from the instance through the S3 VPC endpoint.
3. Run `ash` against sample repositories already staged on the host.

### Option B -- CodeBuild (automated)

1. Upload a pre-built ASH bundle + test repos to the artifact S3 bucket.
2. Start a build:
   ```bash
   aws codebuild start-build --project-name <project-name>
   ```
3. Check results in the S3 bucket or in the CodeBuild console.

## Tear down

```bash
cdk destroy
```

The S3 bucket uses `RemovalPolicy.DESTROY` with `auto_delete_objects=True`,
so all objects are removed automatically on stack deletion.
