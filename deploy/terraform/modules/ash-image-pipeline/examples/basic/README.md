# Example: build the ASH image on a daily schedule

Creates an ECR repository, a CodeBuild project that builds ASH from a pinned
revision, and a daily rebuild rule.

It pins `ash_version = "v3.6.0"`. That version builds, but the MCP, gate and executor
targets call ASH options it does not have; see
[the Terraform README](../../../../README.md) before you point them at this image.

## Run it

<!-- doctest: illustrative reason="needs Terraform, network access and AWS credentials" -->
```console
terraform init
terraform plan
terraform apply
```

Then run the first build. The repository is empty until it succeeds, and any
deployment target pointed at `image_uri` cannot pull before then:

<!-- doctest: illustrative reason="needs AWS credentials and an applied Terraform state" -->
```console
aws codebuild start-build --project-name "$(terraform output -raw codebuild_project_name)"
```

`terraform output run_the_first_build` prints the same command with the region
filled in.

## Architecture

This example builds for `x86_64`, which suits the Fargate, Lambda, and
CodeBuild targets. The AgentCore target requires `arm64` — set
`target_architecture = "arm64"` for that one, since AgentCore's container
contract admits no other architecture.
