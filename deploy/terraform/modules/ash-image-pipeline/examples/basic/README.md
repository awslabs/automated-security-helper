# Example: build the ASH image on a daily schedule

Creates an ECR repository, a CodeBuild project that builds ASH from a pinned
revision, and a daily rebuild rule.

## Run it

```console
terraform init
terraform plan
terraform apply
```

Then run the first build. The repository is empty until it succeeds, and any
deployment target pointed at `image_uri` cannot pull before then:

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
