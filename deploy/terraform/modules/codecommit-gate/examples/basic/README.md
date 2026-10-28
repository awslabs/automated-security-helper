# Example: gate CodeCommit pull requests with ASH

Builds the ASH image, layers a Lambda-runnable gate image on top, and scans every
pull request on a repository you already have.

## Before you apply

`main.tf` needs one change before this example works: give the `ash_image` module
a `name_prefix` other than `"ash-pr-gate"`. Both modules use that prefix, so their
image-build CodeBuild projects, IAM roles and log groups get the same names and the
apply fails.

`ash_version` names the ASH release this example comes from. Set it to a tag or
commit whose `ash scan` has `--fail-on-incomplete-scanners`, which the gate needs to
fail a pull request whose scan did not complete; v3.7.1 and earlier do not have it.
See [Which `AshVersion` to use](../../../../../README.md#which-ashversion-to-use). The example leaves `ash_scan_extra_args`
unset.

## Run it

<!-- doctest: illustrative reason="needs Terraform, network access and AWS credentials" -->
```console
terraform init
terraform plan -var 'codecommit_repository_arn=arn:aws:codecommit:<region>:<account>:<repo>'
terraform apply -var 'codecommit_repository_arn=arn:aws:codecommit:<region>:<account>:<repo>'
```

Then build both images, **in this order** — the gate image build pulls the shared
image as its base, so it fails if the base does not exist yet:

<!-- doctest: illustrative reason="needs an applied Terraform state" -->
```console
terraform output -json build_the_images_in_this_order
```

Run the two printed commands in sequence, waiting for the first to succeed.

## Your repository is not modified

The module has no `aws_codecommit_repository` resource. It reads the repository
and posts pull-request comments, and every CodeCommit permission on its role is
scoped to the single ARN you pass.

This example leaves `create_approval_rule_template` at its default of `false`,
so it does not change your repository's settings either. Turning it on adds an
approval rule template association, which is a settings change and is reversible.

## Fitting in 900 seconds

Lambda's timeout ceiling is 900 seconds and is not adjustable, and this gate scans
the whole checked-out tree of the pull request. Narrowing the scan through
`ash_scan_extra_args` is refused: the handler reserves `--changed-files-only`,
and it reserves `--base-ref`, because with them findings outside the diff stop
counting, and so does every finding in a file whose name git prints quoted, which
can turn a failing pull request into a pass. A deployment passing either one ends
every pull request in outcome `error`, so this example leaves `ash_scan_extra_args`
unset. For a repository that does not fit, raise
`lambda_memory_mb` (Lambda scales CPU with memory) or use the
`codepipeline-executor` module.

## When a scan cannot finish

The gate reports three outcomes, and "did not complete" is deliberately not
reported as a pass. Check `terraform output log_group_name` for the reason.
