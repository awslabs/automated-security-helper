# Example: gate CodeCommit pull requests with ASH

Builds the ASH image, layers a Lambda-runnable gate image on top, and scans every
pull request on a repository you already have.

## Run it

```console
terraform init
terraform plan -var 'codecommit_repository_arn=arn:aws:codecommit:<region>:<account>:<repo>'
terraform apply -var 'codecommit_repository_arn=arn:aws:codecommit:<region>:<account>:<repo>'
```

Then build both images, **in this order** — the gate image build pulls the shared
image as its base, so it fails if the base does not exist yet:

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

## Why `--changed-files-only`

Lambda's timeout ceiling is 900 seconds and is not adjustable. A full scan of a
sizable repository does not fit, and the clone alone can take a large share of
the budget. `--changed-files-only --base-ref origin/main` scales the scan with
the size of the change instead.

Adjust `--base-ref` to your default branch name.

## When a scan cannot finish

The gate reports three outcomes, and "did not complete" is deliberately not
reported as a pass. Check `terraform output log_group_name` for the reason.
