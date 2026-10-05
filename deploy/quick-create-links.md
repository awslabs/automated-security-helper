<!--
GENERATED FILE - DO NOT EDIT quick-create-links.md.
Edit quick-create-links.md.template, then regenerate:
    python3 scripts/render_quick_create_links.py render
The IaC drift gate regenerates it on every pull request and fails on any difference.
-->

# One-click launch links

A CloudFormation quick-create link launches a stack from a single URL: it opens the console
with the template chosen and its parameters already filled in. Every deployment target here
ships a committed template that can be launched that way, from a bucket you own.

> **No links below, because ASH hosts no template bucket — by design.**
>
> A quick-create link requires `templateURL`, and CloudFormation accepts
> only an S3 URL there; a GitHub raw URL will not work. ASH publishes these
> templates to no bucket, for the same reason it publishes no container
> image — see [Why there is no upstream
> bucket](#why-there-is-no-upstream-bucket).
>
> So the link column reads `NO-BUCKET-CONFIGURED` rather than an example
> URL naming a bucket you do not control. This is the shipping state of
> this file, not a gap waiting to be filled.
>
> **The links are for you to render.** Copy the templates to a bucket
> you own, set it in `quick-create-hosting.json`, and re-render — 6
> working links, in your account, for you to use or publish internally.
> See [Rendering links for your own
> bucket](#rendering-links-for-your-own-bucket). To launch without any of
> that, `cdk/README.md` has the console and CLI paths.

## The links

`Must be filled in` names the parameters the template declares with no default. A
quick-create link cannot supply those — there is no value to derive from — so the console
opens with the field blank and stack creation fails until you fill it.

| Stack | Launch | Must be filled in |
| --- | --- | --- |
| `AshAgentCore` | `NO-BUCKET-CONFIGURED` | — |
| `AshCodeCommitGate` | `NO-BUCKET-CONFIGURED` | `CodeCommitRepositoryArn` |
| `AshDistributedPipeline` | `NO-BUCKET-CONFIGURED` | — |
| `AshEksOperator` | `NO-BUCKET-CONFIGURED` | `EksClusterName`, `OperatorImageUri` |
| `AshFargate` | `NO-BUCKET-CONFIGURED` | — |
| `AshImagePipeline` | `NO-BUCKET-CONFIGURED` | — |

Deploy `AshImagePipeline` first if you have not already. It builds the ASH container image
into your own ECR repository, and the other four stacks consume the image it produces —
they take an `AshImageTag` and it does not. It is infrastructure the other targets depend
on rather than a fifth target.

## What each link prepopulates

Every value below is copied from that template's own declared `Default` at render time,
not typed into this document. That is what keeps them from going stale: the check
described in the next section compares each one against the template on every pull
request, so a value here cannot disagree with the template it launches.

| Stack | Parameters the link sets |
| --- | --- |
| `AshAgentCore` | `AshVersion`=`v3.7.0`, `AshOfflineMode`=`NO`, `RebuildSchedule`=`cron(0 6 * * ? *)` |
| `AshCodeCommitGate` | `AshVersion`=`v3.7.0`, `AshOfflineMode`=`NO`, `RebuildSchedule`=`cron(0 6 * * ? *)` |
| `AshDistributedPipeline` | `AshVersion`=`v3.7.0`, `AshOfflineMode`=`NO`, `RebuildSchedule`=`cron(0 6 * * ? *)` |
| `AshEksOperator` | — |
| `AshFargate` | `AshVersion`=`v3.7.0`, `AshOfflineMode`=`NO`, `RebuildSchedule`=`cron(0 6 * * ? *)` |
| `AshImagePipeline` | `AshVersion`=`v3.7.0`, `AshOfflineMode`=`NO`, `RebuildSchedule`=`cron(0 6 * * ? *)` |

Anything not listed keeps the template's default, which you can change in the console
before creating the stack.

## Rendering links for your own bucket

Four steps, and the first one is a command `cdk/README.md` already documents for launching
the larger templates — the upload it describes is the same upload these links need.

1. **Copy the templates to a bucket you own.** Any bucket works; the console reads it with
   your credentials, so it does not have to be public.

   ```sh
   aws s3 cp deploy/cdk/templates/ "s3://${YOUR_BUCKET}/ash/" \
     --recursive --exclude '*' --include '*.template.json'
   ```

   `cdk/README.md` under "Launching a committed template" shows the single-file form of this
   alongside the `create-stack` calls, and explains which three templates exceed
   CloudFormation's 51,200-byte inline limit and therefore must be uploaded whether or not
   you want links.

2. **Record the bucket** in `quick-create-hosting.json`: `bucket`, `bucket_region`, and
   `key_prefix`. The prefix must match where you actually put them — `ash/` for the command
   above, including the trailing slash. `launch_regions` lists the regions to emit a link
   for; the stack is created in the region in the link, which is independent of where the
   bucket lives. The renderer refuses a bucket name S3 would not have accepted, and a
   region outside the standard `aws` partition, whose console and S3 host names differ.

3. **Re-render:**

   ```sh
   python3 scripts/render_quick_create_links.py render
   ```

4. **Check what you got:**

   ```sh
   python3 scripts/render_quick_create_links.py check
   ```

   This is the step worth not skipping. It re-reads the rendered links and asserts every
   `param_` name against the template it launches, because CloudFormation will not — see
   the section after next.

The result is one link per template, working for anyone who can read your bucket. Publish
them on your own wiki or runbook; they are specific to your bucket and mean nothing outside
it.

Keep in mind that a link pins the template it points at. If you copy a newer template over
the same key, every previously published link silently starts launching the new one. Use a
versioned prefix (`key_prefix` of `ash/v3.7.0/`, say) if you would rather an old link keep
resolving to the template it was reviewed against.

## Why there is no upstream bucket

ASH publishes no template bucket, and this is the same position it takes on container
images rather than a separate one.

The reasoning is in
[Building your own container image](../docs/content/docs/building-your-own-image.md): ASH
reads your source code, so anything that scans or provisions on your behalf sits in the
same trust position as your build tooling, and "what is in this, when did it change, and
who approved that change" should be answerable by the organization running it rather than
by an upstream publisher.

That argument is weaker here than it is for the image, and it is worth saying so. A
CloudFormation template is text you can read in the diff, and these templates are committed
in this repository, so you can review one without trusting a registry. What an upstream
bucket would add is not provenance you cannot otherwise get — it is a permanent external
dependency in the launch path, and one more artifact whose contents at any moment are
decided elsewhere. Copying the file into your own bucket costs one command and removes
both.

The practical consequence is small, because two of the five templates are under
CloudFormation's inline size cap and the other three have to be uploaded to S3 to launch at
all. For those three the upload is not an extra step this feature imposes; it is the step
you were already taking.

## Why this file is generated, and what checks it

The format is documented under
[Use quick-create links to create CloudFormation stacks](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stacks-quick-create-links.html).
Two of its properties are the reason nothing here is hand-written.

`templateURL` is required, and CloudFormation accepts only an S3 URL — one of
`https://s3.<region>.amazonaws.com/<bucket>/<key>`,
`https://<bucket>.s3.<region>.amazonaws.com/<key>`, or the legacy
`https://s3-<region>.amazonaws.com/<bucket>/<key>`. A link pointing at this repository's
raw file URL does not work.

The renderer uses the virtual-hosted form unless the bucket name contains a period. S3's
wildcard certificate for `*.s3.<region>.amazonaws.com` matches only one DNS label, so a
dotted bucket cannot be fetched virtual-hosted over HTTPS — see
[Virtual hosting of general purpose buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html).
For a dotted bucket the renderer emits the path-style form instead, and `check` rejects a
virtual-hosted URL for one.

More important: **CloudFormation silently ignores a `param_` name the template does not
declare**, and silently ignores any parameter whose `NoEcho` is true. A typo is not an
error. The console opens, the parameter is absent, the template's default quietly applies,
and the stack that gets created is not the one the link described — with nothing reporting
it at any point.

So `scripts/render_quick_create_links.py check` re-reads this file, parses every link it
finds, and asserts that each `param_` name is a parameter the target template actually
declares, that none of them is a `NoEcho` parameter, that each value equals that
parameter's declared default, that the stack name is one CloudFormation will accept, and
that the template URL is one of the three supported S3 forms. It runs in
`.github/workflows/ash-iac-drift.yml` alongside the template drift check, so a stale or
hand-edited link is a red build rather than something an adopter finds at launch time.

That check carries its own positive control. `--self-test` feeds the validator a
deliberately misspelled `param_` name, a `NoEcho` parameter, a value that disagrees with
the template, a raw GitHub URL, a dotted bucket addressed virtual-hosted, an illegal stack
name and a declared parameter outside the plan, and fails unless every one is rejected —
plus a correct link that must be accepted, because a validator that rejected everything
would otherwise pass every negative case and prove nothing.
