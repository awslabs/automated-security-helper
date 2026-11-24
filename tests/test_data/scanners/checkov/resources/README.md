# checkov reports that name each record's resource

What checkov 3.4.6 wrote for one small tree, reduced to the fields
`attach_checkov_resources` reads. The tree had two `aws_db_instance` resources in
`tf/main.tf` (the second with an inline `checkov:skip`), a CloudFormation template,
a Kubernetes Deployment, a Dockerfile, a local module, and `tfplan.json`: the plan
of a configuration that calls that module twice, as `module.db` and `module.db2`.

Run as ASH runs checkov, from the filesystem root:

```sh
cd / && checkov --directory /private/tmp/ash-checkov-fixture/proj --framework all \
  --output sarif --output json --output-file-path /private/tmp/ash-checkov-fixture/out
```

- `results_sarif.sarif`: each result's `ruleId`, URI, line range and suppressions, in
  the order checkov wrote them. The messages, snippets and rules are left out.
- `results_json.json`: each failed and skipped record's `check_id`, `repo_file_path`,
  `file_abs_path`, `file_line_range` and `resource`, in the order checkov wrote them.
  The passed records and every other field are left out.

The two reports list the same 80 records in the same order. The SARIF report has no
field that names a resource; the JSON report does.
