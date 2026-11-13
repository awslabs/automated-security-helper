"""Frozen whole-file and glob suppression entries, read by test_suppression_scope_guard.py.

Generated once, when the guard was added, from the configs at that commit. Do not
add to these lists: a new entry that cannot carry a line range belongs in
``ALLOWLIST`` in the guard, with a reason. Removing an entry from a config means
removing it here too; the guard fails on a stale key, so these lists only shrink.

MAIN_BASELINE holds the entries inherited from ``main``, and only ones that are still
unpinned entries in ``origin/main``'s configs (the guard's subset test). A merge of main
can therefore only shrink it or swap in a key main itself added, within the cap: the
merge of a513530b dropped the directory globs #724 removed (17 keys) and took
#717's B108 entry for tests/snapshot/test_snapshot_normalizer.py. The merge of
origin/main into v4-capabilities (617e17c3629) added the whole-file entries main wrote
one per rule and file (221 in .ash/.ash.yaml, 108 in the community config), listed in
the last block of each list, and raised the caps to match. PRE_GUARD_BASELINE holds the
ones that were already on this branch, from other branches, when the guard was
added. Each is tagged with the branch that landed it.
"""

from __future__ import annotations

# (rule_id, path). A rule_id of None matches every rule on the path.
MAIN_BASELINE: dict[str, tuple[tuple[str | None, str], ...]] = {
    ".ash/.ash.yaml": (
        ("CKV_DOCKER_2", "Dockerfile"),
        (
            "B404",
            "ash-agent-plugins/agentic-coding/transpiler/tools/generate_models.py",
        ),
        (
            "B603",
            "ash-agent-plugins/agentic-coding/transpiler/tools/generate_models.py",
        ),
        (
            "B404",
            "ash-agent-plugins/agentic-coding/transpiler/tools/refresh_schemas.py",
        ),
        (
            "B603",
            "ash-agent-plugins/agentic-coding/transpiler/tools/refresh_schemas.py",
        ),
        (
            "B404",
            "ash-agent-plugins/agentic-coding/transpiler/transpiler/backends/aider/__init__.py",
        ),
        (
            "B404",
            "ash-agent-plugins/agentic-coding/transpiler/transpiler/backends/generic_skill/__init__.py",
        ),
        (
            "B603",
            "ash-agent-plugins/agentic-coding/transpiler/transpiler/backends/generic_skill/__init__.py",
        ),
        ("B404", "ash-agent-plugins/agentic-coding/transpiler/transpiler/core.py"),
        ("B603", "ash-agent-plugins/agentic-coding/transpiler/transpiler/core.py"),
        ("python.lang.compatibility.*", "automated_security_helper/**/*.py"),
        (
            "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected",
            "automated_security_helper/**/*.py",
        ),
        (
            "python.lang.security.audit.non-literal-import.non-literal-import",
            "automated_security_helper/**/*.py",
        ),
        ("CKV_DOCKER_2", "automated_security_helper/assets/Dockerfile"),
        ("SECRET-SECRET-KEYWORD", "automated_security_helper/utils/secret_masking.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "deploy/cdk-constructs/test/ash-scan-step.test.ts",
        ),
        ("SECRET-SECRET-KEYWORD", "deploy/cdk/lib/ash-runtime-config.ts"),
        ("AwsSolutions-IAM5", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("CFN_NAG_W12", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("CFN_NAG_W58", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("CFN_NAG_W76", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("CFN_NAG_W89", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("CKV_AWS_116", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("CKV_AWS_117", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("CKV_AWS_51", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("F3031", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("F3033", "deploy/cdk/templates/AshAgentCore.template.json"),
        (
            "HIPAA.Security-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        (
            "HIPAA.Security-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        ("HIPAA.Security-LambdaDLQ", "deploy/cdk/templates/AshAgentCore.template.json"),
        (
            "HIPAA.Security-LambdaInsideVPC",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        (
            "HIPAA.Security-SecretsManagerRotationEnabled",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        (
            "NIST.800.53.R4-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        (
            "NIST.800.53.R4-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        (
            "NIST.800.53.R4-LambdaInsideVPC",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        (
            "NIST.800.53.R5-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        ("NIST.800.53.R5-LambdaDLQ", "deploy/cdk/templates/AshAgentCore.template.json"),
        (
            "NIST.800.53.R5-LambdaInsideVPC",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        (
            "NIST.800.53.R5-SecretsManagerRotationEnabled",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        (
            "PCI.DSS.321-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        (
            "PCI.DSS.321-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        (
            "PCI.DSS.321-LambdaInsideVPC",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "deploy/cdk/templates/AshAgentCore.template.json",
        ),
        ("CFN_NAG_W12", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("CFN_NAG_W58", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("CFN_NAG_W89", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("CKV_AWS_116", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("CKV_AWS_117", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("CKV_AWS_51", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("F3031", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("F3033", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        (
            "HIPAA.Security-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "HIPAA.Security-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "HIPAA.Security-LambdaDLQ",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "HIPAA.Security-LambdaInsideVPC",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "NIST.800.53.R4-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "NIST.800.53.R4-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "NIST.800.53.R4-LambdaInsideVPC",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "NIST.800.53.R5-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "NIST.800.53.R5-LambdaDLQ",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "NIST.800.53.R5-LambdaInsideVPC",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "PCI.DSS.321-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "PCI.DSS.321-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "PCI.DSS.321-LambdaInsideVPC",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "deploy/cdk/templates/AshCodeCommitGate.template.json",
        ),
        (
            "AwsSolutions-CB5",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        ("CFN_NAG_W12", "deploy/cdk/templates/AshDistributedPipeline.template.json"),
        ("CFN_NAG_W76", "deploy/cdk/templates/AshDistributedPipeline.template.json"),
        ("CKV_AWS_51", "deploy/cdk/templates/AshDistributedPipeline.template.json"),
        ("F3031", "deploy/cdk/templates/AshDistributedPipeline.template.json"),
        ("F3033", "deploy/cdk/templates/AshDistributedPipeline.template.json"),
        (
            "HIPAA.Security-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "HIPAA.Security-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "HIPAA.Security-S3BucketReplicationEnabled",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "HIPAA.Security-S3DefaultEncryptionKMS",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "NIST.800.53.R4-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "NIST.800.53.R4-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "NIST.800.53.R4-S3BucketDefaultLockEnabled",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "NIST.800.53.R4-S3BucketReplicationEnabled",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "NIST.800.53.R5-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "NIST.800.53.R5-S3BucketReplicationEnabled",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "NIST.800.53.R5-S3DefaultEncryptionKMS",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "PCI.DSS.321-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "PCI.DSS.321-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "PCI.DSS.321-S3BucketReplicationEnabled",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "PCI.DSS.321-S3DefaultEncryptionKMS",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        ("AwsSolutions-EC23", "deploy/cdk/templates/AshFargate.template.json"),
        ("CFN_NAG_W12", "deploy/cdk/templates/AshFargate.template.json"),
        ("CFN_NAG_W5", "deploy/cdk/templates/AshFargate.template.json"),
        ("CFN_NAG_W56", "deploy/cdk/templates/AshFargate.template.json"),
        ("CFN_NAG_W58", "deploy/cdk/templates/AshFargate.template.json"),
        ("CFN_NAG_W89", "deploy/cdk/templates/AshFargate.template.json"),
        ("CKV_AWS_103", "deploy/cdk/templates/AshFargate.template.json"),
        ("CKV_AWS_116", "deploy/cdk/templates/AshFargate.template.json"),
        ("CKV_AWS_117", "deploy/cdk/templates/AshFargate.template.json"),
        ("CKV_AWS_2", "deploy/cdk/templates/AshFargate.template.json"),
        ("CKV_AWS_51", "deploy/cdk/templates/AshFargate.template.json"),
        ("F3031", "deploy/cdk/templates/AshFargate.template.json"),
        ("F3033", "deploy/cdk/templates/AshFargate.template.json"),
        (
            "HIPAA.Security-ALBHttpToHttpsRedirection",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "HIPAA.Security-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "HIPAA.Security-EC2RestrictedCommonPorts",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "HIPAA.Security-EC2RestrictedSSH",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "HIPAA.Security-ELBDeletionProtectionEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "HIPAA.Security-ELBv2ACMCertificateRequired",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "HIPAA.Security-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        ("HIPAA.Security-LambdaDLQ", "deploy/cdk/templates/AshFargate.template.json"),
        (
            "HIPAA.Security-LambdaInsideVPC",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "HIPAA.Security-S3BucketReplicationEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "HIPAA.Security-S3DefaultEncryptionKMS",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "HIPAA.Security-SecretsManagerRotationEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "HIPAA.Security-VPCDefaultSecurityGroupClosed",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "HIPAA.Security-VPCNoUnrestrictedRouteToIGW",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R4-ALBHttpToHttpsRedirection",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R4-ALBWAFEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R4-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R4-EC2RestrictedCommonPorts",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R4-EC2RestrictedSSH",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R4-ELBDeletionProtectionEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R4-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R4-LambdaInsideVPC",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R4-S3BucketDefaultLockEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R4-S3BucketReplicationEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R4-VPCDefaultSecurityGroupClosed",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-ALBHttpToHttpsRedirection",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-ALBWAFEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-EC2RestrictedCommonPorts",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-EC2RestrictedSSH",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-ELBDeletionProtectionEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-ELBv2ACMCertificateRequired",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        ("NIST.800.53.R5-LambdaDLQ", "deploy/cdk/templates/AshFargate.template.json"),
        (
            "NIST.800.53.R5-LambdaInsideVPC",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-S3BucketReplicationEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-S3DefaultEncryptionKMS",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-SecretsManagerRotationEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-VPCDefaultSecurityGroupClosed",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "NIST.800.53.R5-VPCNoUnrestrictedRouteToIGW",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "PCI.DSS.321-ALBHttpToHttpsRedirection",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        ("PCI.DSS.321-ALBWAFEnabled", "deploy/cdk/templates/AshFargate.template.json"),
        (
            "PCI.DSS.321-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "PCI.DSS.321-EC2RestrictedCommonPorts",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "PCI.DSS.321-EC2RestrictedSSH",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "PCI.DSS.321-ELBv2ACMCertificateRequired",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "PCI.DSS.321-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "PCI.DSS.321-LambdaInsideVPC",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "PCI.DSS.321-S3BucketReplicationEnabled",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "PCI.DSS.321-S3DefaultEncryptionKMS",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "PCI.DSS.321-VPCDefaultSecurityGroupClosed",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "PCI.DSS.321-VPCNoUnrestrictedRouteToIGW",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "deploy/cdk/templates/AshFargate.template.json",
        ),
        ("CFN_NAG_W12", "deploy/cdk/templates/AshImagePipeline.template.json"),
        ("CKV_AWS_51", "deploy/cdk/templates/AshImagePipeline.template.json"),
        ("F3031", "deploy/cdk/templates/AshImagePipeline.template.json"),
        ("F3033", "deploy/cdk/templates/AshImagePipeline.template.json"),
        (
            "HIPAA.Security-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshImagePipeline.template.json",
        ),
        (
            "HIPAA.Security-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshImagePipeline.template.json",
        ),
        (
            "NIST.800.53.R4-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshImagePipeline.template.json",
        ),
        (
            "NIST.800.53.R4-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshImagePipeline.template.json",
        ),
        (
            "NIST.800.53.R5-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshImagePipeline.template.json",
        ),
        (
            "PCI.DSS.321-CodeBuildProjectSourceRepoUrl",
            "deploy/cdk/templates/AshImagePipeline.template.json",
        ),
        (
            "PCI.DSS.321-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshImagePipeline.template.json",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "deploy/cdk/templates/AshImagePipeline.template.json",
        ),
        ("SECRET-HEX-HIGH-ENTROPY-STRING", "deploy/cdk/test/ash-image-build.test.ts"),
        (
            "SECRET-SECRET-KEYWORD",
            "deploy/terraform/modules/ash-image-pipeline/files/ash-container-init",
        ),
        ("B108", "deploy/terraform/modules/codecommit-gate/files/ash_pr_gate.py"),
        ("B404", "deploy/terraform/modules/codecommit-gate/files/ash_pr_gate.py"),
        ("B603", "deploy/terraform/modules/codecommit-gate/files/ash_pr_gate.py"),
        ("SECRET-BASE64-HIGH-ENTROPY-STRING", "nix/opengrep.nix"),
        ("SECRET-BASE64-HIGH-ENTROPY-STRING", "pyproject.toml"),
        ("B404", "scripts/verify_moto_server_suite.py"),
        ("B603", "scripts/verify_moto_server_suite.py"),
        ("B404", "tests/integration/cli/test_mcp_stdio_server.py"),
        ("B603", "tests/integration/cli/test_mcp_stdio_server.py"),
        ("B108", "tests/snapshot/test_snapshot_normalizer.py"),
        ("B404", "tests/unit/assets/test_install_pinned_tool.py"),
        ("B404", "tests/unit/assets/test_with_retry.py"),
        ("B104", "tests/unit/cli/test_mcp_sse_host_binding.py"),
        ("B104", "tests/unit/cli/test_mcp_stateless_http.py"),
        ("B404", "tests/unit/cli/test_startup_failure_diagnosability.py"),
        ("B603", "tests/unit/cli/test_startup_failure_diagnosability.py"),
        ("B108", "tests/unit/deploy/buildspec_extraction.py"),
        ("B404", "tests/unit/deploy/test_deploy_buildspec_ssm_moto_server.py"),
        ("B603", "tests/unit/deploy/test_deploy_buildspec_ssm_moto_server.py"),
        ("B105", "tests/unit/deploy/test_deploy_mcp_entrypoint_secrets_moto_server.py"),
        ("B404", "tests/unit/deploy/test_deploy_mcp_entrypoint_secrets_moto_server.py"),
        ("B603", "tests/unit/deploy/test_deploy_mcp_entrypoint_secrets_moto_server.py"),
        ("B404", "tests/unit/deploy/test_deploy_s3_sync_moto_server.py"),
        ("B603", "tests/unit/deploy/test_deploy_s3_sync_moto_server.py"),
        ("B105", "tests/unit/interactions/test_gha_layer_cache_args.py"),
        (
            "B404",
            "tests/unit/interactions/test_run_ash_container_entrypoint_coverage.py",
        ),
        ("B404", "tests/unit/interactions/test_run_ash_container_helpers_coverage.py"),
        ("B404", "tests/unit/interactions/test_run_ash_nix.py"),
        (
            "B404",
            "tests/unit/plugin_modules/ash_builtin/converters/test_jupyter_converter.py",
        ),
        (
            "B105",
            "tests/unit/plugin_modules/ash_builtin/test_bandit_scanner_behavior.py",
        ),
        ("B404", "tests/unit/test_ash_bash_entrypoint_build_failure.py"),
        ("B105", "tests/unit/test_release_workflow_token.py"),
        ("B404", "tests/unit/utils/test_get_scan_set_coverage.py"),
        # main's own whole-file entries, carried in by the merge of origin/main
        # (617e17c3629) into v4-capabilities. Each key is an unpinned entry in
        # origin/main's config, one per rule and file; main has no guard, so they were
        # never baselined. Sorted by path, then rule. Nothing here is new: none is on
        # v4's side of the merge.
        ("CKV_GHA_7", ".github/workflows/ash-docs-ci-runners.yml"),
        ("B104", "automated_security_helper/cli/mcp/__init__.py"),
        ("SECRET-SECRET-KEYWORD", "automated_security_helper/utils/scanner_names.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "automated_security_helper/utils/scanner_tool_types.py",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "deploy/cdk-constructs/test/git-ref.test.ts",
        ),
        ("W1030", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("W1030", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("W1030", "deploy/cdk/templates/AshDistributedPipeline.template.json"),
        ("W1030", "deploy/cdk/templates/AshFargate.template.json"),
        ("W1030", "deploy/cdk/templates/AshImagePipeline.template.json"),
        ("SECRET-SECRET-KEYWORD", "deploy/cdk/test/ash-container-scripts.test.ts"),
        ("B604", "tests/conftest.py"),
        ("B108", "tests/integration/docs/ci_runners/fixture.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/integration/docs/ci_runners/jenkins/plugins-bundled.toml",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/integration/docs/ci_runners/jenkins/plugins-lts.toml",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/integration/docs/ci_runners/provenance.py",
        ),
        ("B314", "tests/integration/docs/ci_runners/reports.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/integration/docs/ci_runners/runners.toml",
        ),
        ("B314", "tests/integration/docs/ci_runners/verdict.py"),
        ("SECRET-SECRET-KEYWORD", "tests/integration/sandbox/test_sandbox_escape.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/integration/test_install_hints_on_python310.py",
        ),
        (
            "B108",
            "tests/snapshot/container/runtime/test_container_image_permissions.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/snapshot/container/test_snapshot_container_exit_codes.py",
        ),
        (
            "generic-api-key",
            "tests/snapshot/container/test_snapshot_container_exit_codes.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/snapshot/container/test_snapshot_container_nix.py",
        ),
        ("generic-api-key", "tests/snapshot/container/test_snapshot_container_nix.py"),
        ("B103", "tests/unit/assets/test_install_pinned_tool.py"),
        (
            "SECRET-BASIC-AUTH-CREDENTIALS",
            "tests/unit/assets/test_install_pinned_tool_redirects_and_races.py",
        ),
        (
            "B604",
            "tests/unit/base/test_a_custom_install_command_keeps_its_shell_flag.py",
        ),
        (
            "generic-api-key",
            "tests/unit/base/test_a_failure_after_the_tool_ran_keeps_its_exit_code.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/base/test_a_plugin_whose_check_raised_is_excluded_with_a_warning.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/base/test_uv_tool_mixin_guards_and_decisions.py",
        ),
        (
            "generic-api-key",
            "tests/unit/base/test_uv_tool_mixin_guards_and_decisions.py",
        ),
        ("B324", "tests/unit/characterization/_detect_secrets_double.py"),
        ("B108", "tests/unit/characterization/_harness.py"),
        ("B604", "tests/unit/characterization/_harness.py"),
        ("B102", "tests/unit/characterization/test_harness_confinement.py"),
        ("B310", "tests/unit/characterization/test_harness_confinement.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/characterization/test_harness_confinement.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/inspect/test_each_value_is_shown_once.py",
        ),
        ("generic-api-key", "tests/unit/cli/inspect/test_each_value_is_shown_once.py"),
        ("SECRET-HEX-HIGH-ENTROPY-STRING", "tests/unit/cli/mcp/conftest.py"),
        ("generic-api-key", "tests/unit/cli/mcp/conftest.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_a_refusal_before_the_runner_shows_no_value_the_config_read.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_a_refused_auth_value_builds_nothing_on_the_shared_server.py",
        ),
        (
            "generic-api-key",
            "tests/unit/cli/mcp/test_a_scan_copys_name_is_computed_once_per_scan.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_a_scan_runner_failure_shows_no_value_the_config_read.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_a_scan_that_cannot_start_does_not_hold_its_directory.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_a_workspace_failure_redacts_with_the_runs_values.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_an_auth_header_value_outside_latin_1_is_refused.py",
        ),
        ("SECRET-SECRET-KEYWORD", "tests/unit/cli/mcp/test_get_config.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_get_config_refuses_plugin_modules_a_scan_refuses.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_list_scanners_scan_selection.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_mcp_scan_redaction_values.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_mcp_server_get_scan_progress_keeps_the_producers_view.py",
        ),
        ("B103", "tests/unit/cli/mcp/test_session_paths_workspace_is_private.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_session_plugins_stay_in_their_session.py",
        ),
        (
            "SECRET-BASIC-AUTH-CREDENTIALS",
            "tests/unit/cli/mcp/test_set_source_git_host_allowlist.py",
        ),
        (
            "SECRET-BASIC-AUTH-CREDENTIALS",
            "tests/unit/cli/mcp/test_set_source_git_host_is_the_one_ssh_dials.py",
        ),
        ("B307", "tests/unit/cli/mcp/test_shipped_mcp_guidance_matches_the_server.py"),
        (
            "B103",
            "tests/unit/cli/mcp/test_source_delivery_deletes_read_only_scratch.py",
        ),
        (
            "B103",
            "tests/unit/cli/mcp/test_source_delivery_scratch_that_resists_deletion.py",
        ),
        (
            "generic-api-key",
            "tests/unit/cli/mcp/test_tool_errors_describe_a_wrapped_validation_error.py",
        ),
        (
            "generic-api-key",
            "tests/unit/cli/mcp/test_validation_errors_leave_out_the_input.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/mcp/test_workspace_crash_surfaces_redact_env_values.py",
        ),
        (
            "B604",
            "tests/unit/cli/test_dependencies_a_shell_command_is_one_command_line.py",
        ),
        ("B604", "tests/unit/cli/test_dependencies_install_passes_the_shell_flag.py"),
        ("B604", "tests/unit/cli/test_dependencies_refuses_before_creating.py"),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/unit/cli/test_dependencies_verdict.py",
        ),
        ("B202", "tests/unit/cli/test_genai_guide_ships_with_install.py"),
        ("B108", "tests/unit/cli/test_mcp_errors_show_controls.py"),
        ("B104", "tests/unit/cli/test_mcp_loopback_accepts_only_its_own_origin.py"),
        ("B104", "tests/unit/cli/test_mcp_non_loopback_bind_is_refused.py"),
        ("B104", "tests/unit/cli/test_mcp_upstream_host_check.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/test_merge_shard_errors_hide_the_file.py",
        ),
        ("generic-api-key", "tests/unit/cli/test_merge_shard_errors_hide_the_file.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/test_plugin_list_shows_what_a_scan_selects.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/cli/test_report_refuses_invalid_plugin_options.py",
        ),
        (
            "generic-api-key",
            "tests/unit/cli/test_report_refuses_invalid_plugin_options.py",
        ),
        ("B102", "tests/unit/cli/test_scan_messages_tell_the_truth.py"),
        (
            "B103",
            "tests/unit/config/test_a_checkout_boundary_needs_a_git_shaped_marker.py",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/unit/config/test_a_patched_section_spelling_lands_on_the_section.py",
        ),
        (
            "B506",
            "tests/unit/config/test_a_patched_value_is_recorded_where_later_operations_move_it.py",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/unit/config/test_a_patched_value_is_recorded_where_later_operations_move_it.py",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/unit/config/test_a_value_read_from_the_environment_is_hidden_inside_a_word.py",
        ),
        ("B103", "tests/unit/config/test_add_suppression.py"),
        (
            "B103",
            "tests/unit/config/test_an_undecided_walk_names_the_walk_in_the_warning.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/config/test_config_messages_hide_values.py",
        ),
        ("generic-api-key", "tests/unit/config/test_config_messages_hide_values.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/config/test_results_errors_hide_the_file.py",
        ),
        ("generic-api-key", "tests/unit/config/test_results_errors_hide_the_file.py"),
        ("B108", "tests/unit/config/test_sandbox_environment_setting.py"),
        (
            "SECRET-BASIC-AUTH-CREDENTIALS",
            "tests/unit/config/test_sandbox_environment_setting.py",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/config/test_settle_trace_recordings.py",
        ),
        (
            "SECRET-PRIVATE-KEY",
            "tests/unit/converters/test_archive_member_admission.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/converters/test_archive_plain_gzip_and_lfs_pointers.py",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/unit/core/phases/test_unevaluated_targets_refuse_passed.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/core/resource_management/test_a_scan_entry_redacts_with_its_registered_values.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/core/resource_management/test_error_handling_categories_and_paths.py",
        ),
        (
            "B301",
            "tests/unit/core/resource_management/test_one_category_per_lookup_error_and_full_disk.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/core/resource_management/test_scan_registry_lookups_and_claims.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/core/resource_management/test_scanner_status_summary.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/core/test_engine_phase_scope_handlers_and_check_failures.py",
        ),
        ("B301", "tests/unit/core/test_exceptions_low_unset_variable_error_copy.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/core/test_orchestrator_project_name_holding_an_environment_value.py",
        ),
        (
            "generic-api-key",
            "tests/unit/core/test_orchestrator_project_name_holding_an_environment_value.py",
        ),
        ("B608", "tests/unit/deploy/test_agentcore_stateless_fallback_tripwire.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/deploy/test_deploy_constructs_ash_ref_is_checked.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/deploy/test_deploy_mcp_entrypoint_secret_off_the_command_line.py",
        ),
        ("B108", "tests/unit/deploy/test_deploy_pipeline_config_source.py"),
        ("SECRET-SECRET-KEYWORD", "tests/unit/docs/test_page_claims.py"),
        ("generic-api-key", "tests/unit/docs/test_page_claims.py"),
        (
            "SECRET-BASIC-AUTH-CREDENTIALS",
            "tests/unit/interactions/test_a_leftover_is_removed_only_through_its_own_runtime.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/interactions/test_a_leftover_is_removed_only_through_its_own_runtime.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/interactions/test_a_source_dir_that_is_not_utf8_is_refused.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/interactions/test_an_output_dir_that_is_not_utf8_works.py",
        ),
        ("B108", "tests/unit/interactions/test_container_image_revision.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/interactions/test_run_ash_container_helpers_coverage.py",
        ),
        (
            "SECRET-PRIVATE-KEY",
            "tests/unit/interactions/test_run_ash_container_input_and_run_edges.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/interactions/test_run_ash_container_input_and_run_edges.py",
        ),
        (
            "private-key",
            "tests/unit/interactions/test_run_ash_container_input_and_run_edges.py",
        ),
        (
            "SECRET-BASIC-AUTH-CREDENTIALS",
            "tests/unit/interactions/test_run_ash_nix.py",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/interactions/test_run_ash_nix.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/interactions/test_workspace_config_warning_is_shown.py",
        ),
        (
            "generic-api-key",
            "tests/unit/interactions/test_workspace_config_warning_is_shown.py",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/interactions/test_workspace_inner_run_records_its_outcome.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/models/test_asharp_model_low4_a_failed_failure_report_does_not_block_the_save.py",
        ),
        ("B108", "tests/unit/models/test_flat_vulnerability_ids_are_per_location.py"),
        ("generic-api-key", "tests/unit/models/test_report_id_unique_per_scan.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugin_modules/ash_aws_plugins/test_a_reporters_client_adds_no_retries_of_its_own.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugin_modules/ash_aws_plugins/test_s3_reporter_upload_holds_no_secret_value.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugin_modules/ash_aws_plugins/test_security_hub_batch_import.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugin_modules/ash_builtin/converters/test_jupyter_converter_edge_inputs.py",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/unit/plugin_modules/ash_builtin/scanners/test_cdk_nag_failure_lines_carry_no_environment_value.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugin_modules/ash_builtin/scanners/test_npm_audit_probe_selection_and_report_shapes.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugin_modules/ash_builtin/scanners/test_npm_audit_response_logging.py",
        ),
        (
            "B103",
            "tests/unit/plugin_modules/ash_builtin/scanners/test_scanners_name_a_file_that_is_not_utf8.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugin_modules/ash_builtin/scanners/test_semgrep_scanner_direct_binary_verified.py",
        ),
        ("B604", "tests/unit/plugin_modules/ash_builtin/test_bandit_excludes.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/plugin_modules/ash_builtin/test_cfn_nag_public_policy_rules.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugin_modules/ash_builtin/test_detect_secrets_baseline_entries_are_known.py",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/plugin_modules/ash_builtin/test_detect_secrets_scanner_behavior.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugin_modules/ash_builtin/test_npm_audit_offline_not_audited.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugins/test_a_debug_traceback_hides_env_read_module_paths.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugins/test_a_debug_traceback_hides_env_read_module_paths.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugins/test_a_failed_imports_log_line_redacts_env_values.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugins/test_a_failed_imports_log_line_redacts_env_values.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugins/test_an_environment_value_equal_to_a_derived_module_form_keeps_whole_value_redaction.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugins/test_an_environment_value_equal_to_a_derived_module_form_keeps_whole_value_redaction.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugins/test_discovery_failure_line_redacts_env_values.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugins/test_the_registry_and_decorators_name_a_masked_module_by_its_mask.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugins/test_the_registry_and_decorators_name_a_masked_module_by_its_mask.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/reporters/test_gitlab_sast_scan_section.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/reporters/test_reporter_plugin_doc_samples_run.py",
        ),
        ("B108", "tests/unit/schemas/test_filter_results_by_files_uri_forms.py"),
        ("SECRET-SECRET-KEYWORD", "tests/unit/scripts/test_validate_ferret_plugin.py"),
        ("B108", "tests/unit/scripts/test_verify_external_target_scan.py"),
        ("B102", "tests/unit/test_a_leaked_run_scope_fails_its_test.py"),
        ("B604", "tests/unit/test_conftest_helpers.py"),
        ("B108", "tests/unit/test_container_permissions_probe_covers_the_image.py"),
        ("B108", "tests/unit/test_dockerfile_directory_permissions.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/test_docs_ci_runner_evidence.py",
        ),
        ("B108", "tests/unit/test_docs_ci_runner_fixture.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/test_docs_ci_runner_judgments.py",
        ),
        ("generic-api-key", "tests/unit/test_docs_ci_runner_judgments.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/test_docs_ci_runner_launchers.py",
        ),
        ("B108", "tests/unit/test_docs_ci_runner_provenance.py"),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/unit/test_docs_ci_runner_provenance.py",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/test_docs_ci_runner_provenance.py",
        ),
        ("SECRET-HEX-HIGH-ENTROPY-STRING", "tests/unit/test_docs_ci_runner_rewrite.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/test_docs_install_commands_can_fail.py",
        ),
        ("B108", "tests/unit/test_failure_reports_redact_environment_values.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/test_hatch_build_records_commit.py",
        ),
        ("SECRET-SECRET-KEYWORD", "tests/unit/test_homebrew_macos_ci_job.py"),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/test_reusable_workflow_changed_files_only.py",
        ),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/unit/test_reusable_workflow_defaults.py",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/test_reusable_workflow_defaults.py",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/test_scan_workflow_pins_the_ash_ref.py",
        ),
        ("B310", "tests/unit/utils/conftest.py"),
        (
            "SECRET-BASIC-AUTH-CREDENTIALS",
            "tests/unit/utils/sandbox/test_backends_low_hardening.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/utils/sandbox/test_fs_guard_a_refused_pre_check_is_redacted_from_the_executor.py",
        ),
        ("B301", "tests/unit/utils/sandbox/test_scope_low_hardening.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/utils/test_a_refused_stop_never_prints_an_environment_value.py",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/utils/test_a_scan_set_is_reused_only_for_its_own_tree.py",
        ),
        ("SECRET-BASIC-AUTH-CREDENTIALS", "tests/unit/utils/test_ash_install.py"),
        ("SECRET-HEX-HIGH-ENTROPY-STRING", "tests/unit/utils/test_ash_install.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/utils/test_ash_install_failures_are_logged_redacted.py",
        ),
        (
            "generic-api-key",
            "tests/unit/utils/test_ash_install_failures_are_logged_redacted.py",
        ),
        (
            "SECRET-BASIC-AUTH-CREDENTIALS",
            "tests/unit/utils/test_ash_install_records_and_markers.py",
        ),
        ("SECRET-HEX-HIGH-ENTROPY-STRING", "tests/unit/utils/test_base_ref.py"),
        (
            "B108",
            "tests/unit/utils/test_child_tool_starts_record_what_a_child_starts.py",
        ),
        (
            "B108",
            "tests/unit/utils/test_content_db_refresh_resolves_caches_and_locks_as_the_tools_do.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/utils/test_detect_secrets_worker_caches_lines_per_key.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/utils/test_detect_secrets_worker_output_records.py",
        ),
        ("B301", "tests/unit/utils/test_env_resolved_scalar_survives_copying.py"),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/unit/utils/test_ignore_path_expiration.py",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "tests/unit/utils/test_inner_run_outcome.py",
        ),
        ("B108", "tests/unit/utils/test_link_chain.py"),
        ("B301", "tests/unit/utils/test_link_refusal_family.py"),
        ("B108", "tests/unit/utils/test_normalizers_injective.py"),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/unit/utils/test_pre_installed_tool.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/utils/test_python_children_import_nothing_from_their_cwd.py",
        ),
        ("B301", "tests/unit/utils/test_redacted_model_record_and_scalar_maker.py"),
        ("B301", "tests/unit/utils/test_report_path_links_names_and_pickling.py"),
        ("B103", "tests/unit/utils/test_scan_source.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/utils/test_secret_masking_keys_urls_and_edges.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/utils/test_secret_masking_reported_ranges.py",
        ),
        ("SECRET-SECRET-KEYWORD", "tests/unit/utils/test_severity_ladder.py"),
        ("B301", "tests/unit/utils/test_shown_text_is_shown_once.py"),
        (
            "B604",
            "tests/unit/utils/test_subprocess_utils_stops_resolution_and_records_edges.py",
        ),
        (
            "B604",
            "tests/unit/utils/test_the_server_scoped_run_resolves_its_program_like_every_other_spawn.py",
        ),
        ("B103", "tests/unit/utils/test_tool_config_dir.py"),
        (
            "B102",
            "tests/unit/utils/test_tool_downloads_refusals_and_the_rules_probe.py",
        ),
        (
            "B506",
            "tests/unit/utils/test_yaml_aliases_refuse_a_document_past_the_expansion_bound.py",
        ),
        (
            "B506",
            "tests/unit/utils/test_yaml_aliases_refuse_a_document_past_the_node_bound.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/workspace/test_a_failed_outcome_is_returned_when_the_exposed_values_cannot_be_read.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/workspace/test_a_reduction_that_raises_keeps_the_values_the_scan_exposed.py",
        ),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/workspace/test_a_workspace_path_that_is_not_utf8_is_refused.py",
        ),
        ("B604", "tests/utils/home_rule.py"),
        ("B604", "tests/utils/tool_guard.py"),
        ("SECRET-SECRET-KEYWORD", "tests/utils/tool_guard.py"),
    ),
    ".ash/.ash_community_plugins.yaml": (
        ("*:Apache-2.0", "**"),
        ("*:BSD-2-Clause", "**"),
        ("*:BSD-3-Clause", "**"),
        ("*:ISC", "**"),
        ("*:MIT", "**"),
        ("*:PSF-2.0", "**"),
        ("*:Python Software Foundation License", "**"),
        ("*:Unlicense", "**"),
        ("bash.lang.security.ifs-tampering.ifs-tampering", "**/*.sh"),
        (
            "B404",
            "ash-agent-plugins/agentic-coding/transpiler/tools/generate_models.py",
        ),
        (
            "B603",
            "ash-agent-plugins/agentic-coding/transpiler/tools/generate_models.py",
        ),
        (
            "B404",
            "ash-agent-plugins/agentic-coding/transpiler/tools/refresh_schemas.py",
        ),
        (
            "B603",
            "ash-agent-plugins/agentic-coding/transpiler/tools/refresh_schemas.py",
        ),
        (
            "B404",
            "ash-agent-plugins/agentic-coding/transpiler/transpiler/backends/aider/__init__.py",
        ),
        (
            "B404",
            "ash-agent-plugins/agentic-coding/transpiler/transpiler/backends/generic_skill/__init__.py",
        ),
        (
            "B603",
            "ash-agent-plugins/agentic-coding/transpiler/transpiler/backends/generic_skill/__init__.py",
        ),
        ("B404", "ash-agent-plugins/agentic-coding/transpiler/transpiler/core.py"),
        ("B603", "ash-agent-plugins/agentic-coding/transpiler/transpiler/core.py"),
        ("B110", "automated_security_helper/**/*.py"),
        ("B311", "automated_security_helper/**/*.py"),
        ("B404", "automated_security_helper/**/*.py"),
        ("B603", "automated_security_helper/**/*.py"),
        ("B607", "automated_security_helper/**/*.py"),
        (
            "python.lang.compatibility.python36.python36-compatibility-Popen1",
            "automated_security_helper/**/*.py",
        ),
        (
            "python.lang.compatibility.python36.python36-compatibility-Popen2",
            "automated_security_helper/**/*.py",
        ),
        (
            "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected",
            "automated_security_helper/**/*.py",
        ),
        (
            "python.lang.security.audit.non-literal-import.non-literal-import",
            "automated_security_helper/**/*.py",
        ),
        (
            "python.lang.compatibility.python37.python37-compatibility-importlib2",
            "automated_security_helper/cli/main.py",
        ),
        ("API_KEY_OR_SECRET", "automated_security_helper/cli/mcp/sessions.py"),
        (
            "python.lang.security.audit.non-literal-import.non-literal-import",
            "automated_security_helper/plugin_modules/ash_builtin/__init__.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "automated_security_helper/schemas/cyclonedx_bom_1_6_schema/__init__.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "automated_security_helper/schemas/ocsf/ocsf_vulnerability_finding.py",
        ),
        ("SECRET-SECRET-KEYWORD", "automated_security_helper/utils/secret_masking.py"),
        (
            "python.lang.compatibility.python36.python36-compatibility-Popen1",
            "automated_security_helper/utils/subprocess_utils.py",
        ),
        (
            "python.lang.compatibility.python36.python36-compatibility-Popen2",
            "automated_security_helper/utils/subprocess_utils.py",
        ),
        ("case:(MIT OR GPL-3.0-or-later)", "deploy/cdk/package-lock.json"),
        ("minimatch:BlueOak-1.0.0", "deploy/cdk/package-lock.json"),
        ("AWS-0017", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("AWS-0031", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("AWS-0033", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("AWS-0066", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("AWS-0098", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("AWS-0017", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("AWS-0031", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("AWS-0033", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("AWS-0066", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        ("AWS-0017", "deploy/cdk/templates/AshDistributedPipeline.template.json"),
        ("AWS-0031", "deploy/cdk/templates/AshDistributedPipeline.template.json"),
        ("AWS-0033", "deploy/cdk/templates/AshDistributedPipeline.template.json"),
        ("AWS-0089", "deploy/cdk/templates/AshDistributedPipeline.template.json"),
        ("AWS-0132", "deploy/cdk/templates/AshDistributedPipeline.template.json"),
        ("AWS-0017", "deploy/cdk/templates/AshFargate.template.json"),
        ("AWS-0031", "deploy/cdk/templates/AshFargate.template.json"),
        ("AWS-0033", "deploy/cdk/templates/AshFargate.template.json"),
        ("AWS-0036", "deploy/cdk/templates/AshFargate.template.json"),
        ("AWS-0054", "deploy/cdk/templates/AshFargate.template.json"),
        ("AWS-0066", "deploy/cdk/templates/AshFargate.template.json"),
        ("AWS-0089", "deploy/cdk/templates/AshFargate.template.json"),
        ("AWS-0098", "deploy/cdk/templates/AshFargate.template.json"),
        ("AWS-0104", "deploy/cdk/templates/AshFargate.template.json"),
        ("AWS-0132", "deploy/cdk/templates/AshFargate.template.json"),
        ("AWS-0017", "deploy/cdk/templates/AshImagePipeline.template.json"),
        ("AWS-0031", "deploy/cdk/templates/AshImagePipeline.template.json"),
        ("AWS-0033", "deploy/cdk/templates/AshImagePipeline.template.json"),
        (
            "DS-0002",
            "deploy/terraform/modules/ash-image-pipeline/files/wrapper.Dockerfile",
        ),
        (
            "DS-0026",
            "deploy/terraform/modules/ash-image-pipeline/files/wrapper.Dockerfile",
        ),
        ("AWS-0017", "deploy/terraform/modules/ash-image-pipeline/main.tf"),
        ("AWS-0031", "deploy/terraform/modules/ash-image-pipeline/main.tf"),
        ("AWS-0033", "deploy/terraform/modules/ash-image-pipeline/main.tf"),
        ("B108", "deploy/terraform/modules/codecommit-gate/files/ash_pr_gate.py"),
        ("B404", "deploy/terraform/modules/codecommit-gate/files/ash_pr_gate.py"),
        ("B603", "deploy/terraform/modules/codecommit-gate/files/ash_pr_gate.py"),
        ("DS-0026", "deploy/terraform/modules/codecommit-gate/files/gate.Dockerfile"),
        ("AWS-0017", "deploy/terraform/modules/codecommit-gate/main.tf"),
        ("AWS-0031", "deploy/terraform/modules/codecommit-gate/main.tf"),
        ("AWS-0033", "deploy/terraform/modules/codecommit-gate/main.tf"),
        ("AWS-0066", "deploy/terraform/modules/codecommit-gate/main.tf"),
        ("AWS-0017", "deploy/terraform/modules/codepipeline-executor/main.tf"),
        ("AWS-0089", "deploy/terraform/modules/codepipeline-executor/main.tf"),
        ("API_KEY_OR_SECRET", "deploy/terraform/modules/fargate/main.tf"),
        ("AWS-0054", "deploy/terraform/modules/fargate/main.tf"),
        ("AWS-0104", "deploy/terraform/modules/fargate/main.tf"),
        ("SECRET-SECRET-KEYWORD", "docs/content/docs/plugins/aws/index.md"),
        ("SECRET-SECRET-KEYWORD", "docs/content/docs/plugins/development-guide.md"),
        ("B110", "hatch_build.py"),
        ("API_KEY_OR_SECRET", "pyproject.toml"),
        ("SECRET-BASE64-HIGH-ENTROPY-STRING", "pyproject.toml"),
        ("B404", "scripts/*.py"),
        ("B603", "scripts/*.py"),
        ("B101", "tests/**/*.py"),
        ("B105", "tests/**/*.py"),
        ("B108", "tests/**/*.py"),
        ("B110", "tests/**/*.py"),
        ("B311", "tests/**/*.py"),
        ("B404", "tests/**/*.py"),
        ("B603", "tests/**/*.py"),
        ("B607", "tests/**/*.py"),
        ("SECRET-SECRET-KEYWORD", "tests/integration/cli/conftest.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/integration/cli/test_mcp_file_tracking_integration.py",
        ),
        ("SECRET-SECRET-KEYWORD", "tests/integration/cli/test_mcp_integration.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/integration/cli/test_mcp_integration_simple.py",
        ),
        ("JWT_TOKEN", "tests/unit/cli/mcp/test_session_id_single_component.py"),
        ("API_KEY_OR_SECRET", "tests/unit/cli/mcp/test_sessions.py"),
        ("B104", "tests/unit/cli/test_mcp_sse_host_binding.py"),
        ("B104", "tests/unit/cli/test_mcp_stateless_http.py"),
        ("B110", "tests/unit/config/test_ash_config_regression.py"),
        ("B108", "tests/unit/converters/test_converters.py"),
        ("B110", "tests/unit/core/test_base_plugins_regression.py"),
        ("B108", "tests/unit/core/test_orchestrator_regression.py"),
        (
            "SECRET-SECRET-KEYWORD",
            "tests/unit/plugin_modules/ash_aws_plugins/test_cloudwatch_logs_reporter*",
        ),
        ("API_KEY_OR_SECRET", "tests/unit/test_artifact_contents_gate.py"),
        ("SECRET-HEX-HIGH-ENTROPY-STRING", "tests/unit/test_defense_in_depth.py"),
        ("B110", "tests/unit/test_environ_mutation_fix.py"),
        ("B108", "tests/unit/utils/*.py"),
        ("SECRET-SECRET-KEYWORD", "tests/unit/utils/test_secret_masking*.py"),
        (
            "SECRET-BASE64-HIGH-ENTROPY-STRING",
            "tests/unit/utils/test_secret_masking.py",
        ),
        ("SECRET-SECRET-KEYWORD", "tests/unit/utils/test_secret_masking.py"),
        ("B404", "tests/unit/utils/test_subprocess_utils_regression.py"),
        ("B311", "tests/utils/*.py"),
        # main's own whole-file entries, carried in by the merge of origin/main
        # (617e17c3629) into v4-capabilities; same provenance and ordering as the block
        # at the end of the ``.ash/.ash.yaml`` list above.
        ("API_KEY_OR_SECRET", ".github/release-notes/*.md"),
        ("API_KEY_OR_SECRET", "CHANGELOG.md"),
        ("B104", "automated_security_helper/cli/mcp/__init__.py"),
        ("API_KEY_OR_SECRET", "automated_security_helper/config/operator_paths.py"),
        ("API_KEY_OR_SECRET", "automated_security_helper/config/tool_config_trust.py"),
        (
            "API_KEY_OR_SECRET",
            "automated_security_helper/plugin_modules/ash_ferret_plugins/spec/2026-09-13-ferret-scan-plugin-v2-update-analysis.md",
        ),
        ("API_KEY_OR_SECRET", "deploy/cdk/templates/*.template.json"),
        ("API_KEY_OR_SECRET", "deploy/cdk/templates/AshAgentCore.template.json"),
        ("API_KEY_OR_SECRET", "deploy/cdk/templates/AshCodeCommitGate.template.json"),
        (
            "API_KEY_OR_SECRET",
            "deploy/cdk/templates/AshDistributedPipeline.template.json",
        ),
        ("API_KEY_OR_SECRET", "deploy/cdk/templates/AshFargate.template.json"),
        ("API_KEY_OR_SECRET", "deploy/cdk/templates/AshImagePipeline.template.json"),
        ("SSN", "docs/content/reference/converters.md"),
        ("B604", "tests/conftest.py"),
        (
            "API_KEY_OR_SECRET",
            "tests/integration/codecommit_gate_regression/assert_case.py",
        ),
        ("DS-0002", "tests/integration/docs/ci_runners/gitlab-helper/Dockerfile"),
        ("B314", "tests/integration/docs/ci_runners/reports.py"),
        ("B314", "tests/integration/docs/ci_runners/verdict.py"),
        ("API_KEY_OR_SECRET", "tests/integration/test_install_hints_on_python310.py"),
        (
            "generic-api-key",
            "tests/snapshot/container/test_snapshot_container_exit_codes.py",
        ),
        ("generic-api-key", "tests/snapshot/container/test_snapshot_container_nix.py"),
        ("API_KEY_OR_SECRET", "tests/snapshot/mcp/test_snapshot_mcp_session_tools.py"),
        ("B103", "tests/unit/assets/test_install_pinned_tool.py"),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/base/test_a_failure_after_the_tool_ran_keeps_its_exit_code.py",
        ),
        (
            "generic-api-key",
            "tests/unit/base/test_a_failure_after_the_tool_ran_keeps_its_exit_code.py",
        ),
        (
            "generic-api-key",
            "tests/unit/base/test_uv_tool_mixin_guards_and_decisions.py",
        ),
        ("B324", "tests/unit/characterization/_detect_secrets_double.py"),
        ("B604", "tests/unit/characterization/_harness.py"),
        ("B102", "tests/unit/characterization/test_harness_confinement.py"),
        ("B310", "tests/unit/characterization/test_harness_confinement.py"),
        ("generic-api-key", "tests/unit/cli/inspect/test_each_value_is_shown_once.py"),
        ("API_KEY_OR_SECRET", "tests/unit/cli/mcp/conftest.py"),
        ("generic-api-key", "tests/unit/cli/mcp/conftest.py"),
        (
            "generic-api-key",
            "tests/unit/cli/mcp/test_a_scan_copys_name_is_computed_once_per_scan.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/cli/mcp/test_a_scan_runner_failure_shows_no_value_the_config_read.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/cli/mcp/test_a_stateful_session_the_sweep_removes_is_ended.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/cli/mcp/test_clone_limits_and_delivery_interlocks.py",
        ),
        ("API_KEY_OR_SECRET", "tests/unit/cli/mcp/test_delivered_config_env.py"),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/cli/mcp/test_ending_a_session_deletes_its_workspace_under_a_hidden_name.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/cli/mcp/test_scan_directory_start_failures.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/cli/mcp/test_sessions_a_session_starts_without_a_workspace_root.py",
        ),
        ("B307", "tests/unit/cli/mcp/test_shipped_mcp_guidance_matches_the_server.py"),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/cli/mcp/test_source_delivery_deletes_read_only_scratch.py",
        ),
        (
            "B103",
            "tests/unit/cli/mcp/test_source_delivery_deletes_read_only_scratch.py",
        ),
        (
            "B103",
            "tests/unit/cli/mcp/test_source_delivery_scratch_that_resists_deletion.py",
        ),
        (
            "generic-api-key",
            "tests/unit/cli/mcp/test_tool_errors_describe_a_wrapped_validation_error.py",
        ),
        (
            "generic-api-key",
            "tests/unit/cli/mcp/test_validation_errors_leave_out_the_input.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/cli/mcp/test_workspace_scan_holds_the_session_tree.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/cli/mcp/test_zip_finalize_handle_and_lock.py",
        ),
        ("B202", "tests/unit/cli/test_genai_guide_ships_with_install.py"),
        ("B104", "tests/unit/cli/test_mcp_loopback_accepts_only_its_own_origin.py"),
        ("B104", "tests/unit/cli/test_mcp_non_loopback_bind_is_refused.py"),
        ("B104", "tests/unit/cli/test_mcp_upstream_host_check.py"),
        ("generic-api-key", "tests/unit/cli/test_merge_shard_errors_hide_the_file.py"),
        (
            "generic-api-key",
            "tests/unit/cli/test_report_refuses_invalid_plugin_options.py",
        ),
        ("B102", "tests/unit/cli/test_scan_messages_tell_the_truth.py"),
        (
            "B103",
            "tests/unit/config/test_a_checkout_boundary_needs_a_git_shaped_marker.py",
        ),
        (
            "B506",
            "tests/unit/config/test_a_patched_value_is_recorded_where_later_operations_move_it.py",
        ),
        ("B103", "tests/unit/config/test_add_suppression.py"),
        (
            "B103",
            "tests/unit/config/test_an_undecided_walk_names_the_walk_in_the_warning.py",
        ),
        ("API_KEY_OR_SECRET", "tests/unit/config/test_config_alias_round_trip.py"),
        ("API_KEY_OR_SECRET", "tests/unit/config/test_config_link_bases.py"),
        ("API_KEY_OR_SECRET", "tests/unit/config/test_config_messages_hide_values.py"),
        ("generic-api-key", "tests/unit/config/test_config_messages_hide_values.py"),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/config/test_operator_configs_judged_by_every_name.py",
        ),
        ("generic-api-key", "tests/unit/config/test_results_errors_hide_the_file.py"),
        ("API_KEY_OR_SECRET", "tests/unit/config/test_sandbox_environment_setting.py"),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/core/test_orchestrator_project_name_holding_an_environment_value.py",
        ),
        (
            "generic-api-key",
            "tests/unit/core/test_orchestrator_project_name_holding_an_environment_value.py",
        ),
        ("B608", "tests/unit/deploy/test_agentcore_stateless_fallback_tripwire.py"),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/deploy/test_deploy_constructs_ash_ref_is_checked.py",
        ),
        ("generic-api-key", "tests/unit/docs/test_page_claims.py"),
        ("API_KEY_OR_SECRET", "tests/unit/interactions/test_run_ash_nix.py"),
        (
            "generic-api-key",
            "tests/unit/interactions/test_workspace_config_warning_is_shown.py",
        ),
        ("API_KEY_OR_SECRET", "tests/unit/models/test_flat_occurrence_identity.py"),
        ("generic-api-key", "tests/unit/models/test_report_id_unique_per_scan.py"),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/plugin_modules/ash_aws_plugins/test_security_hub_batch_import.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/plugin_modules/ash_builtin/converters/test_jupyter_converter_edge_inputs.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugin_modules/ash_builtin/scanners/test_npm_audit_probe_selection_and_report_shapes.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugin_modules/ash_builtin/scanners/test_npm_audit_response_logging.py",
        ),
        (
            "B103",
            "tests/unit/plugin_modules/ash_builtin/scanners/test_scanners_name_a_file_that_is_not_utf8.py",
        ),
        ("B604", "tests/unit/plugin_modules/ash_builtin/test_bandit_excludes.py"),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/plugin_modules/ash_builtin/test_bandit_scanner_behavior.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/plugin_modules/ash_builtin/test_detect_secrets_scanner_behavior.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/plugin_modules/ash_snyk_plugins/test_snyk_code_scanner_behavior.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugins/test_a_debug_traceback_hides_env_read_module_paths.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugins/test_a_failed_imports_log_line_redacts_env_values.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugins/test_an_environment_value_equal_to_a_derived_module_form_keeps_whole_value_redaction.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/plugins/test_the_registry_and_decorators_name_a_masked_module_by_its_mask.py",
        ),
        (
            "generic-api-key",
            "tests/unit/plugins/test_the_registry_and_decorators_name_a_masked_module_by_its_mask.py",
        ),
        ("B604", "tests/unit/test_conftest_helpers.py"),
        ("API_KEY_OR_SECRET", "tests/unit/test_docs_ci_runner_judgments.py"),
        ("generic-api-key", "tests/unit/test_docs_ci_runner_judgments.py"),
        ("API_KEY_OR_SECRET", "tests/unit/test_pinned_tool_github_lookup.py"),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/utils/sandbox/test_fs_guard_a_refused_pre_check_is_redacted_from_the_executor.py",
        ),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/utils/sandbox/test_scope_probe_cache_and_spawn_record.py",
        ),
        ("API_KEY_OR_SECRET", "tests/unit/utils/test_ash_install.py"),
        (
            "generic-api-key",
            "tests/unit/utils/test_ash_install_failures_are_logged_redacted.py",
        ),
        ("B301", "tests/unit/utils/test_env_resolved_scalar_survives_copying.py"),
        ("B301", "tests/unit/utils/test_link_refusal_family.py"),
        ("B103", "tests/unit/utils/test_scan_source.py"),
        ("API_KEY_OR_SECRET", "tests/unit/utils/test_secret_masking.py"),
        ("B301", "tests/unit/utils/test_shown_text_is_shown_once.py"),
        (
            "B604",
            "tests/unit/utils/test_the_server_scoped_run_resolves_its_program_like_every_other_spawn.py",
        ),
        ("B103", "tests/unit/utils/test_tool_config_dir.py"),
        (
            "API_KEY_OR_SECRET",
            "tests/unit/workspace/test_workspace_project_config_links.py",
        ),
        ("B604", "tests/utils/home_rule.py"),
        ("B604", "tests/utils/tool_guard.py"),
    ),
}

# (rule_id, path, landed_on).
PRE_GUARD_BASELINE: dict[str, tuple[tuple[str | None, str, str], ...]] = {
    ".ash/.ash.yaml": (
        (
            "CFN_NAG_W12",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "CFN_NAG_W58",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "CKV_AWS_111",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "CKV_AWS_116",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "E1150",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "F3031",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "HIPAA.Security-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "HIPAA.Security-LambdaDLQ",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "HIPAA.Security-LambdaInsideVPC",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "NIST.800.53.R4-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "NIST.800.53.R4-LambdaInsideVPC",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "NIST.800.53.R5-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "NIST.800.53.R5-LambdaDLQ",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "NIST.800.53.R5-LambdaInsideVPC",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "PCI.DSS.321-IAMNoInlinePolicy",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "PCI.DSS.321-LambdaInsideVPC",
            "deploy/cdk/templates/AshEksOperator.template.json",
            "v4-capabilities",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "deploy/kubernetes-operator/generated/config-schema-translation.json",
            "v4-capabilities",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "deploy/kubernetes-operator/generated/crd-ashmcpservers.yaml",
            "v4-capabilities",
        ),
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "deploy/kubernetes-operator/generated/crd-ashscans.yaml",
            "v4-capabilities",
        ),
        (
            "CKV_K8S_15",
            "deploy/kubernetes-operator/manifests/operator.yaml",
            "v4-capabilities",
        ),
        (
            "CKV_K8S_38",
            "deploy/kubernetes-operator/manifests/operator.yaml",
            "v4-capabilities",
        ),
        (
            "CKV_K8S_43",
            "deploy/kubernetes-operator/manifests/operator.yaml",
            "v4-capabilities",
        ),
        (
            "SECRET-*",
            "deploy/kubernetes-operator/tests/e2e/fixtures/dirty/leaked_settings.py",
            "v4-capabilities",
        ),
        (
            "B307",
            "deploy/kubernetes-operator/tests/e2e/fixtures/dirty/vulnerable.py",
            "v4-capabilities",
        ),
        (
            "B602",
            "deploy/kubernetes-operator/tests/e2e/fixtures/dirty/vulnerable.py",
            "v4-capabilities",
        ),
        (
            "SECRET-*",
            "editors/jetbrains/src/test/resources/fixtures/leak.py",
            "v4-capabilities",
        ),
        (
            "SECRET-*",
            "editors/vscode/test/fixtures/planted_secret.py",
            "v4-capabilities",
        ),
    ),
    ".ash/.ash_community_plugins.yaml": (
        (
            "KSV-0048",
            "deploy/kubernetes-operator/manifests/rbac.yaml",
            "v4-capabilities",
        ),
        (
            "KSV-0049",
            "deploy/kubernetes-operator/manifests/rbac.yaml",
            "v4-capabilities",
        ),
        (
            "KSV-0056",
            "deploy/kubernetes-operator/manifests/rbac.yaml",
            "v4-capabilities",
        ),
        (
            "B307",
            "deploy/kubernetes-operator/tests/e2e/fixtures/dirty/vulnerable.py",
            "v4-capabilities",
        ),
        (
            "B602",
            "deploy/kubernetes-operator/tests/e2e/fixtures/dirty/vulnerable.py",
            "v4-capabilities",
        ),
        ("DS-0002", "editors/jetbrains/ui-test/Dockerfile", "v4/train-f"),
        ("DS-0026", "editors/jetbrains/ui-test/Dockerfile", "v4/train-f"),
        ("DS-0026", "editors/vscode/test/visual/Dockerfile", "v4/train-f"),
    ),
}
