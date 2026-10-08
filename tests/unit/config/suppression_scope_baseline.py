"""Frozen whole-file and glob suppression entries, read by test_suppression_scope_guard.py.

Generated once, when the guard was added, from the configs at that commit. Do not
add to these lists: a new entry that cannot carry a line range belongs in
``ALLOWLIST`` in the guard, with a reason. Removing an entry from a config means
removing it here too; the guard fails on a stale key, so these lists only shrink.

MAIN_BASELINE holds the entries inherited from ``main``, and only ones that are still
unpinned entries in ``origin/main``'s configs (the guard's subset test). A merge of main
can therefore only shrink it or swap in a key main itself added, within the cap: the
merge of a513530b dropped the directory globs #724 removed (17 keys) and took
#717's B108 entry for tests/snapshot/test_snapshot_normalizer.py. PRE_GUARD_BASELINE holds the
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
        ("DS-0002", "deploy/terraform/modules/codecommit-gate/files/gate.Dockerfile"),
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
