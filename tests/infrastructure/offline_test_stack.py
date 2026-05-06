"""CDK stack that provisions an air-gapped VPC for testing ASH offline mode.

The stack creates:
- A VPC with isolated subnets only (no NAT, no IGW)
- An EC2 instance in the isolated subnet for manual testing
- A CodeBuild project that runs ASH scans inside the isolated VPC
- An S3 VPC endpoint so the CodeBuild project can fetch artifacts

Nothing in this stack has a path to the public internet.
"""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import (
    aws_codebuild as codebuild,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_s3 as s3,
)
from constructs import Construct


class OfflineTestStack(cdk.Stack):
    """Isolated VPC environment for validating ASH air-gapped operation."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        vpc_cidr: str = "10.0.0.0/16",
        instance_type: str = "t3.medium",
        ash_version: str = "latest",
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # VPC CIDR must be a concrete string at synth time (CDK parses it
        # to compute subnet CIDRs).  Instance type and ASH version are
        # exposed as CfnParameters so they can be overridden at deploy time
        # without re-synthesizing.
        instance_type_param = cdk.CfnParameter(
            self,
            "InstanceType",
            type="String",
            default=instance_type,
            description="EC2 instance type for the offline test host.",
        )
        ash_version_param = cdk.CfnParameter(
            self,
            "AshVersion",
            type="String",
            default=ash_version,
            description="ASH version tag to install on the test host.",
        )

        # ------------------------------------------------------------------
        # VPC -- isolated subnets only, no NAT / IGW
        # ------------------------------------------------------------------
        vpc = ec2.Vpc(
            self,
            "OfflineVpc",
            ip_addresses=ec2.IpAddresses.cidr(vpc_cidr),
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                ),
            ],
        )

        # S3 gateway endpoint -- lets CodeBuild pull artifacts without internet
        vpc.add_gateway_endpoint(
            "S3Endpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3,
        )

        # ------------------------------------------------------------------
        # Security group -- no ingress / egress to the internet
        # ------------------------------------------------------------------
        sg = ec2.SecurityGroup(
            self,
            "OfflineSg",
            vpc=vpc,
            description="Security group for offline ASH testing (no internet)",
            allow_all_outbound=False,
        )
        # Allow traffic within the VPC only
        sg.add_ingress_rule(
            peer=ec2.Peer.ipv4(vpc_cidr),
            connection=ec2.Port.all_traffic(),
            description="Allow intra-VPC traffic",
        )
        sg.add_egress_rule(
            peer=ec2.Peer.ipv4(vpc_cidr),
            connection=ec2.Port.all_traffic(),
            description="Allow outbound within VPC only",
        )

        # SSM endpoints -- required for Session Manager in isolated VPC
        for svc in ["ssm", "ssmmessages", "ec2messages"]:
            vpc.add_interface_endpoint(
                f"{svc}-endpoint",
                service=ec2.InterfaceVpcEndpointAwsService(svc),
                security_groups=[sg],
                subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
            )

        # CloudWatch Logs endpoint -- required for CodeBuild log streaming
        vpc.add_interface_endpoint(
            "logs-endpoint",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            security_groups=[sg],
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
        )

        # ECR endpoints -- required for container image pulls in isolated VPC
        vpc.add_interface_endpoint(
            "ecr-api-endpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR,
            security_groups=[sg],
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
        )
        vpc.add_interface_endpoint(
            "ecr-dkr-endpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
            security_groups=[sg],
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
        )

        # ------------------------------------------------------------------
        # IAM role for the EC2 instance
        # ------------------------------------------------------------------
        instance_role = iam.Role(
            self,
            "OfflineInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonSSMManagedInstanceCore",
                ),
            ],
        )

        # ------------------------------------------------------------------
        # EC2 instance in the isolated subnet
        # ------------------------------------------------------------------
        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            "#!/bin/bash",
            "set -euo pipefail",
            f"echo 'ASH_VERSION={ash_version_param.value_as_string}' >> /etc/environment",
            "# Pre-installed dependencies would come from the AMI or an S3 bundle.",
            "# This user-data script runs at first boot in the isolated subnet",
            "# so it cannot reach the internet. Any packages must already be present.",
        )

        ec2.Instance(
            self,
            "OfflineTestHost",
            vpc=vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
            ),
            instance_type=ec2.InstanceType(instance_type_param.value_as_string),
            machine_image=ec2.AmazonLinuxImage(
                generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2023,
            ),
            security_group=sg,
            role=instance_role,
            user_data=user_data,
        )

        # ------------------------------------------------------------------
        # S3 bucket for ASH bundle / scan artifacts
        # ------------------------------------------------------------------
        artifact_bucket = s3.Bucket(
            self,
            "AshArtifacts",
            removal_policy=cdk.RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        )

        # ------------------------------------------------------------------
        # CodeBuild project -- runs ASH scans inside the isolated VPC
        # ------------------------------------------------------------------
        build_project = codebuild.Project(
            self,
            "OfflineAshBuild",
            vpc=vpc,
            subnet_selection=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
            ),
            security_groups=[sg],
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                compute_type=codebuild.ComputeType.MEDIUM,
                privileged=True,  # needed for Docker-in-Docker if ASH uses containers
                environment_variables={
                    "ASH_VERSION": codebuild.BuildEnvironmentVariable(
                        value=ash_version_param.value_as_string,
                    ),
                },
            ),
            build_spec=codebuild.BuildSpec.from_object(
                {
                    "version": "0.2",
                    "phases": {
                        "install": {
                            "commands": [
                                "echo 'Running in air-gapped VPC -- no internet access'",
                                "echo 'ASH and dependencies must be pre-bundled in the build image or S3'",
                            ],
                        },
                        "build": {
                            "commands": [
                                "echo 'Running ASH offline scan...'",
                                "ash --version || echo 'ASH not found in image -- upload bundle to S3 first'",
                            ],
                        },
                    },
                    "artifacts": {
                        "files": ["**/*"],
                        "base-directory": ".",
                    },
                },
            ),
            artifacts=codebuild.Artifacts.s3(
                bucket=artifact_bucket,
                include_build_id=True,
                package_zip=True,
            ),
            description="Runs ASH scans in an isolated VPC to validate offline mode",
        )

        # Grant CodeBuild read/write on the artifact bucket
        artifact_bucket.grant_read_write(build_project)

        # ------------------------------------------------------------------
        # Outputs
        # ------------------------------------------------------------------
        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "ArtifactBucketName", value=artifact_bucket.bucket_name)
        cdk.CfnOutput(self, "CodeBuildProject", value=build_project.project_name)
