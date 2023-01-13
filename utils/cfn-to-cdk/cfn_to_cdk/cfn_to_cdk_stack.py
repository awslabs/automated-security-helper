import aws_cdk as cdk
from aws_cdk import cloudformation_include as cfn_inc
from constructs import Construct


class CfnToCdkStack(cdk.Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

    
        template0 = cfn_inc.CfnInclude(self, "/app/test.yaml",  
                template_file="/app/test.yaml")
    