from aws_cdk import Stack
from constructs import Construct


class SecurityServicesStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        # Lambda, DynamoDB, SNS, IAM, and EventBridge will be added here.