from aws_cdk import Stack
from constructs import Construct


class NetworkingStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        # VPC, subnets, endpoints, and flow logs will be added here.