from aws_cdk import Stack
from constructs import Construct


class MonitoringStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        # CloudWatch dashboard, metrics, alarms, and log groups will be added here.