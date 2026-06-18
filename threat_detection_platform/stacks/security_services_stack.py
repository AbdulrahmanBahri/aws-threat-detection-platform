from aws_cdk import (
    Stack,
    CfnOutput,
    RemovalPolicy,
    Duration,
)

from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_sns as sns
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_iam as iam
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets

from constructs import Construct


class SecurityServicesStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        self.findings_table = dynamodb.Table(
            self,
            "GuardDutyFindingsTable",
            table_name="GuardDutyFindings",
            partition_key=dynamodb.Attribute(
                name="FindingId",
                type=dynamodb.AttributeType.STRING,
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.alerts_topic = sns.Topic(
            self,
            "GuardDutyAlertsTopic",
            topic_name="GuardDutyAlerts",
        )

        self.findings_processor = lambda_.Function(
            self,
            "GuardDutyFindingProcessor",
            function_name="GuardDutyFindingProcessor",
            runtime=lambda_.Runtime.PYTHON_3_13,
            handler="lambda_function.lambda_handler",
            code=lambda_.Code.from_asset(
                "threat_detection_platform/lambda_src/findings_processor"
            ),
            timeout=Duration.seconds(30),
            memory_size=128,
            environment={
                "TABLE_NAME": self.findings_table.table_name,
                "SNS_TOPIC_ARN": self.alerts_topic.topic_arn,
            },
        )

        self.findings_table.grant_write_data(self.findings_processor)
        self.alerts_topic.grant_publish(self.findings_processor)

        self.findings_processor.add_to_role_policy(
            iam.PolicyStatement(
                actions=["cloudwatch:PutMetricData"],
                resources=["*"],
            )
        )

        guardduty_rule = events.Rule(
            self,
            "GuardDutyFindingsRule",
            rule_name="GuardDutyFindingsRule",
            description="Routes GuardDuty findings to the finding processor Lambda",
            event_pattern=events.EventPattern(
                source=["aws.guardduty"],
                detail_type=["GuardDuty Finding"],
            ),
        )

        guardduty_rule.add_target(
            targets.LambdaFunction(self.findings_processor)
        )

        securityhub_rule = events.Rule(
            self,
            "SecurityHubFindingsRule",
            rule_name="SecurityHubFindingsRule",
            description="Routes Security Hub findings to the finding processor Lambda",
            event_pattern=events.EventPattern(
                source=["aws.securityhub"],
                detail_type=["Security Hub Findings - Imported"],
            ),
        )

        securityhub_rule.add_target(
            targets.LambdaFunction(self.findings_processor)
        )

        CfnOutput(
            self,
            "FindingsTableName",
            value=self.findings_table.table_name,
        )

        CfnOutput(
            self,
            "AlertsTopicArn",
            value=self.alerts_topic.topic_arn,
        )

        CfnOutput(
            self,
            "FindingsProcessorName",
            value=self.findings_processor.function_name,
        )

        CfnOutput(
            self,
            "GuardDutyRuleName",
            value=guardduty_rule.rule_name,
        )

        CfnOutput(
            self,
            "SecurityHubRuleName",
            value=securityhub_rule.rule_name,
        )