from aws_cdk import (
    Stack,
    Duration,
)

from aws_cdk import aws_cloudwatch as cloudwatch
from aws_cdk import aws_lambda as lambda_
from constructs import Construct


class MonitoringStack(Stack):

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        findings_processor: lambda_.IFunction,
        **kwargs
    ):
        super().__init__(scope, construct_id, **kwargs)

        dashboard = cloudwatch.Dashboard(
            self,
            "ThreatDetectionPlatformDashboard",
            dashboard_name="ThreatDetectionPlatformDashboard",
        )

        lambda_errors_alarm = cloudwatch.Alarm(
            self,
            "ThreatDetectionLambdaErrorsAlarm",
            alarm_name="ThreatDetection-LambdaErrors",
            metric=findings_processor.metric_errors(
                period=Duration.minutes(5)
            ),
            threshold=1,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        )

        high_severity_metric = cloudwatch.Metric(
            namespace="ThreatDetectionPlatform",
            metric_name="HighSeverityFindings",
            statistic="Sum",
            period=Duration.minutes(5),
        )

        critical_severity_metric = cloudwatch.Metric(
            namespace="ThreatDetectionPlatform",
            metric_name="CriticalSeverityFindings",
            statistic="Sum",
            period=Duration.minutes(5),
        )

        duplicate_findings_metric = cloudwatch.Metric(
            namespace="ThreatDetectionPlatform",
            metric_name="DuplicateFindings",
            statistic="Sum",
            period=Duration.minutes(5),
        )

        high_severity_alarm = cloudwatch.Alarm(
            self,
            "ThreatDetectionHighSeverityAlarm",
            alarm_name="ThreatDetection-HighSeverityFindings",
            metric=high_severity_metric,
            threshold=1,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        )

        critical_severity_alarm = cloudwatch.Alarm(
            self,
            "ThreatDetectionCriticalSeverityAlarm",
            alarm_name="ThreatDetection-CriticalSeverityFindings",
            metric=critical_severity_metric,
            threshold=1,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        )

        duplicate_spike_alarm = cloudwatch.Alarm(
            self,
            "ThreatDetectionDuplicateSpikeAlarm",
            alarm_name="ThreatDetection-DuplicateSpike",
            metric=duplicate_findings_metric,
            threshold=10,
            evaluation_periods=1,
            datapoints_to_alarm=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        )

        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Lambda Invocations",
                left=[
                    findings_processor.metric_invocations(
                        period=Duration.minutes(5)
                    )
                ],
            ),
            cloudwatch.GraphWidget(
                title="Lambda Errors",
                left=[
                    findings_processor.metric_errors(
                        period=Duration.minutes(5)
                    )
                ],
            ),
        )

        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="High Severity Findings",
                left=[high_severity_metric],
            ),
            cloudwatch.GraphWidget(
                title="Critical Severity Findings",
                left=[critical_severity_metric],
            ),
        )

        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Duplicate Findings",
                left=[duplicate_findings_metric],
            )
        )

        dashboard.add_widgets(
            cloudwatch.AlarmWidget(
                title="Lambda Errors Alarm",
                alarm=lambda_errors_alarm,
            ),
            cloudwatch.AlarmWidget(
                title="High Severity Alarm",
                alarm=high_severity_alarm,
            ),
            cloudwatch.AlarmWidget(
                title="Critical Severity Alarm",
                alarm=critical_severity_alarm,
            ),
            cloudwatch.AlarmWidget(
                title="Duplicate Spike Alarm",
                alarm=duplicate_spike_alarm,
            ),
        )