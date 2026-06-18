import boto3
import os
from datetime import datetime, timezone
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")
cloudwatch = boto3.client("cloudwatch")

TABLE_NAME = os.environ["TABLE_NAME"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

table = dynamodb.Table(TABLE_NAME)


def classify_severity(severity):
    try:
        severity_number = float(severity)
    except (TypeError, ValueError):
        return "UNKNOWN", False

    if severity_number >= 9.0:
        return "CRITICAL", True
    elif severity_number >= 7.0:
        return "HIGH", True
    elif severity_number >= 4.0:
        return "MEDIUM", False
    elif severity_number > 0:
        return "LOW", False
    else:
        return "UNKNOWN", False


def publish_metric(metric_name, value=1):
    cloudwatch.put_metric_data(
        Namespace="ThreatDetectionPlatform",
        MetricData=[
            {
                "MetricName": metric_name,
                "Value": value,
                "Unit": "Count"
            }
        ]
    )


def build_alert_message(finding):
    return f"""
AWS Security Finding Alert

Source:
{finding["Source"]}

Severity:
{finding["Severity"]} ({finding["SeverityLabel"]})

Title:
{finding["Title"]}

Type:
{finding["FindingType"]}

Description:
{finding["Description"]}

Resource:
{finding["ResourceId"]}

Account:
{finding["AccountId"]}

Region:
{finding["Region"]}

Event Time:
{finding["EventTime"]}

Finding ID:
{finding["FindingId"]}
"""


def normalize_guardduty_event(event):
    detail = event.get("detail", {})

    severity = detail.get("severity", 0)
    severity_label, alert_candidate = classify_severity(severity)

    resource = detail.get("resource", {})
    resource_type = resource.get("resourceType", "Unknown")

    resource_id = "Unknown"

    if "instanceDetails" in resource:
        resource_id = resource["instanceDetails"].get("instanceId", "Unknown")
    elif "accessKeyDetails" in resource:
        resource_id = resource["accessKeyDetails"].get("principalId", "Unknown")
    elif "s3BucketDetails" in resource:
        buckets = resource.get("s3BucketDetails", [])
        if buckets:
            resource_id = buckets[0].get("name", "Unknown")

    return {
        "FindingId": detail.get("id"),
        "Source": "GuardDuty",
        "FindingType": detail.get("type", "Unknown"),
        "Severity": str(severity),
        "SeverityLabel": severity_label,
        "AlertCandidate": alert_candidate,
        "Title": detail.get("title", "Unknown"),
        "Description": detail.get("description", "Unknown"),
        "ResourceType": resource_type,
        "ResourceId": resource_id,
        "AccountId": event.get("account", "Unknown"),
        "Region": event.get("region", "Unknown"),
        "EventTime": event.get("time", "Unknown"),
        "StoredAt": datetime.now(timezone.utc).isoformat()
    }


def normalize_securityhub_event(event):
    findings = event.get("detail", {}).get("findings", [])

    if not findings:
        return None

    finding = findings[0]

    severity_info = finding.get("Severity", {})
    normalized_severity = severity_info.get("Normalized", 0)

    severity_label, alert_candidate = classify_severity(
        normalized_severity / 10
    )

    resources = finding.get("Resources", [])
    resource_id = resources[0].get("Id", "Unknown") if resources else "Unknown"
    resource_type = resources[0].get("Type", "Unknown") if resources else "Unknown"

    return {
        "FindingId": finding.get("Id"),
        "Source": "SecurityHub",
        "FindingType": finding.get("Types", ["Unknown"])[0],
        "Severity": str(normalized_severity),
        "SeverityLabel": severity_label,
        "AlertCandidate": alert_candidate,
        "Title": finding.get("Title", "Unknown"),
        "Description": finding.get("Description", "Unknown"),
        "ResourceType": resource_type,
        "ResourceId": resource_id,
        "AccountId": finding.get("AwsAccountId", event.get("account", "Unknown")),
        "Region": finding.get("Region", event.get("region", "Unknown")),
        "EventTime": finding.get("UpdatedAt", event.get("time", "Unknown")),
        "StoredAt": datetime.now(timezone.utc).isoformat()
    }


def normalize_event(event):
    source = event.get("source")
    detail_type = event.get("detail-type")

    if source == "aws.guardduty" and detail_type == "GuardDuty Finding":
        return normalize_guardduty_event(event)

    if source == "aws.securityhub" and detail_type == "Security Hub Findings - Imported":
        return normalize_securityhub_event(event)

    print(f"Unsupported event source: {source}, detail-type: {detail_type}")
    return None


def lambda_handler(event, context):
    print("Received event")
    print(event)

    finding = normalize_event(event)

    if not finding:
        publish_metric("UnsupportedEvents")
        return {
            "statusCode": 400,
            "message": "Unsupported or invalid event"
        }

    if not finding.get("FindingId"):
        publish_metric("InvalidFindings")
        return {
            "statusCode": 400,
            "message": "Missing finding ID"
        }

    try:
        table.put_item(
            Item=finding,
            ConditionExpression="attribute_not_exists(FindingId)"
        )

        print(f"Stored new finding: {finding['FindingId']}")
        print(f"Source: {finding['Source']}")
        print(f"Severity: {finding['Severity']} ({finding['SeverityLabel']})")

        publish_metric("FindingsProcessed")
        publish_metric(f"{finding['Source']}Findings")

        if finding["SeverityLabel"] == "HIGH":
            publish_metric("HighSeverityFindings")

        if finding["SeverityLabel"] == "CRITICAL":
            publish_metric("CriticalSeverityFindings")

    except ClientError as error:
        if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
            print(f"Duplicate finding skipped: {finding['FindingId']}")
            publish_metric("DuplicateFindings")
            return {
                "statusCode": 200,
                "message": "Duplicate finding skipped"
            }

        print(f"Unexpected DynamoDB error: {error}")
        raise

    if finding["AlertCandidate"]:
        message = build_alert_message(finding)

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"{finding['Source']} Alert: {finding['SeverityLabel']}",
            Message=message
        )

        print(f"Alert sent for finding: {finding['FindingId']}")
        publish_metric("AlertsSent")
    else:
        print(f"No alert sent for finding: {finding['FindingId']}")

    return {
        "statusCode": 200,
        "message": "Finding processed"
    }