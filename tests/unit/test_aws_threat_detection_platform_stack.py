import aws_cdk as core
import aws_cdk.assertions as assertions

from aws_threat_detection_platform.aws_threat_detection_platform_stack import AwsThreatDetectionPlatformStack

# example tests. To run these tests, uncomment this file along with the example
# resource in aws_threat_detection_platform/aws_threat_detection_platform_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = AwsThreatDetectionPlatformStack(app, "aws-threat-detection-platform")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
