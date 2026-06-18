#!/usr/bin/env python3

import aws_cdk as cdk

from threat_detection_platform.stacks.networking_stack import NetworkingStack
from threat_detection_platform.stacks.security_services_stack import SecurityServicesStack
from threat_detection_platform.stacks.monitoring_stack import MonitoringStack


app = cdk.App()

env = cdk.Environment(
    account="478561403051",
    region="us-east-1",
)

networking_stack = NetworkingStack(
    app,
    "ThreatDetectionNetworkingStack",
    env=env,
)

security_services_stack = SecurityServicesStack(
    app,
    "ThreatDetectionSecurityServicesStack",
    env=env,
)

monitoring_stack = MonitoringStack(
    app,
    "ThreatDetectionMonitoringStack",
    findings_processor=security_services_stack.findings_processor,
    env=env,
)

security_services_stack.add_dependency(networking_stack)
monitoring_stack.add_dependency(security_services_stack)

app.synth()