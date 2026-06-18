# AWS Threat Detection Platform — CDK Migration

This project started as a simple GuardDuty alerting system built manually in the AWS console.

Initially, the architecture was:

GuardDuty → EventBridge → Lambda → SNS

As the project evolved, I expanded it into a small cloud security monitoring platform.

Additional components included:

* DynamoDB
* CloudWatch metrics and alarms
* Security Hub
* VPC Flow Logs
* CloudTrail
* Private EC2 instance
* Systems Manager Session Manager
* VPC Endpoints

Everything was first validated through the console before being migrated to AWS CDK.

## How I migrated

I didn't rebuild everything at once.

I converted the infrastructure gradually:

Networking → EC2 → DynamoDB → SNS → Lambda → EventBridge → Monitoring

Main goal:

Don't break a working system.

## If I scale this

I'd add:

* automatic remediation
* tighter IAM permissions
* multi-account support
* Security Hub aggregation
* Infrastructure tests
* CI/CD pipeline

## Running this project

```bash
python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt

cdk bootstrap
cdk deploy --all
```

Notes:

* Requires AWS credentials configured.
* GuardDuty and Security Hub should be enabled.
* Tested in us-east-1.

## Final thought

Building the platform wasn't the difficult part.

The real learning came from understanding networking, event flows, permissions, and how security systems behave when things don't go as expected.
