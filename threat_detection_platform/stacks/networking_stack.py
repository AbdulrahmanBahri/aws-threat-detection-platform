from aws_cdk import (
    Stack,
    CfnOutput,
    RemovalPolicy,
)
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_logs as logs
from constructs import Construct


class NetworkingStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        self.vpc = ec2.Vpc(
            self,
            "ThreatDetectionVPC",
            vpc_name="ThreatDetectionVPC",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
            max_azs=1,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="PublicSubnet",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="PrivateIsolatedSubnet",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask=24,
                ),
            ],
        )

        self.private_ec2_security_group = ec2.SecurityGroup(
            self,
            "PrivateEC2SecurityGroup",
            vpc=self.vpc,
            security_group_name="PrivateEC2SecurityGroup",
            description="Security group for private EC2 workload",
            allow_all_outbound=True,
        )

        self.endpoint_security_group = ec2.SecurityGroup(
            self,
            "VPCEndpointSecurityGroup",
            vpc=self.vpc,
            security_group_name="VPCEndpointSecurityGroup",
            description="Allows HTTPS traffic from VPC resources to interface endpoints",
            allow_all_outbound=True,
        )

        self.endpoint_security_group.add_ingress_rule(
            peer=ec2.Peer.ipv4("10.0.0.0/16"),
            connection=ec2.Port.tcp(443),
            description="Allow HTTPS from inside the VPC",
        )

        self.vpc.add_interface_endpoint(
            "SSMEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.SSM,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
            ),
            security_groups=[self.endpoint_security_group],
            private_dns_enabled=True,
        )

        self.vpc.add_interface_endpoint(
            "SSMMessagesEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
            ),
            security_groups=[self.endpoint_security_group],
            private_dns_enabled=True,
        )

        self.vpc.add_interface_endpoint(
            "EC2MessagesEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
            subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
            ),
            security_groups=[self.endpoint_security_group],
            private_dns_enabled=True,
        )

        flow_logs_group = logs.LogGroup(
            self,
            "ThreatDetectionFlowLogsGroup",
            log_group_name="ThreatDetectionFlowLogs",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.vpc.add_flow_log(
            "ThreatDetectionVPCFlowLogs",
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                flow_logs_group
            ),
            traffic_type=ec2.FlowLogTrafficType.ALL,
        )

        ec2_role = iam.Role(
            self,
            "ThreatDetectionEC2Role",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
        )

        ec2_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name(
                "AmazonSSMManagedInstanceCore"
            )
        )

        instance = ec2.Instance(
            self,
            "ThreatDetectionPrivateEC2",
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
            ),
            security_group=self.private_ec2_security_group,
            role=ec2_role,
            instance_type=ec2.InstanceType("t3.micro"),
            machine_image=ec2.MachineImage.latest_amazon_linux2023(),
        )

        CfnOutput(
            self,
            "VpcId",
            value=self.vpc.vpc_id,
        )

        CfnOutput(
            self,
            "PrivateEC2SecurityGroupId",
            value=self.private_ec2_security_group.security_group_id,
        )

        CfnOutput(
            self,
            "InstanceId",
            value=instance.instance_id,
        )

        CfnOutput(
            self,
            "PrivateIp",
            value=instance.instance_private_ip,
        )