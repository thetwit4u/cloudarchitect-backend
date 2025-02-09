"""
AWS Boto3 client wrapper for managing AWS service connections.
"""
import boto3
from botocore.exceptions import ClientError
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class AWSAPI:
    def __init__(self, access_key_id: str, secret_access_key: str, region: str):
        """
        Initialize AWS API client with credentials
        """
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.region = region
        self._session: Optional[boto3.Session] = None
        self._clients: Dict[str, Any] = {}

    @property
    def session(self) -> boto3.Session:
        """
        Get or create a boto3 session
        """
        if not self._session:
            self._session = boto3.Session(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=self.region
            )
        return self._session

    def get_client(self, service_name: str) -> Any:
        """
        Get or create a boto3 client for the specified service
        """
        if service_name not in self._clients:
            self._clients[service_name] = self.session.client(service_name)
        return self._clients[service_name]

    def test_connection(self) -> bool:
        """
        Test AWS credentials by attempting to list EC2 regions
        """
        try:
            ec2_client = self.get_client('ec2')
            ec2_client.describe_regions()
            return True
        except ClientError as e:
            logger.error(f"Failed to connect to AWS: {str(e)}")
            return False

    def get_account_id(self) -> str:
        """
        Get the AWS account ID using STS
        """
        try:
            sts_client = self.get_client('sts')
            return sts_client.get_caller_identity()['Account']
        except ClientError as e:
            logger.error(f"Failed to get AWS account ID: {str(e)}")
            raise

    def discover_ec2_instances(self) -> list:
        """
        Discover EC2 instances in the current region
        """
        try:
            ec2_client = self.get_client('ec2')
            response = ec2_client.describe_instances()
            
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append({
                        'instance_id': instance['InstanceId'],
                        'instance_type': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'launch_time': instance['LaunchTime'].isoformat(),
                        'tags': instance.get('Tags', []),
                        'platform': instance.get('Platform', 'linux'),
                        'private_ip': instance.get('PrivateIpAddress'),
                        'public_ip': instance.get('PublicIpAddress'),
                        'vpc_id': instance.get('VpcId'),
                        'subnet_id': instance.get('SubnetId'),
                        'security_groups': instance.get('SecurityGroups', [])
                    })
            
            return instances
        except ClientError as e:
            logger.error(f"Failed to discover EC2 instances: {str(e)}")
            raise

    def discover_vpc_resources(self) -> dict:
        """
        Discover VPC resources including VPCs, subnets, route tables, internet gateways, and NACLs
        """
        try:
            ec2_client = self.get_client('ec2')
            vpc_resources = {
                'vpcs': [],
                'subnets': [],
                'route_tables': [],
                'internet_gateways': [],
                'network_acls': []
            }

            # Discover VPCs
            vpcs = ec2_client.describe_vpcs()
            for vpc in vpcs['Vpcs']:
                vpc_resources['vpcs'].append({
                    'vpc_id': vpc['VpcId'],
                    'cidr_block': vpc['CidrBlock'],
                    'state': vpc['State'],
                    'is_default': vpc['IsDefault'],
                    'tags': vpc.get('Tags', [])
                })

                # Discover Subnets for this VPC
                subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
                for subnet in subnets['Subnets']:
                    vpc_resources['subnets'].append({
                        'subnet_id': subnet['SubnetId'],
                        'vpc_id': subnet['VpcId'],
                        'cidr_block': subnet['CidrBlock'],
                        'availability_zone': subnet['AvailabilityZone'],
                        'state': subnet['State'],
                        'tags': subnet.get('Tags', [])
                    })

                # Discover Route Tables
                route_tables = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
                for rt in route_tables['RouteTables']:
                    vpc_resources['route_tables'].append({
                        'route_table_id': rt['RouteTableId'],
                        'vpc_id': rt['VpcId'],
                        'routes': rt['Routes'],
                        'associations': rt['Associations'],
                        'tags': rt.get('Tags', [])
                    })

                # Discover Internet Gateways
                igws = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc['VpcId']]}])
                for igw in igws['InternetGateways']:
                    vpc_resources['internet_gateways'].append({
                        'internet_gateway_id': igw['InternetGatewayId'],
                        'attachments': igw['Attachments'],
                        'tags': igw.get('Tags', [])
                    })

                # Discover Network ACLs
                nacls = ec2_client.describe_network_acls(Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}])
                for nacl in nacls['NetworkAcls']:
                    vpc_resources['network_acls'].append({
                        'network_acl_id': nacl['NetworkAclId'],
                        'vpc_id': nacl['VpcId'],
                        'is_default': nacl['IsDefault'],
                        'entries': nacl['Entries'],
                        'associations': nacl['Associations'],
                        'tags': nacl.get('Tags', [])
                    })

            return vpc_resources
        except Exception as e:
            logger.error(f"Error discovering VPC resources: {str(e)}")
            raise

    def discover_load_balancers(self) -> dict:
        """
        Discover Load Balancers (ALB, NLB, CLB) and their associated resources
        """
        try:
            elb_client = self.get_client('elbv2')  # For ALB and NLB
            elb_classic_client = self.get_client('elb')  # For Classic Load Balancers
            
            lb_resources = {
                'load_balancers': [],
                'target_groups': [],
                'listeners': [],
                'classic_load_balancers': []
            }

            # Discover Application and Network Load Balancers
            lbs = elb_client.describe_load_balancers()
            for lb in lbs['LoadBalancers']:
                lb_info = {
                    'load_balancer_arn': lb['LoadBalancerArn'],
                    'load_balancer_name': lb['LoadBalancerName'],
                    'type': lb['Type'],
                    'scheme': lb['Scheme'],
                    'vpc_id': lb.get('VpcId'),
                    'availability_zones': lb['AvailabilityZones'],
                    'state': lb['State'],
                    'dns_name': lb['DNSName'],
                    'created_time': lb['CreatedTime'].isoformat()
                }

                # Get tags for the load balancer
                tags = elb_client.describe_tags(ResourceArns=[lb['LoadBalancerArn']])
                lb_info['tags'] = tags['TagDescriptions'][0]['Tags']

                # Get listeners for this load balancer
                listeners = elb_client.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
                for listener in listeners['Listeners']:
                    lb_resources['listeners'].append({
                        'listener_arn': listener['ListenerArn'],
                        'load_balancer_arn': listener['LoadBalancerArn'],
                        'port': listener['Port'],
                        'protocol': listener['Protocol'],
                        'default_actions': listener['DefaultActions']
                    })

                lb_resources['load_balancers'].append(lb_info)

            # Discover Target Groups
            target_groups = elb_client.describe_target_groups()
            for tg in target_groups['TargetGroups']:
                tg_info = {
                    'target_group_arn': tg['TargetGroupArn'],
                    'target_group_name': tg['TargetGroupName'],
                    'protocol': tg['Protocol'],
                    'port': tg['Port'],
                    'vpc_id': tg.get('VpcId'),
                    'target_type': tg['TargetType'],
                    'health_check': tg['HealthCheckProtocol']
                }

                # Get targets for this target group
                targets = elb_client.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                tg_info['targets'] = targets['TargetHealthDescriptions']

                lb_resources['target_groups'].append(tg_info)

            # Discover Classic Load Balancers
            classic_lbs = elb_classic_client.describe_load_balancers()
            for clb in classic_lbs['LoadBalancerDescriptions']:
                clb_info = {
                    'load_balancer_name': clb['LoadBalancerName'],
                    'dns_name': clb['DNSName'],
                    'scheme': clb['Scheme'],
                    'vpc_id': clb.get('VPCId'),
                    'availability_zones': clb['AvailabilityZones'],
                    'subnets': clb.get('Subnets', []),
                    'security_groups': clb.get('SecurityGroups', []),
                    'instances': clb['Instances'],
                    'listener_descriptions': clb['ListenerDescriptions']
                }

                # Get tags for classic load balancer
                tags = elb_classic_client.describe_tags(LoadBalancerNames=[clb['LoadBalancerName']])
                clb_info['tags'] = tags['TagDescriptions'][0]['Tags']

                lb_resources['classic_load_balancers'].append(clb_info)

            return lb_resources
        except Exception as e:
            logger.error(f"Error discovering Load Balancer resources: {str(e)}")
            raise
