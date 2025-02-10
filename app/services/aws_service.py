import boto3
from botocore.exceptions import ClientError
from ..schemas.aws import AWSCredentialsBase, ResourceSummary
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid
from uuid import UUID, uuid4
import logging
from sqlalchemy.orm import Session
from ..models import AWSCredentials, Project

# Configure logging
logger = logging.getLogger(__name__)

class AWSService:
    def __init__(self, db: Session, project_id: str, user_id: str):
        """Initialize AWS service with project ID and user ID"""
        self.db = db
        self.project_id = project_id
        self.user_id = user_id
        self.credentials = self.get_credentials(project_id, user_id, db)
        if self.credentials:
            self.session = boto3.Session(
                aws_access_key_id=self.credentials.aws_access_key_id,
                aws_secret_access_key=self.credentials.aws_secret_access_key,
                region_name=self.credentials.region
            )
            logger.info(f"Initialized AWS service for region {self.credentials.region}")
        else:
            logger.error("Failed to initialize AWS service due to missing credentials")
            raise ValueError("Failed to initialize AWS service due to missing credentials")

    def validate_credentials(self) -> bool:
        """Validate AWS credentials by attempting to list S3 buckets"""
        try:
            s3 = self.session.client('s3')
            s3.list_buckets()
            return True
        except ClientError as e:
            logger.error(f"Failed to validate AWS credentials: {str(e)}", exc_info=True)
            return False

    def get_account_id(self) -> str:
        """Get AWS account ID using STS"""
        try:
            sts = self.session.client('sts')
            account_id = sts.get_caller_identity()['Account']
            logger.info(f"Retrieved AWS account ID: {account_id}")
            return account_id
        except ClientError as e:
            error_message = f"Failed to get AWS account ID: {str(e)}"
            logger.error(error_message, exc_info=True)
            raise ValueError(error_message)

    def list_resources(self) -> List[ResourceSummary]:
        """List all AWS resources for the project"""
        resources: List[ResourceSummary] = []
        
        # Get S3 buckets with extended information
        s3 = self.session.client('s3')
        try:
            buckets = s3.list_buckets()
            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']
                # Get bucket location
                try:
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    region = location['LocationConstraint'] or 'us-east-1'
                except ClientError:
                    region = 'unknown'
                    logger.warning(f"Could not get location for bucket {bucket_name}")

                details = {
                    'region': region,
                    'creation_date': bucket['CreationDate'].isoformat(),
                    'storage_classes': {},
                    'public_access': {},
                    'lifecycle_rules': [],
                }

                # Get public access block configuration
                try:
                    public_access = s3.get_public_access_block(Bucket=bucket_name)
                    details['public_access'] = public_access['PublicAccessBlockConfiguration']
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                        logger.warning(f"Error getting public access block for {bucket_name}: {str(e)}")

                # Get bucket policy
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    details['has_bucket_policy'] = True
                    details['is_public'] = 'Principal": "*"' in policy['Policy']
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                        logger.warning(f"Error getting bucket policy for {bucket_name}: {str(e)}")
                    details['has_bucket_policy'] = False
                    details['is_public'] = False

                # Get lifecycle rules
                try:
                    lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                    details['lifecycle_rules'] = lifecycle.get('Rules', [])
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchLifecycleConfiguration':
                        logger.warning(f"Error getting lifecycle rules for {bucket_name}: {str(e)}")

                # Get storage class analytics
                try:
                    analytics = s3.list_bucket_analytics_configurations(Bucket=bucket_name)
                    for config in analytics.get('AnalyticsConfigurationList', []):
                        if 'StorageClassAnalysis' in config:
                            details['storage_classes'][config['Id']] = config['StorageClassAnalysis']
                except ClientError as e:
                    logger.warning(f"Error getting analytics for {bucket_name}: {str(e)}")

                resources.append(ResourceSummary(
                    id=uuid4(),
                    resource_id=bucket_name,
                    type='s3',
                    name=bucket_name,
                    region=region,
                    status='available',
                    created_at=bucket['CreationDate'].replace(tzinfo=timezone.utc),
                    details=details
                ))
        except ClientError as e:
            logger.error(f"Error listing S3 buckets: {str(e)}")

        # Get EC2 instances
        ec2 = self.session.client('ec2')
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                # Get instance name from tags
                name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance['InstanceId'])
                
                # Get IAM instance profile if it exists
                instance_profile = None
                if 'IamInstanceProfile' in instance:
                    instance_profile = instance['IamInstanceProfile'].get('Arn')

                # Get network interfaces
                network_interfaces = []
                for eni in instance.get('NetworkInterfaces', []):
                    network_interfaces.append({
                        'id': eni['NetworkInterfaceId'],
                        'subnet_id': eni.get('SubnetId'),
                        'vpc_id': eni.get('VpcId'),
                        'private_ip': eni.get('PrivateIpAddress'),
                        'private_dns': eni.get('PrivateDnsName'),
                        'public_ip': eni.get('Association', {}).get('PublicIp'),
                        'public_dns': eni.get('Association', {}).get('PublicDnsName'),
                        'security_groups': [sg['GroupId'] for sg in eni.get('Groups', [])]
                    })

                # Get all tags
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}

                resources.append(ResourceSummary(
                    id=uuid4(),
                    resource_id=instance['InstanceId'],
                    type='ec2',
                    name=name,
                    region=self.credentials.region,
                    status=instance['State']['Name'],
                    created_at=instance['LaunchTime'].replace(tzinfo=timezone.utc),
                    details={
                        'status': instance['State']['Name'],
                        'instance_type': instance['InstanceType'],
                        'ami_id': instance['ImageId'],
                        'platform': instance.get('Platform'),
                        'architecture': instance.get('Architecture'),
                        'vpc_id': instance.get('VpcId'),
                        'subnet_id': instance.get('SubnetId'),
                        'availability_zone': instance.get('Placement', {}).get('AvailabilityZone'),
                        'private_ip': instance.get('PrivateIpAddress'),
                        'public_ip': instance.get('PublicIpAddress'),
                        'private_dns': instance.get('PrivateDnsName'),
                        'public_dns': instance.get('PublicDnsName'),
                        'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                        'iam_instance_profile': instance_profile,
                        'network_interfaces': network_interfaces,
                        'tags': tags,
                        'ebs_optimized': instance.get('EbsOptimized', False),
                        'metadata_options': instance.get('MetadataOptions', {}),
                        'monitoring': instance.get('Monitoring', {}).get('State')
                    }
                ))

        # Get VPCs
        ec2 = self.session.client('ec2')
        try:
            # Get VPCs with their basic information
            vpcs = ec2.describe_vpcs()
            for vpc in vpcs['Vpcs']:
                vpc_id = vpc['VpcId']
                name = next((tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'), vpc_id)

                # Get subnets for this VPC
                subnets = []
                try:
                    vpc_subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                    for subnet in vpc_subnets['Subnets']:
                        subnet_details = {
                            'id': subnet['SubnetId'],
                            'cidr_block': subnet['CidrBlock'],
                            'availability_zone': subnet['AvailabilityZone'],
                            'state': subnet['State'],
                            'available_ip_count': subnet['AvailableIpAddressCount'],
                            'default_for_az': subnet.get('DefaultForAz', False),
                            'map_public_ip': subnet.get('MapPublicIpOnLaunch', False)
                        }
                        # Get route table associations
                        try:
                            route_tables = ec2.describe_route_tables(
                                Filters=[{'Name': 'association.subnet-id', 'Values': [subnet['SubnetId']]}]
                            )
                            if route_tables['RouteTables']:
                                routes = []
                                for rt in route_tables['RouteTables']:
                                    for route in rt['Routes']:
                                        route_info = {
                                            'destination': route.get('DestinationCidrBlock', 'unknown'),
                                            'target': None
                                        }
                                        # Determine route target
                                        if 'GatewayId' in route:
                                            route_info['target'] = {'type': 'gateway', 'id': route['GatewayId']}
                                        elif 'NatGatewayId' in route:
                                            route_info['target'] = {'type': 'nat', 'id': route['NatGatewayId']}
                                        elif 'VpcPeeringConnectionId' in route:
                                            route_info['target'] = {'type': 'peering', 'id': route['VpcPeeringConnectionId']}
                                        routes.append(route_info)
                                subnet_details['routes'] = routes
                        except ClientError as e:
                            logger.warning(f"Error getting route tables for subnet {subnet['SubnetId']}: {str(e)}")
                        subnets.append(subnet_details)
                except ClientError as e:
                    logger.warning(f"Error getting subnets for VPC {vpc_id}: {str(e)}")

                # Get Internet Gateways
                internet_gateways = []
                try:
                    igws = ec2.describe_internet_gateways(
                        Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
                    )
                    for igw in igws['InternetGateways']:
                        internet_gateways.append({
                            'id': igw['InternetGatewayId'],
                            'state': next((attachment['State'] for attachment in igw['Attachments'] 
                                         if attachment['VpcId'] == vpc_id), 'unknown')
                        })
                except ClientError as e:
                    logger.warning(f"Error getting internet gateways for VPC {vpc_id}: {str(e)}")

                # Get NAT Gateways
                nat_gateways = []
                try:
                    nats = ec2.describe_nat_gateways(
                        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                    )
                    for nat in nats['NatGateways']:
                        nat_gateways.append({
                            'id': nat['NatGatewayId'],
                            'subnet_id': nat['SubnetId'],
                            'state': nat['State'],
                            'public_ip': nat.get('PublicIp'),
                            'private_ip': nat.get('PrivateIp'),
                            'elastic_ip_id': next((addr['AllocationId'] for addr in nat.get('NatGatewayAddresses', [])), None)
                        })
                except ClientError as e:
                    logger.warning(f"Error getting NAT gateways for VPC {vpc_id}: {str(e)}")

                # Get Network Interfaces
                network_interfaces = []
                try:
                    enis = ec2.describe_network_interfaces(
                        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                    )
                    for eni in enis['NetworkInterfaces']:
                        network_interfaces.append({
                            'id': eni['NetworkInterfaceId'],
                            'subnet_id': eni.get('SubnetId'),
                            'private_ip': eni.get('PrivateIpAddress'),
                            'public_ip': eni.get('Association', {}).get('PublicIp'),
                            'status': eni['Status'],
                            'security_groups': [sg['GroupId'] for sg in eni.get('Groups', [])],
                            'attachment': {
                                'instance_id': eni.get('Attachment', {}).get('InstanceId'),
                                'status': eni.get('Attachment', {}).get('Status')
                            } if eni.get('Attachment') else None
                        })
                except ClientError as e:
                    logger.warning(f"Error getting network interfaces for VPC {vpc_id}: {str(e)}")

                resources.append(ResourceSummary(
                    id=uuid4(),
                    resource_id=vpc_id,
                    type='vpc',
                    name=name,
                    region=self.credentials.region,
                    status=vpc['State'],
                    created_at=datetime.now(timezone.utc),
                    details={
                        'status': vpc['State'],
                        'cidr_block': vpc['CidrBlock'],
                        'state': vpc['State'],
                        'is_default': vpc.get('IsDefault', False),
                        'dhcp_options_id': vpc.get('DhcpOptionsId'),
                        'instance_tenancy': vpc.get('InstanceTenancy'),
                        'subnets': subnets,
                        'internet_gateways': internet_gateways,
                        'nat_gateways': nat_gateways,
                        'network_interfaces': network_interfaces,
                        'tags': {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
                    }
                ))
        except ClientError as e:
            logger.error(f"Error describing VPCs: {str(e)}")

        # Get Load Balancers and their listeners
        elb = self.session.client('elbv2')
        try:
            lbs = elb.describe_load_balancers()
            for lb in lbs['LoadBalancers']:
                # Get load balancer name
                name = next((tag['Value'] for tag in elb.describe_tags(
                    ResourceArns=[lb['LoadBalancerArn']])['TagDescriptions'][0]['Tags'] 
                    if tag['Key'] == 'Name'), lb['LoadBalancerName'])
                
                # Get listeners with certificates
                listeners = []
                try:
                    lb_listeners = elb.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
                    for listener in lb_listeners['Listeners']:
                        listener_info = {
                            'port': listener['Port'],
                            'protocol': listener['Protocol'],
                            'ssl_policy': listener.get('SslPolicy'),
                            'certificates': []
                        }
                        
                        # Get SSL certificates if present
                        if 'Certificates' in listener:
                            for cert in listener['Certificates']:
                                try:
                                    cert_details = self.session.client('acm').describe_certificate(
                                        CertificateArn=cert['CertificateArn']
                                    )['Certificate']
                                    listener_info['certificates'].append({
                                        'arn': cert['CertificateArn'],
                                        'domain_name': cert_details.get('DomainName'),
                                        'status': cert_details.get('Status'),
                                        'type': cert_details.get('Type'),
                                        'issued_at': cert_details.get('IssuedAt').isoformat() if cert_details.get('IssuedAt') else None,
                                        'expires_at': cert_details.get('NotAfter').isoformat() if cert_details.get('NotAfter') else None
                                    })
                                except ClientError as e:
                                    logger.warning(f"Error getting certificate details: {str(e)}")
                        
                        # Get target groups for this listener
                        if 'DefaultActions' in listener:
                            for action in listener['DefaultActions']:
                                if action['Type'] == 'forward' and 'TargetGroupArn' in action:
                                    try:
                                        tg_details = elb.describe_target_groups(
                                            TargetGroupArns=[action['TargetGroupArn']]
                                        )['TargetGroups'][0]
                                        
                                        # Get health check configuration
                                        health_check = {
                                            'protocol': tg_details['HealthCheckProtocol'],
                                            'port': tg_details['HealthCheckPort'],
                                            'path': tg_details.get('HealthCheckPath'),
                                            'interval': tg_details['HealthCheckIntervalSeconds'],
                                            'timeout': tg_details['HealthCheckTimeoutSeconds'],
                                            'healthy_threshold': tg_details['HealthyThresholdCount'],
                                            'unhealthy_threshold': tg_details['UnhealthyThresholdCount'],
                                            'matcher': tg_details.get('Matcher', {}).get('HttpCode')
                                        }
                                        
                                        # Get target health
                                        targets = elb.describe_target_health(
                                            TargetGroupArn=action['TargetGroupArn']
                                        )['TargetHealthDescriptions']
                                        
                                        listener_info['target_groups'] = {
                                            'arn': action['TargetGroupArn'],
                                            'name': tg_details['TargetGroupName'],
                                            'protocol': tg_details['Protocol'],
                                            'port': tg_details['Port'],
                                            'target_type': tg_details['TargetType'],
                                            'health_check': health_check,
                                            'targets': [{
                                                'id': target['Target']['Id'],
                                                'port': target['Target'].get('Port'),
                                                'health': {
                                                    'state': target['TargetHealth']['State'],
                                                    'reason': target['TargetHealth'].get('Reason'),
                                                    'description': target['TargetHealth'].get('Description')
                                                }
                                            } for target in targets]
                                        }
                                    except ClientError as e:
                                        logger.warning(f"Error getting target group details: {str(e)}")
                        
                        listeners.append(listener_info)
                except ClientError as e:
                    logger.warning(f"Error getting listeners for load balancer {lb['LoadBalancerArn']}: {str(e)}")
                
                # Get security groups
                security_groups = []
                if 'SecurityGroups' in lb:
                    try:
                        ec2 = self.session.client('ec2')
                        sg_details = ec2.describe_security_groups(
                            GroupIds=lb['SecurityGroups']
                        )['SecurityGroups']
                        
                        for sg in sg_details:
                            security_groups.append({
                                'id': sg['GroupId'],
                                'name': sg['GroupName'],
                                'description': sg['Description'],
                                'vpc_id': sg['VpcId'],
                                'inbound_rules': [{
                                    'protocol': rule['IpProtocol'],
                                    'from_port': rule.get('FromPort'),
                                    'to_port': rule.get('ToPort'),
                                    'sources': [
                                        ip_range['CidrIp'] for ip_range in rule.get('IpRanges', [])
                                    ] + [
                                        group['GroupId'] for group in rule.get('UserIdGroupPairs', [])
                                    ]
                                } for rule in sg['IpPermissions']],
                                'outbound_rules': [{
                                    'protocol': rule['IpProtocol'],
                                    'from_port': rule.get('FromPort'),
                                    'to_port': rule.get('ToPort'),
                                    'destinations': [
                                        ip_range['CidrIp'] for ip_range in rule.get('IpRanges', [])
                                    ] + [
                                        group['GroupId'] for group in rule.get('UserIdGroupPairs', [])
                                    ]
                                } for rule in sg['IpPermissionsEgress']]
                            })
                    except ClientError as e:
                        logger.warning(f"Error getting security groups for load balancer: {str(e)}")

                resources.append(ResourceSummary(
                    id=uuid4(),
                    resource_id=lb['LoadBalancerArn'],
                    type='load_balancer',
                    name=name,
                    region=self.credentials.region,
                    status=lb.get('State', {}).get('Code', 'unknown'),
                    created_at=datetime.now(timezone.utc),
                    details={
                        'status': lb.get('State', {}).get('Code', 'unknown'),
                        'dns_name': lb['DNSName'],
                        'type': lb['Type'],
                        'scheme': lb['Scheme'],
                        'vpc_id': lb.get('VpcId'),
                        'availability_zones': lb['AvailabilityZones'],
                        'listeners': listeners,
                        'security_groups': security_groups
                    }
                ))
        except ClientError as e:
            logger.error(f"Error describing load balancers: {str(e)}")

        # Get EKS clusters and node groups
        try:
            logger.info("Starting EKS cluster discovery")
            eks = self.session.client('eks')
            clusters = eks.list_clusters()
            
            for cluster_name in clusters['clusters']:
                # Get cluster details
                cluster = eks.describe_cluster(name=cluster_name)['cluster']
                
                # Get node groups for this cluster
                nodegroups = eks.list_nodegroups(clusterName=cluster_name)
                nodegroup_details = []
                total_managed_nodes = 0
                
                for nodegroup_name in nodegroups.get('nodegroups', []):
                    try:
                        nodegroup = eks.describe_nodegroup(
                            clusterName=cluster_name,
                            nodegroupName=nodegroup_name
                        )['nodegroup']
                        
                        desired_size = nodegroup.get('scalingConfig', {}).get('desiredSize', 0)
                        total_managed_nodes += desired_size
                        
                        nodegroup_details.append({
                            'name': nodegroup_name,
                            'status': nodegroup['status'],
                            'capacity_type': nodegroup.get('capacityType'),
                            'instance_types': nodegroup.get('instanceTypes', []),
                            'disk_size': nodegroup.get('diskSize'),
                            'scaling_config': nodegroup.get('scalingConfig', {}),
                            'subnet_ids': nodegroup.get('subnets', []),
                            'node_role': nodegroup.get('nodeRole'),
                            'labels': nodegroup.get('labels', {})
                        })
                    except ClientError as e:
                        logger.warning(f"Could not get details for nodegroup {nodegroup_name}: {str(e)}")

                # Get directly attached nodes
                try:
                    # Get cluster OIDC issuer without https:// prefix
                    oidc_issuer = cluster['identity']['oidc']['issuer'].replace('https://', '')
                    
                    # List nodes using EC2 describe_instances with cluster tag
                    ec2 = self.session.client('ec2')
                    response = ec2.describe_instances(
                        Filters=[
                            {
                                'Name': 'tag:kubernetes.io/cluster/' + cluster_name,
                                'Values': ['owned']
                            }
                        ]
                    )
                    
                    direct_nodes = []
                    for reservation in response['Reservations']:
                        for instance in reservation['Instances']:
                            # Check if node is not part of a managed node group
                            if not any(tag['Key'].startswith('eks:nodegroup-name') for tag in instance.get('Tags', [])):
                                direct_nodes.append({
                                    'instance_id': instance['InstanceId'],
                                    'instance_type': instance['InstanceType'],
                                    'state': instance['State']['Name'],
                                    'private_ip': instance.get('PrivateIpAddress'),
                                    'public_ip': instance.get('PublicIpAddress')
                                })
                    
                    total_direct_nodes = len(direct_nodes)
                except ClientError as e:
                    logger.warning(f"Could not get directly attached nodes for cluster {cluster_name}: {str(e)}")
                    direct_nodes = []
                    total_direct_nodes = 0
                
                # Add cluster as a resource
                resources.append(ResourceSummary(
                    id=uuid4(),
                    resource_id=cluster['name'],
                    type='eks',
                    name=cluster['name'],
                    region=self.credentials.region,
                    status=cluster['status'],
                    created_at=cluster['createdAt'].replace(tzinfo=timezone.utc),
                    details={
                        'status': cluster['status'],
                        'version': cluster['version'],
                        'endpoint': cluster['endpoint'],
                        'role_arn': cluster['roleArn'],
                        'vpc_config': {
                            'vpc_id': cluster['resourcesVpcConfig'].get('vpcId'),
                            'subnet_ids': cluster['resourcesVpcConfig'].get('subnetIds', []),
                            'security_groups': cluster['resourcesVpcConfig'].get('securityGroupIds', []),
                            'cluster_security_group': cluster['resourcesVpcConfig'].get('clusterSecurityGroupId'),
                            'endpoint_public_access': cluster['resourcesVpcConfig'].get('endpointPublicAccess'),
                            'endpoint_private_access': cluster['resourcesVpcConfig'].get('endpointPrivateAccess')
                        },
                        'logging': cluster.get('logging', {}).get('clusterLogging', []),
                        'nodegroups': nodegroup_details,
                        'direct_nodes': direct_nodes,
                        'nodes_summary': {
                            'managed_nodes': total_managed_nodes,
                            'direct_nodes': total_direct_nodes,
                            'total_nodes': total_managed_nodes + total_direct_nodes
                        },
                        'tags': cluster.get('tags', {})
                    }
                ))
                logger.info(f"Successfully added EKS cluster {cluster_name} to resources")
                
        except ClientError as e:
            logger.error(f"Error listing EKS clusters: {str(e)}")

        # List OpenSearch domains
        try:
            opensearch = self.session.client('opensearch')
            domains = opensearch.list_domain_names()
            for domain in domains.get('DomainNames', []):
                domain_name = domain['DomainName']
                try:
                    domain_info = opensearch.describe_domain(DomainName=domain_name)['DomainStatus']
                    logger.info(f"OpenSearch domain info: {domain_info}")
                    
                    # Get cluster health status
                    try:
                        health = opensearch.describe_domain_health(DomainName=domain_name)
                        cluster_health = health.get('DomainHealth', {}).get('ClusterHealth', 'unknown')
                        logger.info(f"OpenSearch health status: {cluster_health}")
                    except ClientError as e:
                        logger.warning(f"Could not get health status: {str(e)}")
                        cluster_health = 'unknown'
                    
                    # Get region from ARN (format: arn:aws:es:region:account:domain/name)
                    arn = domain_info.get('ARN')
                    if arn and ':' in arn:
                        try:
                            region = arn.split(':')[3]
                            logger.info(f"Extracted region from ARN: {region}")
                        except (IndexError, AttributeError) as e:
                            logger.warning(f"Could not extract region from ARN: {str(e)}")
                            region = self.credentials.region
                    else:
                        logger.warning(f"No ARN found in domain info, using credentials region: {self.credentials.region}")
                        region = self.credentials.region
                    
                    # Get status from DomainProcessingStatus and domain status
                    domain_status = domain_info.get('DomainProcessingStatus', '').lower()  # Convert to lowercase
                    domain_active = domain_info.get('Processing', False) == False and domain_info.get('Deleted', False) == False
                    
                    if domain_active and cluster_health != 'unknown':
                        status = cluster_health.lower()  # Convert cluster health to lowercase
                    elif domain_status:
                        status = domain_status  # Already lowercase
                    else:
                        status = 'unknown'  # Already lowercase
                    
                    logger.info(f"Final status: {status}")
                    
                    # Get creation time
                    created_at = domain_info.get('Created')
                    if not isinstance(created_at, datetime):
                        created_at = datetime.now(timezone.utc)
                    
                    # Get instance counts by type
                    instance_counts = {}
                    if 'ClusterConfig' in domain_info:
                        config = domain_info['ClusterConfig']
                        if 'InstanceCount' in config:
                            instance_type = config.get('InstanceType', 'unknown')
                            instance_counts[instance_type] = config['InstanceCount']
                    
                    # Create a summary of the instances
                    instance_summary = [
                        f"{count}x {type}" 
                        for type, count in instance_counts.items()
                    ]
                    
                    # Create resource summary
                    resource_summary = ResourceSummary(
                        id=uuid4(),
                        resource_id=domain_info['DomainId'],
                        type='opensearch',
                        name=domain_name,
                        created_at=created_at,
                        region=region,
                        status=status,  
                        details={
                            'endpoint': domain_info.get('Endpoints', {}).get('vpc'),
                            'engine_version': domain_info.get('EngineVersion'),
                            'instance_summary': ', '.join(instance_summary),
                            'volume_size': domain_info.get('EBSOptions', {}).get('VolumeSize'),
                            'volume_type': domain_info.get('EBSOptions', {}).get('VolumeType'),
                            'vpc_id': domain_info.get('VPCOptions', {}).get('VPCId'),
                            'zone_awareness': domain_info.get('ClusterConfig', {}).get('ZoneAwarenessEnabled', False),
                            'dedicated_master': domain_info.get('ClusterConfig', {}).get('DedicatedMasterEnabled', False),
                            'encryption_at_rest': domain_info.get('EncryptionAtRestOptions', {}).get('Enabled', False),
                            'node_to_node_encryption': domain_info.get('NodeToNodeEncryptionOptions', {}).get('Enabled', False),
                            'cluster_health': cluster_health,
                            'tags': domain_info.get('Tags', {}),
                            'region': region,
                            'status': status
                        }
                    )
                    
                    logger.info(f"Created resource summary: {resource_summary}")
                    resources.append(resource_summary)
                except ClientError as e:
                    logger.warning(f"Could not get details for OpenSearch domain {domain_name}: {str(e)}")
        except ClientError as e:
            logger.error(f"Error listing OpenSearch domains: {str(e)}")

        return resources

    def get_resource_details(self, resource_type: str, resource_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific AWS resource"""
        logger.info(f"Getting details for {resource_type} resource: {resource_id}")
        try:
            if resource_type == "s3":
                s3 = self.session.client('s3')
                bucket_details = s3.get_bucket_location(Bucket=resource_id)
                return {
                    "name": resource_id,
                    "type": "s3",
                    "location": bucket_details['LocationConstraint'] or "us-east-1",
                    "arn": f"arn:aws:s3:::{resource_id}"
                }
            elif resource_type == "ec2":
                ec2 = self.session.client('ec2')
                instance_details = ec2.describe_instances(InstanceIds=[resource_id])
                instance = instance_details['Reservations'][0]['Instances'][0]
                
                # Get account ID
                sts = self.session.client('sts')
                account_id = sts.get_caller_identity()['Account']
                
                return {
                    "name": next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance['InstanceId']),
                    "type": "ec2",
                    "state": instance['State']['Name'],
                    "instance_type": instance['InstanceType'],
                    "launch_time": instance['LaunchTime'].replace(tzinfo=timezone.utc).isoformat(),
                    "public_ip": instance.get('PublicIpAddress'),
                    "private_ip": instance.get('PrivateIpAddress'),
                    "arn": f"arn:aws:ec2:{self.credentials.region}:{account_id}:instance/{instance['InstanceId']}"
                }
            elif resource_type == "eks":
                eks = self.session.client('eks')
                cluster = eks.describe_cluster(name=resource_id)['cluster']
                
                # Get node groups
                nodegroups = eks.list_nodegroups(clusterName=resource_id)
                nodegroup_details = []
                
                for nodegroup_name in nodegroups.get('nodegroups', []):
                    try:
                        nodegroup = eks.describe_nodegroup(
                            clusterName=resource_id,
                            nodegroupName=nodegroup_name
                        )['nodegroup']
                        
                        nodegroup_details.append({
                            'name': nodegroup_name,
                            'status': nodegroup['status'],
                            'capacity_type': nodegroup.get('capacityType'),
                            'instance_types': nodegroup.get('instanceTypes', []),
                            'scaling_config': nodegroup.get('scalingConfig', {}),
                            'current_size': nodegroup.get('scalingConfig', {}).get('desiredSize', 0)
                        })
                    except ClientError as e:
                        logger.warning(f"Could not get details for nodegroup {nodegroup_name}: {str(e)}")
                
                return {
                    "name": cluster['name'],
                    "type": "eks",
                    "status": cluster['status'],
                    "version": cluster['version'],
                    "endpoint": cluster['endpoint'],
                    "vpc_id": cluster['resourcesVpcConfig'].get('vpcId'),
                    "nodegroups": nodegroup_details,
                    "arn": cluster['arn']
                }
            elif resource_type == "opensearch":
                opensearch = self.session.client('opensearch')
                domain = opensearch.describe_domain(DomainName=resource_id)['DomainStatus']
                
                # Get instance counts by type
                instance_counts = {}
                if 'ClusterConfig' in domain:
                    config = domain['ClusterConfig']
                    if 'InstanceCount' in config:
                        instance_type = config.get('InstanceType', 'unknown')
                        instance_counts[instance_type] = config['InstanceCount']
                    if 'WarmCount' in config:
                        instance_type = config.get('WarmType', 'unknown')
                        instance_counts[instance_type] = config['WarmCount']
                
                # Create a summary of the instances
                instance_summary = [
                    f"{count}x {type}" 
                    for type, count in instance_counts.items()
                ]
                
                return {
                    "name": domain['DomainName'],
                    "type": "opensearch",
                    "status": domain['Processing'] and 'processing' or domain['Deleted'] and 'deleted' or 'active',
                    "endpoint": domain.get('Endpoints', {}).get('vpc'),
                    "engine_version": domain.get('EngineVersion'),
                    "instance_summary": ', '.join(instance_summary),
                    "volume_size": domain.get('EBSOptions', {}).get('VolumeSize'),
                    "volume_type": domain.get('EBSOptions', {}).get('VolumeType'),
                    "vpc_id": domain.get('VPCOptions', {}).get('VPCId'),
                    "zone_awareness": domain.get('ClusterConfig', {}).get('ZoneAwarenessEnabled', False),
                    "dedicated_master": domain.get('ClusterConfig', {}).get('DedicatedMasterEnabled', False),
                    "encryption_at_rest": domain.get('EncryptionAtRestOptions', {}).get('Enabled', False),
                    "node_to_node_encryption": domain.get('NodeToNodeEncryptionOptions', {}).get('Enabled', False),
                    "tags": domain.get('Tags', {})
                }
            else:
                logger.error(f"Unsupported resource type: {resource_type}")
                raise ValueError(f"Unsupported resource type: {resource_type}")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"Failed to get resource details: {error_code} - {error_message}")
            raise ValueError(f"Failed to get resource details: {error_code} - {error_message}")

    @staticmethod
    def get_credentials(project_id: str, user_id: str, db: Session) -> Optional[AWSCredentialsBase]:
        """Get AWS credentials for a project from the database"""
        try:
            # Convert string IDs to UUIDs if they aren't already
            project_uuid = project_id if isinstance(project_id, UUID) else UUID(project_id)
            user_uuid = user_id if isinstance(user_id, UUID) else UUID(user_id)
            
            logger.info(f"Getting AWS credentials for project {project_uuid} and user {user_uuid}")
            
            # First verify the project belongs to the user
            project = db.query(Project).filter(
                Project.id == project_uuid,
                Project.user_id == user_uuid
            ).first()
            
            if not project:
                logger.warning(f"Project {project_uuid} not found or does not belong to user {user_uuid}")
                return None
            
            # Query the database for credentials
            credentials = db.query(AWSCredentials).filter(
                AWSCredentials.project_id == project_uuid
            ).first()
            
            if credentials:
                logger.info(f"Found AWS credentials for project {project_uuid}")
                return credentials
            
            logger.warning(f"No AWS credentials found for project {project_uuid} (user: {user_uuid})")
            return None
            
        except ValueError as e:
            logger.error(f"Invalid UUID format - project_id: {project_id}, user_id: {user_id}. Error: {str(e)}")
            return None
