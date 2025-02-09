import boto3
from botocore.exceptions import ClientError
from ..schemas.aws import AWSCredentialsBase, ResourceSummary
from typing import List, Dict, Any, Optional
from datetime import datetime
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
        
        # Get EC2 instances
        ec2 = self.session.client('ec2')
        instances = ec2.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance['InstanceId'])
                resources.append(ResourceSummary(
                    id=uuid4(),
                    resource_id=instance['InstanceId'],
                    type='ec2',
                    name=name,
                    region=self.credentials.region,
                    status=instance['State']['Name'],
                    created_at=datetime.now(),
                    details={
                        'status': instance['State']['Name'],
                        'region': self.credentials.region,
                        'instance_type': instance['InstanceType'],
                        'private_ip': instance.get('PrivateIpAddress'),
                        'public_ip': instance.get('PublicIpAddress'),
                        'vpc_id': instance.get('VpcId'),
                        'subnet_id': instance.get('SubnetId'),
                        'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    }
                ))

        # Get VPCs
        vpcs = ec2.describe_vpcs()
        for vpc in vpcs['Vpcs']:
            name = next((tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'), vpc['VpcId'])
            resources.append(ResourceSummary(
                id=uuid4(),
                resource_id=vpc['VpcId'],
                type='vpc',
                name=name,
                region=self.credentials.region,
                status=vpc['State'],
                created_at=datetime.now(),
                details={
                    'status': vpc['State'],
                    'cidr_block': vpc['CidrBlock'],
                    'state': vpc['State'],
                    'is_default': vpc.get('IsDefault', False),
                    'dhcp_options_id': vpc.get('DhcpOptionsId'),
                    'instance_tenancy': vpc.get('InstanceTenancy')
                }
            ))

        # Get Load Balancers and their listeners
        elb = self.session.client('elbv2')
        load_balancers = elb.describe_load_balancers()
        for lb in load_balancers['LoadBalancers']:
            # Get listeners for this load balancer
            listeners = elb.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])
            
            name = lb['LoadBalancerName']
            resources.append(ResourceSummary(
                id=uuid4(),
                resource_id=lb['LoadBalancerArn'].split('/')[-1],  # Get the last part of the ARN as resource_id
                type='load_balancer',
                name=name,
                region=self.credentials.region,
                status=lb.get('State', {}).get('Code', 'unknown'),
                created_at=datetime.now(),
                details={
                    'status': lb.get('State', {}).get('Code', 'unknown'),
                    'dns_name': lb['DNSName'],
                    'scheme': lb.get('Scheme'),
                    'vpc_id': lb.get('VpcId'),
                    'type': lb.get('Type'),
                    'availability_zones': [az.get('ZoneName') for az in lb.get('AvailabilityZones', [])],
                    'listeners': [
                        {
                            'protocol': listener['Protocol'],
                            'port': listener['Port']
                        }
                        for listener in listeners.get('Listeners', [])
                    ]
                }
            ))

        # Get S3 buckets
        s3 = self.session.client('s3')
        try:
            logger.info("Starting S3 bucket discovery")
            buckets = s3.list_buckets()
            logger.info(f"Found {len(buckets.get('Buckets', []))} S3 buckets")
            
            for bucket in buckets['Buckets']:
                logger.info(f"Processing bucket: {bucket['Name']}")
                # Get bucket location
                try:
                    location = s3.get_bucket_location(Bucket=bucket['Name'])
                    bucket_region = location.get('LocationConstraint') or 'us-east-1'
                    logger.debug(f"Bucket {bucket['Name']} is in region {bucket_region}")
                except ClientError as e:
                    logger.warning(f"Could not get location for bucket {bucket['Name']}: {str(e)}")
                    bucket_region = 'unknown'

                # Get bucket versioning status
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket['Name'])
                    versioning_status = versioning.get('Status', 'Disabled')
                except ClientError as e:
                    logger.warning(f"Could not get versioning for bucket {bucket['Name']}: {str(e)}")
                    versioning_status = 'unknown'

                # Get bucket encryption
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket['Name'])
                    encryption_rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                    encryption_enabled = bool(encryption_rules)
                except ClientError as e:
                    logger.debug(f"Could not get encryption for bucket {bucket['Name']}: {str(e)}")
                    encryption_enabled = False

                # Check if bucket is public
                try:
                    public_access = s3.get_public_access_block(Bucket=bucket['Name'])
                    is_public = not all([
                        public_access['PublicAccessBlockConfiguration'].get('BlockPublicAcls', False),
                        public_access['PublicAccessBlockConfiguration'].get('BlockPublicPolicy', False),
                        public_access['PublicAccessBlockConfiguration'].get('IgnorePublicAcls', False),
                        public_access['PublicAccessBlockConfiguration'].get('RestrictPublicBuckets', False)
                    ])
                except ClientError as e:
                    logger.debug(f"Could not get public access block for bucket {bucket['Name']}: {str(e)}")
                    # If we can't get the public access block configuration, assume it might be public
                    is_public = True

                resources.append(ResourceSummary(
                    id=uuid4(),
                    resource_id=bucket['Name'],
                    type='s3',
                    name=bucket['Name'],
                    region=bucket_region,
                    status='available',  # S3 buckets are always available if we can list them
                    created_at=bucket['CreationDate'],
                    details={
                        'status': 'available',
                        'creation_date': bucket['CreationDate'].isoformat(),
                        'region': bucket_region,
                        'versioning': versioning_status,
                        'encryption_enabled': encryption_enabled,
                        'is_public': is_public
                    }
                ))
                logger.info(f"Successfully added bucket {bucket['Name']} to resources")
        except ClientError as e:
            logger.error(f"Error listing S3 buckets: {str(e)}")

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
                    created_at=cluster['createdAt'],
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
                    
                    # Get cluster health status
                    try:
                        health = opensearch.describe_domain_health(DomainName=domain_name)
                        cluster_health = health.get('DomainHealth', {}).get('ClusterHealth', 'unknown')
                    except ClientError:
                        cluster_health = 'unknown'
                    
                    # Determine domain status
                    status = 'active'
                    if domain_info.get('Processing', False):
                        status = 'processing'
                    elif domain_info.get('Deleted', False):
                        status = 'deleted'
                    
                    # Get creation time
                    created_at = domain_info.get('Created')
                    if not isinstance(created_at, datetime):
                        # Use current time as fallback
                        created_at = datetime.now()
                    
                    # Get instance counts by type
                    instance_counts = {}
                    if 'ClusterConfig' in domain_info:
                        config = domain_info['ClusterConfig']
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
                    
                    resources.append(ResourceSummary(
                        id=uuid4(),
                        resource_id=domain_info['DomainId'],
                        type='opensearch',
                        name=domain_name,
                        region=self.credentials.region,
                        status=status,
                        created_at=created_at,
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
                            'tags': domain_info.get('Tags', {})
                        }
                    ))
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
                    "launch_time": instance['LaunchTime'].isoformat(),
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
