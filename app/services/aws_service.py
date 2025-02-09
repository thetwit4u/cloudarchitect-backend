import boto3
from botocore.exceptions import ClientError
from ..schemas.aws import AWSCredentialsBase, ResourceSummary
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
from uuid import uuid4
import logging
from sqlalchemy.orm import Session
from ..models import AWSCredentials, Project
from uuid import UUID

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
                        'encryption_enabled': encryption_enabled
                    }
                ))
                logger.info(f"Successfully added bucket {bucket['Name']} to resources")
        except ClientError as e:
            logger.error(f"Error listing S3 buckets: {str(e)}")

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
