import boto3
from botocore.exceptions import ClientError
from ..schemas.aws import AWSCredentialsBase, ResourceSummary
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
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
            logger.info("AWS credentials validated successfully")
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"AWS Credentials validation failed: {error_code} - {error_message}")
            raise ValueError(f"AWS Credentials validation failed: {error_code} - {error_message}")

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
        """List AWS resources in the account"""
        resources = []
        logger.info("Starting AWS resource discovery...")
        
        try:
            # List EC2 instances
            ec2 = self.session.client('ec2')
            logger.info("Discovering EC2 instances...")
            response = ec2.describe_instances()
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    logger.debug(f"Processing EC2 instance: {instance['InstanceId']}")
                    
                    # Get instance name from tags
                    name = next((tag['Value'] for tag in instance.get('Tags', []) 
                               if tag['Key'] == 'Name'), instance['InstanceId'])
                    
                    # Create ARN
                    arn = f"arn:aws:ec2:{self.credentials.region}:{self.get_account_id()}:instance/{instance['InstanceId']}"
                    
                    # Convert datetime objects to strings for JSON serialization
                    instance_details = {
                        'InstanceId': instance['InstanceId'],
                        'InstanceType': instance['InstanceType'],
                        'State': instance['State']['Name'],
                        'LaunchTime': instance['LaunchTime'].isoformat(),
                        'PrivateIpAddress': instance.get('PrivateIpAddress'),
                        'PublicIpAddress': instance.get('PublicIpAddress'),
                        'Tags': instance.get('Tags', []),
                        'SecurityGroups': instance.get('SecurityGroups', [])
                    }
                    
                    resources.append(ResourceSummary(
                        id=str(uuid.uuid4()),
                        name=name,
                        type='ec2',
                        arn=arn,
                        region=self.credentials.region,
                        status=instance['State']['Name'],
                        details=instance_details,
                        created_at=instance['LaunchTime']
                    ))
            
            logger.info(f"Discovered {len(resources)} EC2 instances")
            
            # List S3 buckets
            s3 = self.session.client('s3')
            logger.info("Discovering S3 buckets...")
            buckets = s3.list_buckets()['Buckets']
            
            for bucket in buckets:
                logger.debug(f"Processing S3 bucket: {bucket['Name']}")
                try:
                    # Get bucket location
                    location = s3.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint'] or 'us-east-1'
                    
                    # Only include buckets in our region
                    if location == self.credentials.region:
                        arn = f"arn:aws:s3:::{bucket['Name']}"
                        
                        # Convert datetime objects to strings for JSON serialization
                        bucket_details = {
                            'Name': bucket['Name'],
                            'CreationDate': bucket['CreationDate'].isoformat(),
                            'Location': location
                        }
                        
                        resources.append(ResourceSummary(
                            id=str(uuid.uuid4()),
                            name=bucket['Name'],
                            type='s3',
                            arn=arn,
                            region=location,
                            status='available',
                            details=bucket_details,
                            created_at=bucket['CreationDate']
                        ))
                except ClientError as e:
                    logger.warning(f"Error getting location for bucket {bucket['Name']}: {str(e)}")
                    continue
            
            logger.info(f"Discovered {len(resources) - len(response['Reservations'])} S3 buckets")
            
            return resources
            
        except ClientError as e:
            error_message = f"Error discovering AWS resources: {str(e)}"
            logger.error(error_message, exc_info=True)
            raise ValueError(error_message)

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
