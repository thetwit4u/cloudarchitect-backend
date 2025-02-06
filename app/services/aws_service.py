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

    def list_resources(self) -> List[ResourceSummary]:
        """List AWS resources in the account"""
        resources = []
        logger.info("Starting AWS resource discovery...")
        
        try:
            # Get account ID first since we'll need it for ARNs
            try:
                sts = self.session.client('sts')
                account_id = sts.get_caller_identity()['Account']
                logger.info(f"Using AWS Account ID: {account_id}")
            except ClientError as e:
                logger.error(f"Failed to get AWS account ID: {str(e)}")
                raise ValueError("Failed to get AWS account ID. Please check your credentials.")

            # List S3 buckets
            try:
                logger.info("Discovering S3 buckets...")
                s3 = self.session.client('s3')
                buckets = s3.list_buckets()['Buckets']
                logger.info(f"Found {len(buckets)} S3 buckets")
                for bucket in buckets:
                    resources.append(ResourceSummary(
                        type="s3",
                        name=bucket['Name'],
                        arn=f"arn:aws:s3:::{bucket['Name']}",
                        region=self.credentials.region,
                        created_at=bucket['CreationDate']
                    ))
            except ClientError as e:
                logger.warning(f"Failed to list S3 buckets: {str(e)}")

            # List EC2 instances
            try:
                logger.info("Discovering EC2 instances...")
                ec2 = self.session.client('ec2')
                instances = ec2.describe_instances()
                instance_count = sum(len(r['Instances']) for r in instances['Reservations'])
                logger.info(f"Found {instance_count} EC2 instances")

                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance['InstanceId'])
                        resources.append(ResourceSummary(
                            type="ec2",
                            name=name,
                            arn=f"arn:aws:ec2:{self.credentials.region}:{account_id}:instance/{instance['InstanceId']}",
                            region=self.credentials.region,
                            created_at=instance['LaunchTime'],
                            status=instance['State']['Name']
                        ))
                        logger.debug(f"Added EC2 instance: {name} ({instance['InstanceId']})")
            except ClientError as e:
                logger.warning(f"Failed to list EC2 instances: {str(e)}")

            logger.info(f"Resource discovery completed. Found {len(resources)} total resources")
            return resources
        except Exception as e:
            error_message = f"Failed to list AWS resources: {str(e)}"
            logger.error(error_message)
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
