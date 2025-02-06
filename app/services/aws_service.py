import boto3
from typing import List, Dict, Optional
from ..schemas.aws import AWSCredentials, ResourceSummary, StoredAWSCredentials
from botocore.exceptions import ClientError
from datetime import datetime
import uuid

# In-memory storage for demo purposes
credentials_db: Dict[str, StoredAWSCredentials] = {}

class AWSService:
    def __init__(self, credentials: Optional[AWSCredentials] = None):
        self.session = self._create_session(credentials) if credentials else None
        self.project_id = credentials.project_id if credentials else None
        self.region = credentials.region if credentials else None

    def _create_session(self, credentials: AWSCredentials):
        return boto3.Session(
            aws_access_key_id=credentials.aws_access_key_id,
            aws_secret_access_key=credentials.aws_secret_access_key,
            region_name=credentials.region
        )

    def validate_credentials(self) -> bool:
        """
        Validate AWS credentials by attempting to list S3 buckets
        Returns True if credentials are valid, raises an exception otherwise
        """
        if not self.session:
            raise ValueError("AWS session not initialized")
        
        try:
            # Try to list S3 buckets as a simple validation
            s3 = self.session.client('s3')
            s3.list_buckets()
            return True
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['InvalidAccessKeyId', 'SignatureDoesNotMatch']:
                raise ValueError("Invalid AWS credentials")
            elif error_code == 'InvalidToken':
                raise ValueError("AWS credentials have expired")
            else:
                raise ValueError(f"AWS error: {str(e)}")
        except Exception as e:
            raise ValueError(f"Error validating AWS credentials: {str(e)}")

    @staticmethod
    def store_credentials(credentials: AWSCredentials, user_id: str) -> StoredAWSCredentials:
        cred_id = str(uuid.uuid4())
        now = datetime.utcnow()
        stored_creds = StoredAWSCredentials(
            id=cred_id,
            project_id=credentials.project_id,
            aws_access_key_id=credentials.aws_access_key_id,
            aws_secret_access_key=credentials.aws_secret_access_key,
            region=credentials.region,
            created_at=now,
            updated_at=now,
            user_id=user_id
        )
        credentials_db[cred_id] = stored_creds
        return stored_creds

    @staticmethod
    def get_credentials(project_id: str, user_id: str) -> Optional[StoredAWSCredentials]:
        for cred in credentials_db.values():
            if cred.project_id == project_id and cred.user_id == user_id:
                return cred
        return None

    async def discover_resources(self) -> List[ResourceSummary]:
        if not self.session or not self.project_id:
            raise ValueError("AWS session not initialized or project_id not set")

        resources = []
        
        # Discover EC2 instances
        try:
            ec2_client = self.session.client('ec2')
            instances = ec2_client.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    resources.append(ResourceSummary(
                        id=instance['InstanceId'],
                        type='EC2',
                        name=next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), ''),
                        status=instance['State']['Name'],
                        project_id=self.project_id,
                        region=self.region
                    ))
        except ClientError as e:
            print(f"Error discovering EC2 instances: {str(e)}")

        # Discover S3 buckets
        try:
            s3_client = self.session.client('s3')
            buckets = s3_client.list_buckets()
            for bucket in buckets['Buckets']:
                resources.append(ResourceSummary(
                    id=bucket['Name'],
                    type='S3',
                    name=bucket['Name'],
                    status='available',
                    project_id=self.project_id,
                    region=self.region
                ))
        except ClientError as e:
            print(f"Error discovering S3 buckets: {str(e)}")

        # Discover RDS instances
        try:
            rds_client = self.session.client('rds')
            db_instances = rds_client.describe_db_instances()
            for instance in db_instances['DBInstances']:
                resources.append(ResourceSummary(
                    id=instance['DBInstanceIdentifier'],
                    type='RDS',
                    name=instance['DBInstanceIdentifier'],
                    status=instance['DBInstanceStatus'],
                    project_id=self.project_id,
                    region=self.region
                ))
        except ClientError as e:
            print(f"Error discovering RDS instances: {str(e)}")

        return resources
