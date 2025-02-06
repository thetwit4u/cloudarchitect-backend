import boto3
from botocore.exceptions import ClientError
from ..schemas.aws import AWSCredentialsBase, ResourceSummary, StoredAWSCredentials
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

# In-memory storage for AWS credentials
credentials_db: Dict[str, StoredAWSCredentials] = {}

class AWSService:
    def __init__(self, credentials: AWSCredentialsBase):
        """Initialize AWS service with credentials"""
        self.credentials = credentials
        self.session = boto3.Session(
            aws_access_key_id=credentials.aws_access_key_id,
            aws_secret_access_key=credentials.aws_secret_access_key,
            region_name=credentials.region
        )

    def validate_credentials(self) -> bool:
        """Validate AWS credentials by attempting to list S3 buckets"""
        try:
            s3 = self.session.client('s3')
            s3.list_buckets()
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            raise ValueError(f"AWS Credentials validation failed: {error_code} - {error_message}")

    def list_resources(self) -> List[ResourceSummary]:
        """List AWS resources in the account"""
        resources = []
        
        try:
            # List S3 buckets
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                resources.append(ResourceSummary(
                    type="s3",
                    name=bucket['Name'],
                    arn=f"arn:aws:s3:::{bucket['Name']}",
                    region=self.credentials.region,
                    created_at=bucket['CreationDate']
                ))

            # List EC2 instances
            ec2 = self.session.client('ec2')
            instances = ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    resources.append(ResourceSummary(
                        type="ec2",
                        name=next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance['InstanceId']),
                        arn=f"arn:aws:ec2:{self.credentials.region}:{instance['OwnerId']}:instance/{instance['InstanceId']}",
                        region=self.credentials.region,
                        created_at=instance['LaunchTime']
                    ))

            return resources
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            raise ValueError(f"Failed to list AWS resources: {error_code} - {error_message}")

    def get_resource_details(self, resource_type: str, resource_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific AWS resource"""
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
                return {
                    "name": next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance['InstanceId']),
                    "type": "ec2",
                    "state": instance['State']['Name'],
                    "instance_type": instance['InstanceType'],
                    "launch_time": instance['LaunchTime'].isoformat(),
                    "public_ip": instance.get('PublicIpAddress'),
                    "private_ip": instance.get('PrivateIpAddress'),
                    "arn": f"arn:aws:ec2:{self.credentials.region}:{instance['OwnerId']}:instance/{instance['InstanceId']}"
                }
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            raise ValueError(f"Failed to get resource details: {error_code} - {error_message}")

    @staticmethod
    def store_credentials(credentials: AWSCredentialsBase, user_id: str) -> StoredAWSCredentials:
        cred_id = str(uuid.uuid4())
        now = datetime.utcnow()
        stored_creds = StoredAWSCredentials(
            id=cred_id,
            created_at=now,
            updated_at=now,
            user_id=user_id,
            **credentials.model_dump()
        )
        credentials_db[cred_id] = stored_creds
        return stored_creds

    @staticmethod
    def get_credentials(project_id: str, user_id: str) -> Optional[StoredAWSCredentials]:
        for cred in credentials_db.values():
            if cred.project_id == project_id and cred.user_id == user_id:
                return cred
        return None
