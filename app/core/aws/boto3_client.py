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
