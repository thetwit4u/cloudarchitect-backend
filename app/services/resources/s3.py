from datetime import datetime
from typing import List, Dict, Any
from uuid import uuid4
from botocore.exceptions import ClientError
from .base import AWSResourceBase
from ...schemas.aws import ResourceSummary
import logging

logger = logging.getLogger(__name__)

class S3Resource(AWSResourceBase):
    def list_resources(self) -> List[ResourceSummary]:
        """List all S3 buckets with detailed information"""
        resources = []
        s3 = self.session.client('s3')

        try:
            buckets = s3.list_buckets()
            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']
                details = self.get_resource_details(bucket_name)
                details['creation_date'] = bucket['CreationDate'].isoformat()

                resources.append(ResourceSummary(
                    id=uuid4(),
                    resource_id=bucket_name,
                    type='s3',
                    name=bucket_name,
                    region=details.get('region', 'unknown'),
                    status='active',  # Set status directly here since we know the bucket exists
                    created_at=bucket['CreationDate'],
                    details=details
                ))

        except ClientError as e:
            self.handle_client_error(e, 's3', 'list_buckets')

        return resources

    def get_resource_details(self, resource_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific S3 bucket"""
        s3 = self.session.client('s3')
        details = {}

        try:
            # Get bucket location
            location = s3.get_bucket_location(Bucket=resource_id)
            details['region'] = location['LocationConstraint'] or 'us-east-1'

            # Get public access block configuration
            try:
                public_access = s3.get_public_access_block(Bucket=resource_id)
                details['public_access'] = public_access['PublicAccessBlockConfiguration']
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
                    self.handle_client_error(e, 's3', 'get_public_access_block', resource_id)
                details['public_access'] = {}

            # Get bucket policy and check if public
            try:
                policy = s3.get_bucket_policy(Bucket=resource_id)
                details['has_bucket_policy'] = True
                details['is_public'] = 'Principal": "*"' in policy['Policy']
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    self.handle_client_error(e, 's3', 'get_bucket_policy', resource_id)
                details['has_bucket_policy'] = False
                details['is_public'] = False

            # Get lifecycle rules
            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=resource_id)
                details['lifecycle_rules'] = lifecycle.get('Rules', [])
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchLifecycleConfiguration':
                    self.handle_client_error(e, 's3', 'get_lifecycle_rules', resource_id)
                details['lifecycle_rules'] = []

            # Get storage class analytics
            try:
                analytics = s3.list_bucket_analytics_configurations(Bucket=resource_id)
                details['storage_classes'] = {}
                for config in analytics.get('AnalyticsConfigurationList', []):
                    if 'StorageClassAnalysis' in config:
                        details['storage_classes'][config['Id']] = config['StorageClassAnalysis']
            except ClientError as e:
                self.handle_client_error(e, 's3', 'list_analytics_configurations', resource_id)
                details['storage_classes'] = {}

            # Get bucket tagging
            try:
                tagging = s3.get_bucket_tagging(Bucket=resource_id)
                details['tags'] = {tag['Key']: tag['Value'] for tag in tagging['TagSet']}
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchTagSet':
                    self.handle_client_error(e, 's3', 'get_bucket_tagging', resource_id)
                details['tags'] = {}

            # Get bucket versioning
            try:
                versioning = s3.get_bucket_versioning(Bucket=resource_id)
                details['versioning'] = versioning.get('Status', 'Disabled')
            except ClientError as e:
                self.handle_client_error(e, 's3', 'get_bucket_versioning', resource_id)
                details['versioning'] = 'Unknown'

            # Get bucket encryption
            try:
                encryption = s3.get_bucket_encryption(Bucket=resource_id)
                details['encryption'] = encryption['ServerSideEncryptionConfiguration']
            except ClientError as e:
                if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                    self.handle_client_error(e, 's3', 'get_bucket_encryption', resource_id)
                details['encryption'] = None

            # Get bucket policy and check if public
            try:
                policy = s3.get_bucket_policy(Bucket=resource_id)
                details['has_bucket_policy'] = True
                details['is_public'] = 'Principal": "*"' in policy['Policy']
                details['bucket_policy'] = policy['Policy']
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    self.handle_client_error(e, 's3', 'get_bucket_policy', resource_id)
                details['has_bucket_policy'] = False
                details['is_public'] = False
                details['bucket_policy'] = None

            return details

        except ClientError as e:
            self.handle_client_error(e, 's3', 'get_resource_details', resource_id)
            details['status'] = 'error'  # Set status to error if we can't access the bucket
            return details
