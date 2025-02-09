from abc import ABC, abstractmethod
from typing import List, Dict, Any
from ...schemas.aws import ResourceSummary
import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

class AWSResourceBase(ABC):
    def __init__(self, session: boto3.Session, region: str):
        self.session = session
        self.region = region

    @abstractmethod
    def list_resources(self) -> List[ResourceSummary]:
        """List all resources of this type"""
        pass

    @abstractmethod
    def get_resource_details(self, resource_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific resource"""
        pass

    def handle_client_error(self, e: ClientError, resource_type: str, operation: str, resource_id: str = None) -> None:
        """Handle AWS client errors in a consistent way"""
        resource_info = f" for {resource_id}" if resource_id else ""
        logger.error(
            f"Error {operation} {resource_type}{resource_info}: {str(e)}",
            extra={
                "error_code": e.response["Error"]["Code"],
                "resource_type": resource_type,
                "operation": operation,
                "resource_id": resource_id
            },
            exc_info=True
        )
