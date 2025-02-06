"""
Pydantic schemas for AWS resources.
"""
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime
from .base import CamelModel
from ..models.aws_resources import ResourceType

class AWSResourceBase(CamelModel):
    resource_id: str
    resource_type: ResourceType
    name: Optional[str] = None
    region: str
    details: Dict[str, Any]

class AWSResourceCreate(AWSResourceBase):
    credentials_id: str
    project_id: str

class AWSResourceResponse(AWSResourceBase):
    id: str
    credentials_id: str
    project_id: str
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class EC2InstanceDetails(BaseModel):
    instance_id: str
    instance_type: str
    state: str
    launch_time: str
    platform: Optional[str] = None
    private_ip: Optional[str] = None
    public_ip: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    tags: List[Dict[str, str]] = []
    security_groups: List[Dict[str, str]] = []
