from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class AWSCredentials(BaseModel):
    project_id: str
    aws_access_key_id: str
    aws_secret_access_key: str
    region: str = "us-east-1"

class StoredAWSCredentials(AWSCredentials):
    id: str
    created_at: datetime
    updated_at: datetime
    user_id: str

    class Config:
        from_attributes = True

class ResourceSummary(BaseModel):
    id: str
    type: str
    name: Optional[str] = None
    status: Optional[str] = None
    project_id: str
    region: str
    metadata: Optional[Dict[str, Any]] = None

class ResourceDetails(ResourceSummary):
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    tags: Optional[Dict[str, str]] = None
    arn: Optional[str] = None
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    security_groups: Optional[list[str]] = None
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None

class ResourceMetrics(BaseModel):
    cpu_utilization: Optional[float] = None
    memory_utilization: Optional[float] = None
    network_in: Optional[float] = None
    network_out: Optional[float] = None
    disk_read: Optional[float] = None
    disk_write: Optional[float] = None
