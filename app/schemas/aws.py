from pydantic import BaseModel, UUID4
from datetime import datetime
from typing import Optional, Dict, Any

class AWSCredentialsBase(BaseModel):
    aws_access_key_id: str
    aws_secret_access_key: str
    region: str

class AWSCredentialsCreate(AWSCredentialsBase):
    pass

class AWSCredentialsResponse(AWSCredentialsBase):
    id: UUID4
    project_id: UUID4
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
        json_encoders = {
            UUID4: lambda x: str(x)
        }

class StoredAWSCredentials(AWSCredentialsBase):
    id: UUID4
    project_id: UUID4
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
        json_encoders = {
            UUID4: lambda x: str(x)
        }

class ResourceSummary(BaseModel):
    type: str
    name: str
    arn: str
    region: str
    created_at: datetime

    class Config:
        from_attributes = True

class ResourceDetails(ResourceSummary):
    id: str
    status: Optional[str] = None
    project_id: str
    resource_metadata: Optional[Dict[str, Any]] = None
    updated_at: Optional[datetime] = None
    tags: Optional[Dict[str, str]] = None
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
