from pydantic import BaseModel, UUID4, ConfigDict
from datetime import datetime
from typing import Optional, Dict, Any, List
from ..models.aws_resources import ResourceType

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

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={UUID4: str}
    )

class StoredAWSCredentials(AWSCredentialsBase):
    id: UUID4
    project_id: UUID4
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(
        from_attributes=True,
        json_encoders={UUID4: str}
    )

class ResourceSummary(BaseModel):
    id: UUID4
    resource_id: str
    name: str
    type: str
    details: Dict[str, Any] = {}  # Default to empty dict
    created_at: datetime
    region: str = 'unknown'
    status: str = 'unknown'

    model_config = ConfigDict(
        from_attributes=True,
        arbitrary_types_allowed=True,
        json_encoders={UUID4: str}
    )

class ResourceDetails(ResourceSummary):
    id: UUID4
    project_id: str
    resource_metadata: Optional[Dict[str, Any]] = None
    updated_at: Optional[datetime] = None
    tags: Optional[Dict[str, str]] = None
    vpc_id: Optional[str] = None
    subnet_id: Optional[str] = None
    security_groups: Optional[List[str]] = None
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None

    model_config = ConfigDict(
        from_attributes=True,
        arbitrary_types_allowed=True,
        use_enum_values=True
    )

class ResourceMetrics(BaseModel):
    cpu_utilization: Optional[float] = None
    memory_utilization: Optional[float] = None
    network_in: Optional[float] = None
    network_out: Optional[float] = None
    disk_read: Optional[float] = None
    disk_write: Optional[float] = None
