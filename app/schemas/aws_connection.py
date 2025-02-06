from pydantic import BaseModel
from datetime import datetime
from uuid import UUID

class AWSConnectionBase(BaseModel):
    aws_access_key_id: str
    aws_secret_access_key: str
    region: str

class AWSConnectionCreate(AWSConnectionBase):
    pass

class AWSConnection(AWSConnectionBase):
    id: UUID
    project_id: UUID
    user_id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
