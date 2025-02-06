from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class AWSConnectionBase(BaseModel):
    name: str
    aws_account_id: str
    aws_region: str
    aws_role_arn: str
    aws_external_id: Optional[str] = None

class AWSConnectionCreate(AWSConnectionBase):
    pass

class AWSConnection(AWSConnectionBase):
    id: str
    project_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
