"""
SQLAlchemy models for AWS resources.
"""
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from ..core.database import Base
import uuid
import enum

def generate_uuid():
    return str(uuid.uuid4())

class ResourceType(str, enum.Enum):
    EC2 = "ec2"
    S3 = "s3"
    RDS = "rds"
    LAMBDA = "lambda"
    VPC = "vpc"

class AWSResource(Base):
    __tablename__ = "aws_resources"

    id = Column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    resource_id = Column(String, index=True)  # AWS resource ID (e.g., i-1234567890abcdef0)
    resource_type = Column(Enum(ResourceType), index=True)
    name = Column(String, nullable=True)
    region = Column(String)
    details = Column(JSON)  # Store resource-specific details
    credentials_id = Column(UUID(as_uuid=True), ForeignKey("aws_credentials.id"))
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"))
    created_at = Column(DateTime(timezone=True), server_default="now()")
    updated_at = Column(DateTime(timezone=True), onupdate="now()")

    # Relationships
    credentials = relationship("AWSCredentials", back_populates="resources")
    project = relationship("Project", back_populates="resources")

    def to_dict(self):
        """Convert the model instance to a dictionary"""
        return {
            "id": str(self.id),
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "name": self.name,
            "region": self.region,
            "details": self.details,
            "credentials_id": str(self.credentials_id),
            "project_id": str(self.project_id),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }
