"""
SQLAlchemy models for AWS resources.
"""
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, Enum as SQLAlchemyEnum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from enum import Enum
from typing import Optional, Dict, Any
import uuid
from datetime import datetime
from ..core.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class ResourceType(str, Enum):
    EC2 = "ec2"
    S3 = "s3"
    RDS = "rds"
    LAMBDA = "lambda"
    VPC = "vpc"
    LOAD_BALANCER = "load_balancer"
    EKS = "eks"

    @classmethod
    def _missing_(cls, value):
        """Handle case-insensitive lookup"""
        for member in cls:
            if member.value.lower() == str(value).lower():
                return member
        return None

class AWSResource(Base):
    """Model for AWS resources discovered in a project"""
    __tablename__ = "aws_resources"

    id = Column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    resource_id = Column(String, nullable=False)
    resource_type = Column(SQLAlchemyEnum(ResourceType), nullable=False)
    name = Column(String, nullable=False)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    project = relationship("Project", back_populates="aws_resources")

    def __repr__(self):
        return f"<AWSResource(id={self.id}, name={self.name}, type={self.resource_type})>"
