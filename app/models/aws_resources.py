"""
SQLAlchemy models for AWS resources.
"""
from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from ..core.database import Base
import uuid
import enum
from datetime import datetime

def generate_uuid():
    return str(uuid.uuid4())

class ResourceType(str, enum.Enum):
    EC2 = "ec2"
    S3 = "s3"
    RDS = "rds"
    LAMBDA = "lambda"
    VPC = "vpc"
