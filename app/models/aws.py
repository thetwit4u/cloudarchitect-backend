from sqlalchemy import Column, String, DateTime, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from ..core.database import Base
import uuid

class AWSCredentials(Base):
    __tablename__ = "aws_credentials"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"))
    aws_access_key_id = Column(String)
    aws_secret_access_key = Column(String)
    region = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    project = relationship("Project", back_populates="aws_credentials")

class Resource(Base):
    __tablename__ = "resources"

    id = Column(String, primary_key=True)
    type = Column(String, index=True)
    name = Column(String, nullable=True)
    status = Column(String, nullable=True)
    project_id = Column(String, ForeignKey("projects.id"))
    region = Column(String)
    resource_metadata = Column(JSON, nullable=True)  # Renamed from metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    arn = Column(String, nullable=True)
    vpc_id = Column(String, nullable=True)
    subnet_id = Column(String, nullable=True)
    security_groups = Column(JSON, nullable=True)
    public_ip = Column(String, nullable=True)
    private_ip = Column(String, nullable=True)
    tags = Column(JSON, nullable=True)

    # Relationships
    project = relationship("Project")
    metrics = relationship("ResourceMetrics", back_populates="resource", cascade="all, delete-orphan")

class ResourceMetrics(Base):
    __tablename__ = "resource_metrics"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    resource_id = Column(String, ForeignKey("resources.id"))
    cpu_utilization = Column(JSON, nullable=True)  # Store time series data
    memory_utilization = Column(JSON, nullable=True)
    network_in = Column(JSON, nullable=True)
    network_out = Column(JSON, nullable=True)
    disk_read = Column(JSON, nullable=True)
    disk_write = Column(JSON, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    resource = relationship("Resource", back_populates="metrics")
