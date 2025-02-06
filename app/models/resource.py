from sqlalchemy import Column, String, JSON, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from ..core.database import Base
import uuid

class Resource(Base):
    __tablename__ = "resources"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    resource_type = Column(String, index=True)
    name = Column(String, nullable=True)
    status = Column(String, nullable=True)
    resource_id = Column(String, index=True)
    region = Column(String, index=True)
    resource_metadata = Column(JSON, nullable=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # AWS specific fields
    arn = Column(String, nullable=True)
    vpc_id = Column(String, nullable=True)
    subnet_id = Column(String, nullable=True)
    security_groups = Column(JSON, nullable=True)
    public_ip = Column(String, nullable=True)
    private_ip = Column(String, nullable=True)
    tags = Column(JSON, nullable=True)

    # Relationships
    project = relationship("Project", back_populates="resources", overlaps="resources")

class ResourceMetrics(Base):
    __tablename__ = "resource_metrics"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    resource_id = Column(String, ForeignKey("resources.id", ondelete="CASCADE"), nullable=False)
    cpu_utilization = Column(JSON, nullable=True)  # Store time series data
    memory_utilization = Column(JSON, nullable=True)
    network_in = Column(JSON, nullable=True)
    network_out = Column(JSON, nullable=True)
    disk_read = Column(JSON, nullable=True)
    disk_write = Column(JSON, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    resource = relationship("Resource", back_populates="metrics")

# Add the metrics relationship to Resource
Resource.metrics = relationship("ResourceMetrics", back_populates="resource", cascade="all, delete-orphan")
