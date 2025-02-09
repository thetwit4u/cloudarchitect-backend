from sqlalchemy import Boolean, Column, ForeignKey, String, DateTime, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID
from ..core.database import Base
import uuid

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)
    api_key = Column(String, unique=True, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    projects = relationship("Project", back_populates="user", cascade="all, delete-orphan")

class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    name = Column(String)
    description = Column(String, nullable=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="projects")
    resources = relationship("Resource", back_populates="project", cascade="all, delete-orphan")
    aws_credentials = relationship("AWSCredentials", back_populates="project", cascade="all, delete-orphan", uselist=False)
    aws_resources = relationship("AWSResource", back_populates="project", cascade="all, delete-orphan")

class Resource(Base):
    __tablename__ = "resources"

    id = Column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    name = Column(String, nullable=True)
    type = Column(String, index=True)
    resource_id = Column(String, index=True, unique=True)
    details = Column(JSON)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    project = relationship("Project", back_populates="resources")

    def to_dict(self):
        """Convert the model instance to a dictionary"""
        return {
            'id': str(self.id),
            'name': self.name,
            'type': self.type,
            'resource_id': self.resource_id,
            'details': self.details,
            'project_id': str(self.project_id),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class AWSCredentials(Base):
    __tablename__ = "aws_credentials"

    id = Column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"))
    aws_access_key_id = Column(String)
    aws_secret_access_key = Column(String)
    region = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    project = relationship("Project", back_populates="aws_credentials")

User = User
Project = Project
AWSCredentials = AWSCredentials
Resource = Resource

__all__ = ["User", "Project", "AWSCredentials", "Resource"]
