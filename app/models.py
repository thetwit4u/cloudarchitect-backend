from sqlalchemy import Boolean, Column, ForeignKey, String, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID
from .core.database import Base
import uuid

def generate_uuid():
    return str(uuid.uuid4())

class BaseModel(Base):
    __abstract__ = True

    def to_dict(self):
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, uuid.UUID):
                value = str(value)
            result[column.name] = value
        return result

class User(BaseModel):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String, nullable=True)
    api_key = Column(String, unique=True, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    projects = relationship("Project", back_populates="user", cascade="all, delete-orphan")

class Project(BaseModel):
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

class Resource(BaseModel):
    __tablename__ = "resources"

    id = Column(UUID(as_uuid=True), primary_key=True, default=generate_uuid)
    name = Column(String)
    type = Column(String)
    arn = Column(String, unique=True)
    region = Column(String)
    status = Column(String, nullable=True)
    details = Column(String, nullable=True)  # JSON string for additional details
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    project = relationship("Project", back_populates="resources")

class AWSCredentials(BaseModel):
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
