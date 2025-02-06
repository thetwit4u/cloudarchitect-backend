from sqlalchemy import Column, String, ForeignKey, DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from ..core.database import Base

class AWSConnection(Base):
    __tablename__ = "aws_connections"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id = Column(UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    aws_account_id = Column(String, nullable=False)
    aws_region = Column(String, nullable=False)
    aws_role_arn = Column(String, nullable=False)
    aws_external_id = Column(String, nullable=True)  # Optional external ID for enhanced security
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    project = relationship("Project", back_populates="aws_connections")
    user = relationship("User", back_populates="aws_connections")
