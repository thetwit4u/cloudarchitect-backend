from sqlalchemy import Column, String, ForeignKey, DateTime, func
from ..core.database import Base

class AWSConnection(Base):
    __tablename__ = "aws_connections"

    id = Column(String, primary_key=True, server_default=func.gen_random_uuid().cast(String))
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)
    aws_account_id = Column(String, nullable=False)
    aws_region = Column(String, nullable=False)
    aws_role_arn = Column(String, nullable=False)
    aws_external_id = Column(String, nullable=True)  # Optional external ID for enhanced security
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
