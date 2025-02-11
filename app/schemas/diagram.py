"""
Pydantic schemas for diagram operations.
"""
from typing import Dict, Optional
from pydantic import BaseModel, UUID4
from datetime import datetime

class DiagramBase(BaseModel):
    """Base schema for diagram operations."""
    diagram_metadata: Optional[Dict] = None

class DiagramCreate(DiagramBase):
    """Schema for creating a new diagram."""
    pass

class DiagramResponse(DiagramBase):
    """Schema for diagram responses."""
    id: UUID4
    project_id: UUID4
    user_id: UUID4
    version: str
    created_at: datetime

    class Config:
        orm_mode = True

class LayoutBase(BaseModel):
    """Base schema for layout operations."""
    layout_data: Dict
    is_default: bool = False

class LayoutCreate(LayoutBase):
    """Schema for creating a new layout."""
    pass

class LayoutResponse(LayoutBase):
    """Schema for layout responses."""
    id: UUID4
    diagram_id: UUID4
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
