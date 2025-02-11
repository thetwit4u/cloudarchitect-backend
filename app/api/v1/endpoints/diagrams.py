"""
API endpoints for diagram operations.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ....core.deps import get_db, get_current_user
from ....services.diagram_service import DiagramService
from ....schemas.diagram import (
    DiagramCreate,
    DiagramResponse,
    LayoutCreate,
    LayoutResponse
)
from uuid import UUID

router = APIRouter()

@router.post("/{project_id}/diagrams", response_model=DiagramResponse)
def create_diagram(
    project_id: UUID,
    metadata: Optional[DiagramCreate] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new diagram version for a project.
    """
    diagram_service = DiagramService(db, str(project_id), current_user["id"])
    try:
        diagram = diagram_service.save_diagram(metadata.dict() if metadata else None)
        return diagram
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{project_id}/diagrams", response_model=List[DiagramResponse])
def get_diagram_history(
    project_id: UUID,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get diagram version history for a project.
    """
    diagram_service = DiagramService(db, str(project_id), current_user["id"])
    return diagram_service.get_diagram_history(limit)

@router.post("/{project_id}/diagrams/{diagram_id}/layout", response_model=LayoutResponse)
def save_layout(
    project_id: UUID,
    diagram_id: UUID,
    layout: LayoutCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Save layout preferences for a diagram.
    """
    diagram_service = DiagramService(db, str(project_id), current_user["id"])
    try:
        return diagram_service.save_layout(
            str(diagram_id),
            layout.layout_data,
            layout.is_default
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{project_id}/diagrams/{diagram_id}/layout", response_model=LayoutResponse)
def get_layout(
    project_id: UUID,
    diagram_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get layout preferences for a diagram.
    """
    diagram_service = DiagramService(db, str(project_id), current_user["id"])
    layout = diagram_service.get_layout(str(diagram_id))
    if not layout:
        raise HTTPException(status_code=404, detail="Layout not found")
    return layout
