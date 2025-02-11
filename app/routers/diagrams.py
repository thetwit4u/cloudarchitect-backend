"""
Router for diagram-related endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from ..core.database import get_db
from ..services.diagram_service import DiagramService
from ..schemas.diagram import DiagramResponse, DiagramCreate, LayoutResponse, LayoutCreate
from ..models import DiagramHistory, DiagramLayout
from ..core.auth import get_current_user
import uuid

router = APIRouter()

@router.post("/projects/{project_id}/diagrams", response_model=DiagramResponse)
async def create_diagram(
    project_id: uuid.UUID,
    data: Optional[DiagramCreate] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new diagram for a project."""
    service = DiagramService(db, str(project_id), current_user["id"])
    
    # Extract relationships and create diagram
    relationships = service.extract_relationships()
    
    # Create diagram history entry
    diagram = DiagramHistory(
        project_id=project_id,
        user_id=current_user["id"],
        version="1.0.0",  # Initial version
        diagram_metadata=data.diagram_metadata if data else {}
    )
    db.add(diagram)
    
    # Create initial layout
    layout = DiagramLayout(
        diagram_id=diagram.id,
        layout_data=relationships,
        is_default=True
    )
    db.add(layout)
    
    try:
        db.commit()
        db.refresh(diagram)
        return diagram
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/projects/{project_id}/diagrams", response_model=List[DiagramResponse])
async def get_diagram_history(
    project_id: uuid.UUID,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get diagram history for a project."""
    diagrams = db.query(DiagramHistory).filter(
        DiagramHistory.project_id == project_id
    ).order_by(
        DiagramHistory.created_at.desc()
    ).limit(limit).all()
    
    return diagrams

@router.post("/projects/{project_id}/diagrams/{diagram_id}/layouts", response_model=LayoutResponse)
async def save_layout(
    project_id: uuid.UUID,
    diagram_id: uuid.UUID,
    layout: LayoutCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Save a new layout for a diagram."""
    # Check if diagram exists and belongs to project
    diagram = db.query(DiagramHistory).filter(
        DiagramHistory.id == diagram_id,
        DiagramHistory.project_id == project_id
    ).first()
    
    if not diagram:
        raise HTTPException(status_code=404, detail="Diagram not found")
    
    # If this is set as default, unset any existing default layouts
    if layout.is_default:
        db.query(DiagramLayout).filter(
            DiagramLayout.diagram_id == diagram_id,
            DiagramLayout.is_default == True
        ).update({"is_default": False})
    
    # Create new layout
    new_layout = DiagramLayout(
        diagram_id=diagram_id,
        layout_data=layout.layout_data,
        is_default=layout.is_default
    )
    db.add(new_layout)
    
    try:
        db.commit()
        db.refresh(new_layout)
        return new_layout
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/projects/{project_id}/diagrams/{diagram_id}/layouts/default", response_model=LayoutResponse)
async def get_default_layout(
    project_id: uuid.UUID,
    diagram_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get the default layout for a diagram."""
    layout = db.query(DiagramLayout).filter(
        DiagramLayout.diagram_id == diagram_id,
        DiagramLayout.is_default == True
    ).first()
    
    if not layout:
        raise HTTPException(status_code=404, detail="Default layout not found")
    
    return layout
