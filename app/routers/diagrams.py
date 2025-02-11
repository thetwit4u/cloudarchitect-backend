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
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/projects/{project_id}/diagrams", response_model=DiagramResponse)
async def create_diagram(
    project_id: uuid.UUID,
    data: Optional[DiagramCreate] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new diagram for a project."""
    try:
        logger.info(f"Starting diagram creation for project {project_id}")
        service = DiagramService(db, str(project_id), str(current_user.id))
        
        # Extract relationships and create diagram
        logger.debug("Extracting resource relationships...")
        relationships = service.extract_relationships()
        logger.debug(f"Extracted relationships: {relationships}")
        
        # Count total resources
        logger.debug("Counting project resources...")
        resources = service.get_project_resources()
        resource_count = len(resources)
        logger.info(f"Found {resource_count} resources in project")
        
        # Create diagram history entry
        logger.debug("Creating diagram history entry...")
        metadata = {
            "resourceCount": resource_count,
            "generatedAt": datetime.now(timezone.utc).isoformat()
        }
        if data and data.diagram_metadata:
            metadata.update(data.diagram_metadata)
            
        diagram = DiagramHistory(
            project_id=project_id,
            user_id=current_user.id,
            version="1.0.0",  # Initial version
            diagram_metadata=metadata
        )
        db.add(diagram)
        
        try:
            # First commit to get the diagram ID
            logger.debug("Committing diagram...")
            db.commit()
            db.refresh(diagram)
            
            # Now create the layout with the diagram ID
            logger.debug("Creating initial layout...")
            layout = DiagramLayout(
                diagram_id=diagram.id,
                layout_data=relationships,
                is_default=True
            )
            db.add(layout)
            
            # Commit the layout
            logger.debug("Committing layout...")
            db.commit()
            logger.info(f"Successfully created diagram {diagram.id} for project {project_id}")
            return diagram
        except Exception as e:
            logger.error(f"Failed to commit diagram creation: {str(e)}")
            db.rollback()
            raise HTTPException(status_code=500, detail="Failed to create diagram")
    except Exception as e:
        logger.error(f"Error creating diagram: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/projects/{project_id}/diagrams", response_model=List[DiagramResponse])
async def get_diagram_history(
    project_id: uuid.UUID,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get diagram history for a project."""
    try:
        logger.info(f"Retrieving diagram history for project {project_id}")
        diagrams = db.query(DiagramHistory).filter(
            DiagramHistory.project_id == project_id
        ).order_by(
            DiagramHistory.created_at.desc()
        ).limit(limit).all()
        logger.debug(f"Found {len(diagrams)} diagrams in project history")
        return diagrams
    except Exception as e:
        logger.error(f"Error retrieving diagram history: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/projects/{project_id}/diagrams/{diagram_id}/layouts", response_model=LayoutResponse)
async def save_layout(
    project_id: uuid.UUID,
    diagram_id: uuid.UUID,
    layout: LayoutCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Save a new layout for a diagram."""
    try:
        logger.info(f"Saving layout for diagram {diagram_id} in project {project_id}")
        # Check if diagram exists and belongs to project
        diagram = db.query(DiagramHistory).filter(
            DiagramHistory.id == diagram_id,
            DiagramHistory.project_id == project_id
        ).first()
        
        if not diagram:
            logger.error(f"Diagram {diagram_id} not found in project {project_id}")
            raise HTTPException(status_code=404, detail="Diagram not found")
        
        # If this is set as default, unset any existing default layouts
        if layout.is_default:
            logger.debug("Unsetting existing default layouts...")
            db.query(DiagramLayout).filter(
                DiagramLayout.diagram_id == diagram_id,
                DiagramLayout.is_default == True
            ).update({"is_default": False})
        
        # Create new layout
        logger.debug("Creating new layout...")
        new_layout = DiagramLayout(
            diagram_id=diagram_id,
            layout_data=layout.layout_data,
            is_default=layout.is_default
        )
        db.add(new_layout)
        
        try:
            logger.debug("Committing transaction...")
            db.commit()
            db.refresh(new_layout)
            logger.info(f"Successfully saved layout {new_layout.id} for diagram {diagram_id}")
            return new_layout
        except Exception as e:
            logger.error(f"Failed to commit layout save: {str(e)}")
            db.rollback()
            raise HTTPException(status_code=500, detail="Failed to save layout")
    except Exception as e:
        logger.error(f"Error saving layout: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/projects/{project_id}/diagrams/{diagram_id}/layouts/default", response_model=LayoutResponse)
async def get_default_layout(
    project_id: uuid.UUID,
    diagram_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get the default layout for a diagram."""
    try:
        logger.info(f"Retrieving default layout for diagram {diagram_id} in project {project_id}")
        layout = db.query(DiagramLayout).filter(
            DiagramLayout.diagram_id == diagram_id,
            DiagramLayout.is_default == True
        ).first()
        
        if not layout:
            logger.error(f"Default layout not found for diagram {diagram_id}")
            raise HTTPException(status_code=404, detail="Default layout not found")
        
        logger.debug(f"Found default layout {layout.id} for diagram {diagram_id}")
        return layout
    except Exception as e:
        logger.error(f"Error retrieving default layout: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
