from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from ..schemas.project import Project, ProjectCreate
from ..core.auth import get_current_user
from ..core.database import get_db
from .. import models
from datetime import datetime
from uuid import UUID

router = APIRouter()

@router.post("", response_model=Project)
async def create_project(
    project: ProjectCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new project
    """
    now = datetime.utcnow()
    db_project = models.Project(
        name=project.name,
        description=project.description,
        user_id=current_user.id,
        created_at=now,
        updated_at=now
    )
    
    db.add(db_project)
    db.commit()
    db.refresh(db_project)
    return db_project

@router.get("", response_model=List[Project])
async def list_projects(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List all projects for the current user
    """
    return db.query(models.Project).filter(
        models.Project.user_id == current_user.id
    ).all()

@router.get("/{project_id}", response_model=Project)
async def get_project(
    project_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a specific project by ID
    """
    try:
        project_uuid = UUID(project_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = db.query(models.Project).filter(
        models.Project.id == project_uuid,
        models.Project.user_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return project

@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a project
    """
    try:
        project_uuid = UUID(project_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    project = db.query(models.Project).filter(
        models.Project.id == project_uuid,
        models.Project.user_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    db.delete(project)
    db.commit()
    
    return {"message": "Project deleted successfully"}
