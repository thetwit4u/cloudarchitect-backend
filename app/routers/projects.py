from fastapi import APIRouter, Depends, HTTPException
from typing import List
from ..schemas.project import Project, ProjectCreate
from ..core.auth import get_current_user
from ..schemas.auth import User
from datetime import datetime
import uuid

router = APIRouter()

# In-memory storage for demo purposes
projects_db = {}

@router.post("", response_model=Project)
async def create_project(
    project: ProjectCreate,
    current_user: User = Depends(get_current_user)
):
    """
    Create a new project
    """
    project_id = str(uuid.uuid4())
    now = datetime.utcnow()
    
    db_project = Project(
        id=project_id,
        name=project.name,
        description=project.description,
        created_at=now,
        updated_at=now,
        user_id=current_user.id
    )
    
    projects_db[project_id] = db_project
    return db_project

@router.get("", response_model=List[Project])
async def list_projects(current_user: User = Depends(get_current_user)):
    """
    List all projects for the current user
    """
    user_projects = [
        project for project in projects_db.values()
        if project.user_id == current_user.id
    ]
    return user_projects

@router.get("/{project_id}", response_model=Project)
async def get_project(
    project_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get a specific project by ID
    """
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")
        
    project = projects_db[project_id]
    if project.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this project")
        
    return project

@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Delete a project
    """
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")
        
    project = projects_db[project_id]
    if project.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this project")
        
    del projects_db[project_id]
    return {"message": "Project deleted successfully"}
