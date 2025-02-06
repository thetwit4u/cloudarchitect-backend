from fastapi import APIRouter, Depends, HTTPException, status, Path
from sqlalchemy.orm import Session
from typing import List, Annotated
from ..core.database import get_db
from ..core.auth import get_current_user
from ..models import Project, AWSCredentials, User
from ..schemas.aws import AWSCredentialsCreate, AWSCredentialsResponse
from uuid import UUID
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

def get_project_access(
    project_id: str = Path(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Project:
    """
    Verify that the current user has access to the specified project
    """
    try:
        project_uuid = UUID(project_id)
    except ValueError:
        logger.error(f"Invalid project ID format: {project_id}")
        raise HTTPException(
            status_code=400,
            detail="Invalid project ID format"
        )
    
    project = db.query(Project).filter(
        Project.id == project_uuid,
        Project.user_id == current_user.id
    ).first()

    if not project:
        # Get all projects for this user to debug
        all_projects = db.query(Project).filter(Project.user_id == current_user.id).all()
        logger.warning(f"Access denied: User {current_user.username} attempted to access project {project_id}")
        raise HTTPException(
            status_code=403,
            detail="You don't have access to this project"
        )
    
    return project

@router.get("/projects/{project_id}/aws-connections", response_model=List[AWSCredentialsResponse])
async def get_aws_credentials(
    project_id: str = Path(...),
    project: Project = Depends(get_project_access),
    db: Session = Depends(get_db)
):
    """
    Get all AWS credentials for a project
    """
    credentials = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project.id
    ).all()
    
    return credentials

@router.post("/projects/{project_id}/aws-connections", response_model=AWSCredentialsResponse)
async def create_aws_credentials(
    credentials: AWSCredentialsCreate,
    project_id: str = Path(...),
    project: Project = Depends(get_project_access),
    db: Session = Depends(get_db)
):
    """
    Create AWS credentials for a project
    """
    # Check if credentials already exist for this project
    existing = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project.id
    ).first()

    if existing:
        logger.warning(f"Attempted to create duplicate AWS credentials for project {project.id}")
        raise HTTPException(
            status_code=400,
            detail="AWS credentials already exist for this project"
        )

    db_credentials = AWSCredentials(
        project_id=project.id,
        aws_access_key_id=credentials.aws_access_key_id,
        aws_secret_access_key=credentials.aws_secret_access_key,
        region=credentials.region
    )
    
    db.add(db_credentials)
    db.commit()
    db.refresh(db_credentials)
    
    return db_credentials

@router.get("/projects/{project_id}/aws-connections/{credentials_id}", response_model=AWSCredentialsResponse)
async def get_aws_credentials_by_id(
    project_id: str = Path(...),
    credentials_id: str = Path(...),
    project: Project = Depends(get_project_access),
    db: Session = Depends(get_db)
):
    """
    Get specific AWS credentials by ID
    """
    try:
        credentials_uuid = UUID(credentials_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid credentials ID format"
        )

    credentials = db.query(AWSCredentials).filter(
        AWSCredentials.id == credentials_uuid,
        AWSCredentials.project_id == project.id
    ).first()
    
    if not credentials:
        logger.warning(f"AWS credentials {credentials_id} not found for project {project.id}")
        raise HTTPException(
            status_code=404,
            detail="AWS credentials not found"
        )
    
    return credentials

@router.delete("/projects/{project_id}/aws-connections/{credentials_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_aws_credentials_by_id(
    project_id: str = Path(...),
    credentials_id: str = Path(...),
    project: Project = Depends(get_project_access),
    db: Session = Depends(get_db)
):
    """
    Delete AWS credentials by ID
    """
    try:
        credentials_uuid = UUID(credentials_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid credentials ID format"
        )

    result = db.query(AWSCredentials).filter(
        AWSCredentials.id == credentials_uuid,
        AWSCredentials.project_id == project.id
    ).delete()
    
    if not result:
        logger.warning(f"Attempted to delete non-existent AWS credentials {credentials_id} for project {project.id}")
        raise HTTPException(
            status_code=404,
            detail="AWS credentials not found"
        )
    
    db.commit()
    return {"message": "AWS credentials deleted successfully"}

@router.delete("/projects/{project_id}/aws-connections", status_code=status.HTTP_204_NO_CONTENT)
async def delete_aws_credentials(
    project_id: str = Path(...),
    project: Project = Depends(get_project_access),
    db: Session = Depends(get_db)
):
    """
    Delete AWS credentials
    """
    query = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project.id
    )
    credentials = query.first()
    if not credentials:
        logger.warning(f"AWS credentials not found for project {project.id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AWS credentials not found"
        )
    
    db.delete(credentials)
    db.commit()
    logger.info("AWS credentials deleted successfully")
    logger.info("=== AWS Credentials Deletion Complete ===")
    return {"message": "AWS credentials deleted successfully"}
