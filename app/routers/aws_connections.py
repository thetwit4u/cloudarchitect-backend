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
    logger.info("=== Starting Project Access Verification ===")
    logger.info(f"Project ID from path (raw): {project_id}")
    logger.info(f"Current user: id={current_user.id} ({type(current_user.id)}), username={current_user.username}")
    
    try:
        project_uuid = UUID(project_id)
        logger.info(f"Project ID converted to UUID: {project_uuid} ({type(project_uuid)})")
    except ValueError:
        logger.error(f"Invalid project ID format: {project_id}")
        raise HTTPException(
            status_code=400,
            detail="Invalid project ID format"
        )
    
    # Debug query
    query = db.query(Project).filter(
        Project.id == project_uuid,
        Project.user_id == current_user.id
    )
    logger.info("Executing SQL Query:")
    logger.info(f"SQL: {query.statement.compile(compile_kwargs={'literal_binds': True})}")
    
    project = query.first()
    if project:
        logger.info(f"Found project:")
        logger.info(f"  ID: {project.id} ({type(project.id)})")
        logger.info(f"  Name: {project.name}")
        logger.info(f"  User ID: {project.user_id} ({type(project.user_id)})")
        logger.info("=== Project Access Verification Successful ===")
    else:
        # Get all projects for this user to debug
        all_projects = db.query(Project).filter(Project.user_id == current_user.id).all()
        logger.warning(f"No project found with id={project_uuid} and user_id={current_user.id}")
        logger.warning(f"All projects for user {current_user.username}:")
        for p in all_projects:
            logger.warning(f"  - ID: {p.id} ({type(p.id)}), Name: {p.name}")
        logger.info("=== Project Access Verification Failed ===")
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
    Get AWS credentials for a project
    """
    logger.info("=== Getting AWS Credentials ===")
    logger.info(f"Project ID from path: {project_id}")
    logger.info(f"Project ID from dependency: {project.id}")
    
    query = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project.id
    )
    logger.info("Executing SQL Query:")
    logger.info(f"SQL: {query.statement.compile(compile_kwargs={'literal_binds': True})}")
    
    credentials = query.all()
    logger.info(f"Found {len(credentials)} AWS credentials")
    logger.info("=== AWS Credentials Retrieved Successfully ===")
    
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
    logger.info("=== Creating AWS Credentials ===")
    logger.info(f"Project ID from path: {project_id}")
    logger.info(f"Project ID from dependency: {project.id}")
    
    # Check for existing credentials
    existing_query = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project.id
    )
    logger.info("Checking for existing credentials:")
    logger.info(f"SQL: {existing_query.statement.compile(compile_kwargs={'literal_binds': True})}")
    
    existing_credentials = existing_query.first()
    if existing_credentials:
        logger.warning(f"AWS credentials already exist for project {project.id}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AWS credentials already exist for this project"
        )
    
    # Create new credentials
    db_credentials = AWSCredentials(
        project_id=project.id,
        aws_access_key_id=credentials.aws_access_key_id,
        aws_secret_access_key=credentials.aws_secret_access_key,
        region=credentials.region
    )
    
    db.add(db_credentials)
    db.commit()
    db.refresh(db_credentials)
    
    logger.info("AWS credentials created successfully")
    logger.info("=== AWS Credentials Creation Complete ===")
    return db_credentials

@router.get("/projects/{project_id}/aws-connections/{credentials_id}", response_model=AWSCredentialsResponse)
async def get_aws_credentials_by_id(
    project_id: str = Path(...),
    credentials_id: str = Path(...),
    project: Project = Depends(get_project_access),
    db: Session = Depends(get_db)
):
    logger.info("=== Getting AWS Credentials By ID ===")
    logger.info(f"Project ID from path: {project_id}")
    logger.info(f"Project ID from dependency: {project.id}")
    logger.info(f"Credentials ID: {credentials_id}")
    
    try:
        credentials_uuid = UUID(credentials_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid credentials ID format"
        )
    
    query = db.query(AWSCredentials).filter(
        AWSCredentials.id == credentials_uuid,
        AWSCredentials.project_id == project.id
    )
    logger.info("Executing SQL Query:")
    logger.info(f"SQL: {query.statement.compile(compile_kwargs={'literal_binds': True})}")
    
    credentials = query.first()
    if not credentials:
        logger.warning(f"AWS credentials not found for project {project.id} and credentials ID {credentials_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AWS credentials not found"
        )
    
    logger.info("AWS credentials found successfully")
    logger.info("=== AWS Credentials Retrieved By ID Successfully ===")
    return credentials

@router.delete("/projects/{project_id}/aws-connections/{credentials_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_aws_credentials_by_id(
    project_id: str = Path(...),
    credentials_id: str = Path(...),
    project: Project = Depends(get_project_access),
    db: Session = Depends(get_db)
):
    logger.info("=== Deleting AWS Credentials By ID ===")
    logger.info(f"Project ID from path: {project_id}")
    logger.info(f"Project ID from dependency: {project.id}")
    logger.info(f"Credentials ID: {credentials_id}")
    
    try:
        credentials_uuid = UUID(credentials_id)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid credentials ID format"
        )
    
    query = db.query(AWSCredentials).filter(
        AWSCredentials.id == credentials_uuid,
        AWSCredentials.project_id == project.id
    )
    logger.info("Executing SQL Query:")
    logger.info(f"SQL: {query.statement.compile(compile_kwargs={'literal_binds': True})}")
    
    credentials = query.first()
    if not credentials:
        logger.warning(f"AWS credentials not found for project {project.id} and credentials ID {credentials_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AWS credentials not found"
        )
    
    db.delete(credentials)
    db.commit()
    logger.info("AWS credentials deleted successfully")
    logger.info("=== AWS Credentials Deletion By ID Complete ===")
    return {"message": "AWS credentials deleted successfully"}

@router.delete("/projects/{project_id}/aws-connections", status_code=status.HTTP_204_NO_CONTENT)
async def delete_aws_credentials(
    project_id: str = Path(...),
    project: Project = Depends(get_project_access),
    db: Session = Depends(get_db)
):
    logger.info("=== Deleting AWS Credentials ===")
    logger.info(f"Project ID from path: {project_id}")
    logger.info(f"Project ID from dependency: {project.id}")
    
    query = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project.id
    )
    logger.info("Executing SQL Query:")
    logger.info(f"SQL: {query.statement.compile(compile_kwargs={'literal_binds': True})}")
    
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
