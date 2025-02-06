from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ..core.database import get_db
from ..core.auth import get_current_user
from ..schemas.auth import UserResponse
from ..models import Project, AWSCredentials
from ..schemas.aws import AWSCredentialsCreate, AWSCredentialsResponse
from uuid import UUID

router = APIRouter(prefix="/projects/{project_id}/aws-credentials", tags=["aws-credentials"])

async def verify_project_access(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user)
) -> Project:
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(
            status_code=403,
            detail="You don't have access to this project"
        )
    
    return project

@router.post("", response_model=AWSCredentialsResponse)
async def create_aws_credentials(
    project_id: UUID,
    credentials: AWSCredentialsCreate,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
    project: Project = Depends(verify_project_access)
):
    existing_credentials = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project_id
    ).first()
    
    if existing_credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AWS credentials already exist for this project"
        )
    
    db_credentials = AWSCredentials(
        project_id=project_id,
        aws_access_key_id=credentials.aws_access_key_id,
        aws_secret_access_key=credentials.aws_secret_access_key,
        region=credentials.region
    )
    
    db.add(db_credentials)
    db.commit()
    db.refresh(db_credentials)
    
    return db_credentials

@router.get("", response_model=AWSCredentialsResponse)
async def get_aws_credentials(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
    project: Project = Depends(verify_project_access)
):
    credentials = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project_id
    ).first()
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AWS credentials not found"
        )
    
    return credentials

@router.get("/{credentials_id}", response_model=AWSCredentialsResponse)
async def get_aws_credentials_by_id(
    project_id: UUID,
    credentials_id: UUID,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
    project: Project = Depends(verify_project_access)
):
    credentials = db.query(AWSCredentials).filter(
        AWSCredentials.id == credentials_id,
        AWSCredentials.project_id == project_id
    ).first()
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AWS credentials not found"
        )
    
    return credentials

@router.delete("/{credentials_id}")
async def delete_aws_credentials_by_id(
    project_id: UUID,
    credentials_id: UUID,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
    project: Project = Depends(verify_project_access)
):
    credentials = db.query(AWSCredentials).filter(
        AWSCredentials.id == credentials_id,
        AWSCredentials.project_id == project_id
    ).first()
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AWS credentials not found"
        )
    
    db.delete(credentials)
    db.commit()
    return {"status": "success"}

@router.delete("")
async def delete_aws_credentials(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
    project: Project = Depends(verify_project_access)
):
    result = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project_id
    ).delete()
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AWS credentials not found"
        )
    
    db.commit()
    return None
