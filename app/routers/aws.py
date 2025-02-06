from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from ..schemas.aws import AWSCredentialsBase, StoredAWSCredentials
from ..core.database import get_db
from ..core.auth import get_current_user
from ..schemas.auth import UserResponse
from ..models import Project, AWSCredentials
from typing import List
from uuid import UUID

router = APIRouter(tags=["aws"])

@router.post("/credentials", response_model=StoredAWSCredentials)
async def store_aws_credentials(
    credentials: AWSCredentialsBase,
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user)
):
    # Check if project exists and user has access
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Check if credentials already exist for this project
    existing_credentials = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project_id
    ).first()

    if existing_credentials:
        # Update existing credentials
        existing_credentials.aws_access_key_id = credentials.aws_access_key_id
        existing_credentials.aws_secret_access_key = credentials.aws_secret_access_key
        existing_credentials.region = credentials.region
        db.commit()
        return existing_credentials

    # Create new credentials
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

@router.get("/credentials/{project_id}", response_model=StoredAWSCredentials)
async def get_aws_credentials(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user)
):
    # Check if project exists and user has access
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Get credentials
    credentials = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project_id
    ).first()
    
    if not credentials:
        raise HTTPException(status_code=404, detail="AWS credentials not found")
    
    return credentials
