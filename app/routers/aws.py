from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..schemas.aws import AWSCredentials, StoredAWSCredentials
from ..services.aws_service import AWSService
from ..core.auth import get_current_user
from ..schemas.auth import User
from ..core.database import get_db
from .. import models

router = APIRouter()

@router.post("/aws/connect", response_model=StoredAWSCredentials)
async def connect_aws(
    credentials: AWSCredentials,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Connect to AWS using provided credentials
    """
    try:
        # Create AWS service to validate credentials
        aws_service = AWSService(credentials)
        
        # Check if project exists and belongs to user
        project = db.query(models.Project).filter(
            models.Project.id == credentials.project_id,
            models.Project.user_id == current_user.id
        ).first()
        
        if not project:
            raise HTTPException(
                status_code=404,
                detail="Project not found or not authorized"
            )

        # Validate AWS credentials
        try:
            aws_service.validate_credentials()
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=str(e)
            )
        
        # Check if credentials already exist for this project
        existing_credentials = db.query(models.AWSCredentials).filter(
            models.AWSCredentials.project_id == credentials.project_id
        ).first()

        if existing_credentials:
            # Update existing credentials
            existing_credentials.aws_access_key_id = credentials.aws_access_key_id
            existing_credentials.aws_secret_access_key = credentials.aws_secret_access_key
            existing_credentials.region = credentials.region
            db_credentials = existing_credentials
        else:
            # Store new credentials
            db_credentials = models.AWSCredentials(
                project_id=credentials.project_id,
                aws_access_key_id=credentials.aws_access_key_id,
                aws_secret_access_key=credentials.aws_secret_access_key,
                region=credentials.region
            )
            db.add(db_credentials)
        
        db.commit()
        db.refresh(db_credentials)
        return db_credentials
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.get("/aws/connect/{project_id}", response_model=StoredAWSCredentials)
async def check_aws_connection(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Check AWS connection status for a project
    """
    # Check if project exists and belongs to user
    project = db.query(models.Project).filter(
        models.Project.id == project_id,
        models.Project.user_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found or not authorized"
        )
    
    # Get AWS credentials
    credentials = db.query(models.AWSCredentials).filter(
        models.AWSCredentials.project_id == project_id
    ).first()
    
    if not credentials:
        raise HTTPException(
            status_code=404,
            detail="AWS credentials not found for this project"
        )
    
    return credentials
