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
        # Create AWS session to validate credentials
        aws_service = AWSService(credentials)
        
        # Check if project exists
        project = db.query(models.Project).filter(
            models.Project.id == credentials.project_id,
            models.Project.user_id == current_user.id
        ).first()
        
        if not project:
            raise HTTPException(
                status_code=404,
                detail="Project not found or not authorized"
            )
        
        # Store credentials if valid
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
            status_code=400,
            detail=f"Failed to connect to AWS: {str(e)}"
        )

@router.get("/aws/status/{project_id}")
async def check_aws_connection(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Check AWS connection status for a project
    """
    # Get credentials from database
    credentials = db.query(models.AWSCredentials).join(models.Project).filter(
        models.Project.id == project_id,
        models.Project.user_id == current_user.id
    ).first()
    
    if not credentials:
        raise HTTPException(
            status_code=404,
            detail="AWS credentials not found for this project"
        )

    try:
        aws_service = AWSService(credentials)
        # Try to list resources as a connection test
        await aws_service.discover_resources()
        return {"status": "connected"}
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
