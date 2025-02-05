from fastapi import APIRouter, Depends, HTTPException
from ..schemas.aws import AWSCredentials, StoredAWSCredentials
from ..services.aws_service import AWSService
from ..core.auth import get_current_user
from ..schemas.auth import User

router = APIRouter()

@router.post("/aws/connect", response_model=StoredAWSCredentials)
async def connect_aws(
    credentials: AWSCredentials,
    current_user: User = Depends(get_current_user)
):
    """
    Connect to AWS using provided credentials
    """
    try:
        # Create AWS session to validate credentials
        aws_service = AWSService(credentials)
        
        # Store credentials if valid
        stored_credentials = AWSService.store_credentials(credentials, current_user.id)
        return stored_credentials
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to connect to AWS: {str(e)}"
        )

@router.get("/aws/status/{project_id}")
async def check_aws_connection(
    project_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Check AWS connection status for a project
    """
    credentials = AWSService.get_credentials(project_id, current_user.id)
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
