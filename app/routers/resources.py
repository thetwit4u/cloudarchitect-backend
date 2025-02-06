from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from ..schemas.aws import ResourceSummary
from ..services.aws_service import AWSService
from ..core.auth import get_current_user
from ..schemas.auth import UserResponse

router = APIRouter()

@router.get("/{project_id}/resources", response_model=List[ResourceSummary])
async def get_resources(
    project_id: str,
    resource_type: Optional[str] = None,
    region: Optional[str] = None,
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Get all resources for a project with optional filtering
    """
    credentials = AWSService.get_credentials(project_id, current_user.id)
    if not credentials:
        return []

    aws_service = AWSService(credentials)
    resources = await aws_service.discover_resources()

    # Apply filters if provided
    if resource_type:
        resources = [r for r in resources if r.type == resource_type]
    if region:
        resources = [r for r in resources if r.region == region]

    return resources

@router.get("/{project_id}/resources/types")
async def get_resource_types(
    project_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Get available resource types for a project
    """
    credentials = AWSService.get_credentials(project_id, current_user.id)
    if not credentials:
        return {"resource_types": []}

    aws_service = AWSService(credentials)
    resources = await aws_service.discover_resources()
    
    # Extract unique resource types
    resource_types = sorted(list(set(r.type for r in resources)))
    return {"resource_types": resource_types}

@router.get("/{project_id}/resources/summary")
async def get_resource_summary(
    project_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Get resource count summary by type and status
    """
    credentials = AWSService.get_credentials(project_id, current_user.id)
    if not credentials:
        return {
            "total_resources": 0,
            "by_type": {},
            "by_status": {}
        }

    aws_service = AWSService(credentials)
    resources = await aws_service.discover_resources()
    
    # Count resources by type
    type_summary = {}
    for resource in resources:
        if resource.type not in type_summary:
            type_summary[resource.type] = 1
        else:
            type_summary[resource.type] += 1
            
    # Count resources by status
    status_summary = {}
    for resource in resources:
        if resource.status:
            if resource.status not in status_summary:
                status_summary[resource.status] = 1
            else:
                status_summary[resource.status] += 1
    
    return {
        "total_resources": len(resources),
        "by_type": type_summary,
        "by_status": status_summary
    }

@router.post("/{project_id}/resources/discover", status_code=status.HTTP_202_ACCEPTED)
async def start_resource_discovery(
    project_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Start the resource discovery process for a project
    """
    credentials = AWSService.get_credentials(project_id, current_user.id)
    if not credentials:
        return {
            "status": "error",
            "message": "AWS credentials not found for this project"
        }

    aws_service = AWSService(credentials)
    try:
        await aws_service.discover_resources()
        return {
            "status": "started",
            "message": "Resource discovery started successfully"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@router.get("/{project_id}/resources/discover/status")
async def get_discovery_status(
    project_id: str,
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Get the status of the resource discovery process
    """
    credentials = AWSService.get_credentials(project_id, current_user.id)
    if not credentials:
        return {
            "status": "error",
            "message": "AWS credentials not found for this project"
        }

    # For now, we'll return a simple status since discovery is synchronous
    return {
        "status": "completed",
        "message": "Resource discovery completed"
    }
