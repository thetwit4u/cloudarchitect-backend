from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional, Dict
from ..schemas.aws import ResourceSummary
from ..services.aws_service import AWSService
from ..core.auth import get_current_user
from ..schemas.auth import UserResponse
from ..core.database import get_db
from sqlalchemy.orm import Session
import logging
from datetime import datetime, timedelta
from uuid import UUID

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter()

# Cache to store discovered resources
_resource_cache: Dict[str, Dict] = {}

def _get_cached_resources(project_id: str) -> Optional[List[ResourceSummary]]:
    """Get cached resources if they exist and are not expired"""
    if project_id in _resource_cache:
        cache_entry = _resource_cache[project_id]
        # Check if cache is still valid (less than 5 minutes old)
        if datetime.now() - cache_entry['timestamp'] < timedelta(minutes=5):
            return cache_entry['resources']
    return None

def _update_cache(project_id: str, resources: List[ResourceSummary]):
    """Update the resource cache"""
    _resource_cache[project_id] = {
        'resources': resources,
        'timestamp': datetime.now()
    }

@router.get("/{project_id}/resources", response_model=List[ResourceSummary])
def get_resources(
    project_id: UUID,
    resource_type: Optional[str] = None,
    region: Optional[str] = None,
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get all resources for a project with optional filtering
    """
    logger.info(f"Getting resources for project {project_id}")
    
    # Try to get resources from cache first
    cached_resources = _get_cached_resources(str(project_id))
    if cached_resources is not None:
        logger.info("Using cached resources")
        resources = cached_resources
    else:
        logger.info("No cached resources found")
        return []

    # Apply filters if provided
    if resource_type:
        logger.info(f"Filtering resources by type: {resource_type}")
        resources = [r for r in resources if r.type == resource_type]
    if region:
        logger.info(f"Filtering resources by region: {region}")
        resources = [r for r in resources if r.region == region]

    logger.info(f"Returning {len(resources)} resources")
    return resources

@router.post("/{project_id}/resources/discover")
def start_resource_discovery(
    project_id: UUID,
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Start the resource discovery process for a project
    """
    logger.info(f"Starting resource discovery for project {project_id}")
    try:
        aws_service = AWSService(db, str(project_id), str(current_user.id))
        resources = aws_service.list_resources()
        
        # Update cache with new resources
        _update_cache(str(project_id), resources)
        
        logger.info(f"Resource discovery completed. Found {len(resources)} resources")
        return {"status": "completed", "resource_count": len(resources)}
    except ValueError as e:
        logger.error(f"Error during resource discovery: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/{project_id}/resources/types")
def get_resource_types(
    project_id: UUID,
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get available resource types for a project
    """
    logger.info(f"Getting resource types for project {project_id}")
    
    # Use cached resources if available
    cached_resources = _get_cached_resources(str(project_id))
    if cached_resources is not None:
        resource_types = sorted(list(set(r.type for r in cached_resources)))
        logger.info(f"Found resource types from cache: {resource_types}")
        return {"resource_types": resource_types}
    
    return {"resource_types": []}

@router.get("/{project_id}/resources/summary")
def get_resource_summary(
    project_id: UUID,
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get resource count summary by type and status
    """
    logger.info(f"Getting resource summary for project {project_id}")
    
    # Use cached resources if available
    cached_resources = _get_cached_resources(str(project_id))
    if cached_resources is None:
        return {
            "total_resources": 0,
            "by_type": {},
            "by_status": {}
        }
    
    resources = cached_resources
    
    # Count resources by type
    type_summary = {}
    for resource in resources:
        resource_type = resource.type
        type_summary[resource_type] = type_summary.get(resource_type, 0) + 1
            
    # Count resources by status
    status_summary = {}
    for resource in resources:
        if resource.status:  # Only count resources that have a status
            status = resource.status
            status_summary[status] = status_summary.get(status, 0) + 1
    
    logger.info(f"Resource summary: {len(resources)} total, {type_summary} by type, {status_summary} by status")
    return {
        "total_resources": len(resources),
        "by_type": type_summary,
        "by_status": status_summary
    }

@router.get("/{project_id}/resources/discover/status")
def get_discovery_status(
    project_id: UUID,
    current_user: UserResponse = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get the status of the resource discovery process
    """
    logger.info(f"Checking discovery status for project {project_id}")
    try:
        aws_service = AWSService(db, str(project_id), str(current_user.id))
        # For now, we'll return a simple status since discovery is synchronous
        logger.info("Discovery status: completed")
        return {
            "status": "completed",
            "message": "Resource discovery is complete"
        }
    except ValueError as e:
        logger.error(f"Error checking discovery status: {str(e)}")
        return {
            "status": "error",
            "message": str(e)
        }
