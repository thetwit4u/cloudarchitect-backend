from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional, Dict
from ..schemas.aws import ResourceSummary
from ..services.aws_service import AWSService
from ..core.auth import get_current_user
from ..schemas.auth import UserResponse
from ..core.database import get_db
from ..models import Resource, Project
from sqlalchemy.orm import Session
import logging
from datetime import datetime, timedelta
from uuid import UUID, uuid4
import json

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
        else:
            # Remove expired cache entry
            del _resource_cache[project_id]
    return None

def _update_cache(project_id: str, resources: List[ResourceSummary], db: Session):
    """Update both the resource cache and database"""
    logger.info(f"Updating resource cache and database for project {project_id} with {len(resources)} resources")
    
    # Update cache
    _resource_cache[project_id] = {
        'resources': resources,
        'timestamp': datetime.now()
    }
    
    # Update database
    for resource in resources:
        existing = db.query(Resource).filter(
            Resource.arn == resource.arn,
            Resource.project_id == UUID(project_id)
        ).first()
        
        resource_data = {
            "name": resource.name,
            "type": resource.type,
            "arn": resource.arn,
            "region": resource.region,
            "status": resource.status,
            "details": json.dumps(resource.details) if resource.details else None,
            "created_at": resource.created_at
        }
        
        if existing:
            logger.info(f"Updating existing resource in database: {resource.arn}")
            for key, value in resource_data.items():
                setattr(existing, key, value)
        else:
            logger.info(f"Creating new resource in database: {resource.arn}")
            new_resource = Resource(
                id=uuid4(),
                project_id=UUID(project_id),
                **resource_data
            )
            db.add(new_resource)
    
    try:
        db.commit()
        logger.info(f"Successfully persisted {len(resources)} resources to database")
    except Exception as e:
        db.rollback()
        logger.error(f"Error persisting resources to database: {str(e)}", exc_info=True)
        raise

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
    
    # Check project access
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()
    
    if not project:
        logger.warning(f"Project not found: {project_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Try to get from cache first
    cached_resources = _get_cached_resources(str(project_id))
    if cached_resources:
        logger.info(f"Returning {len(cached_resources)} resources from cache")
        return cached_resources
    
    # If not in cache, get from database
    query = db.query(Resource).filter(Resource.project_id == project_id)
    
    if resource_type:
        query = query.filter(Resource.type == resource_type)
    if region:
        query = query.filter(Resource.region == region)
    
    resources = query.all()
    logger.info(f"Found {len(resources)} resources in database")
    
    # Convert to ResourceSummary objects
    summaries = [
        ResourceSummary(
            id=str(r.id),
            name=r.name,
            type=r.type,
            arn=r.arn,
            region=r.region,
            status=r.status,
            details=json.loads(r.details) if r.details else None
        ) for r in resources
    ]
    
    # Update cache with database results
    _update_cache(str(project_id), summaries, db)
    
    return summaries

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
        _update_cache(str(project_id), resources, db)
        
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
    last_scan_time = None
    
    if str(project_id) in _resource_cache:
        last_scan_time = _resource_cache[str(project_id)]['timestamp']
    
    if cached_resources is None:
        return {
            "total_resources": 0,
            "by_type": {},
            "by_status": {},
            "regions": [],
            "last_scan_at": last_scan_time.isoformat() if last_scan_time else None
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
    
    # Get unique regions
    regions = sorted(list(set(r.region for r in resources if r.region)))
    
    logger.info(f"Resource summary: {len(resources)} total, {type_summary} by type, {status_summary} by status, regions: {regions}, last scan: {last_scan_time}")
    return {
        "total_resources": len(resources),
        "by_type": type_summary,
        "by_status": status_summary,
        "regions": regions,
        "last_scan_at": last_scan_time.isoformat() if last_scan_time else None
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
