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
    
    try:
        # First, get all existing resources for this project
        existing_resources = db.query(Resource).filter(
            Resource.project_id == UUID(project_id)
        ).all()
        logger.info(f"Found {len(existing_resources)} existing resources in database")
        
        # Create a map of resource IDs to existing resources for faster lookup
        existing_map = {r.resource_id: r for r in existing_resources}
        
        # Keep track of processed resource IDs
        processed_ids = set()
        
        # Update database
        for resource in resources:
            logger.debug(f"Processing resource: {resource.resource_id}")
            processed_ids.add(resource.resource_id)
            
            resource_data = {
                "name": resource.name,
                "type": resource.resource_type.value,
                "resource_id": resource.resource_id,
                "region": resource.region,
                "details": json.dumps(resource.details) if resource.details else None,
                "project_id": UUID(project_id)
            }
            
            if resource.resource_id in existing_map:
                # Update existing resource
                existing_resource = existing_map[resource.resource_id]
                for key, value in resource_data.items():
                    setattr(existing_resource, key, value)
            else:
                # Create new resource
                new_resource = Resource(**resource_data)
                db.add(new_resource)
        
        # Delete resources that no longer exist
        for resource in existing_resources:
            if resource.resource_id not in processed_ids:
                db.delete(resource)
        
        db.commit()
        
    except Exception as e:
        logger.error(f"Error persisting resources to database: {str(e)}")
        db.rollback()
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
    
    # Get from database
    query = db.query(Resource).filter(Resource.project_id == project_id)
    
    if resource_type:
        logger.debug(f"Filtering by resource type: {resource_type}")
        query = query.filter(Resource.type == resource_type)
    if region:
        logger.debug(f"Filtering by region: {region}")
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
            details=json.loads(r.details) if r.details else None,
            created_at=r.created_at
        ) for r in resources
    ]
    
    logger.info(f"Returning {len(summaries)} resources")
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
        
        aws_service = AWSService(db, str(project_id), str(current_user.id))
        resources = aws_service.list_resources()
        
        logger.info(f"Resource discovery found {len(resources)} resources")
        if resources:
            logger.debug(f"First discovered resource: {resources[0].dict()}")
        
        # Update cache with new resources
        _update_cache(str(project_id), resources, db)
        
        # Verify resources were saved
        saved_resources = db.query(Resource).filter(Resource.project_id == project_id).all()
        logger.info(f"Verified {len(saved_resources)} resources saved to database")
        if saved_resources:
            logger.debug(f"First saved resource: {vars(saved_resources[0])}")
        
        logger.info(f"Resource discovery completed successfully")
        return {"message": "Resource discovery started", "resource_count": len(resources)}
        
    except Exception as e:
        logger.error(f"Error during resource discovery: {str(e)}", exc_info=True)
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
    
    # Get all resources from database
    resources = db.query(Resource).filter(
        Resource.project_id == project_id
    ).all()
    
    logger.info(f"Found {len(resources)} resources in database")
    
    # Initialize summary dictionaries
    type_summary = {}
    status_summary = {}
    region_summary = {}
    
    # Calculate summaries
    for resource in resources:
        # Type summary
        resource_type = resource.type
        type_summary[resource_type] = type_summary.get(resource_type, 0) + 1
        
        # Status summary (from details)
        status = resource.details.get('status', 'unknown') if resource.details else 'unknown'
        status_summary[status] = status_summary.get(status, 0) + 1
        
        # Region summary (from details)
        region = resource.details.get('region', 'unknown') if resource.details else 'unknown'
        region_summary[region] = region_summary.get(region, 0) + 1
    
    return {
        "type_summary": type_summary,
        "status_summary": status_summary,
        "region_summary": region_summary,
        "total_resources": len(resources)
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
