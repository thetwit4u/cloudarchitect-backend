"""
API routes for AWS resource discovery and management.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ..core.database import get_db
from ..core.auth import get_current_user
from ..models import Project, AWSCredentials, User, Resource
from ..schemas.aws_resources import AWSResourceResponse, EC2InstanceDetails
from ..schemas.aws import ResourceSummary
from ..core.aws.boto3_client import AWSAPI
from .resources import _update_cache
import logging
import json

logger = logging.getLogger(__name__)
router = APIRouter()

def get_aws_client(credentials: AWSCredentials) -> AWSAPI:
    """Create an AWS API client from credentials"""
    return AWSAPI(
        access_key_id=credentials.aws_access_key_id,
        secret_access_key=credentials.aws_secret_access_key,
        region=credentials.region
    )

def save_resource(db: Session, project_id: str, resource_data: dict):
    """Save or update an AWS resource in the database"""
    existing = db.query(Resource).filter(
        Resource.resource_id == resource_data["resource_id"],
        Resource.project_id == project_id
    ).first()

    if existing:
        # Update existing resource
        logger.info(f"Updating existing resource: {resource_data['resource_id']}")
        for key, value in resource_data.items():
            if key != "id" and hasattr(existing, key):
                setattr(existing, key, value)
        resource = existing
        logger.info(f"Resource updated successfully: {resource.resource_id}")
    else:
        # Create new resource
        logger.info(f"Creating new resource: {resource_data['resource_id']}")
        resource = Resource(
            project_id=project_id,
            **resource_data
        )
        db.add(resource)
        logger.info(f"New resource created successfully: {resource.resource_id}")

    return resource

@router.post("/projects/{project_id}/discover/ec2", 
            response_model=List[AWSResourceResponse],
            status_code=status.HTTP_201_CREATED)
async def discover_ec2_instances(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Discover EC2 instances for a project using stored AWS credentials
    """
    logger.info(f"Starting EC2 discovery for project: {project_id}")
    
    # Get project and verify access
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
    
    # Get AWS credentials
    credentials = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project.id
    ).first()
    
    if not credentials:
        logger.warning(f"AWS credentials not found for project: {project_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AWS credentials not found"
        )
    
    # Initialize AWS client
    aws = get_aws_client(credentials)
    logger.info(f"AWS client initialized for region: {credentials.region}")
    
    try:
        # Discover EC2 instances
        instances = aws.discover_ec2_instances()
        logger.info(f"Discovered {len(instances)} EC2 instances")
        
        # Save each instance to the database
        saved_resources = []
        for instance in instances:
            # Create ARN for the instance
            instance_arn = f"arn:aws:ec2:{credentials.region}:{aws.get_account_id()}:instance/{instance['instance_id']}"
            
            # Extract tags into a dictionary
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            logger.debug(f"Processing instance: {instance['instance_id']} with tags: {tags}")
            
            # Prepare resource data
            resource_data = {
                "name": next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance['instance_id']),
                "type": "ec2",
                "resource_id": instance['instance_id'],
                "region": credentials.region,
                "status": instance['state'],
                "details": instance
            }
            
            # Save to database
            resource = save_resource(db, str(project.id), resource_data)
            saved_resources.append(resource)
        
        # Commit the transaction
        db.commit()
        logger.info(f"Successfully saved {len(saved_resources)} EC2 instances to database")
        
        # Convert to response schema
        response_resources = [
            ResourceSummary(
                id=str(r.id),
                name=r.name,
                type=r.type,
                resource_id=r.resource_id,
                region=r.details.get('region', 'unknown') if r.details else 'unknown',
                status=r.details.get('status', 'unknown') if r.details else 'unknown',
                details=r.details,
                created_at=r.created_at
            ) for r in saved_resources
        ]
        
        # Update the resource cache with the latest data
        _update_cache(str(project_id), response_resources)
        
        # Convert to AWSResourceResponse for the API response
        return [
            AWSResourceResponse(
                id=str(r.id),
                name=r.name,
                type=r.type,
                resource_id=r.resource_id,
                region=r.details.get('region', 'unknown') if r.details else 'unknown',
                status=r.details.get('status', 'unknown') if r.details else 'unknown',
                details=r.details,
                created_at=r.created_at
            ) for r in saved_resources
        ]
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error discovering EC2 instances: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error discovering EC2 instances: {str(e)}"
        )

@router.get("/projects/{project_id}/resources/ec2",
           response_model=List[AWSResourceResponse])
async def list_ec2_instances(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List all discovered EC2 instances for a project
    """
    logger.info(f"Fetching EC2 instances for project: {project_id}")
    
    # Verify project access
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
    
    # Query resources
    resources = db.query(Resource).filter(
        Resource.project_id == project_id,
        Resource.type == "ec2"
    ).all()
    
    logger.info(f"Found {len(resources)} EC2 instances in database")
    logger.debug("Resource details:")
    for r in resources:
        logger.debug(f"- {r.name} ({r.arn}): {r.status}")
    
    # Convert to response schema
    result = [
        AWSResourceResponse(
            id=r.id,
            name=r.name,
            type=r.type,
            resource_id=r.resource_id,
            region=r.details.get('region', 'unknown') if r.details else 'unknown',
            status=r.details.get('status', 'unknown') if r.details else 'unknown',
            details=r.details,
            created_at=r.created_at
        ) for r in resources
    ]
    
    logger.info(f"Successfully returned {len(result)} EC2 instances")
    return result
