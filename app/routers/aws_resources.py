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
        Resource.arn == resource_data["arn"],
        Resource.project_id == project_id
    ).first()

    if existing:
        # Update existing resource
        for key, value in resource_data.items():
            if key != "id" and hasattr(existing, key):
                setattr(existing, key, value)
        resource = existing
    else:
        # Create new resource
        resource = Resource(
            project_id=project_id,
            **resource_data
        )
        db.add(resource)

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
    # Get project and verify access
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Get AWS credentials
    credentials = db.query(AWSCredentials).filter(
        AWSCredentials.project_id == project.id
    ).first()
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AWS credentials not found"
        )
    
    # Initialize AWS client
    aws = get_aws_client(credentials)
    
    try:
        # Discover EC2 instances
        instances = aws.list_ec2_instances()
        
        # Save each instance to the database
        saved_resources = []
        for instance in instances:
            resource_data = {
                "name": instance.get("name", instance["instance_id"]),
                "type": "ec2",
                "arn": instance["arn"],
                "region": credentials.region,
                "status": instance.get("state", {}).get("name"),
                "details": json.dumps(instance)
            }
            
            resource = save_resource(db, project_id, resource_data)
            saved_resources.append(resource)
        
        # Commit the transaction
        db.commit()
        
        # Convert to response schema
        response_resources = [
            ResourceSummary(
                type=r.type,
                name=r.name,
                arn=r.arn,
                region=r.region,
                status=r.status,
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
                arn=r.arn,
                region=r.region,
                status=r.status,
                details=EC2InstanceDetails(**json.loads(r.details))
            ) for r in saved_resources
        ]
        
    except Exception as e:
        db.rollback()
        logger.error(f"Error discovering EC2 instances: {str(e)}")
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
    # Verify project access
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.user_id == current_user.id
    ).first()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Query resources
    resources = db.query(Resource).filter(
        Resource.project_id == project_id,
        Resource.type == "ec2"
    ).all()
    
    # Convert to response schema
    return [
        AWSResourceResponse(
            id=str(r.id),
            name=r.name,
            type=r.type,
            arn=r.arn,
            region=r.region,
            status=r.status,
            details=EC2InstanceDetails(**json.loads(r.details))
        ) for r in resources
    ]
