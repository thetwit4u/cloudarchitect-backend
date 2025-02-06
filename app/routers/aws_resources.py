"""
API routes for AWS resource discovery and management.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ..core.database import get_db
from ..core.auth import get_current_user
from ..models import Project, AWSCredentials, User, AWSResource
from ..schemas.aws_resources import AWSResourceResponse, EC2InstanceDetails
from ..core.aws.boto3_client import AWSAPI
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

def get_aws_client(credentials: AWSCredentials) -> AWSAPI:
    """Create an AWS API client from credentials"""
    return AWSAPI(
        access_key_id=credentials.aws_access_key_id,
        secret_access_key=credentials.aws_secret_access_key,
        region=credentials.region
    )

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
            detail="AWS credentials not found for this project"
        )
    
    # Initialize AWS client
    aws_client = get_aws_client(credentials)
    
    try:
        # Discover EC2 instances
        instances = aws_client.discover_ec2_instances()
        
        # Store discovered instances
        resources = []
        for instance in instances:
            # Create or update resource
            resource = db.query(AWSResource).filter(
                AWSResource.resource_id == instance['instance_id'],
                AWSResource.project_id == project.id
            ).first()
            
            if not resource:
                resource = AWSResource(
                    resource_id=instance['instance_id'],
                    resource_type='ec2',
                    name=next((tag['Value'] for tag in instance['tags'] 
                             if tag['Key'] == 'Name'), None),
                    region=credentials.region,
                    details=instance,
                    credentials_id=credentials.id,
                    project_id=project.id
                )
                db.add(resource)
            else:
                resource.details = instance
                resource.name = next((tag['Value'] for tag in instance['tags'] 
                                    if tag['Key'] == 'Name'), None)
            
            resources.append(resource)
        
        db.commit()
        
        return resources
    
    except Exception as e:
        logger.error(f"Failed to discover EC2 instances: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to discover EC2 instances: {str(e)}"
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
    
    # Get EC2 resources
    resources = db.query(AWSResource).filter(
        AWSResource.project_id == project.id,
        AWSResource.resource_type == 'ec2'
    ).all()
    
    return resources
