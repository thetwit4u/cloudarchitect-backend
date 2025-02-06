from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from ..core.database import get_db
from ..models.aws_connection import AWSConnection
from ..schemas.aws_connection import AWSConnectionCreate, AWSConnection as AWSConnectionSchema
from ..core.auth import get_current_user
from uuid import UUID

router = APIRouter(prefix="/api/v1/projects/{project_id}/aws-connections", tags=["aws-connections"])

@router.post("", response_model=AWSConnectionSchema)
async def create_aws_connection(
    project_id: UUID,
    connection: AWSConnectionCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    db_connection = AWSConnection(
        **connection.model_dump(),
        project_id=project_id
    )
    db.add(db_connection)
    db.commit()
    db.refresh(db_connection)
    return db_connection

@router.get("", response_model=List[AWSConnectionSchema])
async def list_aws_connections(
    project_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    connections = db.query(AWSConnection).filter(AWSConnection.project_id == project_id).all()
    return connections

@router.get("/{connection_id}", response_model=AWSConnectionSchema)
async def get_aws_connection(
    project_id: UUID,
    connection_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    connection = db.query(AWSConnection).filter(
        AWSConnection.id == connection_id,
        AWSConnection.project_id == project_id
    ).first()
    if not connection:
        raise HTTPException(status_code=404, detail="AWS connection not found")
    return connection

@router.delete("/{connection_id}")
async def delete_aws_connection(
    project_id: UUID,
    connection_id: UUID,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    connection = db.query(AWSConnection).filter(
        AWSConnection.id == connection_id,
        AWSConnection.project_id == project_id
    ).first()
    if not connection:
        raise HTTPException(status_code=404, detail="AWS connection not found")
    db.delete(connection)
    db.commit()
    return {"status": "success"}
