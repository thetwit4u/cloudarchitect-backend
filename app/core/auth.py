from datetime import datetime
from typing import Optional
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from ..core.database import get_db
from .. import models
import logging

logger = logging.getLogger(__name__)

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

async def get_api_key(
    api_key_header: str = Security(api_key_header),
    db: Session = Depends(get_db)
) -> models.User:
    logger.info(f"Received API key header: {api_key_header[:8]}...")
    
    if not api_key_header:
        logger.warning("API key is missing")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key is missing"
        )
    
    # Get user by API key
    user = db.query(models.User).filter(
        models.User.api_key == api_key_header,
        models.User.is_active == True
    ).first()
    
    if not user:
        logger.warning(f"Invalid API key: {api_key_header[:8]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    logger.info(f"Authenticated user: {user.username}")
    return user

# Alias for backwards compatibility
get_current_user = get_api_key
