from fastapi import Depends, HTTPException, status, Request
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from .database import get_db
from .. import models
import logging

logger = logging.getLogger(__name__)

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

async def get_api_key(
    request: Request,
    api_key_header: str = Depends(api_key_header),
    db: Session = Depends(get_db)
) -> models.User:
    """
    Get and validate the API key from the request header
    """
    logger.info("=== Starting API Key Authentication ===")
    logger.info(f"Received API key header: {api_key_header[:8]}...")
    logger.info(f"Current route path: {request.url.path}")
    
    # Query database for user with API key
    logger.info("Querying database for user with API key")
    query = db.query(models.User).filter(
        models.User.api_key == api_key_header,
        models.User.is_active == True
    )
    logger.info("SQL Query: " + str(query.statement.compile(compile_kwargs={'literal_binds': True})))
    
    user = query.first()
    if not user:
        logger.warning(f"No user found with API key: {api_key_header[:8]}...")
        logger.info("=== API Key Authentication Failed ===")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    logger.info(f"Found user: username={user.username}, id={user.id}, id_type={type(user.id)}")
    logger.info("=== API Key Authentication Successful ===")
    return user

# Alias for backwards compatibility
get_current_user = get_api_key
