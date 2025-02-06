from fastapi import Depends, HTTPException, status, Request
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..models import User
import logging

logger = logging.getLogger(__name__)

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

def get_current_user(
    request: Request,
    api_key_header: str = Depends(api_key_header),
    db: Session = Depends(get_db)
) -> User:
    """
    Get the current user based on the API key in the header.
    """
    if not api_key_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key is missing"
        )

    query = db.query(User).filter(
        User.api_key == api_key_header,
        User.is_active == True
    )
    
    user = query.first()
    if not user:
        logger.error(f"Invalid API key attempt for path: {request.url.path}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )

    return user

# Alias for backwards compatibility
get_api_key = get_current_user
