from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..core.auth import get_current_user
from ..schemas.auth import UserCreate, UserResponse
from .. import models
import secrets
import logging
from passlib.context import CryptContext

logger = logging.getLogger(__name__)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter()

def generate_api_key():
    return secrets.token_urlsafe(32)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

@router.post("/register", response_model=UserResponse)
async def register_user(
    user: UserCreate,
    db: Session = Depends(get_db)
):
    """
    Register a new user and get an API key
    """
    logger.info(f"Attempting to register user with email: {user.email}")
    
    # Check if user already exists
    existing_email = db.query(models.User).filter(
        models.User.email == user.email
    ).first()
    
    if existing_email:
        logger.warning(f"Registration failed: Email already exists: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    existing_username = db.query(models.User).filter(
        models.User.username == user.username
    ).first()
    
    if existing_username:
        logger.warning(f"Registration failed: Username already taken: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    try:
        # Create new user with API key
        api_key = generate_api_key()
        logger.info(f"Generated API key for user {user.email}: {api_key[:8]}...")
        
        db_user = models.User(
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            hashed_password=get_password_hash(user.password),
            api_key=api_key,
            is_active=True  # Ensure user is active by default
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        logger.info(f"Successfully registered user: {user.email}")
        return db_user
        
    except Exception as e:
        logger.error(f"Error during user registration: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during registration"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: models.User = Depends(get_current_user)
):
    """
    Get current user information
    """
    return current_user
