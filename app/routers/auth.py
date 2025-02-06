from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..core.auth import get_current_user, verify_password, create_access_token
from ..schemas.auth import UserCreate, UserResponse, Token, UserLogin
from .. import models
import secrets
import logging
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta

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
        # Create new user
        hashed_password = get_password_hash(user.password)
        api_key = generate_api_key()
        
        db_user = models.User(
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            hashed_password=hashed_password,
            api_key=api_key
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        logger.info(f"Successfully registered user: {user.email}")
        return db_user
    except Exception as e:
        logger.error(f"Error during registration: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during registration"
        )

@router.post("/login", response_model=UserResponse)
async def login(
    user_login: UserLogin,
    db: Session = Depends(get_db)
):
    """
    Login with username/email and password
    """
    try:
        # Try to find user by email first, then username
        user = db.query(models.User).filter(models.User.email == user_login.username).first()
        if not user:
            user = db.query(models.User).filter(models.User.username == user_login.username).first()
        
        if not user or not verify_password(user_login.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username/email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Generate new API key on login
        user.api_key = generate_api_key()
        db.commit()
        
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during login"
        )

@router.post("/login/token", response_model=Token)
async def login_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Login with username/email and password
    """
    # Try to find user by email first, then username
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user:
        user = db.query(models.User).filter(models.User.username == form_data.username).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/logout")
async def logout(current_user: models.User = Depends(get_current_user)):
    """
    Logout the current user
    Note: Since JWT tokens are stateless, this endpoint is mostly for frontend cleanup.
    The frontend should remove the token from storage.
    """
    return {"message": "Successfully logged out"}

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: models.User = Depends(get_current_user)
):
    """
    Get current user information
    """
    return current_user
