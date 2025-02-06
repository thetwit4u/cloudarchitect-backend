from pydantic import BaseModel, EmailStr
from typing import Optional

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: str | None = None

class UserCreate(UserBase):
    pass

class User(UserBase):
    id: str
    api_key: str
    is_active: bool
    
    class Config:
        from_attributes = True

class UserInDB(User):
    hashed_password: str
