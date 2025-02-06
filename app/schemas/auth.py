from pydantic import BaseModel, EmailStr, UUID4
from datetime import datetime
from typing import Optional

class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: str

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: UUID4
    api_key: Optional[str] = None
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
