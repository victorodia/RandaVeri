from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict
from datetime import datetime

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    telephone: Optional[str] = None

class RegisterUser(BaseModel):
    username: str
    email: EmailStr
    password: str
    telephone: Optional[str] = None
    organisation_id: Optional[int] = None
    roles: str = "IDENTITY,WALLET"

class OrgCreate(BaseModel):
    name: str
    slug: str
    primary_color: str = "#3B82F6"
    secondary_color: str = "#64748B"
    admin_username: Optional[str] = None
    admin_email: Optional[EmailStr] = None
    admin_password: Optional[str] = None
    admin_telephone: Optional[str] = None
    tier_id: Optional[int] = None
    custom_unit_cost: Optional[float] = None
    subscription_price: float = 500000.0

class Token(BaseModel):
    access_token: str
    token_type: str
    require_password_change: bool

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class PasswordReset(BaseModel):
    token: str
    new_password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class VerifyEmailRequest(BaseModel):
    token: str
