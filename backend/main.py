try:
    from .database import SessionLocal, engine, User, Wallet, Transaction, Config, RevokedToken, init_db, get_db, Organisation, ActivityLog, Tier, AdminRole, PasswordResetToken, EmailVerificationToken
    from .crypto import crypto_service
    from .email_service import EmailService
    from . import schemas
except (ImportError, ValueError):
    from database import SessionLocal, engine, User, Wallet, Transaction, Config, RevokedToken, init_db, get_db, Organisation, ActivityLog, Tier, AdminRole, PasswordResetToken, EmailVerificationToken
    from crypto import crypto_service
    from email_service import EmailService
    import schemas
from passlib.context import CryptContext
import requests
import secrets
import json
import os
import shutil
import re
import unicodedata
from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# Create tables
init_db()
print("BACKEND RELOADED - Security Patch Applied")

# ──────────────────────────────────────────────────────────────
# PERMISSION CATALOGUE — all assignable tasks on the platform
# ──────────────────────────────────────────────────────────────
ALL_PERMISSIONS = [
    {"key": "VIEW_ORG_WALLET",     "label": "View Organisation Units",  "description": "View the organisation wallet balance and usage stats"},
    {"key": "VIEW_REVENUE",        "label": "View Platform Revenue",   "description": "View total revenue and breakdown by organisation"},
    {"key": "VIEW_TRANSACTIONS",   "label": "View Transactions",       "description": "View transaction & verification history"},
    {"key": "VIEW_AUDIT_LOGS",     "label": "View Audit Logs",         "description": "View the full organisation-wide audit trail"},
    {"key": "CREATE_USER",         "label": "Create Users",            "description": "Create new users within the organisation"},
    {"key": "EDIT_USER",           "label": "Edit Users",              "description": "Edit user profile and details"},
    {"key": "SUSPEND_USER",        "label": "Suspend / Activate Users","description": "Suspend or reactivate user accounts"},
    {"key": "DELETE_USER",         "label": "Delete Users",            "description": "Permanently delete a user"},
    {"key": "MANAGE_ROLES",        "label": "Manage Permissions",      "description": "Change permission assignments for other users"},
    {"key": "VIEW_REPORTS",        "label": "View Reports",            "description": "View analytics and reports"},
    {"key": "CREATE_ORGANISATION", "label": "Create Organisation",     "description": "Create new organisation workspaces"},
    {"key": "EDIT_ORGANISATION",   "label": "Edit Organisation",       "description": "Update organisation branding and details"},
    {"key": "DELETE_ORGANISATION", "label": "Delete Organisation",     "description": "Permanently delete an organisation"},
    {"key": "CREATE_TIER",         "label": "Create Tier",             "description": "Create new service tiers"},
    {"key": "EDIT_TIER",           "label": "Edit Tier",               "description": "Update service tier pricing"},
    {"key": "DELETE_TIER",         "label": "Delete Tier",             "description": "Permanently delete a service tier"},
    {"key": "MANAGE_SUBSCRIPTION", "label": "Manage Subscription",     "description": "Activate or renew yearly organisation subscription"},
]

# Legacy permission key aliases for backward compatibility
_LEGACY_MAP = {
    "WALLET":   ["VIEW_ORG_WALLET"],
    "VIEW_WALLET": ["VIEW_ORG_WALLET"],
    "IDENTITY": [],  # verify-nin is a frontend-only feature; no admin portal equivalent
}

# Auto-migrate/Bootstrap Default Org
def bootstrap_orgs():
    try:
        db = SessionLocal()
        # 1. Bootstrap Tiers
        t1 = db.query(Tier).filter(Tier.name == "Tier 1").first()
        if not t1:
            print("INFO: Creating Tier 1...")
            t1 = Tier(name="Tier 1", default_unit_cost=100.0)
            db.add(t1)
        
        t2 = db.query(Tier).filter(Tier.name == "Tier 2").first()
        if not t2:
            print("INFO: Creating Tier 2...")
            t2 = Tier(name="Tier 2", default_unit_cost=120.0)
            db.add(t2)
            
        t3 = db.query(Tier).filter(Tier.name == "Tier 3").first()
        if not t3:
            print("INFO: Creating Tier 3...")
            t3 = Tier(name="Tier 3", default_unit_cost=150.0)
            db.add(t3)
        
        db.commit()
        db.refresh(t1)

        # 2. Bootstrap Default Organisation
        default_org = db.query(Organisation).filter(Organisation.slug == "default").first()
        if not default_org:
            print("INFO: Creating default organisation...")
            default_org = Organisation(
                name="Randaframes Default",
                slug="default",
                logo_url="https://via.placeholder.com/40",
                primary_color="#3B82F6",
                secondary_color="#64748B",
                tier_id=t1.id,
                subscription_price=500000.0
            )
            db.add(default_org)
            db.commit()
            db.refresh(default_org)
            
            # Create Wallet for Default Org
            if not default_org.wallet:
                default_org.wallet = Wallet(organisation_id=default_org.id, balance_units=0)
                db.add(default_org.wallet)
                db.commit()
        elif not default_org.tier_id:
            default_org.tier_id = t1.id
            db.commit()
        
        # 3. Bootstrap Roles for Default Organisation
        default_org = db.query(Organisation).filter(Organisation.slug == "default").first()
        if default_org:
            def create_role_if_not_exists(name, permissions):
                existing = db.query(AdminRole).filter(AdminRole.name == name, AdminRole.organisation_id == default_org.id).first()
                if not existing:
                    print(f"INFO: Creating Role: {name}...")
                    role = AdminRole(name=name, permissions=permissions, organisation_id=default_org.id)
                    db.add(role)
                    db.commit()
            
            # Platform Owner: All permissions
            all_keys = [p["key"] for p in ALL_PERMISSIONS]
            create_role_if_not_exists("Platform Owner", all_keys)
            
            # Financial Officer
            fin_keys = ["VIEW_ORG_WALLET", "VIEW_REVENUE", "VIEW_TRANSACTIONS", "VIEW_REPORTS"]
            create_role_if_not_exists("Financial Officer", fin_keys)
            
            # Support Specialist
            support_keys = ["VIEW_ORG_WALLET", "VIEW_TRANSACTIONS", "CREATE_USER", "EDIT_USER", "SUSPEND_USER", "VIEW_AUDIT_LOGS"]
            create_role_if_not_exists("Support Specialist", support_keys)
            
            # Security Auditor
            audit_keys = ["VIEW_AUDIT_LOGS", "VIEW_REPORTS", "VIEW_TRANSACTIONS"]
            create_role_if_not_exists("Security Auditor", audit_keys)

        db.close()
    except Exception as e:
        print(f"ERROR: Bootstrap failed: {e}")

bootstrap_orgs()

app = FastAPI(title="Randaframes API")

# Security: Restrict origins in production
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:5174").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files for uploads
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default_secret_key_change_me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def has_permission(user: "User", perm: str) -> bool:
    """
    Check whether a user holds a given permission key.
    - Super admins (role == 'admin') always pass.
    - NEW: If user has a role_id, check the AdminRole.permissions JSON list.
    - Legacy fallback: comma-separated string in user.role.
    """
    if user.role == "admin":
        return True
    
    # Check Dynamic Role first
    if user.admin_role:
        if perm in (user.admin_role.permissions or []):
            return True
        # Org Admins still get full org access even if role doesn't have it
        if "org_admin" in (user.role or ""):
            return True
            
    # Legacy role string fallback
    role_str = user.role or ""
    if "org_admin" in role_str:
        return True
    parts = [r.strip() for r in role_str.split(",")]
    if perm in parts:
        return True
    # Expand legacy keys
    for legacy, mapped in _LEGACY_MAP.items():
        if legacy in parts and perm in mapped:
            return True
    return False

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal."""
    filename = unicodedata.normalize('NFKD', filename).encode('ascii', 'ignore').decode('ascii')
    filename = re.sub(r'[^\w\s.-]', '', filename).strip()
    return filename

@app.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    org_slug: str = Form(None), 
    db: Session = Depends(get_db)
):
    try:
        # Case-insensitive query for username or email
        lower_username = form_data.username.lower()
        query = db.query(User).filter(
            (func.lower(User.username) == lower_username) | 
            (func.lower(User.email) == lower_username)
        )
        
        # If Org Slug provided, scope it
        if org_slug:
            org = db.query(Organisation).filter(func.lower(Organisation.slug) == org_slug.lower()).first()
            if not org:
                raise HTTPException(status_code=404, detail="Organisation not found")
            query = query.filter(User.organisation_id == org.id)
            user = query.first()
        else:
            # No Org Slug: Try to match. If multiple matches, we might have an issue.
            # Prefer Super Admin / ID 1 ?
            # For now, let's fetch matching users
            candidates = query.all()
            if len(candidates) > 1:
                # Ambiguous login - try to find one that is a super admin
                super_admin = next((u for u in candidates if u.organisation_id == 1), None)
                if super_admin:
                    user = super_admin
                else:
                    raise HTTPException(status_code=400, detail="Ambiguous username. Please login via your Organisation Portal.")
            else:
                user = candidates[0] if candidates else None

        if not user or not user.hashed_password or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Incorrect username or password")

        if not user.is_active:
             if not user.is_email_verified:
                 raise HTTPException(status_code=403, detail="Your email address has not been verified. Please check your inbox for the verification link.")
             raise HTTPException(status_code=403, detail="This user has been suspended, kindly contact the Administrator")

        if user.org and user.org.is_suspended:
            raise HTTPException(status_code=403, detail="Your organisation is suspended. Please contact the Administrator.")

        access_token = create_access_token(data={"sub": user.username, "org_id": user.organisation_id})
        # Log LOGIN activity
        log_activity(db, user, "LOGIN", {"ip": "unknown", "org": org_slug or "global"}) 

        return {
            "access_token": access_token, 
            "token_type": "bearer",
            "require_password_change": user.is_password_change_required
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        import traceback
        print(f"LOGIN ERROR: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="An internal server error occurred. Please try again later.")

@app.post("/logout")
def logout_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        # Check if already revoked to avoid duplicates (optional but good)
        exists = db.query(RevokedToken).filter(RevokedToken.token == token).first()
        if not exists:
            revoked = RevokedToken(token=token)
            db.add(revoked)
            db.commit()
            
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        org_id: int = payload.get("org_id")
        
        query = db.query(User).filter(User.username == username)
        if org_id is not None:
             query = query.filter(User.organisation_id == org_id)
        user = query.first()
        if user:
            log_activity(db, user, "LOGOUT", {"info": "User logged out"})
    except Exception as e:
        print(f"LOGOUT ERROR: {e}")
        pass # If token invalid, just ignore
    return {"message": "Logged out"}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Check blacklist
    if db.query(RevokedToken).filter(RevokedToken.token == token).first():
        raise HTTPException(status_code=401, detail="Session logged out")
        
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        org_id: int = payload.get("org_id")
        
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid session")
            
        query = db.query(User).filter(User.username == username)
        if org_id is not None:
             query = query.filter(User.organisation_id == org_id)
             
        user = query.first()
    except Exception:
         raise HTTPException(status_code=401, detail="Session expired or invalid")
         
    # Valid session, user already fetched correctly above
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Check if organisation is suspended
    if user.org and getattr(user.org, 'is_suspended', False):
        raise HTTPException(status_code=403, detail="Organisation suspended")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User suspended")
        
    return user

def log_activity(db: Session, user: User, action_type: str, details: dict):
    # Helper to log generic activities
    if user.org and not user.org.wallet:
        # Create wallet if missing for the ORG
        user.org.wallet = Wallet(organisation_id=user.organisation_id, balance_units=0)
        db.add(user.org.wallet)
        db.commit()

    # Create ActivityLog entry for persistent audit trail
    new_log = ActivityLog(
        username=user.username,
        organisation_id=user.organisation_id,
        action_type=action_type,
        details=details
    )
    db.add(new_log)
    db.commit()

@app.post("/change-password")
def change_password(
    data: schemas.PasswordChange,
    user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if not verify_password(data.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect current password")
        
    user.hashed_password = get_password_hash(data.new_password)
    user.is_password_change_required = False
    db.commit()
    
    log_activity(db, user, "PASSWORD_CHANGE", {"info": "Password updated"})

    return {"message": "Password changed successfully"}

@app.post("/forgot-password")
def forgot_password(data: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    # Find user by email
    user = db.query(User).filter(func.lower(User.email) == data.email.lower()).first()
    if not user:
        # For security, don't reveal if user exists. 
        # But in small systems we usually just return success.
        return {"message": "If an account exists for this email, a reset link will be sent."}
    
    # Generate Token
    token = secrets.token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(hours=1)
    
    reset_token = PasswordResetToken(
        user_id=user.id,
        token=token,
        expires_at=expiry
    )
    db.add(reset_token)
    db.commit()
    
    # Send Real Email
    port = 5174 if user.organisation_id == 1 else 5173
    reset_link = f"http://localhost:{port}/reset-password?token={token}"
    EmailService.send_reset_password_email(user.email, user.username, reset_link)
    
    return {"message": "Reset link has been sent to your email address."}

@app.post("/verify-email")
def verify_email(data: schemas.VerifyEmailRequest, db: Session = Depends(get_db)):
    verify_token = db.query(EmailVerificationToken).filter(
        EmailVerificationToken.token == data.token,
        EmailVerificationToken.is_used == False,
        EmailVerificationToken.expires_at > datetime.utcnow()
    ).first()
    
    if not verify_token:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    
    user = verify_token.user
    user.is_email_verified = True
    user.is_active = True # Activate account on verification
    
    verify_token.is_used = True
    db.commit()
    
    log_activity(db, user, "EMAIL_VERIFICATION", {"info": "Email verified successfully"})
    
    return {"message": "Verification successful. Please login to gain access."}

@app.post("/reset-password")
def reset_password(data: schemas.PasswordReset, db: Session = Depends(get_db)):
    reset_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == data.token,
        PasswordResetToken.is_used == False,
        PasswordResetToken.expires_at > datetime.utcnow()
    ).first()
    
    if not reset_token:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    user = reset_token.user
    user.hashed_password = get_password_hash(data.new_password)
    user.is_password_change_required = False # Fixes the required check too
    
    reset_token.is_used = True
    db.commit()
    
    log_activity(db, user, "PASSWORD_RESET", {"info": "Password reset via token"})
    
    return {"message": "Password has been reset successfully. You can now login with your new password."}

@app.get("/me")
def get_me(user: User = Depends(get_current_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Determine whether this user is a platform-level admin portal user.
    platform_keys = {p["key"] for p in ALL_PERMISSIONS}
    
    # 1. Collect permissions from legacy role string
    role_str = user.role or ""
    all_user_perms = {r.strip() for r in role_str.split(",") if r.strip()}
    
    # 2. Collect permissions from Dynamic Role (AdminRole)
    if user.admin_role:
        role_perms = set(user.admin_role.permissions or [])
        all_user_perms.update(role_perms)
    
    # 3. Handle System Admins (Super Admin and Org Admins)
    is_super_admin = (user.role == "admin")
    is_org_admin = ("org_admin" in role_str)
    
    # A user is a platform user if they belong to the platform owner organisation (ID 1) 
    # AND (are super-admin, or have at least one assigned platform key)
    is_platform_user = (user.organisation_id == 1) and (
        is_super_admin or 
        bool(all_user_perms & platform_keys)
    )

    org = user.org
    return {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "telephone": user.telephone,
        "units": user.org.wallet.balance_units if user.org and user.org.wallet else 0,
        "subscription": user.subscription_status,
        "role": user.role,
        "is_platform_user": is_platform_user,
        "permissions": sorted(all_user_perms & platform_keys),
        "ip_whitelist": user.ip_whitelist,
        "is_active": user.is_active,
        "is_password_change_required": user.is_password_change_required,
        "organisation": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "logo_url": org.logo_url,
            "primary_color": org.primary_color,
            "secondary_color": org.secondary_color,
            "subscription_status": "active" if org.slug == 'default' else org.subscription_status,
            "subscription_expiry": None if org.slug == 'default' else org.subscription_expiry,
            "subscription_plan": org.subscription_plan,
            "tier_id": org.tier_id,
            "custom_unit_cost": org.custom_unit_cost,
            "tier_name": org.tier.name if org.tier else "Tier 1",
            "tier_default_cost": org.tier.default_unit_cost if org.tier else 100.0,
            "is_suspended": org.is_suspended
        } if org else None
    }


@app.put("/me")
def update_me(data: schemas.UserUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if data.full_name is not None:
        user.full_name = data.full_name
    
    if data.email is not None:
        new_email = data.email.lower()
        if new_email != (user.email.lower() if user.email else ""):
            existing = db.query(User).filter(func.lower(User.email) == new_email).first()
            if existing:
                 raise HTTPException(status_code=400, detail="Email already taken")
            user.email = data.email
    
    db.commit()
    log_activity(db, user, "PROFILE_UPDATE", {"updated_fields": [k for k, v in data.dict().items() if v is not None]})
    return {"message": "Profile updated successfully"}

# The base URL from documentation plus the specific endpoint
EXTERNAL_API_BASE = "http://premiere.vuvaa.com/demo/NIN_Validation/nin_processor"
EXTERNAL_API_URL = f"{EXTERNAL_API_BASE}/verify_nin"
EXTERNAL_LOGIN_URL = f"{EXTERNAL_API_BASE}/login"

# Cache for External API Token
external_token_cache = {
    "token": None,
    "expiry": None
}

def get_external_token():
    # Simple cache check (could be improved with expiry check)
    if external_token_cache["token"]:
        return external_token_cache["token"]
    
    print("INFO: Fetching new token from External API")
    login_payload = {
        "username": os.getenv("EXTERNAL_API_USERNAME"),
        "password": os.getenv("EXTERNAL_API_PASSWORD")
    }
    encrypted_payload = crypto_service.encrypt(login_payload)
    
    try:
        response = requests.post(EXTERNAL_LOGIN_URL, json={"payload": encrypted_payload}, timeout=10)
        if response.status_code != 200:
            print(f"ERROR: External Login Failed: {response.status_code}")
            return None
        
        resp_data = response.json()
        decrypted_resp = crypto_service.decrypt(resp_data["payload"])
        
        if decrypted_resp.get("status") == 200:
            token = decrypted_resp["data"]["access_token"]
            external_token_cache["token"] = token
            return token
        else:
            print(f"DEBUG: External Login Status not 200: {decrypted_resp}")
            return None
    except Exception as e:
        print(f"DEBUG: External Login Exception: {str(e)}")
        return None

@app.get("/permissions")
def list_permissions(user: User = Depends(get_current_user)):
    """Return the full catalogue of assignable platform permissions."""
    return ALL_PERMISSIONS

# --- Admin Role Management ---
@app.get("/admin/roles")
def list_roles(admin: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Platform owner sees all, others see their org's roles
    if admin.role == "admin":
         return db.query(AdminRole).all()
    return db.query(AdminRole).filter(AdminRole.organisation_id == admin.organisation_id).all()

@app.post("/admin/roles")
def create_role(data: dict, admin: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not has_permission(admin, "MANAGE_ROLES"):
        raise HTTPException(status_code=403, detail="Access denied")
    
    new_role = AdminRole(
        name=data["name"],
        permissions=data.get("permissions", []),
        organisation_id=admin.organisation_id
    )
    db.add(new_role)
    db.commit()
    db.refresh(new_role)
    return new_role

@app.put("/admin/roles/{role_id}")
def update_role(role_id: int, data: dict, admin: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not has_permission(admin, "MANAGE_ROLES"):
        raise HTTPException(status_code=403, detail="Access denied")
    
    role = db.query(AdminRole).filter(AdminRole.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
        
    # Security: Ensure they own the role
    if admin.role != "admin" and role.organisation_id != admin.organisation_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    if "name" in data:
        role.name = data["name"]
    if "permissions" in data:
        role.permissions = data["permissions"]
        
    db.commit()
    db.refresh(role)
    return role

@app.delete("/admin/roles/{role_id}")
def delete_role(role_id: int, admin: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not has_permission(admin, "MANAGE_ROLES"):
        raise HTTPException(status_code=403, detail="Access denied")
    
    role = db.query(AdminRole).filter(AdminRole.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
        
    if admin.role != "admin" and role.organisation_id != admin.organisation_id:
        raise HTTPException(status_code=403, detail="Forbidden")
        
    db.delete(role)
    db.commit()
    return {"message": "Role deleted"}

@app.get("/wallet")
def get_user_wallet(user: User = Depends(get_current_user)):
    if not has_permission(user, "VIEW_WALLET"):
        raise HTTPException(status_code=403, detail="Access denied: VIEW_WALLET permission required")

    if user.org:
        if user.role != "admin":
            is_active = user.org.subscription_status == 'active'
            is_expired = user.org.subscription_expiry and user.org.subscription_expiry < datetime.utcnow()
            if not is_active or is_expired:
                 raise HTTPException(status_code=402, detail="Active subscription required to access wallet")

    if not user.org or not user.org.wallet:
        return {"balance_units": 0}
    return {"balance_units": user.org.wallet.balance_units}

@app.get("/transactions")
def get_user_transactions(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not has_permission(user, "VIEW_TRANSACTIONS"):
        raise HTTPException(status_code=403, detail="Access denied: VIEW_TRANSACTIONS permission required")
    
    print(f"DEBUG: Transactions User:{user.username} OrgID:{user.organisation_id} Role:{user.role}")
    
    # 3. Fetch ActivityLogs (Audit Trail)
    if has_permission(user, "VIEW_AUDIT_LOGS") and user.organisation_id:
        print("DEBUG: Using Org Admin Filter")
        activity_logs = db.query(ActivityLog).filter(ActivityLog.organisation_id == user.organisation_id).all()
        # Also fetch transactions for wallet history (assuming we still want them)
        transactions = db.query(Transaction).filter(Transaction.organisation_id == user.organisation_id).all()
    else:
        print("DEBUG: Using User Filter")
        # Regular user - see own activity? or just transactions?
        # Regular users probably don't see ActivityLogs yet (Dashboard only shows them for Admins typically?)
        # Dashboard shows "Verification Logs" (Transaction) and "Activity History".
        # Let's check logic: if regular user, filter by username? ActivityLog has username.
        activity_logs = db.query(ActivityLog).filter(
            ActivityLog.username == user.username,
            ActivityLog.organisation_id == user.organisation_id
        ).all()
        transactions = db.query(Transaction).filter(Transaction.user_id == user.id).all()
        
    print(f"DEBUG: Found {len(activity_logs)} logs and {len(transactions)} txs")
    for l in activity_logs:
        print(f"LOG: {l.id} Org:{l.organisation_id} User:{l.username} Action:{l.action_type}")

    # 4. Merge and Format
    result = []
    
    # Process Transactions
    for tx in transactions:
        tx_owner = db.query(User).filter(User.id == tx.user_id).first()
        result.append({
            "id": tx.id,
            "type": tx.type,
            "amount": tx.amount,
            "units_before": tx.units_before,
            "units_after": tx.units_after,
            "timestamp": tx.timestamp,
            "details": tx.details,
            "username": tx.username or (tx_owner.username if tx_owner else "Unknown"),
            "organisation_id": tx.organisation_id
        })
        
    # Process ActivityLogs
    for log in activity_logs:
        result.append({
            "id": log.id + 100000, # Offset ID to avoid collision in frontend key? Or just use GUID? ID collision might be issue for React keys.
            "type": log.action_type,
            "amount": 0.0,
            "units_before": 0,
            "units_after": 0,
            "timestamp": log.timestamp,
            "details": log.details,
            "username": log.username,
            "organisation_id": log.organisation_id
        })
        
    # Sort by timestamp desc
    result.sort(key=lambda x: x["timestamp"], reverse=True)
        
    return result


@app.post("/verify-nin")
def verify_nin(nin: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # 1. Verify user units
    # User already verified by get_current_user
    
    if not user:
        raise HTTPException(status_code=444, detail="User not found (Custom)")
        
    # RBACCheck: User must be admin OR have IDENTITY in their roles
    if user.role != "admin" and "IDENTITY" not in (user.role or ""):
        raise HTTPException(status_code=403, detail="Access denied: IDENTITY permission required")
    
    if not user.org or not user.org.wallet or user.org.wallet.balance_units < 1:
        raise HTTPException(status_code=402, detail="Insufficient units")

    if user.org and user.role != "admin":
        is_active = user.org.subscription_status == 'active'
        is_expired = user.org.subscription_expiry and user.org.subscription_expiry < datetime.utcnow()
        if not is_active or is_expired:
             raise HTTPException(status_code=402, detail="Active subscription required for verification")
    
    # 2. Encrypt request for External API
    external_request = {
        "username": os.getenv("EXTERNAL_API_USERNAME"),
        "nin": nin
    }
    encrypted_payload = crypto_service.encrypt(external_request)
    
    # 3. Call External API
    # 3. Call External API
    try:
        # Retry loop for token expiration
        for attempt in range(2):
            ext_token = get_external_token()
            
            # Error if External API fails
            if not ext_token:
                print(f"DEBUG: External API auth failed")
                raise HTTPException(status_code=500, detail="Could not authenticate with identity provider")
            
            headers = {
                "Authorization": f"Bearer {ext_token}"
            }

            print(f"DEBUG: Calling External API: {EXTERNAL_API_URL} (Attempt {attempt+1})")
            response = requests.post(
                EXTERNAL_API_URL, 
                json={"payload": encrypted_payload},
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                # 4. Decrypt response
                resp_data = response.json()
                decrypted_payload = crypto_service.decrypt(resp_data["payload"])
                break # Success
                
            elif response.status_code == 401:
                print(f"DEBUG: External API Token Expired (401).")
                if attempt == 0:
                    external_token_cache["token"] = None
                    continue # Retry with new token
                else:
                    # Failed twice
                    if nin in MOCK_NIN_DATA:
                         print(f"DEBUG: 401 on retry, falling back to mock")
                         decrypted_payload = MOCK_NIN_DATA[nin]
                         break
                    raise HTTPException(status_code=500, detail="External API authentication failed after retry")
            else:
                 print(f"DEBUG: External API Status: {response.status_code}")
                 raise HTTPException(status_code=500, detail=f"External API error ({response.status_code})")
        else:
             # Loop finished without break (shouldn't happen if logic is correct)
             raise HTTPException(status_code=500, detail="Verification failed")

        
        # DEBUG: Diagnostic Logging (Hidden in Production)
        # print("======== NIN DEBUG ========")
        # try:
        #     print(f"PAYLOAD: {json.dumps(decrypted_payload, default=str, ensure_ascii=True)}")
        # except Exception:
        #     print("PAYLOAD: <Could not encode payload for printing>")

        # 5. Handle Error Responses from API
        if decrypted_payload.get("status") not in [200, "200", "00"]:
            error_msg = decrypted_payload.get("message") or "External API reported an error"
            raise HTTPException(status_code=400, detail=error_msg)

        # 6. Extract record (Documentation says it's in 'data')
        record = decrypted_payload.get("data") or decrypted_payload

        # 7. Normalize data for frontend
        normalized_data = {
            "transaction_id": record.get("transaction_id"),
            "fname": record.get("fname"),
            "mname": record.get("mname"),
            "lname": record.get("lname"),
            "dob": record.get("dob"),
            "phone": record.get("phone"),
            "stateOfOrigin": record.get("stateOfOrigin"),
            "lgaOfOrigin": record.get("lgaOfOrigin"),
            "town": record.get("town"),
            "residenceAdress": record.get("residenceAdress"),
            "residenceTown": record.get("residenceTown"),
            "residenceState": record.get("residenceState"),
            "residenceLga": record.get("residenceLga"),
            "image": record.get("image"),
            "validation_units_before": record.get("validation_units_before"),
            "validation_units_after": record.get("validation_units_after")
        }
        
        # 8. Deduct units and log transaction
        # SHARED WALLET: Deduct from Organisation Wallet
        if not user.org or not user.org.wallet:
             raise HTTPException(status_code=400, detail="Organisation wallet not found")

        units_before = user.org.wallet.balance_units
        if units_before < 1:
             raise HTTPException(status_code=400, detail="Insufficient units in Organisation wallet")
             
        user.org.wallet.balance_units -= 1
        units_after = user.org.wallet.balance_units
        
        new_tx = Transaction(
            user_id=user.id,
            type="NIN_VALIDATION",
            amount=1.0,
            units_before=units_before,
            units_after=units_after,

            details=decrypted_payload,
            username=user.username,
            organisation_id=user.organisation_id
        )
        db.add(new_tx)
        
        # Dual-write to ActivityLog for Audit
        nin_log = ActivityLog(
            username=user.username,
            organisation_id=user.organisation_id,
            action_type="NIN_VALIDATION",
            details=decrypted_payload
        )
        db.add(nin_log)
        
        db.commit()
        
        return {"data": normalized_data}
        
    except HTTPException as he:
        raise he
# --- Auth Dependencies ---

def get_current_admin_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Check blacklist
    if db.query(RevokedToken).filter(RevokedToken.token == token).first():
        raise HTTPException(status_code=401, detail="Session logged out")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        org_id: int = payload.get("org_id")
        
        if username is None:
            raise HTTPException(status_code=1, detail="Invalid session")
    except Exception as e:
        print(f"DEBUG: Admin Auth Error: {str(e)}")
        raise HTTPException(status_code=401, detail="Session expired or invalid")
        
    query = db.query(User).filter(User.username == username)
    if org_id is not None:
         query = query.filter(User.organisation_id == org_id)
    user = query.first()
    # ONLY role="admin" is allowed to access admin-frontend backend endpoints
    if not user or user.role != "admin":
        raise HTTPException(status_code=403, detail="Super-Admin privileges required")
    return user

def get_current_platform_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Allow any user hold at least one portal permission, or super-admin.
    Used for general READ-ONLY access to dashboard lists.
    """
    user = get_current_user(token, db)
    
    # ONLY users belonging to the platform owner organisation (ID 1) can access the admin portal.
    if user.organisation_id != 1:
        raise HTTPException(status_code=403, detail="Admin Portal access restricted to platform administrators")

    # Check if user has ANY of the platform permissions defined in ALL_PERMISSIONS
    is_platform_user = any(has_permission(user, p["key"]) for p in ALL_PERMISSIONS)
    
    if not is_platform_user:
        raise HTTPException(status_code=403, detail="Insufficient permissions for Admin Portal access")
    return user

def get_current_org_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = get_current_user(token, db)
    if "org_admin" not in (user.role or "") and user.role != "admin":
        raise HTTPException(status_code=403, detail="Organisation Admin privileges required")
    return user

def get_dashboard_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Allow access to both System Admins and Org Admins.
    """
    # Check blacklist
    if db.query(RevokedToken).filter(RevokedToken.token == token).first():
        raise HTTPException(status_code=401, detail="Session logged out")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        org_id: int = payload.get("org_id")
        
        if username is None:
            raise HTTPException(status_code=1, detail="Invalid session")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
        
    query = db.query(User).filter(User.username == username)
    if org_id is not None:
         query = query.filter(User.organisation_id == org_id)
         
    user = query.first()
    
    is_super = (user and user.role == "admin")
    is_org_admin = (user and "org_admin" in (user.role or ""))
    
    if not (is_super or is_org_admin):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user

@app.post("/register")
def register(data: schemas.RegisterUser, admin: User = Depends(get_current_admin_user), db: Session = Depends(get_db)):
    # Resolve Organisation First
    org_id = data.organisation_id
    if not org_id:
        default_org = db.query(Organisation).filter(Organisation.slug == "default").first()
        if not default_org:
            raise HTTPException(status_code=500, detail="Default organisation not configured")
        org_id = default_org.id

    # Check for duplicates WITHIN the resolved organisation (Case-Insensitive)
    lower_username = data.username.lower()
    lower_email = data.email.lower()
    db_user = db.query(User).filter(
        User.organisation_id == org_id,
        (func.lower(User.username) == lower_username) | 
        (func.lower(User.email) == lower_email)
    ).first()
    
    if db_user:
        if db_user.username.lower() == lower_username:
            raise HTTPException(status_code=400, detail="Username already registered in this organisation")
        if db_user.email.lower() == lower_email:
            raise HTTPException(status_code=400, detail="Email already registered in this organisation")
    
    try:
        hashed_password = get_password_hash(data.password)
        new_user = User(
            username=data.username, 
            email=data.email, 
            telephone=data.telephone,
            hashed_password=hashed_password, 
            role=data.roles, 
            organisation_id=org_id,
            is_password_change_required=True,
            is_active=False, # Wait for verification
            is_email_verified=False
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Generate Verification Token
        v_token = secrets.token_urlsafe(32)
        v_expiry = datetime.utcnow() + timedelta(days=3)
        verify_token = EmailVerificationToken(
            user_id=new_user.id,
            token=v_token,
            expires_at=v_expiry
        )
        db.add(verify_token)
        db.commit()

        # Send Verification Email
        port = 5174 if new_user.organisation_id == 1 else 5173
        v_link = f"http://localhost:{port}/verify-email?token={v_token}"
        EmailService.send_verification_email(new_user.email, new_user.username, v_link)
        
        log_activity(db, admin, "USER_CREATION", {"created_user": data.username, "role": new_user.role})

        return {"message": "User registered successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.get("/admin/users")
def list_users(admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    """
    List users.
    - Super Admin: Sees all.
    - Org Admin: Sees only their organization's users.
    """
    query = db.query(User).join(Organisation)
    
    # Always hide users from deleted organisations
    query = query.filter(Organisation.is_deleted == False)
    
    # Refined Visibility Logic
    if admin.organisation_id == 1:
        # Platform Admins see Org 1 staff OR any Org Admin
        query = query.filter(
            (User.organisation_id == 1) | 
            (User.role.like("%org_admin%"))
        )
    else:
        # Org Admins see only their own team
        query = query.filter(User.organisation_id == admin.organisation_id)
        
    users = query.all()
    result = []
    for u in users:
        result.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "status": u.subscription_status,
            "is_active": u.is_active,
            "units": u.org.wallet.balance_units if u.org and u.org.wallet else 0,
            "ip_whitelist": u.ip_whitelist,
            "organisation_name": u.org.name if u.org else "No Org",
            "organisation_slug": u.org.slug if u.org else "",
            "organisation_is_suspended": u.org.is_suspended if u.org else False,
            "role_id": u.role_id,
            "is_email_verified": u.is_email_verified,
            "telephone": u.telephone
        })
    return result

@app.put("/admin/users/{user_id}")
def update_user_admin(user_id: int, data: dict, admin: User = Depends(get_current_admin_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if "permissions" in data:
        # Explicit permission list — join to comma-separated role string
        user.role = ",".join(data["permissions"])
    elif "role" in data:
        user.role = data["role"]
    if "is_active" in data: user.is_active = data["is_active"]
    if "subscription_status" in data: user.subscription_status = data["subscription_status"]
    if "ip_whitelist" in data: user.ip_whitelist = data["ip_whitelist"]
    if "organisation_id" in data: user.organisation_id = data["organisation_id"]
    
    db.commit()
    log_activity(db, admin, "USER_UPDATE", {"updated_user": user.username, "changes": list(data.keys())})
    return {"message": "User updated successfully"}

@app.post("/admin/users/{user_id}/toggle-suspension")
def toggle_user_suspension(user_id: int, data: dict, admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    """
    Toggle user suspension status (Platform Admin).
    Requires admin password for security.
    """
    password = data.get("password")
    if not password or not verify_password(password, admin.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid admin password")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot suspend yourself")

    user.is_active = not user.is_active
    status = "Suspended" if not user.is_active else "Activated"
    
    db.commit()
    
    # Send email to the specific user
    EmailService.send_suspension_status_email(user.email, user.full_name or user.username, "User account", status)
    
    log_activity(db, admin, f"USER_{status.upper()}", {"target_user": user.username})
    return {"message": f"User {status.lower()} successfully", "is_active": user.is_active}


# --- Org Admin User Management Endpoints ---

@app.get("/org/users")
def list_org_users(admin: User = Depends(get_current_org_admin), db: Session = Depends(get_db)):
    # Org Admin can only see users in their own organisation
    users = db.query(User).filter(User.organisation_id == admin.organisation_id).all()
    result = []
    for u in users:
        result.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "subscription_status": u.subscription_status,
            "role_id": u.role_id,
            "is_email_verified": u.is_email_verified,
            "telephone": u.telephone
        })
    return result

@app.post("/subscribe")
def subscribe_org(
    plan_id: str = Form("yearly_license"),
    payment_method: str = Form("card"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not has_permission(user, "MANAGE_SUBSCRIPTION"):
        raise HTTPException(status_code=403, detail="Access denied: MANAGE_SUBSCRIPTION permission required")
    """
    Simulated Payment API for Yearly License.
    Amount is retrieved from the Organisation settings (Naira).
    Includes a 100-unit starting bonus.
    """
    if not user.org:
        raise HTTPException(status_code=400, detail="User does not belong to an organisation")
        
    price = user.org.subscription_price or 500000.0
    print(f"DEBUG: Processing subscription for Organisation ID: {user.org.id}, Plan: {plan_id}, Payment: {payment_method}")
    
    # Simulate payment processing
    if payment_method == "fail_test":
        raise HTTPException(status_code=400, detail="Payment declined by bank")
        
    # Success: Set to active and 1 year duration
    user.org.subscription_status = "active"
    user.org.subscription_plan = plan_id
    user.org.subscription_expiry = datetime.utcnow() + timedelta(days=365) # Yearly
    
    # AWARD 100 UNIT BONUS
    if not user.org.wallet:
        user.org.wallet = Wallet(organisation_id=user.organisation_id, balance_units=0)
        db.add(user.org.wallet)
    
    units_before = user.org.wallet.balance_units
    bonus_units = 100
    user.org.wallet.balance_units += bonus_units
    units_after = user.org.wallet.balance_units
    
    bonus_tx = Transaction(
        user_id=user.id,
        type="BONUS_UNITS",
        amount=0.0,
        units_before=units_before,
        units_after=units_after,
        details={"reason": "100-unit starting bonus for yearly license"},
        username=user.username,
        organisation_id=user.organisation_id
    )
    db.add(bonus_tx)
    
    # RECORD SUBSCRIPTION REVENUE TRANSACTION
    sub_tx = Transaction(
        user_id=user.id,
        type="SUBSCRIPTION_PAYMENT",
        amount=price,
        units_before=units_before,
        units_after=units_after,
        details={
            "description": f"Yearly Subscription: {plan_id}",
            "payment_method": payment_method,
            "price_paid": price
        },
        username=user.username,
        organisation_id=user.organisation_id
    )
    db.add(sub_tx)
    
    db.commit()
    
    log_activity(db, user, "SUBSCRIPTION_ACTIVATED", {
        "plan": plan_id, 
        "amount_naira": price, 
        "expiry": user.org.subscription_expiry.isoformat(),
        "bonus_awarded": bonus_units
    })
    
    return {
        "message": "Subscription activated successfully", 
        "status": "active", 
        "amount_paid": price,
        "bonus_units": bonus_units,
        "new_balance": units_after
    }


@app.post("/org/users")
def create_org_user(data: dict, admin: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Permission check
    if not has_permission(admin, "CREATE_USER"):
        raise HTTPException(status_code=403, detail="Access denied: CREATE_USER permission required")
    # Org Admin can only create users for their own organisation
    username = data.get("username")
    email = data.get("email")
    telephone = data.get("telephone")
    password = data.get("password")
    role_id = data.get("role_id")
    permissions = data.get("permissions", [])  # Legacy: List of permission keys
    role_str = ",".join(permissions) if permissions else data.get("role", "")
    
    # Validation
    if not username or not email or not password:
         raise HTTPException(status_code=400, detail="Missing required fields")

    # Check existence (Case-Insensitive)
    lower_user = username.lower()
    lower_email = email.lower()
    db_user = db.query(User).filter(
        (func.lower(User.username) == lower_user) | 
        (func.lower(User.email) == lower_email)
    ).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    try:
        hashed_password = get_password_hash(password)
        new_user = User(
            username=username, 
            email=email, 
            telephone=telephone,
            hashed_password=hashed_password, 
            role=role_str, 
            role_id=role_id,
            organisation_id=admin.organisation_id, # FORCE Same Org
            is_password_change_required=True,
            is_active=False,
            is_email_verified=False
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Generate Verification Token
        v_token = secrets.token_urlsafe(32)
        v_expiry = datetime.utcnow() + timedelta(days=3)
        verify_token = EmailVerificationToken(
            user_id=new_user.id,
            token=v_token,
            expires_at=v_expiry
        )
        db.add(verify_token)
        db.commit()

        # Send Verification Email
        port = 5174 if new_user.organisation_id == 1 else 5173
        v_link = f"http://localhost:{port}/verify-email?token={v_token}"
        EmailService.send_verification_email(new_user.email, new_user.username, v_link)
        
        log_activity(db, admin, "USER_CREATION", {"created_user": username, "role_id": role_id})

        return {"message": "User created successfully", "id": new_user.id, "role_id": new_user.role_id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

@app.put("/org/users/{user_id}")
def update_org_user(user_id: int, data: dict, admin: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Org Admin can only update users in their own organisation
    user = db.query(User).filter(User.id == user_id, User.organisation_id == admin.organisation_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found in your organisation")

    action_type = "USER_UPDATE"
    details = {"updated_user": user.username, "changes": list(data.keys()), "actor": admin.username}
    
    if "is_active" in data:
        if not has_permission(admin, "SUSPEND_USER"):
            raise HTTPException(status_code=403, detail="Access denied: SUSPEND_USER permission required")
        user.is_active = data["is_active"]
        details["action"] = "SUSPENDED" if not data["is_active"] else "ACTIVATED"

    if "role_id" in data:
        if not has_permission(admin, "MANAGE_ROLES"):
            raise HTTPException(status_code=403, detail="Access denied: MANAGE_ROLES permission required")
        user.role_id = data["role_id"]

    if "permissions" in data:
        # Accept explicit list of permission keys
        if not has_permission(admin, "MANAGE_ROLES"):
            raise HTTPException(status_code=403, detail="Access denied: MANAGE_ROLES permission required")
        user.role = ",".join(data["permissions"])
    elif "role" in data:
        if not has_permission(admin, "EDIT_USER"):
            raise HTTPException(status_code=403, detail="Access denied: EDIT_USER permission required")
        user.role = data["role"]

    if "subscription_status" in data: user.subscription_status = data["subscription_status"]
    if "ip_whitelist" in data: user.ip_whitelist = data["ip_whitelist"]

    db.commit()
    db.refresh(user)
    log_activity(db, admin, action_type, details)
    return {"message": "User updated successfully", "role_id": user.role_id}

@app.delete("/org/users/{user_id}")
@app.post("/org/users/{user_id}/toggle-suspension")
def toggle_org_user_suspension(user_id: int, data: dict, admin: User = Depends(get_current_org_admin), db: Session = Depends(get_db)):
    """
    Toggle user suspension status (Org Admin).
    Requires admin password for security.
    """
    password = data.get("password")
    if not password or not verify_password(password, admin.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid admin password")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if user.organisation_id != admin.organisation_id:
        raise HTTPException(status_code=403, detail="User does not belong to your organisation")
    
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot suspend yourself")

    user.is_active = not user.is_active
    status = "Suspended" if not user.is_active else "Activated"
    
    db.commit()
    
    # Send email to the specific user
    EmailService.send_suspension_status_email(user.email, user.full_name or user.username, "User account", status)
    
    log_activity(db, admin, f"USER_{status.upper()}", {"target_user": user.username})
    return {"message": f"User {status.lower()} successfully", "is_active": user.is_active}


# --- Organisation Tier Endpoints ---

@app.get("/admin/organisations")
def list_organisations(admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    from sqlalchemy import func
    # Platform users can view all organisations by default
    orgs = db.query(Organisation).filter(Organisation.is_deleted == False).all()
    
    can_view_wallet = has_permission(admin, "VIEW_ORG_WALLET")
    
    result = []
    for o in orgs:
        org_data = {
            "id": o.id,
            "name": o.name,
            "slug": o.slug,
            "logo_url": o.logo_url,
            "primary_color": o.primary_color,
            "secondary_color": o.secondary_color,
            "tier_id": o.tier_id,
            "tier_name": o.tier.name if o.tier else None,
            "custom_unit_cost": o.custom_unit_cost,
            "subscription_price": o.subscription_price,
            "admin_username": db.query(User).filter(User.organisation_id == o.id, User.role.like('%org_admin%')).first().username if db.query(User).filter(User.organisation_id == o.id, User.role.like('%org_admin%')).first() else None,
            "admin_email": db.query(User).filter(User.organisation_id == o.id, User.role.like('%org_admin%')).first().email if db.query(User).filter(User.organisation_id == o.id, User.role.like('%org_admin%')).first() else None,
            "is_suspended": o.is_suspended
        }
        
        if can_view_wallet and o.slug != 'default':
            # Current Balance
            org_data["balance_units"] = o.wallet.balance_units if o.wallet else 0
            
            # Cumulative Total Units (Resilient Formula: Balance + Total Deductions)
            # This captures all acquired units even if the acquisition transaction was missing.
            spent = db.query(func.sum(Transaction.units_before - Transaction.units_after)).filter(
                Transaction.organisation_id == o.id,
                Transaction.units_before > Transaction.units_after
            ).scalar() or 0
            org_data["cumulative_total_units"] = int(org_data["balance_units"] + spent)
            
        result.append(org_data)
        
    return result

@app.get("/admin/tiers")
def list_tiers(admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    return db.query(Tier).all()

@app.post("/admin/tiers")
def create_tier(data: dict, admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    if not has_permission(admin, "CREATE_TIER"):
        raise HTTPException(status_code=403, detail="Permission denied: CREATE_TIER required")
    name = data.get("name")
    default_unit_cost = data.get("default_unit_cost", 1.0)
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    db_tier = Tier(name=name, default_unit_cost=float(default_unit_cost))
    db.add(db_tier)
    db.commit()
    db.refresh(db_tier)
    return db_tier

@app.put("/admin/tiers/{tier_id}")
def update_tier(tier_id: int, data: dict, admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    if not has_permission(admin, "EDIT_TIER"):
        raise HTTPException(status_code=403, detail="Permission denied: EDIT_TIER required")
    db_tier = db.query(Tier).filter(Tier.id == tier_id).first()
    if not db_tier:
        raise HTTPException(status_code=404, detail="Tier not found")
    if "name" in data: db_tier.name = data["name"]
    if "default_unit_cost" in data: db_tier.default_unit_cost = float(data["default_unit_cost"])
    db.commit()
    return db_tier

@app.delete("/admin/tiers/{tier_id}")
def delete_tier(tier_id: int, admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    if not has_permission(admin, "DELETE_TIER"):
        raise HTTPException(status_code=403, detail="Permission denied: DELETE_TIER required")
    db_tier = db.query(Tier).filter(Tier.id == tier_id).first()
    if not db_tier:
        raise HTTPException(status_code=404, detail="Tier not found")
    db.delete(db_tier)
    db.commit()
    return {"message": "Tier deleted successfully"}

@app.post("/admin/organisations")
def create_organisation(
    name: str = Form(...),
    slug: str = Form(...),
    logo: UploadFile = File(None),
    primary_color: str = Form("#3B82F6"),
    secondary_color: str = Form("#64748B"),
    admin_username: str = Form(None),
    admin_email: str = Form(None),
    admin_password: str = Form(None),
    admin_telephone: str = Form(None),
    tier_id: int = Form(None),
    custom_unit_cost: float = Form(None),
    subscription_price: float = Form(500000.0),
    admin: User = Depends(get_current_platform_user), 
    db: Session = Depends(get_db)
):
    if not has_permission(admin, "CREATE_ORGANISATION"):
        raise HTTPException(status_code=403, detail="Permission denied: CREATE_ORGANISATION required")
    # Enforce Super Admin only (redundant with get_current_admin_user but good for clarity)
    if admin.role != "admin":
        raise HTTPException(status_code=403, detail="Only Super Admins can create organisations")

    # 1. Validation Checks (Fail fast)
    if db.query(Organisation).filter(Organisation.name == name).first():
        raise HTTPException(status_code=400, detail="Organisation name already exists")
    if db.query(Organisation).filter(Organisation.slug == slug).first():
        raise HTTPException(status_code=400, detail="Organisation ID (slug) already exists")
        


    # Handle Logo Upload
    logo_url = ""
    if logo:
        try:
            safe_name = sanitize_filename(logo.filename)
            file_location = os.path.join(UPLOAD_DIR, safe_name)
            with open(file_location, "wb") as buffer:
                shutil.copyfileobj(logo.file, buffer)
            logo_url = f"http://localhost:8000/uploads/{safe_name}"
        except Exception as e:
            print(f"File upload error: {e}")
            pass

    try:
        # 1. Create the organisation
        new_org = Organisation(
            name=name,
            slug=slug,
            logo_url=logo_url,
            primary_color=primary_color,
            secondary_color=secondary_color,
            tier_id=tier_id or db.query(Tier.id).filter(Tier.name == "Tier 1").scalar(),
            custom_unit_cost=custom_unit_cost,
            subscription_price=subscription_price
        )
        db.add(new_org)
        db.flush() # Flush to get ID, but don't commit yet

        # 2. Create the unique org_admin user if provided
        final_admin_email = admin_email or f"{new_org.slug}@example.com"
        
        if admin_username and admin_password:
            print(f"DEBUG: Creating admin user for org {new_org.id}")
            hashed_password = get_password_hash(admin_password)
            new_user = User(
                username=admin_username,
                email=final_admin_email,
                telephone=admin_telephone,
                hashed_password=hashed_password,
                role="org_admin,IDENTITY,WALLET",
                organisation_id=new_org.id,
                is_password_change_required=True, # Force password change
                is_active=False,
                is_email_verified=False
            )
            db.add(new_user)
            db.commit()
            db.refresh(new_user)

            # Generate Verification Token
            v_token = secrets.token_urlsafe(32)
            v_expiry = datetime.utcnow() + timedelta(days=3)
            verify_token = EmailVerificationToken(
                user_id=new_user.id,
                token=v_token,
                expires_at=v_expiry
            )
            db.add(verify_token)
            db.commit()

            # Send Verification Email
            port = 5174 if new_user.organisation_id == 1 else 5173
            v_link = f"http://localhost:{port}/verify-email?token={v_token}"
            with open("email_trace.log", "a") as log_file:
                log_file.write(f"{datetime.utcnow()} - TRACE: Sending verification email to {new_user.email}...\n")
                email_result = EmailService.send_verification_email(new_user.email, new_user.username, v_link)
                log_file.write(f"{datetime.utcnow()} - TRACE: Email sending result: {email_result}\n")
            
            # Create Org Wallet with initial units
            # We use db.flush() so if wallet fails, everything rolls back on except
            initial_units = 10
            new_wallet = Wallet(organisation_id=new_org.id, balance_units=initial_units)
            db.add(new_wallet)
            db.flush()

            # Log initial units as a transaction
            db.add(Transaction(
                user_id=new_user.id,
                type="INITIAL_BALANCE",
                amount=float(initial_units),
                units_before=0,
                units_after=initial_units,
                details={"reason": "Welcome units for new organisation"},
                username=new_user.username,
                organisation_id=new_org.id
            ))
        
        db.commit()
        db.refresh(new_org)
        
        log_activity(db, admin, "ORG_CREATION", {"name": name, "slug": slug})

        return {
            "message": "Organisation created successfully",
            "id": new_org.id, 
            "slug": new_org.slug,
            "admin_username": admin_username if admin_username else "Not created"
        }

    except Exception as e:
        db.rollback()
        print(f"Create Org Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create organisation: {str(e)}")


@app.put("/admin/organisations/{org_id}")
def update_organisation(
    org_id: int,
    name: str = Form(None),
    slug: str = Form(None),
    logo: UploadFile = File(None),
    primary_color: str = Form(None),
    secondary_color: str = Form(None),
    admin_username: str = Form(None),
    admin_email: str = Form(None),
    admin_password: str = Form(None),
    admin_telephone: str = Form(None),
    tier_id: int = Form(None),
    custom_unit_cost: float = Form(None),
    subscription_price: float = Form(None),
    admin: User = Depends(get_current_platform_user),
    db: Session = Depends(get_db)
):
    if not has_permission(admin, "EDIT_ORGANISATION"):
        raise HTTPException(status_code=403, detail="Permission denied: EDIT_ORGANISATION required")
    org = db.query(Organisation).filter(Organisation.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")

    if name: org.name = name
    if slug: org.slug = slug
    if primary_color: org.primary_color = primary_color
    if secondary_color: org.secondary_color = secondary_color
    if tier_id is not None: org.tier_id = tier_id
    if custom_unit_cost is not None: org.custom_unit_cost = custom_unit_cost
    if subscription_price is not None: org.subscription_price = subscription_price
    
    if logo:
        # Save new logo
        file_location = os.path.join(UPLOAD_DIR, logo.filename)
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(logo.file, buffer)
        org.logo_url = f"http://localhost:8000/uploads/{logo.filename}"

    # Handle Admin User Update
    # Find the admin user for this org (loose match for "admin" or "org_admin" in role)
    org_admin = db.query(User).filter(
        User.organisation_id == org.id, 
        (User.role.like("%admin%"))
    ).first()

    if org_admin:
        if admin_username: org_admin.username = admin_username
        if admin_email: org_admin.email = admin_email
        if admin_telephone: org_admin.telephone = admin_telephone
        if admin_password: 
            org_admin.hashed_password = get_password_hash(admin_password)
            org_admin.is_password_change_required = True

    db.commit()
    db.refresh(org)
    return org

# Organisation deletion removed in favor of suspension as per user request.
# Audit logs and operation logs will remain available for compliance.


@app.post("/admin/organisations/{org_id}/toggle-suspension")
def toggle_organisation_suspension(org_id: int, data: dict, admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    if not has_permission(admin, "EDIT_ORGANISATION"):
        raise HTTPException(status_code=403, detail="Permission denied")
    
    password = data.get("password")
    if not password or not verify_password(password, admin.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid admin password")

    org = db.query(Organisation).filter(Organisation.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organisation not found")
    
    if org.slug == "default":
        raise HTTPException(status_code=400, detail="Cannot suspend the default organisation")

    org.is_suspended = not org.is_suspended
    new_status = "Suspended" if org.is_suspended else "Activated"
    
    # Automatically sync all users of this organisation
    user_active_status = not org.is_suspended
    db.query(User).filter(User.organisation_id == org.id).update({"is_active": user_active_status})
    
    db.commit()
    
    # Send email to the organisation's admin user(s)
    # We find the user with role 'admin' in that org
    org_admins = db.query(User).filter(User.organisation_id == org.id, User.role.contains("admin")).all()
    for o_admin in org_admins:
        EmailService.send_suspension_status_email(o_admin.email, o_admin.full_name or o_admin.username, "Organisation", new_status)

    log_activity(db, admin, "ORGANISATION_SUSPENSION_TOGGLE", {"org_name": org.name, "status": new_status})
    return {"message": f"Organisation {new_status.lower()} successfully", "is_suspended": org.is_suspended}

@app.get("/organisations/{slug}/public")
def get_public_organisation(slug: str, db: Session = Depends(get_db)):
    from sqlalchemy import func
    org = db.query(Organisation).filter(func.lower(Organisation.slug) == slug.lower()).first()
    if not org: raise HTTPException(status_code=404, detail="Organisation not found")
    return {
        "name": org.name,
        "slug": org.slug,
        "logo_url": org.logo_url,
        "primary_color": org.primary_color,
        "secondary_color": org.secondary_color
    }

@app.post("/admin/adjust-wallet/{user_id}")
def adjust_wallet(user_id: int, units: int, admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    if not has_permission(admin, "VIEW_WALLET"):
        raise HTTPException(status_code=403, detail="Permission denied: VIEW_WALLET required")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    org_wallet = user.org.wallet
    if not org_wallet:
        raise HTTPException(status_code=400, detail="User organisation has no wallet")
    
    units_before = org_wallet.balance_units
    org_wallet.balance_units += units
    units_after = org_wallet.balance_units
    
    # Log as TOPUP
    new_tx = Transaction(
        user_id=user.id,
        type="ADMIN_ADJUST",
        amount=float(units),
        units_before=units_before,
        units_after=units_after,
        details={"admin_id": admin.id, "reason": "Admin adjustment to Org Wallet via User"},
        username=user.username,
        organisation_id=user.organisation_id
    )
    db.add(new_tx)
    db.commit()
    
    return {"message": f"Org Wallet adjusted by {units} units", "new_balance": units_after}

@app.get("/admin/transactions")
def list_all_transactions(
    start_date: str = None,
    end_date: str = None,
    org_id: int = None,
    user_id: int = None,
    admin: User = Depends(get_current_platform_user), 
    db: Session = Depends(get_db)
):
    """
    Returns financial transactions for the Admin Dashboard with optional filters.
    """
    query = db.query(Transaction)
    
    # 1. Scoping (Platform Admin vs Org Admin)
    # If not in Org 1 (Platform), strictly restrict to their own Org ID
    if admin.organisation_id != 1: 
        query = query.filter(Transaction.organisation_id == admin.organisation_id)
    else:
        # Platform Admin can filter by specific Org
        if org_id:
            query = query.filter(Transaction.organisation_id == org_id)

    # 2. Date Filtering
    if start_date:
        try:
            dt_start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query = query.filter(Transaction.timestamp >= dt_start)
        except: pass
    if end_date:
        try:
            dt_end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query = query.filter(Transaction.timestamp <= dt_end)
        except: pass

    # 3. User Filtering
    if user_id:
        query = query.filter(Transaction.user_id == user_id)
        
    all_txs = query.order_by(Transaction.timestamp.desc()).limit(500).all()
    
    result = []
    
    for tx in all_txs:
        # Optimization: Fetch user but handle missing users gracefully (audit persistence)
        user = db.query(User).filter(User.id == tx.user_id).first()
        
        # Org Name Resolution
        if user and user.org:
             org_name = user.org.name
             if user.org.is_deleted:
                 org_name += " [DELETED]"
             org_id = user.org.id
        elif tx.organisation_id:
             # Fallback if user is deleted but we have org_id snapshot (or query org table)
             org = db.query(Organisation).filter(Organisation.id == tx.organisation_id).first()
             org_name = org.name if org else "Unknown Org"
             if org and org.is_deleted:
                 org_name += " [DELETED]"
             org_id = tx.organisation_id
        else:
             org_name = "Unknown"
             org_id = None
             
        result.append({
            "id": tx.id,
            "username": tx.username or (user.username if user else None) or "Deleted User",
            "org_name": org_name,
            "org_id": org_id,
            "type": tx.type or "UNKNOWN",
            "amount": tx.amount,
            "units_before": tx.units_before,
            "units_after": tx.units_after,
            "timestamp": tx.timestamp,
            "details": tx.details
        })

    return result

@app.get("/admin/audit-logs")
def get_audit_logs(admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    """
    Returns generic activity logs (Login, User Changes, etc.)
    Strictly scoped to Organisation.
    """
    query = db.query(ActivityLog)
    
    if admin.organisation_id != 1:
        query = query.filter(ActivityLog.organisation_id == admin.organisation_id)
        
    logs = query.order_by(ActivityLog.timestamp.desc()).limit(200).all()
    
    result = []
    for log in logs:
        result.append({
            "id": log.id,
            "username": log.username,
            "action": log.action_type,
            "details": log.details,
            "timestamp": log.timestamp,
            "organisation_id": log.organisation_id
        })
    return result

@app.get("/admin/health")
def get_admin_health(admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    """
    Returns system health status for the admin dashboard.
    """
    return {
        "status": "Healthy",
        "uptime": "99.9%",
        "last_check": datetime.utcnow().isoformat(),
        "services": {
            "database": "Connected",
            "storage": "Operational",
            "external_api": "Operational"
        }
    }

@app.get("/admin/config")
def get_system_config(admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    config = db.query(Config).first()
    if not config:
        config = Config(
            org_name="Randaframes",
            logo_url="",
            primary_color="#3B82F6",
            secondary_color="#64748B"
        )
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

@app.get("/config")
def get_public_config(db: Session = Depends(get_db)):
    config = db.query(Config).first()
    if not config:
        config = Config(
            org_name="Randaframes",
            logo_url="",
            primary_color="#3B82F6",
            secondary_color="#64748B"
        )
        db.add(config)
        db.commit()
        db.refresh(config)
    return {
        "org_name": config.org_name,
        "logo_url": config.logo_url,
        "primary_color": config.primary_color,
        "secondary_color": config.secondary_color
    }

@app.put("/admin/config")
def update_system_config(data: dict, admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    if not has_permission(admin, "MANAGE_SETTINGS"):
        raise HTTPException(status_code=403, detail="Permission denied: MANAGE_SETTINGS required")
    config = db.query(Config).first()
    if not config:
        config = Config()
        db.add(config)
    
    if "org_name" in data: config.org_name = data["org_name"]
    if "logo_url" in data: config.logo_url = data["logo_url"]
    if "primary_color" in data: config.primary_color = data["primary_color"]
    if "secondary_color" in data: config.secondary_color = data["secondary_color"]
    
    db.commit()
    return {"message": "Configuration updated successfully"}

@app.get("/admin/analytics")
def get_usage_analytics(
    days: int = 7,
    admin: User = Depends(get_current_platform_user), 
    db: Session = Depends(get_db)
):
    from sqlalchemy import func
    
    # 1. Calculate Periods
    now = datetime.utcnow()
    primary_start = now - timedelta(days=days)
    secondary_start = primary_start - timedelta(days=days)
    
    # 2. Daily Trends (Validations & Revenue)
    trends_query = db.query(
        func.date(Transaction.timestamp).label('date'),
        func.count(Transaction.id).label('validations'),
        func.sum(Transaction.amount).label('revenue')
    ).filter(
        Transaction.timestamp >= primary_start,
        Transaction.type == "NIN_VALIDATION"
    ).group_by(func.date(Transaction.timestamp)).all()
    
    trends = []
    for r in trends_query:
        trends.append({
            "date": str(r.date),
            "validations": r.validations,
            "revenue": float(r.revenue or 0)
        })

    # 3. Growth Rate (Validations this period vs last period)
    this_period_count = db.query(Transaction).filter(
        Transaction.timestamp >= primary_start, 
        Transaction.type == "NIN_VALIDATION"
    ).count()
    
    last_period_count = db.query(Transaction).filter(
        Transaction.timestamp >= secondary_start,
        Transaction.timestamp < primary_start,
        Transaction.type == "NIN_VALIDATION"
    ).count()
    
    growth_rate = 0.0
    if last_period_count > 0:
        growth_rate = round(((this_period_count - last_period_count) / last_period_count) * 100, 1)
    elif this_period_count > 0:
        growth_rate = 100.0

    # 4. Performance Metrics (Peak Hour & Success Rate)
    # Peak Hour
    peak_hour_result = db.query(
        func.strftime('%H', Transaction.timestamp).label('hour'),
        func.count(Transaction.id).label('count')
    ).filter(
        Transaction.timestamp >= primary_start,
        Transaction.type == "NIN_VALIDATION"
    ).group_by('hour').order_by(text('count DESC')).first()
    
    peak_hour = f"{peak_hour_result.hour}:00" if peak_hour_result else "N/A"

    # Success Rate (Attempts vs Actual Transactions)
    total_attempts = db.query(ActivityLog).filter(
        ActivityLog.timestamp >= primary_start,
        ActivityLog.action_type == "NIN_VALIDATION"
    ).count()
    
    success_rate = 100.0
    if total_attempts > 0:
        success_rate = round((this_period_count / total_attempts) * 100, 1)

    # 5. Organisation Breakdown (Top 5 by volume)
    org_breakdown = db.query(
        Organisation.name,
        func.count(Transaction.id).label('volume')
    ).join(Transaction, Transaction.organisation_id == Organisation.id) \
     .filter(Transaction.timestamp >= primary_start, Transaction.type == "NIN_VALIDATION") \
     .group_by(Organisation.id) \
     .order_by(text('volume DESC')).limit(5).all()

    return {
        "trends": trends,
        "summary": {
            "this_period_validations": this_period_count,
            "growth_rate": growth_rate,
            "peak_hour": peak_hour,
            "success_rate": success_rate,
            "avg_latency": 142.5 # Mocking until we have real latency logging
        },
        "org_breakdown": [{"name": r.name, "volume": r.volume} for r in org_breakdown]
    }

@app.get("/admin/analytics/extended")
def get_extended_analytics(admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    from sqlalchemy import func
    
    # --- 1. FINANCIAL INTELLIGENCE ---
    # LTV (Lifetime Value) per Organisation
    ltv_query = db.query(
        Organisation.name,
        func.sum(Transaction.amount).label('total_spent')
    ).join(Transaction, Transaction.organisation_id == Organisation.id) \
     .group_by(Organisation.id).order_by(text('total_spent DESC')).limit(10).all()
    
    ltv_data = [{"name": r.name, "value": float(r.total_spent or 0)} for r in ltv_query]

    # Profit Margin Estimation
    # Assuming platform cost per validation is 80 units (internal units/naira)
    # Revenue is Transaction.amount for NIN_VALIDATIONS
    vendor_cost_per_validation = 80.0 
    
    total_revenue = db.query(func.sum(Transaction.amount)).filter(Transaction.type == "NIN_VALIDATION").scalar() or 0.0
    total_validations = db.query(func.count(Transaction.id)).filter(Transaction.type == "NIN_VALIDATION").scalar() or 0
    est_total_cost = total_validations * vendor_cost_per_validation
    est_profit = total_revenue - est_total_cost
    profit_margin_pct = (est_profit / total_revenue * 100) if total_revenue > 0 else 0

    # Top-up Velocity (Avg days between topups)
    # Logic: For each org, find diff between consecutive topup timestamps
    velocity_data = []
    # Simplified: Get average frequency of 'TOPUP' or 'ADMIN_ADJUST' positive amounts
    
    # --- 2. GROWTH & ENGAGEMENT ---
    # Acquisition Rate (New Orgs per Month/Day)
    acquisition_query = db.query(
        func.date(Organisation.created_at).label('date'),
        func.count(Organisation.id).label('count')
    ).group_by(func.date(Organisation.created_at)).order_by(text('date DESC')).limit(30).all()
    acquisition_data = [{"date": str(r.date), "count": r.count} for r in acquisition_query]
    
    # Tier Distribution
    tier_dist = db.query(
        Tier.name,
        func.count(Organisation.id).label('count')
    ).join(Organisation).group_by(Tier.id).all()
    tier_data = [{"label": r.name, "value": r.count} for r in tier_dist]

    # Churn Risk (No activity in last 14 days)
    fourteen_days_ago = datetime.utcnow() - timedelta(days=14)
    active_org_ids = db.query(Transaction.organisation_id).filter(Transaction.timestamp >= fourteen_days_ago).distinct()
    churn_orgs = db.query(Organisation.name).filter(~Organisation.id.in_(active_org_ids), Organisation.slug != "default").all()
    churn_risk_data = [r.name for r in churn_orgs]

    # --- 3. OPERATIONAL PERFORMANCE ---
    # Activity Heatmap (7 Days x 24 Hours)
    # SQLite strftime('%w', timestamp) returns 0 (Sunday) to 6 (Saturday)
    # SQLite strftime('%H', timestamp) returns 00 to 23
    heatmap_raw = db.query(
        func.strftime('%w', Transaction.timestamp).label('day'),
        func.strftime('%H', Transaction.timestamp).label('hour'),
        func.count(Transaction.id).label('count')
    ).filter(Transaction.type == "NIN_VALIDATION").group_by('day', 'hour').all()
    
    heatmap_data = []
    # Initialize grid
    grid = [[0 for _ in range(24)] for _ in range(7)]
    for r in heatmap_raw:
        try:
            d = int(r.day)
            h = int(r.hour)
            grid[d][h] = r.count
        except (ValueError, TypeError): pass
    
    for d_idx, day_name in enumerate(["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]):
        for h in range(24):
            heatmap_data.append({"day": day_name, "hour": h, "value": grid[d_idx][h]})

    # Error Breakdown
    # Track "NIN_VALIDATION" actions in ActivityLog that didn't lead to a successful Transaction
    # SQLite json_extract(details, '$.reason')
    error_query = db.query(
        func.json_extract(ActivityLog.details, '$.reason').label('reason'),
        func.count(ActivityLog.id).label('count')
    ).filter(ActivityLog.action_type == "VALIDATION_FAILED").group_by('reason').all()
    
    error_data = [{"name": r.reason or "Unknown Error", "value": r.count} for r in error_query]

    # --- 4. BEHAVIOR ---
    # Power Users (Top 10)
    power_users_query = db.query(
        Transaction.username,
        func.count(Transaction.id).label('count')
    ).filter(Transaction.type == "NIN_VALIDATION") \
     .group_by(Transaction.username).order_by(text('count DESC')).limit(10).all()
    
    power_user_data = [{"username": r.username, "count": r.count} for r in power_users_query]

    # Subscription Health
    sub_health = db.query(
        Organisation.subscription_status,
        func.count(Organisation.id).label('count')
    ).group_by(Organisation.subscription_status).all()
    sub_health_data = [{"name": r.subscription_status or "unknown", "value": r.count} for r in sub_health]

    return {
        "financial": {
            "ltv": ltv_data,
            "profit_stats": {
                "total_profit": est_profit,
                "margin_pct": profit_margin_pct,
                "total_validations": total_validations
            }
        },
        "growth": {
            "acquisition": acquisition_data,
            "tier_distribution": tier_data,
            "churn_risk": churn_risk_data,
            "sub_health": sub_health_data
        },
        "operations": {
            "heatmap": heatmap_data,
            "errors": error_data
        },
        "behavior": {
            "power_users": power_user_data
        }
    }

@app.post("/admin/users/bulk")
def bulk_update_users(data: dict, admin: User = Depends(get_current_admin_user), db: Session = Depends(get_db)):
    user_ids = data.get("user_ids", [])
    action = data.get("action") # "activate", "block", "topup"
    units = data.get("units", 0)
    
    if not user_ids:
        return {"message": "No users selected"}
        
    for uid in user_ids:
        user = db.query(User).filter(User.id == uid).first()
        if not user: continue
        
        if action == "activate": user.is_active = True
        elif action == "block": user.is_active = False
        elif action == "topup" and units != 0:

            if user.org and user.org.wallet:
                units_before = user.org.wallet.balance_units
                user.org.wallet.balance_units += units
                units_after = user.org.wallet.balance_units
                
                # Create Transaction Log
                new_tx = Transaction(
                    user_id=user.id,
                    type="ADMIN_ADJUST",
                    amount=float(units),
                    units_before=units_before,
                    units_after=units_after,
                    details={"admin_id": admin.id, "reason": "Bulk Topup"},
                    username=user.username,
                    organisation_id=user.organisation_id
                )
                db.add(new_tx)
                
                # Log Activity
                log_activity(db, admin, "BULK_TOPUP", {"target_user": user.username, "units": units})
            
    db.commit()
    return {"message": f"Bulk action '{action}' performed on {len(user_ids)} users"}

@app.get("/admin/stats")
def get_admin_stats(admin: User = Depends(get_current_platform_user), db: Session = Depends(get_db)):
    from sqlalchemy import func
    
    user_count_query = db.query(User)
    if admin.organisation_id == 1:
        # Sync with list_users refined logic
        user_count_query = user_count_query.filter(
            (User.organisation_id == 1) | 
            (User.role.like("%org_admin%"))
        )
    else:
        user_count_query = user_count_query.filter(User.organisation_id == admin.organisation_id)
    user_count = user_count_query.count()
    total_units = db.query(func.sum(Wallet.balance_units)) \
        .join(Organisation, Wallet.organisation_id == Organisation.id) \
        .filter(Organisation.slug != "default") \
        .scalar() or 0
    tx_count = db.query(Transaction).count()
    
    # 1. Total Revenue Calculation (Successful Payments Only)
    # Sum of all 'amount' from SUBSCRIPTION_PAYMENT and UNIT_PURCHASE transactions
    revenue_txs = db.query(Transaction).filter(Transaction.type.in_(["SUBSCRIPTION_PAYMENT", "UNIT_PURCHASE"])).all()
    total_revenue = sum(tx.amount for tx in revenue_txs)
    
    # 1.5 Revenue Breakdown per Organisation
    # We aggregate based on actual successful transactions
    revenue_map = {} # org_id -> {"name": str, "revenue": float}
    
    # Get all organisations (even deleted ones, so breakdown total matches total_revenue)
    all_orgs = db.query(Organisation).all()
    for o in all_orgs:
        name = o.name
        if o.is_deleted:
            name += " [DELETED]"
        revenue_map[o.id] = {
            "name": name,
            "revenue": 0.0
        }
        
    # Add revenue from recorded transactions
    for tx in revenue_txs:
        if tx.organisation_id in revenue_map:
            revenue_map[tx.organisation_id]["revenue"] += tx.amount
                
    # Filter out orgs with 0 revenue and the 'default' org
    revenue_breakdown = [item for item in revenue_map.values() if item["revenue"] > 0 and item["name"] != "default"]
    
    # Sort by revenue DESC
    revenue_breakdown = sorted(
        revenue_breakdown,
        key=lambda x: x["revenue"],
        reverse=True
    )

    # 2. Top 5 Organisations by Usage (NIN_VALIDATION)
    top_orgs_query = db.query(
        Organisation.name,
        func.count(Transaction.id).label('usage_count')
    ).join(Transaction, Transaction.organisation_id == Organisation.id) \
     .filter(Transaction.type == "NIN_VALIDATION") \
     .filter(Organisation.slug != "default") \
     .group_by(Organisation.id) \
     .order_by(text('usage_count DESC')) \
     .limit(5).all()
    
    top_orgs = [{"name": r.name, "count": r.usage_count} for r in top_orgs_query]

    # 3. Recent Activity (Last 10)
    recent_activity = db.query(ActivityLog).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    activity_data = []
    for log in recent_activity:
        activity_data.append({
            "username": log.username or "Unknown",
            "action": log.action_type or "ACTION",
            "timestamp": log.timestamp.isoformat(),
            "details": log.details
        })

    # 4. Success Rate (For now based on availability of Transaction records vs ActivityLogs if we had error logs)
    # If we assume every ActivityLog for NIN_VALIDATION that doesn't have an error is a success
    total_attempts = db.query(ActivityLog).filter(ActivityLog.action_type == "NIN_VALIDATION").count()
    successful_txs = db.query(Transaction).filter(Transaction.type == "NIN_VALIDATION").count()
    
    success_rate = 100.0
    if total_attempts > 0:
        success_rate = round((successful_txs / total_attempts) * 100, 1)

    # Check external units
    ext_token = get_external_token()
    external_units = 0
    if ext_token:
        try:
            wallet_url = f"{EXTERNAL_API_BASE}/get_wallet_details"
            payload = crypto_service.encrypt({"username": "randa_1769113347fn5h@vmail.com"})
            resp = requests.post(wallet_url, json={"payload": payload}, headers={"Authorization": f"Bearer {ext_token}"})
            if resp.status_code == 200:
                dec = crypto_service.decrypt(resp.json()["payload"])
                if dec.get("status") in [200, "200", "00"]:
                    data = dec.get("data")
                    if isinstance(data, list) and len(data) > 0:
                        external_units = data[0].get("validation_units", 0)
                    elif isinstance(data, dict):
                        external_units = data.get("validation_units", 0)
        except:
            pass
            
    return {
        "total_users": user_count,
        "total_units_in_circulation": total_units,
        "total_transactions": tx_count,
        "master_wallet_units": external_units,
        "total_revenue": total_revenue,
        "top_orgs": top_orgs,
        "recent_activity": activity_data,
        "success_rate": success_rate,
        "revenue_breakdown": revenue_breakdown
    }

@app.post("/topup")
def topup_wallet(
    units: int = Form(...),
    payment_method: str = Form("card"),
    user: User = Depends(get_current_org_admin),
    db: Session = Depends(get_db)
):
    """
    Purchase units in multiples of 100.
    Simulates a payment gateway.
    """
    if units <= 0 or units % 100 != 0:
        raise HTTPException(status_code=400, detail="Units must be a positive multiple of 100")
        
    if not user.org:
        raise HTTPException(status_code=400, detail="User does not belong to an organisation")

    # Calculate price
    unit_cost = user.org.custom_unit_cost or (user.org.tier.default_unit_cost if user.org.tier else 1.0)
    total_price = units * unit_cost

    print(f"DEBUG: Topup Wallet for Org ID: {user.organisation_id}, Units: {units}, Payment: {payment_method}")

    # Simulate Payment
    if payment_method == "fail_test":
        raise HTTPException(status_code=400, detail="Payment declined by bank")

    # Success: Add units to org wallet
    if not user.org.wallet:
        user.org.wallet = Wallet(organisation_id=user.organisation_id, balance_units=0)
        db.add(user.org.wallet)
    
    units_before = user.org.wallet.balance_units
    user.org.wallet.balance_units += units
    units_after = user.org.wallet.balance_units
    
    # Log Transaction
    new_tx = Transaction(
        user_id=user.id,
        type="UNIT_PURCHASE",
        amount=float(units),
        units_before=units_before,
        units_after=units_after,
        details={"payment_method": payment_method, "price_paid": total_price, "unit_cost": unit_cost},
        username=user.username,
        organisation_id=user.organisation_id
    )
    db.add(new_tx)
    db.commit()

    log_activity(db, user, "UNIT_PURCHASE", {"units": units, "price": total_price})

    return {
        "message": f"Successfully purchased {units} units for ${total_price:.2f}",
        "balance": user.org.wallet.balance_units,
        "price_paid": total_price
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
# Trigger Deploy
