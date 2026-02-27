from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON, Boolean, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy import create_engine
import datetime

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Default to SQLite for local Development
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DEFAULT_DB_PATH = os.path.join(PROJECT_ROOT, "randaframes.db")

# Use PostgreSQL if DATABASE_URL is provided, otherwise fall back to SQLite
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# Fix for Render/Postgres: ensure the URL starts with postgresql://
if SQLALCHEMY_DATABASE_URL and SQLALCHEMY_DATABASE_URL.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URL = SQLALCHEMY_DATABASE_URL.replace("postgres://", "postgresql://", 1)

print(f"DATABASE: Using {'PostgreSQL' if SQLALCHEMY_DATABASE_URL.startswith('postgresql') else 'SQLite'}")

engine_args = {"check_same_thread": False, "timeout": 60} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, **engine_args
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Tier(Base):
    __tablename__ = "tiers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    default_unit_cost = Column(Float, default=1.0)
    
    organisations = relationship("Organisation", back_populates="tier")

class Organisation(Base):
    __tablename__ = "organisations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    slug = Column(String, unique=True, index=True)
    logo_url = Column(String)
    primary_color = Column(String)
    secondary_color = Column(String)
    subscription_status = Column(String, default="inactive")
    subscription_expiry = Column(DateTime)
    subscription_plan = Column(String, default="none")
    is_deleted = Column(Boolean, default=False)
    is_suspended = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    tier_id = Column(Integer, ForeignKey("tiers.id"))
    custom_unit_cost = Column(Float) # Override default_unit_cost
    subscription_price = Column(Float, default=500000.0) # Yearly license price in Naira
    
    tier = relationship("Tier", back_populates="organisations")
    users = relationship("User", back_populates="org")
    wallet = relationship("Wallet", back_populates="organisation", uselist=False)
    roles = relationship("AdminRole", back_populates="organisation")

class AdminRole(Base):
    __tablename__ = "admin_roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    permissions = Column(JSON, default=list) # List of permission keys: ["VIEW_REVENUE", "CREATE_USER"]
    organisation_id = Column(Integer, ForeignKey("organisations.id"))
    
    organisation = relationship("Organisation", back_populates="roles")
    users = relationship("User", back_populates="admin_role")

class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint('username', 'organisation_id', name='uq_username_org'),
        UniqueConstraint('email', 'organisation_id', name='uq_email_org'),
    )

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True) # Unique per org
    email = Column(String, index=True)    # Unique per org
    hashed_password = Column(String)
    full_name = Column(String)
    telephone = Column(String)
    organisation_id = Column(Integer, ForeignKey("organisations.id"))
    subscription_status = Column(String, default="active")
    role = Column(String, default="user") # user, admin
    ip_whitelist = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    is_password_change_required = Column(Boolean, default=True)
    is_email_verified = Column(Boolean, default=False)
    role_id = Column(Integer, ForeignKey("admin_roles.id"))
    
    org = relationship("Organisation", back_populates="users")
    admin_role = relationship("AdminRole", back_populates="users")
    # wallet = relationship("Wallet", back_populates="owner", uselist=False) # Moved to Organisation
    # transactions = relationship("Transaction", back_populates="owner")

class Wallet(Base):
    __tablename__ = "wallets"

    id = Column(Integer, primary_key=True, index=True)
    organisation_id = Column(Integer, ForeignKey("organisations.id")) # Changed from user_id
    balance_units = Column(Integer, default=0)
    
    organisation = relationship("Organisation", back_populates="wallet")

class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True) # No ForeignKey to allow persistence after user deletion
    type = Column(String)  # NIN_VALIDATION, TOPUP
    amount = Column(Float)
    units_before = Column(Integer)
    units_after = Column(Integer)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    details = Column(JSON)  # Store API response or NIN details
    username = Column(String) # Snapshot of username
    organisation_id = Column(Integer) # Snapshot for efficient filtering
    
    owner = relationship("User", primaryjoin="Transaction.user_id==User.id", foreign_keys=[user_id]) # Removed back_populates

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token = Column(String, unique=True, index=True) # Usually a hashed version
    expires_at = Column(DateTime)
    is_used = Column(Boolean, default=False)
    
    user = relationship("User")

class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token = Column(String, unique=True, index=True)
    expires_at = Column(DateTime)
    is_used = Column(Boolean, default=False)
    
    user = relationship("User")

class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    revoked_at = Column(DateTime, default=datetime.datetime.utcnow)

class ActivityLog(Base):
    __tablename__ = "activity_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    organisation_id = Column(Integer, index=True)
    action_type = Column(String)
    details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class Config(Base):
    __tablename__ = "system_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    org_name = Column(String)
    logo_url = Column(String)
    primary_color = Column(String)
    secondary_color = Column(String)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
