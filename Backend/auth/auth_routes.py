"""
Authentication Routes for DarkHook Defense
"""

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import os
from passlib.context import CryptContext
from jose import jwt

# Import MongoDB configuration
from modules.database.mongo_config import get_database

router = APIRouter()

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Configuration - Require SECRET_KEY from environment
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required. Please set it in your .env file.")

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# User models
class User(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserResponse(BaseModel):
    name: str
    email: str

# Helper function to get users collection from MongoDB
def get_users_collection():
    """Get the users collection from MongoDB"""
    db = get_database()
    return db["users"]

def create_access_token(data: dict):
    """Create JWT access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    """Verify JWT token and return payload"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user_email(token: str = Depends(oauth2_scheme)):
    """Extract email from JWT token"""
    payload = verify_token(token)
    return payload.get("sub")

@router.post("/register", response_model=Token)
async def register(user: User):
    """Register a new user"""
    try:
        users_collection = get_users_collection()
        
        # Check if user already exists
        existing_user = users_collection.find_one({"email": user.email})
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Hash the password and store user
        hashed_password = pwd_context.hash(user.password)
        
        user_doc = {
            "name": user.name,
            "email": user.email,
            "password": hashed_password,
            "created_at": datetime.utcnow()
        }
        
        users_collection.insert_one(user_doc)
        
        access_token = create_access_token(data={"sub": user.email})
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.post("/login", response_model=Token)
async def login(user_login: UserLogin):
    """Login user"""
    try:
        users_collection = get_users_collection()
        
        # Find user by email
        user = users_collection.find_one({"email": user_login.email})
        
        if not user or not pwd_context.verify(user_login.password, user["password"]):
            raise HTTPException(status_code=401, detail="Incorrect email or password")
        
        access_token = create_access_token(data={"sub": user_login.email})
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/me", response_model=UserResponse)
async def get_current_user(current_user: str = Depends(get_current_user_email)):
    """Get current user info"""
    users_collection = get_users_collection()
    user = users_collection.find_one({"email": current_user})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"name": user["name"], "email": user["email"]}
