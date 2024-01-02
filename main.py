from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from cryptography.fernet import Fernet
from pydantic import BaseModel
from passlib.context import CryptContext
import os
from dotenv import load_dotenv
import json

load_dotenv()

app = FastAPI()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# CORS middleware
origins = ["http://localhost:3000", "http://localhost:3333"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class UserBase(BaseModel):
    name: str
    email: str

class LearningStats(BaseModel):
    hoursStudied: int
    subjectsCovered: list

class UserRegister(UserBase):
    password: str
    learning_stats: LearningStats

class UserLogin(BaseModel):
    username: str
    password: str

class UserInDB(UserBase):
    hashed_password: str
    learning_stats: LearningStats

# OAuth2 password bearer token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# In-memory storage for demonstration
# Replace with a real database in production
db: dict[str, UserInDB] = {}

# Register endpoint
@app.post("/register/{user_name}")
async def register_user(user_name: str, user: UserRegister):
    if user_name in db:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = pwd_context.hash(user.password)
    user_data = UserInDB(**user.dict(exclude={"password"}), hashed_password=hashed_password)
    db[user_name] = user_data
    return {"message": f"User {user_name} registered successfully"}

# Login endpoint
@app.post("/login/{user_name}")
async def login_user(user_name: str, form_data: UserLogin):
    # Authenticate the username and password
    user_data = db.get(user_name)
    if not user_data or not pwd_context.verify(form_data.password, user_data.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {"message": f"User {user_name} logged in successfully"}

# Get user learning stats endpoint
@app.get("/users/{user_name}/learning_stats")
async def get_user_learning_stats(user_name: str, token: str = Depends(oauth2_scheme)):
    # Token would be used for real authentication
    user = db.get(user_name)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user.learning_stats

# Generic error handling for demonstration purposes
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )
