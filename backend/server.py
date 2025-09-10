from fastapi import FastAPI, APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import hashlib
import jwt
import smtplib
import threading
import asyncio
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import re

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-here')
JWT_ALGORITHM = "HS256"

# SMTP Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = "ariffmolla42@gmail.com"
SMTP_PASSWORD = "ohpd rzxq bmbb rzud"

# Define Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    full_name: str
    password_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True

class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    created_at: datetime
    is_active: bool

class SymptomEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    symptoms: Dict[str, Any]  # Flexible structure for different symptom types
    custom_symptoms: Optional[str] = None
    severity_prediction: str  # "low", "medium", "high"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    alert_sent: bool = False

class SymptomCreate(BaseModel):
    symptoms: Dict[str, Any]
    custom_symptoms: Optional[str] = None

class SymptomResponse(BaseModel):
    id: str
    user_id: str
    symptoms: Dict[str, Any]
    custom_symptoms: Optional[str]
    severity_prediction: str
    timestamp: datetime
    alert_sent: bool

class AlertHistory(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    symptom_id: str
    severity: str
    email_sent: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Utility Functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hashlib.sha256(password.encode()).hexdigest() == hashed

def validate_password_strength(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = await db.users.find_one({"id": user_id})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return User(**user)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ML Model for Risk Assessment (Placeholder - will be enhanced later)
def assess_symptom_risk(symptoms: Dict[str, Any], custom_symptoms: Optional[str] = None) -> str:
    """Basic rule-based risk assessment. Will be replaced with ML model later."""
    risk_score = 0
    
    # Check vital signs
    if 'temperature' in symptoms:
        temp = float(symptoms.get('temperature', 0))
        if temp > 103:
            risk_score += 3
        elif temp > 101:
            risk_score += 2
        elif temp > 99.5:
            risk_score += 1
    
    if 'heart_rate' in symptoms:
        hr = int(symptoms.get('heart_rate', 0))
        if hr > 120 or hr < 50:
            risk_score += 3
        elif hr > 100 or hr < 60:
            risk_score += 1
    
    if 'blood_pressure_systolic' in symptoms:
        sys_bp = int(symptoms.get('blood_pressure_systolic', 0))
        if sys_bp > 180 or sys_bp < 90:
            risk_score += 3
        elif sys_bp > 140:
            risk_score += 2
    
    # Check pain level
    if 'pain_level' in symptoms:
        pain = int(symptoms.get('pain_level', 0))
        if pain >= 8:
            risk_score += 2
        elif pain >= 6:
            risk_score += 1
    
    # Check breathing difficulty
    if symptoms.get('breathing_difficulty') == 'severe':
        risk_score += 3
    elif symptoms.get('breathing_difficulty') == 'moderate':
        risk_score += 2
    elif symptoms.get('breathing_difficulty') == 'mild':
        risk_score += 1
    
    # Check custom symptoms for emergency keywords
    if custom_symptoms:
        emergency_keywords = ['chest pain', 'difficulty breathing', 'unconscious', 'seizure', 'bleeding']
        custom_lower = custom_symptoms.lower()
        for keyword in emergency_keywords:
            if keyword in custom_lower:
                risk_score += 3
                break
    
    # Determine severity
    if risk_score >= 6:
        return "high"
    elif risk_score >= 3:
        return "medium"
    else:
        return "low"

# Email Alert System
def send_email_alert(user: User, symptom_entry: SymptomEntry):
    """Send email alert using threading to avoid blocking"""
    def send_email():
        try:
            msg = MIMEMultipart()
            msg['From'] = SMTP_EMAIL
            msg['To'] = SMTP_EMAIL  # Sending to the specified email
            msg['Subject'] = f"HEALTH ALERT - {symptom_entry.severity_prediction.upper()} RISK DETECTED"
            
            body = f"""
ALERTRX HEALTH MONITORING SYSTEM

🚨 ALERT DETAILS:
Patient: {user.full_name}
Email: {user.email}
Timestamp: {symptom_entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Risk Level: {symptom_entry.severity_prediction.upper()}

📊 REPORTED SYMPTOMS:
{format_symptoms_for_email(symptom_entry.symptoms)}

{f"Additional Notes: {symptom_entry.custom_symptoms}" if symptom_entry.custom_symptoms else ""}

This is an automated alert from AlertRx Health Monitoring System.
Please take appropriate action based on the risk level.

Risk Levels:
🔴 HIGH: Immediate medical attention required
🟡 MEDIUM: Monitor closely, consider medical consultation
🟢 LOW: General monitoring recommended
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            text = msg.as_string()
            server.sendmail(SMTP_EMAIL, SMTP_EMAIL, text)
            server.quit()
            
            logging.info(f"Alert email sent for user {user.email}")
            
        except Exception as e:
            logging.error(f"Failed to send email alert: {str(e)}")
    
    # Run email sending in a separate thread
    thread = threading.Thread(target=send_email)
    thread.daemon = True
    thread.start()

def format_symptoms_for_email(symptoms: Dict[str, Any]) -> str:
    """Format symptoms for email display"""
    formatted = []
    for key, value in symptoms.items():
        formatted_key = key.replace('_', ' ').title()
        formatted.append(f"• {formatted_key}: {value}")
    return '\n'.join(formatted)

# API Routes
@api_router.post("/auth/signup", response_model=UserResponse)
async def signup(user_data: UserCreate):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Validate password strength
    if not validate_password_strength(user_data.password):
        raise HTTPException(
            status_code=400, 
            detail="Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character"
        )
    
    # Create user
    user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        password_hash=hash_password(user_data.password)
    )
    
    await db.users.insert_one(user.dict())
    
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        created_at=user.created_at,
        is_active=user.is_active
    )

@api_router.post("/auth/login")
async def login(login_data: UserLogin):
    user = await db.users.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user["is_active"]:
        raise HTTPException(status_code=401, detail="Account is inactive")
    
    access_token = create_access_token(data={"sub": user["id"]})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse(**user)
    }

@api_router.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        created_at=current_user.created_at,
        is_active=current_user.is_active
    )

@api_router.post("/symptoms", response_model=SymptomResponse)
async def log_symptoms(
    symptom_data: SymptomCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    # Assess risk level
    severity = assess_symptom_risk(symptom_data.symptoms, symptom_data.custom_symptoms)
    
    # Create symptom entry
    symptom_entry = SymptomEntry(
        user_id=current_user.id,
        symptoms=symptom_data.symptoms,
        custom_symptoms=symptom_data.custom_symptoms,
        severity_prediction=severity
    )
    
    # Save to database
    await db.symptom_entries.insert_one(symptom_entry.dict())
    
    # Send email alert if medium or high risk
    if severity in ["medium", "high"]:
        send_email_alert(current_user, symptom_entry)
        symptom_entry.alert_sent = True
        await db.symptom_entries.update_one(
            {"id": symptom_entry.id},
            {"$set": {"alert_sent": True}}
        )
        
        # Log alert history
        alert_history = AlertHistory(
            user_id=current_user.id,
            symptom_id=symptom_entry.id,
            severity=severity,
            email_sent=True
        )
        await db.alert_history.insert_one(alert_history.dict())
    
    return SymptomResponse(**symptom_entry.dict())

@api_router.get("/symptoms", response_model=List[SymptomResponse])
async def get_symptoms(current_user: User = Depends(get_current_user)):
    symptoms = await db.symptom_entries.find({"user_id": current_user.id}).sort("timestamp", -1).to_list(100)
    return [SymptomResponse(**symptom) for symptom in symptoms]

@api_router.get("/alerts", response_model=List[AlertHistory])
async def get_alert_history(current_user: User = Depends(get_current_user)):
    alerts = await db.alert_history.find({"user_id": current_user.id}).sort("timestamp", -1).to_list(50)
    return [AlertHistory(**alert) for alert in alerts]

@api_router.get("/")
async def root():
    return {"message": "AlertRx Health Monitoring System API"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()