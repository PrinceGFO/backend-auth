import uuid
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel, EmailStr
import bcrypt
from jose import jwt
from datetime import datetime, timedelta

# --- DB ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./auth.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    full_name = Column(String, nullable=True)
    bio = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# --- Schemas ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# --- Helpers ---
SECRET_KEY = "day1-super-secret-key-change-in-prod"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- App ---
app = FastAPI(title="Backend Auth Day 1 - Complete")

@app.get("/")
def home():
    return {"message": "Auth API is running! Go to /docs"}

@app.post("/auth/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user = User(email=user.email, hashed_password=hash_password(user.password))
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"id": db_user.id, "email": db_user.email}

@app.post("/auth/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}
# --- DAY 2: Protected Route ---



from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    from jose import JWTError
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@app.get("/auth/me")
def read_me(current_user: User = Depends(get_current_user)):
    return {"email": current_user.email, "id": current_user.id, "message": f"Welcome Prince, you are authenticated!"}


# --- Forgot Password ---
reset_tokens = {}

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

@app.post("/auth/forgot-password")
def forgot_password(data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    token = str(uuid.uuid4())
    reset_tokens[token] = {"user_id": user.id, "expires": datetime.utcnow() + timedelta(minutes=15)}
    return {"message": "Reset token generated", "reset_token": token}

@app.post("/auth/reset-password")
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    if data.token not in reset_tokens:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    token_data = reset_tokens[data.token]
    if datetime.utcnow() > token_data["expires"]:
        del reset_tokens[data.token]
        raise HTTPException(status_code=400, detail="Token expired")
    if len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    user = db.query(User).filter(User.id == token_data["user_id"]).first()
    user.hashed_password = hash_password(data.new_password)
    db.commit()
    del reset_tokens[data.token]
    return {"message": "Password reset successfully"}

# --- DAY 3: Change Password ---
class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

@app.post("/auth/change-password")
def change_password(
    data: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # 1. Check old password is correct
    if not verify_password(data.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Old password is incorrect")
    if data.old_password == data.new_password:
        raise HTTPException(status_code=400, detail="New password must be different from old password")
    
    # 2. New password must be different and at least 6 chars
    if len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")

    # 3. Save new hashed password
    current_user.hashed_password = hash_password(data.new_password)
    db.commit()
    return {"message": "Password changed successfully"}