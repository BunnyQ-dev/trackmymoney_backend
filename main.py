from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt, JWTError

# FastAPI app initialization
app = FastAPI()

# Database setup
DATABASE_URL = "sqlite:///./test.db"
Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Config
SECRET_KEY = "e7696c2c4bfff3f0a2833596832f09f0fa7291dd9d9873de5accfbce302f7427"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Balance(Base):
    __tablename__ = "balance"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    balance = Column(Float, default=0.0)

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    category_id = Column(Integer, ForeignKey("categories.id"))  # Зв'язок із категоріями
    type = Column(String)  # "income" або "expense"
    amount = Column(Float)
    date = Column(DateTime, default=datetime.utcnow)

class Goal(Base):
    __tablename__ = "goals"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    name = Column(String)
    target_amount = Column(Float)
    saved_amount = Column(Float, default=0.0)

class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    is_income = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic Models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class BalanceResponse(BaseModel):
    balance: float

class CategoryCreate(BaseModel):
    name: str
    is_income: bool

class CategoryResponse(BaseModel):
    id: int
    name: str
    is_income: bool

    class Config:
        from_attributes = True

class TransactionCreate(BaseModel):
    category_id: int
    amount: float

class TransactionResponse(BaseModel):
    id: int
    type: str
    amount: float
    category: str
    date: datetime

    class Config:
        from_attributes = True

class GoalCreate(BaseModel):
    name: str
    target_amount: float

class GoalResponse(BaseModel):
    id: int
    name: str
    target_amount: float
    saved_amount: float

    class Config:
        from_attributes = True


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

# Utils
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Routes
@app.post("/register/")
def register(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    db.add(Balance(user_id=db_user.id, balance=0.0))
    db.commit()
    return {"message": "User registered successfully."}

@app.post("/login/")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_access_token(data={"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/balance/", response_model=BalanceResponse)
def get_balance(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    balance = db.query(Balance).filter(Balance.user_id == current_user.id).first()
    if not balance:
        raise HTTPException(status_code=404, detail="Balance not found")
    return {"balance": balance.balance}

@app.post("/transactions/", response_model=TransactionResponse)
def create_transaction(transaction: TransactionCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user))
    db_category = db.query(Category).filter(Category.id == transaction.category_id).first()
    if not db_category:
        raise HTTPException(status_code=400, detail="Category not found")


    transaction_type = "income" if db_category.is_income else "expense"


    db_transaction = Transaction(
        user_id=current_user.id,
        category_id=transaction.category_id,
        type=transaction_type,
        amount=transaction.amount
    )
    db.add(db_transaction)
    db.commit()
    db.refresh(db_transaction)


    balance = db.query(Balance).filter(Balance.user_id == current_user.id).first()
    if transaction_type == "income":
        balance.balance += transaction.amount
    elif transaction_type == "expense":
        balance.balance -= transaction.amount
    db.commit()


    return TransactionResponse(
        id=db_transaction.id,
        type=db_transaction.type,
        amount=db_transaction.amount,
        category=db_category.name,
        date=db_transaction.date
    )

@app.get("/transactions/", response_model=List[TransactionResponse])
def list_transactions(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    transactions = db.query(Transaction).filter(Transaction.user_id == current_user.id).all()
    result = []
    for transaction in transactions:
        category = db.query(Category).filter(Category.id == transaction.category_id).first()
        result.append(TransactionResponse(
            id=transaction.id,
            type=transaction.type,
            amount=transaction.amount,
            category=category.name if category else "Без категорії",
            date=transaction.date
        ))
    return result

@app.post("/goals/", response_model=GoalResponse)
def create_goal(goal: GoalCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_goal = Goal(**goal.dict(), user_id=current_user.id)
    db.add(db_goal)
    db.commit()
    db.refresh(db_goal)
    return db_goal

@app.get("/goals/", response_model=List[GoalResponse])
def list_goals(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Goal).filter(Goal.user_id == current_user.id).all()

@app.post("/goals/{goal_id}/add-funds/")
def add_funds_to_goal(goal_id: int, amount: float, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    goal = db.query(Goal).filter(Goal.id == goal_id, Goal.user_id == current_user.id).first()
    if not goal:
        raise HTTPException(status_code=404, detail="Goal not found")

    balance = db.query(Balance).filter(Balance.user_id == current_user.id).first()
    if balance.balance < amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    balance.balance -= amount
    goal.saved_amount += amount
    
    db.commit()
    return {"message": "Funds added successfully"}


@app.post("/goals/{goal_id}/return-funds/")
def return_funds_from_goal(
    goal_id: int,
    username: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    goal = db.query(Goal).filter(Goal.id == goal_id, Goal.user_id == current_user.id).first()
    if not goal or goal.saved_amount <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No funds to return")

    balance = db.query(Balance).filter(Balance.user_id == current_user.id).first()
    balance.balance += goal.saved_amount
    goal.saved_amount = 0
    db.commit()

    return {"message": "Funds returned successfully"}

@app.get("/", include_in_schema=False)
def redirect_to_docs():
    return RedirectResponse(url="/docs")

@app.post("/categories/", response_model=CategoryResponse)
def create_category(category: CategoryCreate, db: Session = Depends(get_db)):
    existing_category = db.query(Category).filter(Category.name == category.name).first()
    if existing_category:
        raise HTTPException(status_code=400, detail="Category already exists")

    db_category = Category(**category.dict())
    db.add(db_category)
    db.commit()
    db.refresh(db_category)
    return db_category


@app.get("/categories/", response_model=List[CategoryResponse])
def list_categories(db: Session = Depends(get_db)):
    return db.query(Category).all()


@app.post("/change-password/")
def change_password(
    request: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    old_password = request.old_password
    new_password = request.new_password

    # Verify the old password and update the password logic here
    if not verify_password(old_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Old password is incorrect"
        )

    current_user.hashed_password = get_password_hash(new_password)
    db.commit()
    return {"message": "Password updated successfully"}

@app.delete("/goals/{goal_id}/")
def delete_goal(goal_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    goal = db.query(Goal).filter(Goal.id == goal_id, Goal.user_id == current_user.id).first()
    if not goal:
        raise HTTPException(status_code=404, detail="Goal not found")

    if goal.saved_amount > 0:
        balance = db.query(Balance).filter(Balance.user_id == current_user.id).first()
        balance.balance += goal.saved_amount

    db.delete(goal)
    db.commit()
    
    return {"message": "Goal deleted successfully"}