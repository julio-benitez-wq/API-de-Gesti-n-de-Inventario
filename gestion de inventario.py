"""
📦 Inventory Management API
Tecnologías demostradas:
- FastAPI (REST API)
- SQLAlchemy (ORM)
- Pydantic (Validación)
- JWT (Autenticación)
- pytest (Testing)
- Docker (Contenedores)
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List, Optional
import sqlalchemy as db
import uvicorn
import bcrypt
import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Configuración
load_dotenv()
app = FastAPI(title="Inventory API", version="1.0")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database
engine = db.create_engine("sqlite:///inventory.db")
metadata = db.MetaData()

# Modelos DB
items = db.Table(
    "items",
    metadata,
    db.Column("id", db.Integer, primary_key=True),
    db.Column("name", db.String(50), nullable=False),
    db.Column("category", db.String(20)),
    db.Column("stock", db.Integer, default=0),
    db.Column("price", db.Float)
)

users = db.Table(
    "users",
    metadata,
    db.Column("id", db.Integer, primary_key=True),
    db.Column("username", db.String(25), unique=True),
    db.Column("hashed_password", db.String(100))
)

metadata.create_all(engine)

# Schemas Pydantic
class Item(BaseModel):
    name: str
    category: Optional[str] = None
    stock: int = 0
    price: float

class User(BaseModel):
    username: str
    password: str

# Auth
SECRET_KEY = os.getenv("SECRET_KEY", "secret")
ALGORITHM = "HS256"

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# API Endpoints
@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: User):
    """Registro de nuevos usuarios"""
    hashed = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())
    with engine.connect() as conn:
        conn.execute(users.insert().values(
            username=user.username,
            hashed_password=hashed.decode()
        ))
        conn.commit()
    return {"message": "User created"}

@app.post("/token")
async def login(user: User):
    """Autenticación JWT"""
    with engine.connect() as conn:
        query = db.select([users]).where(users.c.username == user.username)
        result = conn.execute(query).fetchone()
    
    if not result or not bcrypt.checkpw(
        user.password.encode(),
        result["hashed_password"].encode()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    return {
        "access_token": create_access_token({"sub": user.username}),
        "token_type": "bearer"
    }

@app.get("/items", response_model=List[Item])
async def read_items(token: str = Depends(oauth2_scheme)):
    """Obtener todos los items (requiere autenticación)"""
    with engine.connect() as conn:
        query = db.select([items])
        result = conn.execute(query).fetchall()
    return result

@app.post("/items", status_code=status.HTTP_201_CREATED)
async def add_item(item: Item, token: str = Depends(oauth2_scheme)):
    """Añadir nuevo item al inventario"""
    with engine.connect() as conn:
        conn.execute(items.insert().values(**item.dict()))
        conn.commit()
    return {"message": "Item added"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)