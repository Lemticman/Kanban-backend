from typing import Optional
from sqlmodel import SQLModel, Field

class UserBase(SQLModel):
    email: str

class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str

class UserCreate(UserBase):
    password: str

class UserRead(UserBase):
    id: int

# Boards
class BoardBase(SQLModel):
    name: str

class Board(BoardBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)

class BoardCreate(BoardBase):
    pass

class BoardRead(BoardBase):
    id: int
