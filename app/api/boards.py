from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from app.database import get_session
from app.models import Board, BoardCreate, BoardRead

router = APIRouter()

@router.get("/", response_model=list[BoardRead])
def list_boards(session: Session = Depends(get_session)):
    boards = session.exec(select(Board)).all()
    return boards

@router.post("/", response_model=BoardRead, status_code=201)
def create_board(board: BoardCreate, session: Session = Depends(get_session)):
    db_board = Board(name=board.name)
    session.add(db_board)
    session.commit()
    session.refresh(db_board)
    return db_board
