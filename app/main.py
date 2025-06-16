from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import create_db_and_tables
from app.api import auth, boards

app = FastAPI(title="Kanban API")

# CORS - adjust origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def _startup():
    create_db_and_tables()

@app.get("/health")
def health():
    return {"ok": True}

# Routers
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(boards.router, prefix="/boards", tags=["boards"])
