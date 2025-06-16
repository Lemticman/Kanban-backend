# Kanban Backend (FastAPI)

## Local Dev

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

The app exposes:

* `GET /health` – health‑check
* `POST /auth/signup` – create user
* `POST /auth/login` – JWT login
* `GET /boards` – list boards
* `POST /boards` – create board
