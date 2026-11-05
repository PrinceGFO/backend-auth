# Backend Auth

FastAPI backend with Register, Login and Protected Route.
Built on Day 1 and Day 2 of my backend journey.

## Features
- POST /auth/register - Create a new user
- POST /auth/login - Login and get JWT token
- GET /auth/me - Protected route, needs token

## Tech
- Python
- FastAPI
- SQLAlchemy + SQLite
- JWT Auth

## Run it
pip install fastapi uvicorn sqlalchemy python-jose passlib bcrypt python-multipart
uvicorn main:app --reload