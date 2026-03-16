import time

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import OperationalError

from app.api.routes import router
from app.db.session import Base, engine

app = FastAPI(title="Portal API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3001",
        "http://127.0.0.1:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.on_event("startup")
def startup() -> None:
    for attempt in range(15):
        try:
            Base.metadata.create_all(bind=engine)
            print("[portal-api] database initialized")
            return
        except OperationalError as exc:
            print(f"[portal-api] database not ready yet, retry {attempt + 1}/15: {exc}")
            time.sleep(2)

    raise RuntimeError("portal-api could not connect to database after retries")