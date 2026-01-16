import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1 import auth, user
from app.core.config import settings

app = FastAPI(
    title=settings.TITLE,
    description="Микросервис авторизации и пользователей",
    version="1.0.0"
)

# CORS (чтобы фронтенд мог стучаться)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Для разработки разрешим все
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1")
app.include_router(user.router, prefix="/api/v1")

@app.get("/health")
def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)