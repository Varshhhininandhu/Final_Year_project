from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError
# 1. Update this import to include 'init_db'
from app.database.connection import Base, engine, SessionLocal, init_db
from app.routes import auth, doctor, patient, admin, record, access_control, blockchain
from app.services.blockchain_service import verify_chain
from app.utils.logger import logger
from app.routes import connection_router
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBearer

app = FastAPI(title="Medicare Backend")

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173", 
    "http://127.0.0.1:8000", 
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],      
    allow_headers=["*"],      
)

app.include_router(auth.router)
app.include_router(doctor.router)
app.include_router(patient.router)
app.include_router(admin.router)
app.include_router(record.router)
app.include_router(access_control.router)
app.include_router(blockchain.router)
app.include_router(connection_router.router)

# 2. Call init_db() HERE, before initialize_tables()
# This ensures the 'medichain' database is created if it doesn't exist.
init_db()

def initialize_tables():
    try:
        Base.metadata.create_all(bind=engine)
        print("All SQLAlchemy tables created successfully.")
    except SQLAlchemyError as e:
        print(f"Error while creating tables: {e}")

initialize_tables()

@app.get("/")
def root():
    return {"message": "Medicare Backend is Running!"}

@app.middleware("http")
async def catch_exceptions_middleware(request: Request, call_next):
    try:
        response = await call_next(request)
        return response
    except Exception as e:
        logger.exception("Unhandled exception")
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.on_event("startup")
def verify_blockchain_startup():
    db = SessionLocal()
    result = verify_chain(db)

    if result["valid"]:
        print(f"[BLOCKCHAIN] Verified Successfully")
    else:
        print(f"[BLOCKCHAIN]  Verification failed")

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description="MediChain API Documentation",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method.setdefault("security", [{"BearerAuth": []}])
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi