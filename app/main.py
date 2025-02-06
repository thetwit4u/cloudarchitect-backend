from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .core.config import get_settings
from .routers import auth, aws, projects, resources, aws_connections

settings = get_settings()

# API version prefix
api_prefix = "/api/v1"

app = FastAPI(
    title="Cloud Architect API",
    description="API for Cloud Architect application",
    version="1.0.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers with API prefix
app.include_router(auth.router, prefix=f"{api_prefix}/auth", tags=["auth"])
app.include_router(aws.router, prefix=f"{api_prefix}/aws", tags=["aws"])
app.include_router(projects.router, prefix=f"{api_prefix}/projects", tags=["projects"])
app.include_router(resources.router, prefix=f"{api_prefix}/resources", tags=["resources"])
app.include_router(aws_connections.router)  # The router already includes the prefix

@app.get("/")
async def root():
    return {"message": "Welcome to Cloud Architect API"}
