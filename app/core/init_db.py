from ..core.database import Base, engine
from .. import models

def init_db():
    # Import all models here
    from ..models import user, project, aws
    
    # Create all tables
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    print("Creating database tables...")
    init_db()
    print("Database tables created successfully!")
