from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from ..models import Base
from .database import SQLALCHEMY_DATABASE_URL
from datetime import datetime

def init_db():
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    # Create a session
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        # Update any existing records that have NULL timestamps
        now = datetime.utcnow()
        
        # Update projects
        db.execute(
            text("""
                UPDATE projects 
                SET created_at = :now, updated_at = :now 
                WHERE created_at IS NULL OR updated_at IS NULL
            """),
            {"now": now}
        )
        
        # Update resources
        db.execute(
            text("""
                UPDATE resources 
                SET created_at = :now, updated_at = :now 
                WHERE created_at IS NULL OR updated_at IS NULL
            """),
            {"now": now}
        )
        
        db.commit()
    except Exception as e:
        print(f"Error updating timestamps: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    print("Initializing database...")
    init_db()
    print("Database initialized successfully!")
