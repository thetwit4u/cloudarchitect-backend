from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.core.database import SQLALCHEMY_DATABASE_URL
from app.models import Project

def view_projects():
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        projects = db.query(Project).all()
        print("\nProjects in database:")
        print("-" * 80)
        for project in projects:
            print(f"ID: {project.id}")
            print(f"Name: {project.name}")
            print(f"Description: {project.description}")
            print(f"User ID: {project.user_id}")
            print(f"Created at: {project.created_at}")
            print(f"Updated at: {project.updated_at}")
            print("-" * 80)
    finally:
        db.close()

if __name__ == "__main__":
    view_projects()
