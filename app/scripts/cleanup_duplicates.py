from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.core.database import SQLALCHEMY_DATABASE_URL
from app.models import Project

def cleanup_duplicates():
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        # Get all projects ordered by creation date
        projects = db.query(Project).order_by(Project.created_at.desc()).all()
        
        # Group projects by name
        project_dict = {}
        for project in projects:
            if project.name in project_dict:
                # Delete the older duplicate
                print(f"Deleting duplicate project: {project.name} (ID: {project.id})")
                db.delete(project)
            else:
                project_dict[project.name] = project
        
        db.commit()
        print("Cleanup completed successfully!")
        
    finally:
        db.close()

if __name__ == "__main__":
    cleanup_duplicates()
