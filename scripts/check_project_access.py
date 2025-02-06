import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import uuid

# Get the project root directory
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from app.models import Project, User

def main():
    # Database URL
    database_url = "postgresql://neondb_owner:npg_CRfG6edTcw5g@ep-nameless-mouse-a2uuclph-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require"

    # Create database engine and session
    engine = create_engine(database_url)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()

    try:
        # Project ID to check
        project_id = "c92f507f-e8ff-4d7a-a71e-185f56b7f232"
        user_id = "a11099df-e809-4dd6-a8f4-722472111cfa"

        # Convert string IDs to UUIDs
        project_uuid = uuid.UUID(project_id)
        user_uuid = uuid.UUID(user_id)

        # Get project
        project = db.query(Project).filter(Project.id == project_uuid).first()
        if not project:
            print(f"Project {project_id} not found")
            return

        print(f"Found project:")
        print(f"  ID: {project.id} (type: {type(project.id)})")
        print(f"  Name: {project.name}")
        print(f"  User ID: {project.user_id} (type: {type(project.user_id)})")
        print(f"  Created At: {project.created_at}")

        # Get user
        user = db.query(User).filter(User.id == user_uuid).first()
        if not user:
            print(f"User {user_id} not found")
            return

        print(f"\nFound user:")
        print(f"  ID: {user.id} (type: {type(user.id)})")
        print(f"  Username: {user.username}")
        print(f"  Email: {user.email}")

        # Check if project belongs to user
        if project.user_id == user.id:
            print("\nAccess check: PASSED ")
            print(f"Project {project_id} belongs to user {user.username}")
        else:
            print("\nAccess check: FAILED ")
            print(f"Project {project_id} does not belong to user {user.username}")
            print(f"Project user_id: {project.user_id}")
            print(f"User id: {user.id}")

    finally:
        db.close()

if __name__ == "__main__":
    main()
