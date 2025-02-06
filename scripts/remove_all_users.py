#!/usr/bin/env python3

import sys
import os
from pathlib import Path

# Add the parent directory to Python path so we can import our app modules
sys.path.append(str(Path(__file__).parent.parent))

from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.database import SessionLocal, engine
from app.models import User, Project, Resource, AWSCredentials
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def disable_foreign_key_constraints(db: Session):
    """Temporarily disable foreign key constraints"""
    db.execute(text('SET CONSTRAINTS ALL DEFERRED'))

def enable_foreign_key_constraints(db: Session):
    """Re-enable foreign key constraints"""
    db.execute(text('SET CONSTRAINTS ALL IMMEDIATE'))

def remove_all_data(db: Session):
    """
    Remove all data in the correct order to respect foreign key constraints.
    Order of deletion:
    1. AWS Credentials (depends on Projects)
    2. Resources (depends on Projects)
    3. Projects (depends on Users)
    4. Users (no dependencies)
    """
    try:
        # Get count of data before deletion
        user_count = db.query(User).count()
        project_count = db.query(Project).count()
        resource_count = db.query(Resource).count()
        aws_cred_count = db.query(AWSCredentials).count()

        logger.info("Current database state:")
        logger.info(f"Users: {user_count}")
        logger.info(f"Projects: {project_count}")
        logger.info(f"Resources: {resource_count}")
        logger.info(f"AWS Credentials: {aws_cred_count}")

        # Confirm with user
        response = input("\nAre you sure you want to delete ALL data? This action cannot be undone! (yes/no): ")
        if response.lower() != 'yes':
            logger.info("Operation cancelled.")
            return

        # Start transaction
        logger.info("\nStarting deletion process...")
        
        try:
            # Disable foreign key constraints temporarily
            disable_foreign_key_constraints(db)
            
            # Delete in proper order
            aws_creds_deleted = db.query(AWSCredentials).delete(synchronize_session=False)
            logger.info(f"Deleted {aws_creds_deleted} AWS credentials")

            resources_deleted = db.query(Resource).delete(synchronize_session=False)
            logger.info(f"Deleted {resources_deleted} resources")

            projects_deleted = db.query(Project).delete(synchronize_session=False)
            logger.info(f"Deleted {projects_deleted} projects")

            users_deleted = db.query(User).delete(synchronize_session=False)
            logger.info(f"Deleted {users_deleted} users")

            # Re-enable foreign key constraints
            enable_foreign_key_constraints(db)
            
            # Commit the transaction
            db.commit()

            logger.info("\nDeletion completed successfully!")
            logger.info("Summary of deleted items:")
            logger.info(f"- Users: {users_deleted}")
            logger.info(f"- Projects: {projects_deleted}")
            logger.info(f"- Resources: {resources_deleted}")
            logger.info(f"- AWS Credentials: {aws_creds_deleted}")

        except Exception as e:
            logger.error(f"Error during deletion: {str(e)}")
            db.rollback()
            raise

    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        raise

def main():
    logger.info("Starting database cleanup script...")
    
    # Create database session
    db = SessionLocal()
    try:
        remove_all_data(db)
    finally:
        db.close()

if __name__ == "__main__":
    main()
