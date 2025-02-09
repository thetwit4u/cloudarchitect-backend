#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# Add the parent directory to Python path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(backend_dir))

from app.core.database import Base, SessionLocal, engine
from app.models import Resource
import json

def main():
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Get all resources
        resources = db.query(Resource).all()
        
        # Count by type
        type_counts = {}
        for r in resources:
            type_counts[r.type] = type_counts.get(r.type, 0) + 1
        
        print("\n=== Resource Counts by Type ===")
        for type_name, count in type_counts.items():
            print(f"{type_name}: {count}")
        
        print("\n=== Resource Details ===")
        for r in resources:
            print(f"\nType: {r.type}")
            print(f"Name: {r.name}")
            print(f"Resource ID: {r.resource_id}")
            try:
                details = json.dumps(r.details, indent=2) if r.details else "No details"
                print(f"Details: {details}")
            except Exception as e:
                print(f"Error parsing details: {str(e)}")
            print("-" * 50)
            
    finally:
        db.close()

if __name__ == "__main__":
    main()
