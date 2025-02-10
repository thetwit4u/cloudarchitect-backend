#!/usr/bin/env python3

import sys
import os
import json
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pathlib import Path
import dotenv

# Add the parent directory to Python path so we can import our app modules
sys.path.append(str(Path(__file__).parent.parent))

from app.models import Resource, Project
from app.models.aws_resources import ResourceType

# Load environment variables from .env file
dotenv.load_dotenv(Path(__file__).parent.parent / '.env')

# Get database URL from environment
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    print("Error: DATABASE_URL environment variable not set")
    sys.exit(1)

def format_datetime(dt):
    """Format datetime objects for JSON serialization"""
    return dt.isoformat() if dt else None

def export_resources(resource_type: str, project_id: str = None, output_file: str = None):
    """Export resources of specified type to JSON format
    
    Args:
        resource_type: Type of resource to export (e.g., 'ec2', 'vpc', 's3')
        project_id: Optional project ID to filter resources
        output_file: Optional file path to write JSON output
    """
    # Create database connection
    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()

    try:
        # Validate resource type
        if not ResourceType._value2member_map_.get(resource_type.lower()):
            valid_types = ", ".join(ResourceType._value2member_map_.keys())
            print(f"Error: Invalid resource type. Valid types are: {valid_types}")
            return

        # Build query
        query = db.query(Resource).filter(Resource.type == resource_type.lower())
        if project_id:
            query = query.filter(Resource.project_id == project_id)

        # Get resources
        resources = query.all()
        
        # Format resource data
        resource_data = []
        for resource in resources:
            data = {
                "id": str(resource.id),
                "name": resource.name,
                "resource_id": resource.resource_id,
                "type": resource.type,
                "project_id": str(resource.project_id),
                "created_at": format_datetime(resource.created_at),
                "details": resource.details
            }
            resource_data.append(data)

        # Create output
        output = {
            "resource_type": resource_type,
            "export_time": format_datetime(datetime.utcnow()),
            "total_count": len(resource_data),
            "resources": resource_data
        }

        # Write or print output
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(output, f, indent=2)
            print(f"Exported {len(resource_data)} resources to {output_file}")
        else:
            print(json.dumps(output, indent=2))

    finally:
        db.close()

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Export AWS resources from database')
    parser.add_argument('resource_type', help='Type of resource to export (e.g., ec2, vpc, s3)')
    parser.add_argument('--project-id', help='Optional project ID to filter resources')
    parser.add_argument('--output', '-o', help='Output file path (defaults to stdout)')
    
    args = parser.parse_args()
    export_resources(args.resource_type, args.project_id, args.output)

if __name__ == '__main__':
    main()
