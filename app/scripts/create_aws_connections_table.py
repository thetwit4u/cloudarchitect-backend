from sqlalchemy import create_engine, text
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.core.database import SQLALCHEMY_DATABASE_URL

def create_aws_connections_table():
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
    
    # Create aws_connections table
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS aws_connections (
        id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
        project_id VARCHAR NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        name VARCHAR NOT NULL,
        aws_account_id VARCHAR NOT NULL,
        aws_region VARCHAR NOT NULL,
        aws_role_arn VARCHAR NOT NULL,
        aws_external_id VARCHAR,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    
    -- Add index for faster lookups by project_id
    CREATE INDEX IF NOT EXISTS idx_aws_connections_project_id ON aws_connections(project_id);
    """
    
    try:
        with engine.connect() as conn:
            conn.execute(text(create_table_sql))
            conn.commit()
            print("AWS connections table created successfully!")
    except Exception as e:
        print(f"Error creating AWS connections table: {e}")

if __name__ == "__main__":
    create_aws_connections_table()
