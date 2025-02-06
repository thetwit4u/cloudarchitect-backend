import os
import psycopg2
from dotenv import load_dotenv
from urllib.parse import urlparse

def reset_database():
    # Load environment variables from .env
    load_dotenv()
    
    # Get database URL from environment
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        raise ValueError("DATABASE_URL environment variable is not set")
    
    # Parse the database URL
    url = urlparse(database_url)
    db_name = url.path[1:] if url.path else 'cloud_architect'  # Remove leading '/' or use default
    port = url.port if url.port else 5432  # Use default port if not specified
    
    # Create connection parameters for postgres database
    params = {
        'dbname': 'postgres',
        'user': url.username or 'postgres',
        'password': url.password or 'postgres',
        'host': url.hostname or 'localhost',
        'port': port
    }
    
    # Connect to postgres database to drop and create the target database
    conn = psycopg2.connect(**params)
    conn.autocommit = True
    
    try:
        with conn.cursor() as cur:
            # Terminate all connections to the database
            cur.execute(f"""
                SELECT pg_terminate_backend(pg_stat_activity.pid)
                FROM pg_stat_activity
                WHERE pg_stat_activity.datname = '{db_name}'
                AND pid <> pg_backend_pid();
            """)
            
            # Drop and recreate database
            print(f"Dropping database {db_name}...")
            cur.execute(f"DROP DATABASE IF EXISTS {db_name}")
            print(f"Creating database {db_name}...")
            cur.execute(f"CREATE DATABASE {db_name}")
            print("Database reset complete.")
            
    finally:
        conn.close()
    
    # Now connect to the new database and create alembic_version table
    params['dbname'] = db_name
    conn = psycopg2.connect(**params)
    conn.autocommit = True
    
    try:
        with conn.cursor() as cur:
            # Create alembic_version table if it doesn't exist
            cur.execute("""
                CREATE TABLE IF NOT EXISTS alembic_version (
                    version_num VARCHAR(32) NOT NULL,
                    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
                );
            """)
            # Clear any existing version
            cur.execute("DELETE FROM alembic_version;")
    finally:
        conn.close()
    
    print("Database is clean and ready for fresh migrations.")

if __name__ == "__main__":
    reset_database()
