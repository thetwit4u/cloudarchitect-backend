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
    db_name = url.path[1:] if url.path else 'cloudarchitect'
    port = url.port if url.port else 5432
    
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
    
    # Now connect to the new database and create tables
    params['dbname'] = db_name
    conn = psycopg2.connect(**params)
    conn.autocommit = True
    
    try:
        with conn.cursor() as cur:
            # Create UUID extension if it doesn't exist
            cur.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")

            # Create alembic_version table
            cur.execute("""
                CREATE TABLE alembic_version (
                    version_num VARCHAR(32) NOT NULL,
                    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
                );
            """)
            # Set the current version to our latest known good migration
            cur.execute("INSERT INTO alembic_version (version_num) VALUES ('12bc348e9691');")

            # Create users table
            cur.execute("""
                CREATE TABLE users (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    username VARCHAR NOT NULL UNIQUE,
                    email VARCHAR NOT NULL UNIQUE,
                    full_name VARCHAR NOT NULL,
                    hashed_password VARCHAR NOT NULL,
                    api_key VARCHAR UNIQUE,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE
                );
            """)
            
            # Create indexes for users table
            cur.execute("CREATE INDEX ix_users_api_key ON users(api_key);")
            cur.execute("CREATE INDEX ix_users_email ON users(email);")
            cur.execute("CREATE INDEX ix_users_username ON users(username);")

            # Create projects table
            cur.execute("""
                CREATE TABLE projects (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    name VARCHAR NOT NULL,
                    description VARCHAR,
                    user_id UUID REFERENCES users(id) NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE
                );
            """)

            # Create aws_credentials table
            cur.execute("""
                CREATE TABLE aws_credentials (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    project_id UUID REFERENCES projects(id) NOT NULL,
                    aws_access_key_id VARCHAR NOT NULL,
                    aws_secret_access_key VARCHAR NOT NULL,
                    region VARCHAR NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE
                );
            """)

            # Create resources table
            cur.execute("""
                CREATE TABLE resources (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    name VARCHAR NOT NULL,
                    type VARCHAR NOT NULL,
                    arn VARCHAR NOT NULL,
                    region VARCHAR NOT NULL,
                    status VARCHAR NOT NULL,
                    details VARCHAR,
                    project_id UUID REFERENCES projects(id) NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP WITH TIME ZONE
                );
            """)

            print("Tables created successfully.")
            
    finally:
        conn.close()
    
    print("Database is clean and ready to use.")

if __name__ == "__main__":
    reset_database()
