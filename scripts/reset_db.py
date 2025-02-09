#!/usr/bin/env python3
import os
import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from urllib.parse import urlparse, parse_qs
import subprocess

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import get_settings

def terminate_connections(settings):
    """Terminate all connections to the database."""
    try:
        # Parse database URL
        parsed = urlparse(settings.DATABASE_URL)
        db_name = parsed.path[1:].split('?')[0]  # Remove leading / and query params
        db_host = parsed.hostname
        db_user = parsed.username
        db_password = parsed.password
        db_port = parsed.port or 5432
        
        # Get SSL mode from query parameters
        query_params = parse_qs(parsed.query)
        ssl_mode = query_params.get('sslmode', ['prefer'])[0]
        
        # Connect to default postgres database
        conn = psycopg2.connect(
            dbname="postgres",
            user=db_user,
            password=db_password,
            host=db_host,
            port=db_port,
            sslmode=ssl_mode
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        
        # Terminate existing connections
        cur.execute("""
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE datname = %s AND pid <> pg_backend_pid()
        """, (db_name,))
        
        cur.close()
        conn.close()
        print("Terminating existing connections...")
    except Exception as e:
        print(f"Error terminating connections: {e}")
        sys.exit(1)

def reset_database(settings):
    """Drop and recreate the database."""
    try:
        # Parse database URL
        parsed = urlparse(settings.DATABASE_URL)
        db_name = parsed.path[1:].split('?')[0]  # Remove leading / and query params
        db_host = parsed.hostname
        db_user = parsed.username
        db_password = parsed.password
        db_port = parsed.port or 5432
        
        # Get SSL mode from query parameters
        query_params = parse_qs(parsed.query)
        ssl_mode = query_params.get('sslmode', ['prefer'])[0]
        
        # Connect to default postgres database
        conn = psycopg2.connect(
            dbname="postgres",
            user=db_user,
            password=db_password,
            host=db_host,
            port=db_port,
            sslmode=ssl_mode
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()
        
        # Drop database if it exists
        print(f"Dropping database {db_name} if it exists...")
        cur.execute(f"DROP DATABASE IF EXISTS {db_name}")
        
        # Create database
        print(f"Creating database {db_name}...")
        cur.execute(f"CREATE DATABASE {db_name}")
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error resetting database: {e}")
        sys.exit(1)

def run_migrations():
    """Run all database migrations."""
    try:
        print("Running database migrations...")
        # First, stamp the database to clean state
        subprocess.run(['alembic', 'stamp', 'base'], check=True)
        # Then run all migrations
        subprocess.run(['alembic', 'upgrade', 'head'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running migrations: {e}")
        sys.exit(1)

def main():
    """Main function to reset database and run migrations."""
    settings = get_settings()
    terminate_connections(settings)
    reset_database(settings)
    run_migrations()
    print("Database reset complete!")

if __name__ == "__main__":
    main()
