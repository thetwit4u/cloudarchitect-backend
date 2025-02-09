#!/usr/bin/env python3
import os
import sys
import psycopg2
from urllib.parse import urlparse, parse_qs

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import get_settings

def get_table_info(table_name: str) -> None:
    """Get information about a specific table's schema."""
    settings = get_settings()
    
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
    
    try:
        # Connect to the database
        conn = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host,
            port=db_port,
            sslmode=ssl_mode
        )
        
        # Create a cursor
        cur = conn.cursor()
        
        # Get column information
        cur.execute("""
            SELECT 
                column_name, 
                data_type, 
                is_nullable,
                column_default
            FROM information_schema.columns 
            WHERE table_name = %s
            ORDER BY ordinal_position;
        """, (table_name,))
        
        columns = cur.fetchall()
        
        print(f"\nTable: {table_name}")
        print("-" * 80)
        print(f"{'Column Name':<30} {'Data Type':<20} {'Nullable':<10} {'Default':<20}")
        print("-" * 80)
        
        for col in columns:
            name, data_type, nullable, default = col
            print(f"{name:<30} {data_type:<20} {nullable:<10} {str(default):<20}")
        
        # Get index information
        cur.execute("""
            SELECT
                i.relname as index_name,
                a.attname as column_name,
                ix.indisunique as is_unique
            FROM
                pg_class t,
                pg_class i,
                pg_index ix,
                pg_attribute a
            WHERE
                t.oid = ix.indrelid
                and i.oid = ix.indexrelid
                and a.attrelid = t.oid
                and a.attnum = ANY(ix.indkey)
                and t.relkind = 'r'
                and t.relname = %s
            ORDER BY
                i.relname;
        """, (table_name,))
        
        indexes = cur.fetchall()
        
        if indexes:
            print("\nIndexes:")
            print("-" * 80)
            print(f"{'Index Name':<30} {'Column':<30} {'Unique':<10}")
            print("-" * 80)
            
            for idx in indexes:
                index_name, column_name, is_unique = idx
                print(f"{index_name:<30} {column_name:<30} {str(is_unique):<10}")
        
        # Close cursor and connection
        cur.close()
        conn.close()
        
    except Exception as e:
        print(f"Error getting table information: {e}")
        sys.exit(1)

def main():
    """Main function to check database schema."""
    if len(sys.argv) != 2:
        print("Usage: python check_schema.py <table_name>")
        sys.exit(1)
    
    table_name = sys.argv[1]
    get_table_info(table_name)

if __name__ == "__main__":
    main()
