from sqlalchemy import create_engine, text
import sys
import os

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.core.database import SQLALCHEMY_DATABASE_URL

def check_table_schema():
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
    
    check_sql = """
    SELECT column_name, data_type, character_maximum_length
    FROM information_schema.columns
    WHERE table_name = 'projects'
    ORDER BY ordinal_position;
    """
    
    try:
        with engine.connect() as conn:
            result = conn.execute(text(check_sql))
            print("\nProjects table schema:")
            print("-" * 50)
            for row in result:
                print(f"Column: {row[0]}")
                print(f"Type: {row[1]}")
                if row[2]:
                    print(f"Max Length: {row[2]}")
                print("-" * 50)
    except Exception as e:
        print(f"Error checking schema: {e}")

if __name__ == "__main__":
    check_table_schema()
