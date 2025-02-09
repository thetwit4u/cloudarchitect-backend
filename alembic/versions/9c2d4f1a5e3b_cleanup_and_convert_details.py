"""cleanup and convert details

Revision ID: 9c2d4f1a5e3b
Revises: 8bd96bca550b
Create Date: 2025-02-09 16:48:43.123456

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '9c2d4f1a5e3b'
down_revision: Union[str, None] = '8bd96bca550b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create a new connection to ensure we're in a fresh transaction
    connection = op.get_bind()
    
    # Check if columns exist before attempting to drop
    inspector = sa.inspect(connection)
    existing_columns = [col['name'] for col in inspector.get_columns('resources')]
    
    # Drop arn column and its index if they exist
    if 'arn' in existing_columns:
        try:
            # Check if index exists
            for idx in inspector.get_indexes('resources'):
                if idx['name'] == 'ix_resources_arn':
                    op.drop_index('ix_resources_arn', table_name='resources')
                    break
            op.drop_column('resources', 'arn')
        except Exception as e:
            print(f"Error dropping arn column: {e}")
            connection.execute(text("ROLLBACK"))
            raise
    
    # Drop status column if it exists
    if 'status' in existing_columns:
        try:
            op.drop_column('resources', 'status')
        except Exception as e:
            print(f"Error dropping status column: {e}")
            connection.execute(text("ROLLBACK"))
            raise
    
    # Handle details column conversion
    if 'details' in existing_columns:
        try:
            # Add new column
            op.add_column('resources', sa.Column('details_json', postgresql.JSONB, nullable=True))
            
            # Copy and convert data
            connection.execute(text("""
                UPDATE resources 
                SET details_json = CASE 
                    WHEN details IS NULL THEN NULL
                    WHEN details = '' THEN '{}'::jsonb
                    ELSE details::jsonb
                END
            """))
            
            # Drop old column
            op.drop_column('resources', 'details')
            
            # Rename new column
            op.alter_column('resources', 'details_json', new_column_name='details')
            
        except Exception as e:
            print(f"Error converting details column: {e}")
            connection.execute(text("ROLLBACK"))
            raise


def downgrade() -> None:
    connection = op.get_bind()
    try:
        # Create a temporary column for VARCHAR data
        op.add_column('resources', sa.Column('details_text', sa.String(), nullable=True))
        
        # Copy data from details to details_text, converting to text
        connection.execute(text("""
            UPDATE resources 
            SET details_text = CASE 
                WHEN details IS NULL THEN NULL
                ELSE details::text
            END
        """))
        
        # Drop the JSON details column
        op.drop_column('resources', 'details')
        
        # Rename details_text to details
        op.alter_column('resources', 'details_text', new_column_name='details')
        
        # Add back status column
        op.add_column('resources', sa.Column('status', sa.String(), nullable=True))
        
        # Add back arn column and index
        op.add_column('resources', sa.Column('arn', sa.String(), nullable=True))
        op.create_index('ix_resources_arn', 'resources', ['arn'], unique=True)
        
    except Exception as e:
        print(f"Error in downgrade: {e}")
        connection.execute(text("ROLLBACK"))
        raise
