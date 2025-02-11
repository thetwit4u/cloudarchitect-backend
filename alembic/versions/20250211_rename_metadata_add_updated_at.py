"""add updated_at to diagram_history

Revision ID: b70d3383ac4f
Revises: 20250211_add_diagram_tables
Create Date: 2025-02-11 20:33:30.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import func


# revision identifiers, used by Alembic.
revision = 'b70d3383ac4f'
down_revision = '20250211_add_diagram_tables'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add updated_at column to diagram_history table
    op.add_column('diagram_history',
        sa.Column('updated_at', sa.DateTime(timezone=True), 
                 server_default=func.now(), 
                 onupdate=func.now(),
                 nullable=True)
    )


def downgrade() -> None:
    # Remove updated_at column
    op.drop_column('diagram_history', 'updated_at')
