"""add last_scan_at to project

Revision ID: add_last_scan_at
Revises: 722191208fee
Create Date: 2025-02-10 22:03:58.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_last_scan_at'
down_revision = '722191208fee'
branch_labels = None
depends_on = None


def upgrade():
    # Add last_scan_at column to projects table
    op.add_column('projects', sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True))


def downgrade():
    # Remove last_scan_at column from projects table
    op.drop_column('projects', 'last_scan_at')
