"""Add diagram history and layout tables

Revision ID: 20250211_add_diagram_tables
Revises: 
Create Date: 2025-02-11 18:12:30.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '20250211_add_diagram_tables'
down_revision = 'merge_last_scan_at'  # Updated to point to the latest migration
branch_labels = None
depends_on = None

def upgrade():
    # Create diagram_history table
    op.create_table(
        'diagram_history',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('version', sa.String(), nullable=False),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create diagram_layouts table
    op.create_table(
        'diagram_layouts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('diagram_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('layout_data', sa.JSON(), nullable=False),
        sa.Column('is_default', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['diagram_id'], ['diagram_history.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Add indexes for foreign keys and common queries
    op.create_index('ix_diagram_history_project_id', 'diagram_history', ['project_id'])
    op.create_index('ix_diagram_history_user_id', 'diagram_history', ['user_id'])
    op.create_index('ix_diagram_layouts_diagram_id', 'diagram_layouts', ['diagram_id'])

def downgrade():
    # Drop tables in reverse order
    op.drop_index('ix_diagram_layouts_diagram_id')
    op.drop_index('ix_diagram_history_user_id')
    op.drop_index('ix_diagram_history_project_id')
    op.drop_table('diagram_layouts')
    op.drop_table('diagram_history')
