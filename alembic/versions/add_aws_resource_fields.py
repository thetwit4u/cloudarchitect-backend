"""add aws resource fields

Revision ID: add_aws_resource_fields
Revises: 
Create Date: 2025-02-07 01:16:03.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_aws_resource_fields'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Add new columns to resources table
    op.add_column('resources', sa.Column('arn', sa.String(), nullable=True))
    op.add_column('resources', sa.Column('region', sa.String(), nullable=True))
    op.add_column('resources', sa.Column('status', sa.String(), nullable=True))
    
    # Create unique constraint for ARN
    op.create_unique_constraint('uq_resources_arn', 'resources', ['arn'])

def downgrade():
    # Remove unique constraint
    op.drop_constraint('uq_resources_arn', 'resources', type_='unique')
    
    # Remove columns
    op.drop_column('resources', 'status')
    op.drop_column('resources', 'region')
    op.drop_column('resources', 'arn')
