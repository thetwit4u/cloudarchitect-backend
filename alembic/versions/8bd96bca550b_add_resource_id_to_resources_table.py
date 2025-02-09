"""add resource_id to resources table

Revision ID: 8bd96bca550b
Revises: 8423534198d1
Create Date: 2025-02-09 16:34:44.123456

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8bd96bca550b'
down_revision: Union[str, None] = '8423534198d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add resource_id column
    op.add_column('resources', sa.Column('resource_id', sa.String(), nullable=True))
    op.create_index(op.f('ix_resources_resource_id'), 'resources', ['resource_id'], unique=True)


def downgrade() -> None:
    # Drop resource_id column
    op.drop_index(op.f('ix_resources_resource_id'), table_name='resources')
    op.drop_column('resources', 'resource_id')
