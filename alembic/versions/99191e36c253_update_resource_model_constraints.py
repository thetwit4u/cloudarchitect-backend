"""update resource model constraints

Revision ID: 99191e36c253
Revises: 4cf58be8af4e
Create Date: 2025-02-09 17:10:32.021082

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '99191e36c253'
down_revision: Union[str, None] = '4cf58be8af4e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('resources', 'name',
               existing_type=sa.VARCHAR(),
               nullable=False)
    op.alter_column('resources', 'type',
               existing_type=sa.VARCHAR(),
               nullable=False)
    op.alter_column('resources', 'resource_id',
               existing_type=sa.VARCHAR(),
               nullable=False)
    op.alter_column('resources', 'details',
               existing_type=postgresql.JSONB(astext_type=sa.Text()),
               type_=sa.JSON(),
               existing_nullable=True)
    op.alter_column('resources', 'project_id',
               existing_type=sa.UUID(),
               nullable=False)
    op.drop_index('ix_resources_resource_id', table_name='resources')
    op.create_index(op.f('ix_resources_resource_id'), 'resources', ['resource_id'], unique=False)
    op.create_index(op.f('ix_resources_type'), 'resources', ['type'], unique=False)
    op.drop_constraint('resources_project_id_fkey', 'resources', type_='foreignkey')
    op.create_foreign_key(None, 'resources', 'projects', ['project_id'], ['id'], ondelete='CASCADE')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'resources', type_='foreignkey')
    op.create_foreign_key('resources_project_id_fkey', 'resources', 'projects', ['project_id'], ['id'])
    op.drop_index(op.f('ix_resources_type'), table_name='resources')
    op.drop_index(op.f('ix_resources_resource_id'), table_name='resources')
    op.create_index('ix_resources_resource_id', 'resources', ['resource_id'], unique=True)
    op.alter_column('resources', 'project_id',
               existing_type=sa.UUID(),
               nullable=True)
    op.alter_column('resources', 'details',
               existing_type=sa.JSON(),
               type_=postgresql.JSONB(astext_type=sa.Text()),
               existing_nullable=True)
    op.alter_column('resources', 'resource_id',
               existing_type=sa.VARCHAR(),
               nullable=True)
    op.alter_column('resources', 'type',
               existing_type=sa.VARCHAR(),
               nullable=True)
    op.alter_column('resources', 'name',
               existing_type=sa.VARCHAR(),
               nullable=True)
    # ### end Alembic commands ###
