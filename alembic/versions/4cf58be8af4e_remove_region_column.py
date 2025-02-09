"""remove region column

Revision ID: 4cf58be8af4e
Revises: 722191208fee
Create Date: 2025-02-09 17:00:31.123456

"""
from typing import Sequence, Union
from sqlalchemy.engine.reflection import Inspector

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4cf58be8af4e'
down_revision: Union[str, None] = '722191208fee'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Check if column exists before trying to drop it
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    columns = [col['name'] for col in inspector.get_columns('resources')]
    
    if 'region' in columns:
        op.drop_column('resources', 'region')


def downgrade() -> None:
    # Check if column doesn't exist before trying to add it
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    columns = [col['name'] for col in inspector.get_columns('resources')]
    
    if 'region' not in columns:
        op.add_column('resources', sa.Column('region', sa.String(), nullable=True))
