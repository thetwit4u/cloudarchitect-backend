"""add_diagram_metadata_column

Revision ID: a70d3383ac4f
Revises: 20250211_add_diagram_tables
Create Date: 2025-02-11 20:26:35.736585

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a70d3383ac4f'
down_revision: Union[str, None] = '20250211_add_diagram_tables'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add diagram_metadata column to diagram_history table
    op.add_column('diagram_history',
        sa.Column('diagram_metadata', sa.JSON(), nullable=True)
    )


def downgrade() -> None:
    # Remove diagram_metadata column from diagram_history table
    op.drop_column('diagram_history', 'diagram_metadata')
