"""merge diagram heads

Revision ID: 20250211_merge_heads
Revises: b70d3383ac4f, a70d3383ac4f
Create Date: 2025-02-11 20:34:05.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20250211_merge_heads'
down_revision = ('b70d3383ac4f', 'a70d3383ac4f')
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
