"""merge last_scan_at

Revision ID: merge_last_scan_at
Revises: 99191e36c253, add_last_scan_at
Create Date: 2025-02-10 22:07:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'merge_last_scan_at'
down_revision = ('99191e36c253', 'add_last_scan_at')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
