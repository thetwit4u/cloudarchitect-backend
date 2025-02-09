"""add aws resources table

Revision ID: 9a0dcc023b3e
Revises: 1171bc5dda93
Create Date: 2025-02-09 16:27:22.705273

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9a0dcc023b3e'
down_revision: Union[str, None] = '1171bc5dda93'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
