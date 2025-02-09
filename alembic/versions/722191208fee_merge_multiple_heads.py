"""merge_multiple_heads

Revision ID: 722191208fee
Revises: 12bc348e9691, 9c2d4f1a5e3b
Create Date: 2025-02-09 16:55:20.309756

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '722191208fee'
down_revision: Union[str, None] = ('12bc348e9691', '9c2d4f1a5e3b')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
