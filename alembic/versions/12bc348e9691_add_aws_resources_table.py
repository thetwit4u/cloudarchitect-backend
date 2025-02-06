"""add_aws_resources_table

Revision ID: 12bc348e9691
Revises: 22dacf13857d
Create Date: 2025-02-06 23:41:47.262264

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '12bc348e9691'
down_revision: Union[str, None] = '22dacf13857d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
