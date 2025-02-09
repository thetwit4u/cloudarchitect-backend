"""update resource model to use resource_id

Revision ID: 8423534198d1
Revises: 9a0dcc023b3e
Create Date: 2025-02-09 16:29:33.774161

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8423534198d1'
down_revision: Union[str, None] = '9a0dcc023b3e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
