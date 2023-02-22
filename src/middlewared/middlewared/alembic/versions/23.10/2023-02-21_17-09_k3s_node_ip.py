"""k3s_node_ip

Revision ID: 84b393d2a06f
Revises: 62882b2df056
Create Date: 2023-02-21 17:09:35.937035+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '84b393d2a06f'
down_revision = '62882b2df056'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('services_kubernetes', schema=None) as batch_op:
        batch_op.drop_column('node_ip')
        batch_op.add_column(sa.Column('node_ip', sa.JSON()))

def downgrade():
    pass
