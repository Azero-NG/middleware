"""k3s_dual

Revision ID: 62882b2df056
Revises: 653ea1a2ba57
Create Date: 2023-02-21 15:20:22.468417+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '62882b2df056'
down_revision = '653ea1a2ba57'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('services_kubernetes', schema=None) as batch_op:
        batch_op.drop_column('cluster_cidr')
        batch_op.drop_column('service_cidr')
        batch_op.add_column(sa.Column('cluster_cidr', sa.JSON()))
        batch_op.add_column(sa.Column('service_cidr', sa.JSON()))




def downgrade():
    pass
