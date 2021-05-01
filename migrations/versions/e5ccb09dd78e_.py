"""empty message

Revision ID: e5ccb09dd78e
Revises: f14b8a94b6ef
Create Date: 2021-04-30 23:31:14.664478

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e5ccb09dd78e'
down_revision = 'f14b8a94b6ef'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('main_currency', sa.String(length=16), nullable=False))
    op.drop_column('users', 'main_currnecy')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('main_currnecy', sa.VARCHAR(length=16), autoincrement=False, nullable=False))
    op.drop_column('users', 'main_currency')
    # ### end Alembic commands ###