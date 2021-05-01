"""empty message

Revision ID: abd61bd0d94d
Revises: e5ccb09dd78e
Create Date: 2021-05-01 00:43:16.393475

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'abd61bd0d94d'
down_revision = 'e5ccb09dd78e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('role_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'users', 'roles', ['role_id'], ['id'])
    op.add_column('wallets', sa.Column('user_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'wallets', 'users', ['user_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'wallets', type_='foreignkey')
    op.drop_column('wallets', 'user_id')
    op.drop_constraint(None, 'users', type_='foreignkey')
    op.drop_column('users', 'role_id')
    # ### end Alembic commands ###
