"""empty message

Revision ID: 6ee94eeb9c36
Revises: 4b75e0931950
Create Date: 2021-05-01 13:36:25.993311

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6ee94eeb9c36'
down_revision = '4b75e0931950'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('transactions_wallet_id_fkey', 'transactions', type_='foreignkey')
    op.drop_constraint('transactions_receiver_fkey', 'transactions', type_='foreignkey')
    op.drop_constraint('transactions_sender_fkey', 'transactions', type_='foreignkey')
    op.create_foreign_key(None, 'transactions', 'wallets', ['receiver'], ['id'], ondelete='cascade')
    op.create_foreign_key(None, 'transactions', 'wallets', ['sender'], ['id'], ondelete='cascade')
    op.drop_column('transactions', 'wallet_id')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('transactions', sa.Column('wallet_id', sa.INTEGER(), autoincrement=False, nullable=True))
    op.drop_constraint(None, 'transactions', type_='foreignkey')
    op.drop_constraint(None, 'transactions', type_='foreignkey')
    op.create_foreign_key('transactions_sender_fkey', 'transactions', 'users', ['sender'], ['id'])
    op.create_foreign_key('transactions_receiver_fkey', 'transactions', 'users', ['receiver'], ['id'])
    op.create_foreign_key('transactions_wallet_id_fkey', 'transactions', 'wallets', ['wallet_id'], ['id'], ondelete='CASCADE')
    # ### end Alembic commands ###
