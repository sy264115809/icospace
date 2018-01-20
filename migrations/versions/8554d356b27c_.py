"""empty message

Revision ID: 8554d356b27c
Revises: 3d1865c3cf70
Create Date: 2018-01-21 00:40:53.422794

"""
from alembic import op
import sqlalchemy as sa
import app

# revision identifiers, used by Alembic.
revision = '8554d356b27c'
down_revision = '3d1865c3cf70'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('tournament',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('detail', sa.Text(), nullable=True),
    sa.Column('start_time', sa.DateTime(), nullable=True),
    sa.Column('end_time', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('submission',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('upload_filename', sa.String(length=128), nullable=True),
    sa.Column('upload_file_content', sa.LargeBinary(), nullable=True),
    sa.Column('task_id', sa.String(length=128), nullable=True),
    sa.Column('status', app.models.IntEnum(app.models.tournament.SubmissionStatus), nullable=True),
    sa.Column('result', sa.JSON(), nullable=True),
    sa.Column('score', sa.Float(), nullable=True),
    sa.Column('owner_id', sa.Integer(), nullable=True),
    sa.Column('tournament_id', sa.Integer(), nullable=True),
    sa.Column('uploaded_at', sa.DateTime(), nullable=True),
    sa.Column('finished_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['owner_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['tournament_id'], ['tournament.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('submission')
    op.drop_table('tournament')
    # ### end Alembic commands ###
