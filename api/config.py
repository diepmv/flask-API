import os

basedir = ps.path.abspath(os.path.dirname(__file__))
DEBUG=TRUE
PORT=5000
HOST="127.0.0.1"
SQLALCHEMY_ECHO=False
SQLALCHEMY_TRACK_MODIFICATIONS=True
SQLALCHEMY_DATABASE_URI = "postgresql://{DB_USER}:{DB_PASS}@{DB_ADDR}/{DB_NAME}".format(DB_USER="user
_name", DB_PASS="password", DB_ADDR="127.0.0.1", DB_NAME="messages")
SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')
