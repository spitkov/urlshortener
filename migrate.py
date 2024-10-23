from flask_migrate import Migrate, upgrade
from app import app, db

migrate = Migrate(app, db)

if __name__ == '__main__':
    with app.app_context():
        upgrade()
