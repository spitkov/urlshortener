from flask.cli import FlaskGroup
from app import app, db

cli = FlaskGroup(app)

@cli.command("db_init")
def db_init():
    db.create_all()
    print("Database initialized.")

if __name__ == '__main__':
    cli()
