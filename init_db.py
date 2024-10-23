from app import app, db, upgrade

def init_db():
    with app.app_context():
        db.create_all()
        upgrade()
        print("Database initialized.")

if __name__ == "__main__":
    init_db()
