from app import create_app, db
import sys

app = create_app()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "create_db":
        with app.app_context():
            db.create_all()
            print("Database tables created.")
    else:
        app.run(debug=True)