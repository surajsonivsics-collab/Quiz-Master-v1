from app import app, db
from models import Quiz

# Run inside Flask app context
with app.app_context():
    with db.engine.connect() as conn:
        conn.execute("ALTER TABLE quiz ADD COLUMN is_published BOOLEAN DEFAULT 0;")
        print("✅ Column 'is_published' added to Quiz table.")
