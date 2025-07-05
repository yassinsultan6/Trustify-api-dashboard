from app import create_app
from sqlalchemy import text
from app.extensions import db

app = create_app()
with app.app_context():
    with db.engine.connect() as connection:
        connection.execute(text("ALTER TABLE api ADD COLUMN api_key TEXT"))
        print(" Column 'api_key' added to 'api' table.")
