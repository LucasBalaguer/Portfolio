"""migrate_add_dashboard_url_2.py"""
import os
from dotenv import load_dotenv
load_dotenv()

from app import app, db
from sqlalchemy import text

with app.app_context():
    with db.engine.connect() as conn:
        try:
            conn.execute(text(
                "ALTER TABLE project ADD COLUMN IF NOT EXISTS dashboard_url_2 VARCHAR(300);"
            ))
            conn.commit()
            print("✅ Columna 'dashboard_url_2' añadida (o ya existía)")
        except Exception as e:
            print(f"⚠️  Error: {e}")
    print("\n✅ Migración completada.")