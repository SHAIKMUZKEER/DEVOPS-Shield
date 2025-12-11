"""
Database initialization script for DevOps Shield
"""
import os
import sys
from pathlib import Path

# Add backend to path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))

from src.services.db_service import DBService
from src.utils.logger import get_logger
import sqlite3

logger = get_logger(__name__)

def init_database():
    """Initialize the database with schema"""
    try:
        db_path = os.getenv("DB_PATH", "database/fraud_logs.db")
        
        # Ensure database directory exists
        db_dir = Path(db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Initializing database at: {db_path}")
        
        # Create database and schema
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create fraud_events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fraud_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                risk_score REAL NOT NULL,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                metadata TEXT,
                resolved BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        
        logger.info("✓ Database schema created successfully")
        logger.info(f"✓ Database location: {db_path}")
        return True
            
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)
