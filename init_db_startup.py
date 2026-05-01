#!/usr/bin/env python3
"""Initialize database on application startup"""

import os
import sys
from db import init_db
from env_loader import load_dotenv

def init_database():
    """Initialize database connection and schema"""
    load_dotenv()
    db_url = os.environ.get('DATABASE_URL', '')
    
    if not db_url:
        print('⚠ DATABASE_URL not set. Set it in .env to enable database storage.')
        return False
    
    try:
        pool = init_db(db_url)
        pool.closeall()
        print('✓ Database initialized successfully')
        return True
    except Exception as e:
        print(f'⚠ Database initialization failed: {e}')
        print('Continuing without database...')
        return False

if __name__ == '__main__':
    success = init_database()
    sys.exit(0 if success else 1)
