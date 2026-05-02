#!/usr/bin/env python3
"""Initialize database on application startup"""

import os
import sys
from pathlib import Path
from db import init_db
from env_loader import load_dotenv

def init_database():
    """Initialize database connection and schema"""
    # Load project config from the repo .env so the same URL is used in every shell.
    load_dotenv(Path(__file__).resolve().with_name('.env'), override=True)
    db_url = os.environ.get('DATABASE_URL', '')

    # If DATABASE_URL is missing, attempt to scaffold a .env from .env.example
    if not db_url:
        cwd = os.getcwd()
        example = os.path.join(cwd, '.env.example')
        target = os.path.join(cwd, '.env')
        if not os.path.exists(target) and os.path.exists(example):
            try:
                with open(example, 'r', encoding='utf-8') as rf, open(target, 'w', encoding='utf-8') as wf:
                    wf.write(rf.read())
                print('ℹ Created .env from .env.example — please edit it with your DATABASE_URL')
                # Reload env vars from the newly created .env
                load_dotenv(Path(__file__).resolve().with_name('.env'), override=True)
                db_url = os.environ.get('DATABASE_URL', '')
            except Exception as e:
                print(f'⚠ Failed to create .env from .env.example: {e}')

    if not db_url:
        print('⚠ DATABASE_URL not set. Scans will run but database storage is disabled.')
        print('   To enable DB storage, set DATABASE_URL in your environment or edit the .env file.')
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
    # Run init but do not fail the caller if DB is not configured — GUI should still start.
    init_database()
    # Exit 0 to avoid stopping launcher scripts; DB availability is informational only
    sys.exit(0)
