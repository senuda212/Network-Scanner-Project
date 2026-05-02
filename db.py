"""db.py
PostgreSQL helper: connection pool, schema creation, and DB writer (queue-based)
"""
import os
import uuid
import time
import logging
import threading
import queue
from pathlib import Path
from typing import List, Dict, Optional

import psycopg2
from psycopg2 import pool

from env_loader import load_dotenv

load_dotenv(Path(__file__).resolve().with_name(".env"), override=True)

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 100

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    scan_id TEXT NOT NULL,
    target_ip VARCHAR(64) NOT NULL,
    port INTEGER NOT NULL,
    status VARCHAR(16) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    service VARCHAR(128)
);
"""

CREATE_INDEX_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans (scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS idx_scans_target_ip ON scans (target_ip);",
    "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);",
    "CREATE INDEX IF NOT EXISTS idx_scans_port ON scans (port);",
]


class DBWriter:
    """Background DB writer that batches inserts from a queue.

    Usage:
        db = init_db()
        writer = DBWriter(db_pool, batch_size=100)
        writer.start()
        writer.enqueue(result_dict)
        writer.stop()
    """

    def __init__(self, db_pool: pool.ThreadedConnectionPool, batch_size: int = DEFAULT_BATCH_SIZE):
        self.db_pool = db_pool
        self.batch_size = batch_size
        self.q: "queue.Queue[Dict]" = queue.Queue()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        logger.info("Starting DBWriter thread")
        self._thread.start()

    def stop(self, flush: bool = True, timeout: Optional[float] = 5.0) -> None:
        logger.info("Stopping DBWriter thread (flush=%s)", flush)
        self._stop_event.set()
        if flush:
            # wait for queue to drain
            start = time.time()
            while not self.q.empty() and (time.time() - start) < (timeout or 5.0):
                time.sleep(0.1)
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def enqueue(self, item: Dict) -> None:
        self.q.put(item)

    def _run(self) -> None:
        buffer: List[Dict] = []
        while not self._stop_event.is_set() or not self.q.empty():
            try:
                item = self.q.get(timeout=0.5)
            except Exception:
                item = None
            if item:
                buffer.append(item)
            if len(buffer) >= self.batch_size or (self._stop_event.is_set() and buffer):
                try:
                    self._insert_batch(buffer)
                except Exception as exc:
                    logger.exception("Error inserting batch: %s", exc)
                buffer = []
        # final flush
        if buffer:
            try:
                self._insert_batch(buffer)
            except Exception:
                logger.exception("Error inserting final batch")

    def _insert_batch(self, items: List[Dict]) -> None:
        if not items:
            return
        conn = None
        try:
            conn = self.db_pool.getconn()
            with conn.cursor() as cur:
                args = [(
                    i.get("scan_id"),
                    i.get("ip") or i.get("target_ip"),
                    int(i.get("port")),
                    i.get("status"),
                    i.get("service") if i.get("service") is not None else None,
                ) for i in items]
                insert_sql = (
                    "INSERT INTO scans (scan_id, target_ip, port, status, service) VALUES (%s, %s, %s, %s, %s)"
                )
                cur.executemany(insert_sql, args)
            conn.commit()
            logger.info("Inserted %d rows into scans", len(items))
        finally:
            if conn:
                try:
                    self.db_pool.putconn(conn)
                except Exception:
                    pass


def init_db(db_url: Optional[str] = None, minconn: int = 1, maxconn: int = 10) -> pool.ThreadedConnectionPool:
    """Initialize a ThreadedConnectionPool and ensure schema exists."""
    db_url = db_url or os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL is not set; cannot initialize DB")
    logger.info("Initializing DB pool for %s", db_url)
    db_pool = psycopg2.pool.ThreadedConnectionPool(minconn, maxconn, dsn=db_url)
    # create table
    conn = None
    try:
        conn = db_pool.getconn()
        with conn.cursor() as cur:
            cur.execute(CREATE_TABLE_SQL)
            for statement in CREATE_INDEX_SQL:
                cur.execute(statement)
        conn.commit()
    finally:
        if conn:
            db_pool.putconn(conn)
    return db_pool
