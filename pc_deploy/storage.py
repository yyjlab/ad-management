import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet


SCHEMA = '''
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, data TEXT NOT NULL, secret TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, data TEXT NOT NULL, secret TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
 id TEXT PRIMARY KEY, boot_id TEXT NOT NULL, data TEXT NOT NULL, inventory_hash TEXT NOT NULL,
 token_hash TEXT NOT NULL, token_secret TEXT NOT NULL, boot_code TEXT NOT NULL,
 last_seen REAL NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS previews (id TEXT PRIMARY KEY, data TEXT NOT NULL, expires REAL NOT NULL,
 session_id TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id), boot_id TEXT NOT NULL,
 state TEXT NOT NULL, data TEXT NOT NULL, secret TEXT NOT NULL, created REAL NOT NULL,
 updated REAL NOT NULL, expires REAL NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_job ON jobs(device_id)
 WHERE state IN ('queued','preflight','installing','awaiting_report');
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, job_id TEXT, kind TEXT NOT NULL,
 message TEXT NOT NULL, created REAL NOT NULL);
CREATE INDEX IF NOT EXISTS events_by_job ON events(job_id,id);
CREATE TABLE IF NOT EXISTS enrollments (token_hash TEXT PRIMARY KEY, expires REAL NOT NULL,
 uses INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS media_builders (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
 seen REAL NOT NULL, data TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS media_builds (
 id TEXT PRIMARY KEY, builder_id TEXT NOT NULL REFERENCES media_builders(id),
 state TEXT NOT NULL, data TEXT NOT NULL, secret TEXT NOT NULL,
 created REAL NOT NULL, updated REAL NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_media_build ON media_builds(builder_id)
 WHERE state IN ('queued','building','uploading');
'''


class Store:
    def __init__(self, directory):
        self.root = Path(directory)
        self.root.mkdir(parents=True, exist_ok=True)
        keyfile = self.root / 'secret.key'
        if not keyfile.exists():
            # Publish a complete key atomically; AD runs several Gunicorn workers.
            fd, pending = tempfile.mkstemp(prefix='.key-', dir=self.root)
            try:
                with os.fdopen(fd, 'wb') as f:
                    f.write(os.urandom(32))
                    f.flush()
                    os.fsync(f.fileno())
                try:
                    os.link(pending, keyfile)
                except FileExistsError:
                    pass
            finally:
                os.unlink(pending)
        self.key = keyfile.read_bytes()
        if len(self.key) != 32:
            raise RuntimeError('平台密钥文件无效；请恢复备份，不要删除密钥文件')
        self.fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(self.key).digest()))
        self.path = self.root / 'deployment.db'
        with self.connect() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def connect(self, write=False):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        try:
            c.execute('PRAGMA foreign_keys=ON')
            deadline = time.monotonic() + 15
            while True:
                try:
                    if c.execute('PRAGMA journal_mode').fetchone()[0] != 'wal':
                        c.execute('PRAGMA journal_mode=WAL')
                    break
                except sqlite3.OperationalError as exc:
                    if (exc.sqlite_errorcode & 0xff) not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            if write:
                c.execute('BEGIN IMMEDIATE')
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    def encrypt(self, value):
        return self.fernet.encrypt(json.dumps(value, ensure_ascii=True).encode()).decode()

    def decrypt(self, value):
        return json.loads(self.fernet.decrypt(value.encode()))

    @staticmethod
    def setting(c, key, default=None):
        row = c.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        return json.loads(row['value']) if row else default

    @staticmethod
    def put(c, key, value):
        c.execute('INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                  (key, json.dumps(value)))
