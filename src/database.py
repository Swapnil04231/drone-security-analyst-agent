"""
Frame Index Database (SQLite)
Stores processed frames with timestamps and object tags for fast querying.
"""

import sqlite3
import json
import os
from typing import List, Optional, Dict
from src.models import DetectedEvent, SecurityAlert


class FrameIndexDB:
    """
    SQLite-backed frame-by-frame index.
    Supports query by time range, object type, location, and event type.
    """

    def __init__(self, db_path: str = "data/frames.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS frames (
                frame_id    INTEGER PRIMARY KEY,
                timestamp   TEXT NOT NULL,
                location    TEXT NOT NULL,
                description TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                objects     TEXT NOT NULL,   -- JSON array
                confidence  REAL DEFAULT 0.8,
                llm_analysis TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id        TEXT PRIMARY KEY,
                timestamp       TEXT NOT NULL,
                location        TEXT NOT NULL,
                severity        TEXT NOT NULL,
                rule_triggered  TEXT NOT NULL,
                message         TEXT NOT NULL,
                frame_id        INTEGER,
                acknowledged    INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_frames_timestamp ON frames(timestamp);
            CREATE INDEX IF NOT EXISTS idx_frames_location  ON frames(location);
            CREATE INDEX IF NOT EXISTS idx_frames_event     ON frames(event_type);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
        """)
        self.conn.commit()

    # ── Write ──────────────────────────────────────────────────────────────

    def insert_frame(self, event: DetectedEvent):
        self.conn.execute(
            """INSERT OR REPLACE INTO frames
               (frame_id, timestamp, location, description, event_type, objects, confidence, llm_analysis)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.frame_id,
                event.timestamp,
                event.location,
                event.description,
                event.event_type,
                json.dumps(event.objects),
                event.confidence,
                event.llm_analysis,
            ),
        )
        self.conn.commit()

    def insert_alert(self, alert: SecurityAlert):
        self.conn.execute(
            """INSERT OR REPLACE INTO alerts
               (alert_id, timestamp, location, severity, rule_triggered, message, frame_id, acknowledged)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.alert_id,
                alert.timestamp,
                alert.location,
                alert.severity,
                alert.rule_triggered,
                alert.message,
                alert.frame_id,
                int(alert.acknowledged),
            ),
        )
        self.conn.commit()


    def query_by_object(self, keyword: str) -> List[Dict]:
        """Find all frames containing a given object keyword."""
        rows = self.conn.execute(
            "SELECT * FROM frames WHERE LOWER(objects) LIKE ?",
            (f"%{keyword.lower()}%",)
        ).fetchall()
        return [dict(r) for r in rows]

    def query_by_location(self, location: str) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM frames WHERE LOWER(location) LIKE ?",
            (f"%{location.lower()}%",)
        ).fetchall()
        return [dict(r) for r in rows]

    def query_by_time_range(self, start: str, end: str) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM frames WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp",
            (start, end),
        ).fetchall()
        return [dict(r) for r in rows]

    def query_by_event_type(self, event_type: str) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM frames WHERE LOWER(event_type) LIKE ?",
            (f"%{event_type.lower()}%",)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_all_frames(self) -> List[Dict]:
        rows = self.conn.execute("SELECT * FROM frames ORDER BY timestamp").fetchall()
        return [dict(r) for r in rows]

    def get_all_alerts(self) -> List[Dict]:
        rows = self.conn.execute("SELECT * FROM alerts ORDER BY timestamp").fetchall()
        return [dict(r) for r in rows]

    def get_high_severity_alerts(self) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM alerts WHERE severity IN ('HIGH','CRITICAL') ORDER BY timestamp"
        ).fetchall()
        return [dict(r) for r in rows]

    def search_frames(self, keyword: str) -> List[Dict]:
        """Full-text search across description and objects."""
        rows = self.conn.execute(
            "SELECT * FROM frames WHERE LOWER(description) LIKE ? OR LOWER(objects) LIKE ?",
            (f"%{keyword.lower()}%", f"%{keyword.lower()}%"),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> Dict:
        total = self.conn.execute("SELECT COUNT(*) FROM frames").fetchone()[0]
        alert_count = self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_type = self.conn.execute(
            "SELECT event_type, COUNT(*) as cnt FROM frames GROUP BY event_type"
        ).fetchall()
        return {
            "total_frames": total,
            "total_alerts": alert_count,
            "by_event_type": {r["event_type"]: r["cnt"] for r in by_type},
        }

    def close(self):
        self.conn.close()
