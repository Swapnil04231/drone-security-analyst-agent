"""
Test Suite for Drone Security Analyst Agent
Tests: object detection, alert rules, DB indexing, Q&A queries.
Run: python -m pytest tests/ -v
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models import VideoFrame, TelemetryData, DetectedEvent, SecurityAlert, SessionContext
from src.simulator import DroneSimulator
from src.detector import ObjectDetector, _extract_objects
from src.alert_engine import AlertEngine, NightPersonRule, ThreatActivityRule
from src.database import FrameIndexDB
from src.agent import DroneSecurityAgent
from datetime import datetime


# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path):
    db = FrameIndexDB(str(tmp_path / "test.db"))
    yield db
    db.close()


@pytest.fixture
def agent(db):
    return DroneSecurityAgent(db=db, use_llm=False)


@pytest.fixture
def make_frame():
    def _f(desc, location="Main Gate", timestamp="12:00", frame_id=1):
        return VideoFrame(
            frame_id=frame_id,
            timestamp=timestamp,
            description=desc,
            location=location,
            raw_text=f"Frame {frame_id}: {desc}",
        )
    return _f


@pytest.fixture
def make_telemetry():
    def _t(timestamp="12:00", location="Main Gate"):
        return TelemetryData(
            timestamp=timestamp,
            location=location,
            latitude=18.975,
            longitude=73.855,
            altitude_m=30.0,
            battery_pct=80,
            heading_deg=90.0,
        )
    return _t


# ── Simulator tests ────────────────────────────────────────────────────────

class TestSimulator:
    def test_generates_correct_count(self):
        sim = DroneSimulator()
        frames = sim.generate_frames(10)
        assert len(frames) == 10

    def test_frame_has_required_fields(self):
        sim = DroneSimulator()
        frame = sim.generate_frames(1)[0]
        assert frame.frame_id == 1
        assert frame.timestamp
        assert frame.description
        assert frame.location
        assert frame.raw_text.startswith("Frame 1:")

    def test_telemetry_count_matches(self):
        sim = DroneSimulator()
        telemetry = sim.generate_telemetry(7)
        assert len(telemetry) == 7
        for t in telemetry:
            assert 0 <= t.battery_pct <= 100
            assert 0 <= t.heading_deg <= 360


# ── Object detection tests ─────────────────────────────────────────────────

class TestObjectDetection:
    def test_detects_vehicle_keyword(self):
        objs, etype = _extract_objects("blue Ford F150 parked at gate")
        assert any("f150" in o.lower() or "truck" in o.lower() or "ford" in o.lower() for o in objs)
        assert etype == "vehicle"

    def test_detects_person_keyword(self):
        objs, etype = _extract_objects("unknown person loitering near fence")
        assert any("person" in o.lower() for o in objs)
        assert "person" in etype

    def test_threat_activity_flagged(self):
        _, etype = _extract_objects("person climbing over fence")
        assert "threat" in etype

    def test_normal_event_classified(self):
        _, etype = _extract_objects("Clear view, no activity detected")
        assert etype == "normal"

    def test_detector_returns_event(self, make_frame, make_telemetry):
        detector = ObjectDetector(use_llm=False)
        frame = make_frame("blue truck at main gate")
        tel = make_telemetry()
        event = detector.analyze_frame(frame, tel)
        assert event.frame_id == 1
        assert event.event_type == "vehicle"
        assert len(event.objects) > 0

    def test_truck_logged_correctly(self, agent, make_frame, make_telemetry):
        """Expected: 'Blue Ford F150 spotted at garage, 12:00.'"""
        frame = make_frame("Blue Ford F150 spotted at garage", location="Garage", timestamp="12:00")
        tel = make_telemetry(timestamp="12:00", location="Garage")
        agent.process_frame(frame, tel)
        results = agent.db.query_by_object("f150")
        assert len(results) >= 1
        assert results[0]["event_type"] == "vehicle"


# ── Alert engine tests ─────────────────────────────────────────────────────

class TestAlertEngine:
    def _make_event(self, event_type, timestamp, location, objects=None):
        return DetectedEvent(
            frame_id=1,
            timestamp=timestamp,
            location=location,
            objects=objects or ["person"],
            event_type=event_type,
            description="test event",
        )

    def _fresh_context(self):
        return SessionContext(session_id="test", start_time=datetime.now())

    def test_night_person_triggers_alert(self):
        rule = NightPersonRule()
        event = self._make_event("person", "00:01", "Main Gate")
        ctx = self._fresh_context()
        alert = rule.evaluate(event, ctx)
        assert alert is not None
        assert alert.severity == "HIGH"
        assert "Main Gate" in alert.message

    def test_no_alert_for_day_person(self):
        rule = NightPersonRule()
        event = self._make_event("person", "14:00", "Main Gate")
        ctx = self._fresh_context()
        alert = rule.evaluate(event, ctx)
        assert alert is None

    def test_threat_activity_triggers_critical(self):
        rule = ThreatActivityRule()
        event = self._make_event("threat_person", "02:00", "East Fence")
        ctx = self._fresh_context()
        alert = rule.evaluate(event, ctx)
        assert alert is not None
        assert alert.severity == "CRITICAL"

    def test_alert_triggered_at_midnight(self, agent, make_frame, make_telemetry):
        """Expected: 'Person loitering at main gate, 00:01.'"""
        frame = make_frame(
            "person loitering at main gate",
            location="Main Gate",
            timestamp="00:01",
        )
        tel = make_telemetry("00:01", "Main Gate")
        agent.process_frame(frame, tel)
        alerts = agent.db.get_all_alerts()
        assert len(alerts) >= 1
        assert any("Main Gate" in a["message"] for a in alerts)


# ── Database tests ─────────────────────────────────────────────────────────

class TestDatabase:
    def _sample_event(self, frame_id=1, event_type="vehicle", timestamp="12:00"):
        return DetectedEvent(
            frame_id=frame_id,
            timestamp=timestamp,
            location="Parking Lot",
            objects=["blue ford f150"],
            event_type=event_type,
            description="blue ford f150 parked",
        )

    def test_insert_and_retrieve_frame(self, db):
        event = self._sample_event()
        db.insert_frame(event)
        frames = db.get_all_frames()
        assert len(frames) == 1
        assert frames[0]["frame_id"] == 1

    def test_query_by_object_truck(self, db):
        event = self._sample_event()
        db.insert_frame(event)
        results = db.query_by_object("ford f150")
        assert len(results) >= 1

    def test_query_show_all_truck_events(self, db):
        """Expected: queryable by object keyword (ford f150 / vehicle type)."""
        for i in range(1, 4):
            db.insert_frame(self._sample_event(frame_id=i))
        results = db.query_by_object("ford")
        assert len(results) == 3

    def test_query_by_time_range(self, db):
        for i, ts in enumerate(["06:00", "12:00", "22:00"], 1):
            db.insert_frame(self._sample_event(frame_id=i, timestamp=ts))
        results = db.query_by_time_range("06:00", "12:00")
        assert len(results) == 2

    def test_get_stats(self, db):
        db.insert_frame(self._sample_event(frame_id=1, event_type="vehicle"))
        db.insert_frame(self._sample_event(frame_id=2, event_type="person"))
        stats = db.get_stats()
        assert stats["total_frames"] == 2
        assert "vehicle" in stats["by_event_type"]


# ── Integration test ───────────────────────────────────────────────────────

class TestIntegration:
    def test_full_pipeline(self, agent, make_frame, make_telemetry):
        """Full end-to-end: frames → detection → alerts → DB → Q&A."""
        scenarios = [
            ("Blue Ford F150 entered parking lot", "Parking Lot", "08:00"),
            ("Unknown person loitering at east fence", "East Fence", "00:15"),
            ("Blue Ford F150 exiting main gate", "Main Gate", "09:00"),
            ("Security guard patrol passing guard post", "Guard Post", "10:00"),
            ("Male in dark hoodie climbing over fence", "East Fence", "23:00"),
        ]
        for i, (desc, loc, ts) in enumerate(scenarios, 1):
            frame = make_frame(desc, location=loc, timestamp=ts, frame_id=i)
            tel = make_telemetry(ts, loc)
            agent.process_frame(frame, tel)

        stats = agent.db.get_stats()
        assert stats["total_frames"] == 5
        assert stats["total_alerts"] >= 2

        # Test Q&A
        q_vehicle = agent.answer_query("Show all events involving vehicles")
        assert "vehicle" in q_vehicle.lower() or "Frame" in q_vehicle

        q_night = agent.answer_query("Were there any person detections after midnight?")
        assert "Frame" in q_night or "No matching" in q_night

        summary = agent.answer_query("Give me a summary")
        assert len(summary) > 20
