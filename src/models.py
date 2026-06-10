"""
Data models for the Drone Security Analyst Agent.
"""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime


@dataclass
class TelemetryData:
    """Drone telemetry snapshot."""
    timestamp: str          
    location: str          
    latitude: float
    longitude: float
    altitude_m: float
    battery_pct: int
    heading_deg: float

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class VideoFrame:
    """Simulated video frame with text description."""
    frame_id: int
    timestamp: str         
    description: str        
    location: str
    raw_text: str          

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class DetectedEvent:
    """A security-relevant event detected from a frame."""
    frame_id: int
    timestamp: str
    location: str
    objects: List[str]         
    event_type: str            
    description: str
    confidence: float = 1.0
    llm_analysis: Optional[str] = None

    def to_dict(self) -> dict:
        return {**self.__dict__, "objects": self.objects}


@dataclass
class SecurityAlert:
    """A triggered security alert."""
    alert_id: str
    timestamp: str
    location: str
    severity: str          
    rule_triggered: str
    message: str
    frame_id: int
    acknowledged: bool = False

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class SessionContext:
    """Running context for the current monitoring session."""
    session_id: str
    start_time: datetime
    events: List[DetectedEvent] = field(default_factory=list)
    alerts: List[SecurityAlert] = field(default_factory=list)
    object_counts: dict = field(default_factory=dict)
    location_activity: dict = field(default_factory=dict)

    def add_event(self, event: DetectedEvent):
        self.events.append(event)
        for obj in event.objects:
            key = obj.lower()
            self.object_counts[key] = self.object_counts.get(key, 0) + 1
        loc = event.location
        self.location_activity[loc] = self.location_activity.get(loc, 0) + 1

    def add_alert(self, alert: SecurityAlert):
        self.alerts.append(alert)

    def get_summary_text(self) -> str:
        lines = [
            f"Session: {self.session_id}",
            f"Total events detected: {len(self.events)}",
            f"Total alerts triggered: {len(self.alerts)}",
            f"Object counts: {self.object_counts}",
            f"Activity by location: {self.location_activity}",
        ]
        if self.alerts:
            lines.append("\nAlerts:")
            for a in self.alerts:
                lines.append(f"  [{a.severity}] {a.message}")
        return "\n".join(lines)
