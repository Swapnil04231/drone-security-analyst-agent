"""
Alert Rules Engine
Evaluates detected events against predefined security rules and
generates SecurityAlert objects.
"""

import uuid
from typing import List, Optional
from src.models import DetectedEvent, SecurityAlert, SessionContext



def _is_night(timestamp: str) -> bool:
    """Return True if timestamp is between 22:00 and 06:00."""
    try:
        hour = int(timestamp.split(":")[0])
        return hour >= 22 or hour < 6
    except Exception:
        return False


def _object_seen_n_times(context: SessionContext, obj_keyword: str, n: int) -> bool:
    """Check if an object type has been seen >= n times in the session."""
    for key, count in context.object_counts.items():
        if obj_keyword.lower() in key and count >= n:
            return True
    return False


class AlertRule:
    """Base class for an alert rule."""

    def __init__(self, rule_id: str, severity: str, description: str):
        self.rule_id = rule_id
        self.severity = severity
        self.description = description

    def evaluate(
        self, event: DetectedEvent, context: SessionContext
    ) -> Optional[SecurityAlert]:
        raise NotImplementedError


class NightPersonRule(AlertRule):
    """Alert when a person is detected at night."""

    def __init__(self):
        super().__init__("R001", "HIGH", "Person detected during night hours")

    def evaluate(self, event, context):
        if "person" in event.event_type and _is_night(event.timestamp):
            return SecurityAlert(
                alert_id=str(uuid.uuid4())[:8],
                timestamp=event.timestamp,
                location=event.location,
                severity=self.severity,
                rule_triggered=self.rule_id,
                message=f"Person loitering at {event.location}, {event.timestamp}. "
                        f"Objects: {', '.join(event.objects)}",
                frame_id=event.frame_id,
            )


class ThreatActivityRule(AlertRule):
    """Alert when threat keywords are found in the event type."""

    def __init__(self):
        super().__init__("R002", "CRITICAL", "Threat activity detected")

    def evaluate(self, event, context):
        if "threat" in event.event_type:
            return SecurityAlert(
                alert_id=str(uuid.uuid4())[:8],
                timestamp=event.timestamp,
                location=event.location,
                severity=self.severity,
                rule_triggered=self.rule_id,
                message=f"Threat activity at {event.location}, {event.timestamp}: "
                        f"{event.description[:80]}",
                frame_id=event.frame_id,
            )


class RepeatedVehicleRule(AlertRule):
    """Alert when the same vehicle type is seen 2+ times."""

    def __init__(self):
        super().__init__("R003", "MEDIUM", "Repeated vehicle sighting")

    def evaluate(self, event, context):
        if event.event_type == "vehicle":
            for obj in event.objects:
                if _object_seen_n_times(context, obj, 2):
                    return SecurityAlert(
                        alert_id=str(uuid.uuid4())[:8],
                        timestamp=event.timestamp,
                        location=event.location,
                        severity=self.severity,
                        rule_triggered=self.rule_id,
                        message=f"Repeated vehicle sighting: '{obj}' seen multiple times. "
                                f"Latest: {event.location} at {event.timestamp}",
                        frame_id=event.frame_id,
                    )


class PerimeterIntrusionRule(AlertRule):
    """Alert when any activity is detected at perimeter locations."""

    PERIMETER_KEYWORDS = ["perimeter", "fence", "gate"]

    def __init__(self):
        super().__init__("R004", "HIGH", "Perimeter activity")

    def evaluate(self, event, context):
        loc_lower = event.location.lower()
        if any(kw in loc_lower for kw in self.PERIMETER_KEYWORDS):
            if event.event_type not in ("normal",):
                return SecurityAlert(
                    alert_id=str(uuid.uuid4())[:8],
                    timestamp=event.timestamp,
                    location=event.location,
                    severity=self.severity,
                    rule_triggered=self.rule_id,
                    message=f"Activity at perimeter location '{event.location}' "
                            f"at {event.timestamp}: {event.description[:60]}",
                    frame_id=event.frame_id,
                )


class AlertEngine:
    """Evaluates all rules and returns triggered alerts."""

    def __init__(self):
        self.rules: List[AlertRule] = [
            NightPersonRule(),
            ThreatActivityRule(),
            RepeatedVehicleRule(),
            PerimeterIntrusionRule(),
        ]

    def evaluate(
        self, event: DetectedEvent, context: SessionContext
    ) -> List[SecurityAlert]:
        alerts = []
        for rule in self.rules:
            alert = rule.evaluate(event, context)
            if alert:
                alerts.append(alert)
        return alerts
