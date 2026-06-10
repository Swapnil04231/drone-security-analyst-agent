"""
Simulator: generates realistic drone telemetry and video frame descriptions
without requiring real hardware or camera feeds.
"""

import random
from typing import List, Tuple
from src.models import VideoFrame, TelemetryData



LOCATIONS = [
    "Main Gate", "North Perimeter", "South Perimeter",
    "Parking Lot", "Warehouse Entrance", "Loading Dock",
    "Rooftop", "East Fence", "West Fence", "Guard Post",
]

VEHICLES = [
    "blue Ford F150", "white Toyota Camry", "black SUV",
    "red pickup truck", "silver sedan", "delivery van",
    "green minivan", "yellow forklift", "gray cargo truck",
]

PEOPLE_DESCRIPTIONS = [
    "unknown person", "male in dark hoodie", "female in blue jacket",
    "security guard", "worker in high-vis vest", "person carrying bag",
    "two individuals", "group of three people", "person with backpack",
]

ACTIVITIES = [
    "loitering near {location}",
    "attempting to access {location}",
    "parked at {location}",
    "driving through {location}",
    "walking along {location}",
    "climbing over fence at {location}",
    "entering {location}",
    "exiting {location}",
    "stationary at {location}",
    "running from {location}",
]

NORMAL_EVENTS = [
    "Clear view, no activity detected",
    "Scheduled maintenance crew at {location}",
    "Authorized delivery truck at {location}",
    "Security patrol passing {location}",
]


HOURS = [
    "00:01", "00:15", "01:30", "06:00", "07:45",
    "08:00", "09:30", "11:00", "12:00", "14:00",
    "16:00", "18:30", "20:00", "22:45", "23:59",
]

BASE_LAT = 18.9750   
BASE_LON = 73.8553


class DroneSimulator:
    """Generates simulated telemetry and video frame data."""

    def __init__(self, seed: int = 42):
        random.seed(seed)
        self._frame_counter = 0

    def _random_location(self) -> str:
        return random.choice(LOCATIONS)

    def _make_frame_description(self, location: str, hour_str: str) -> Tuple[str, str]:
        """Returns (description, event_type_hint)."""
        hour = int(hour_str.split(":")[0])
        roll = random.random()

        is_night = hour >= 22 or hour < 6

        if is_night and roll < 0.55:
            subject = random.choice(PEOPLE_DESCRIPTIONS)
            activity = random.choice(ACTIVITIES).format(location=location)
            desc = f"{subject} {activity}"
            return desc, "person_night"

        elif roll < 0.30:
            vehicle = random.choice(VEHICLES)
            activity = random.choice(ACTIVITIES[:5]).format(location=location)
            desc = f"{vehicle} {activity}"
            return desc, "vehicle"

        elif roll < 0.55:
            subject = random.choice(PEOPLE_DESCRIPTIONS)
            activity = random.choice(ACTIVITIES[5:]).format(location=location)
            desc = f"{subject} {activity}"
            return desc, "person"

        else:
            event = random.choice(NORMAL_EVENTS).format(location=location)
            return event, "normal"

    def generate_frames(self, count: int = 15) -> List[VideoFrame]:
        """Generate a list of simulated video frames."""
        frames = []
        for i in range(count):
            location = self._random_location()
            timestamp = HOURS[i % len(HOURS)]
            raw_text = f"Frame {i+1}: "
            desc, _ = self._make_frame_description(location, timestamp)
            raw_text += desc
            frame = VideoFrame(
                frame_id=i + 1,
                timestamp=timestamp,
                description=desc,
                location=location,
                raw_text=raw_text,
            )
            frames.append(frame)
        return frames

    def generate_telemetry(self, count: int = 15) -> List[TelemetryData]:
        """Generate matching telemetry records."""
        records = []
        for i in range(count):
            timestamp = HOURS[i % len(HOURS)]
            records.append(TelemetryData(
                timestamp=timestamp,
                location=random.choice(LOCATIONS),
                latitude=BASE_LAT + random.uniform(-0.002, 0.002),
                longitude=BASE_LON + random.uniform(-0.002, 0.002),
                altitude_m=round(random.uniform(10, 80), 1),
                battery_pct=max(20, 100 - i * 4),
                heading_deg=round(random.uniform(0, 360), 1),
            ))
        return records
