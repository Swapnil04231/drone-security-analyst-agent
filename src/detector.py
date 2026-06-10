"""
Object Detection & VLM Analysis
- Rule-based extractor (works without any API key)
- Optional LLM-enhanced analysis via LangChain (OpenAI or Anthropic)
"""

import re
import os
from typing import List, Optional, Tuple
from src.models import VideoFrame, TelemetryData, DetectedEvent


# ── Keyword taxonomy ───────────────────────────────────────────────────────

VEHICLE_KEYWORDS = [
    "truck", "car", "suv", "van", "vehicle", "sedan",
    "pickup", "forklift", "minivan", "f150", "toyota",
    "ford", "delivery", "cargo",
]

PERSON_KEYWORDS = [
    "person", "people", "individual", "group", "male", "female",
    "man", "woman", "worker", "guard", "crew", "hoodie",
]

THREAT_ACTIVITIES = [
    "loitering", "attempting", "climbing", "climbing over",
    "running from", "unauthorized", "suspicious",
]

NORMAL_ACTIVITIES = [
    "scheduled", "authorized", "patrol", "maintenance", "clear",
    "no activity",
]


def _extract_objects(text: str) -> Tuple[List[str], str]:
    """
    Extract detected objects and classify event type from frame description.
    Returns (objects_list, event_type).
    """
    lower = text.lower()
    objects = []
    event_type = "unknown"

    # Vehicle detection
    for kw in VEHICLE_KEYWORDS:
        if kw in lower:
            match = re.search(
                r'\b(?:blue|white|black|red|silver|gray|grey|green|yellow)?\s*'
                r'(?:ford|toyota|honda|gmc|chevy)?\s*'
                r'(?:f150|camry|pickup|truck|suv|van|sedan|minivan|forklift|cargo truck)\b',
                lower
            )
            if match:
                objects.append(match.group(0).strip())
            else:
                objects.append(kw)
            event_type = "vehicle"
            break

    # Person detection
    for kw in PERSON_KEYWORDS:
        if kw in lower:
            match = re.search(
                r'\b(?:unknown person|male|female|person|worker|guard|security guard|'
                r'two individuals|group of \w+ people|person (?:with|carrying|in) \w+(?:\s\w+)?)\b',
                lower
            )
            if match:
                objects.append(match.group(0).strip())
            else:
                objects.append("person")
            if event_type == "unknown":
                event_type = "person"
            break

    # Activity classification
    for act in THREAT_ACTIVITIES:
        if act in lower:
            event_type = "threat_" + event_type if event_type != "unknown" else "threat"
            break

    for act in NORMAL_ACTIVITIES:
        if act in lower:
            event_type = "normal"
            break

    if not objects:
        objects = ["unknown object"]

    return objects, event_type


class ObjectDetector:
    """
    Primary object detection engine.
    Uses rule-based NLP by default; escalates to LLM when enabled.
    """

    def __init__(self, use_llm: bool = False):
        self.use_llm = use_llm
        self._llm_chain = None
        if use_llm:
            self._init_llm()

    def _init_llm(self):
        """Initialize LangChain LLM chain for enhanced analysis."""
        try:
            from langchain.prompts import PromptTemplate
            from langchain.chains import LLMChain

            # Try Anthropic first, fallback to OpenAI
            anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
            openai_key = os.environ.get("OPENAI_API_KEY")

            if anthropic_key:
                from langchain_anthropic import ChatAnthropic
                llm = ChatAnthropic(
                    model="claude-3-haiku-20240307",
                    temperature=0,
                    max_tokens=300,
                )
                print("[LLM] Using Anthropic Claude Haiku for analysis")
            elif openai_key:
                from langchain_openai import ChatOpenAI
                llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0, max_tokens=300)
                print("[LLM] Using OpenAI GPT-3.5 for analysis")
            else:
                print("[LLM] No API key found. Falling back to rule-based detection.")
                self.use_llm = False
                return

            prompt = PromptTemplate(
                input_variables=["frame_description", "location", "timestamp"],
                template="""You are a drone security analyst. Analyze this surveillance frame description and extract structured security information.

Frame: "{frame_description}"
Location: {location}
Time: {timestamp}

Respond in this exact format:
OBJECTS: <comma-separated list of detected objects/people>
EVENT_TYPE: <one of: vehicle, person, loitering, intrusion, normal, suspicious>
THREAT_LEVEL: <one of: none, low, medium, high>
ANALYSIS: <one sentence security assessment>"""
            )
            self._llm_chain = LLMChain(llm=llm, prompt=prompt)

        except ImportError as e:
            print(f"[LLM] LangChain not fully installed ({e}). Using rule-based detection.")
            self.use_llm = False

    def analyze_frame(
        self,
        frame: VideoFrame,
        telemetry: TelemetryData,
    ) -> DetectedEvent:
        """Analyze a single frame and return a DetectedEvent."""
        objects, event_type = _extract_objects(frame.description)
        llm_analysis = None

        if self.use_llm and self._llm_chain:
            try:
                response = self._llm_chain.run(
                    frame_description=frame.description,
                    location=frame.location,
                    timestamp=frame.timestamp,
                )
                llm_analysis = response.strip()
                # Parse LLM output for improved event_type
                for line in response.splitlines():
                    if line.startswith("EVENT_TYPE:"):
                        event_type = line.split(":", 1)[1].strip().lower()
                    if line.startswith("OBJECTS:"):
                        llm_objects = [o.strip() for o in line.split(":", 1)[1].split(",")]
                        if llm_objects:
                            objects = llm_objects
            except Exception as e:
                llm_analysis = f"[LLM error: {e}]"

        return DetectedEvent(
            frame_id=frame.frame_id,
            timestamp=frame.timestamp,
            location=frame.location,
            objects=objects,
            event_type=event_type,
            description=frame.description,
            confidence=0.95 if self.use_llm else 0.80,
            llm_analysis=llm_analysis,
        )
