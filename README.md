# Drone Security Analyst Agent

A prototype AI-powered drone security monitoring system that processes simulated telemetry and video frame data, detects security events, generates real-time alerts, and provides a queryable frame index with follow-up Q&A.

---

## Feature Spec

**Value to property owners:** Automates 24/7 drone surveillance by continuously monitoring simulated video feeds and telemetry, identifying security-relevant objects and behaviours (vehicles, people, intrusion attempts), and generating instant prioritised alerts — reducing reliance on manual review.

**Key Requirements:**
1. **Event Detection** — Identify objects and activities (vehicles, people, suspicious behaviour) from every video frame with contextual logging.
2. **Real-time Alerting** — Trigger severity-graded alerts (LOW/MEDIUM/HIGH/CRITICAL) based on predefined rules (night-time intrusion, perimeter breach, repeated sightings).
3. **Queryable Frame Index** — Store all frames in a SQLite database indexed by timestamp, location, and object type for historical lookup and Q&A.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  INPUT LAYER                                                 │
│  DroneSimulator → VideoFrame + TelemetryData objects        │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  CORE AGENT  (DroneSecurityAgent)                            │
│  Orchestrates: detect → context → alert → index → Q&A       │
└──────┬─────────────────────────┬───────────────────┬────────┘
       │                         │                   │
┌──────▼──────┐    ┌─────────────▼──────┐  ┌────────▼───────┐
│ ObjectDetector│  │  AlertEngine       │  │ FrameIndexDB   │
│ Rule-based   │  │  4 rule classes:   │  │ SQLite         │
│ + LangChain  │  │  Night·Threat·     │  │ Full-text &    │
│ (optional)   │  │  Repeat·Perimeter  │  │ field queries  │
└─────────────┘   └────────────────────┘  └────────────────┘
                                                    │
                                          ┌─────────▼──────────┐
                                          │  CLI Dashboard     │
                                          │  + Q&A Interface   │
                                          └────────────────────┘
```

**Design decisions:**
- **Rule-based detection first** — Works offline with zero API cost; LLM layer is opt-in via `--llm` flag.
- **LangChain for LLM integration** — Abstraction over Anthropic/OpenAI makes it easy to swap providers.
- **SQLite for indexing** — Zero-setup, embedded, fast enough for prototype scale. Can be swapped for PostgreSQL or a vector DB for production.
- **Dataclasses for models** — Type-safe, inspectable, easily serialised to JSON/dict.

---

## Setup

### Prerequisites
- Python 3.9+
- (Optional) Anthropic or OpenAI API key for `--llm` mode

### Install

```bash
git clone <your-repo-url>
cd drone_security_agent

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Run (no API key needed)

```bash
python main.py --mode demo
```

### Run with LLM enhancement

```bash
# Anthropic (recommended)
export ANTHROPIC_API_KEY=sk-ant-...
python main.py --mode demo --llm

# Or OpenAI
export OPENAI_API_KEY=sk-...
python main.py --mode demo --llm
```

### Interactive Q&A mode

```bash
python main.py --mode interactive
# Then type questions like:
#   "Show all truck events"
#   "Were there people detected at midnight?"
#   "What happened at the main gate?"
```

### Run tests

```bash
python -m pytest tests/ -v
```

---

## Sample Output

```
[Frame 01] 00:01  North Perimeter  | person         | Objects: worker
  [ALERT HIGH] Rule R001: Person loitering at North Perimeter, 00:01.

[Frame 04] 06:00  Main Gate        | vehicle        | Objects: red pickup
  [ALERT HIGH] Rule R004: Activity at perimeter location 'Main Gate' at 06:00

[Frame 06] 08:00  Rooftop          | threat_vehicle | Objects: silver sedan
  [ALERT CRITICAL] Rule R002: Threat activity at Rooftop, 08:00: silver sedan loitering

Video Summary:
  Monitored 15 events; detected unknown object (×4), red pickup (×2);
  most activity at Parking Lot and North Perimeter; 13 alert(s) triggered.

Q: Show all events involving vehicles
A: Found 8 result(s):
   Frame 4 @ 06:00 — Main Gate: red pickup [vehicle]
   Frame 10 @ 14:00 — Guard Post: blue ford f150 [vehicle]
   ...
```

---

## File Structure

```
drone_security_agent/
├── main.py                  # Entry point (demo + interactive modes)
├── requirements.txt
├── README.md
├── src/
│   ├── __init__.py
│   ├── models.py            # Data classes: Frame, Telemetry, Event, Alert, Context
│   ├── simulator.py         # Generates synthetic telemetry + video descriptions
│   ├── detector.py          # Object detection (rule-based + optional LangChain/LLM)
│   ├── alert_engine.py      # 4 alert rules: Night, Threat, Repeat, Perimeter
│   ├── database.py          # SQLite frame index + alert store
│   └── agent.py             # Orchestrator, summary, Q&A
├── tests/
│   └── test_agent.py        # 19 test cases covering all components
├── data/                    # SQLite DB written here at runtime
└── logs/                    # Session logs written here
```

---

## Alert Rules

| Rule | ID | Severity | Trigger |
|------|-----|----------|---------|
| Night person | R001 | HIGH | Person detected between 22:00–06:00 |
| Threat activity | R002 | CRITICAL | Loitering, climbing, unauthorised access keywords |
| Repeated vehicle | R003 | MEDIUM | Same vehicle type seen ≥ 2 times |
| Perimeter activity | R004 | HIGH | Any non-normal event at gate/fence/perimeter |

---

## Cross-Domain: Frame Indexing

All frames are stored in SQLite with the following indices:
- `idx_frames_timestamp` — query by time range
- `idx_frames_location` — filter by location name
- `idx_frames_event` — filter by event type

Queryable via `FrameIndexDB` methods:
```python
db.query_by_object("ford f150")       # → all truck frames
db.query_by_time_range("22:00","06:00")  # → night frames
db.query_by_location("gate")          # → gate-related events
db.search_frames("loitering")         # → full-text search
```

---

## Bonus Features

- **Video summarization** — `agent._generate_video_summary()` produces a one-sentence session summary (rule-based fallback + LLM when available).
- **Follow-up Q&A** — `agent.answer_query(question)` routes natural-language questions to the appropriate DB query and returns structured results.

---

## AI Tools Used

- **Claude (Anthropic)** — Used for LangChain prompt design, frame analysis (in `--llm` mode), and iterative code review.
- **LangChain** — Abstracts LLM provider switching; used for `LLMChain` and `PromptTemplate` in `detector.py` and `agent.py`.

---

## What Could Be Improved (Given More Time)

1. **Real VLM integration** — Replace text simulations with actual BLIP-2 or GPT-4V image analysis via Hugging Face Transformers or the OpenAI Vision API.
2. **Vector similarity search** — Use FAISS or ChromaDB to index frame embeddings for semantic queries ("show me frames similar to this one").
3. **Streaming telemetry** — Replace batch simulation with a real-time WebSocket feed from a drone SDK.
4. **Web dashboard** — Replace CLI output with a FastAPI + React frontend showing a live map and alert feed.
5. **Multi-drone context** — Scale `SessionContext` to track multiple drones simultaneously.

---

## Testing

19 test cases across 5 classes:

| Class | Coverage |
|-------|----------|
| `TestSimulator` | Frame/telemetry generation, field validation |
| `TestObjectDetection` | Vehicle/person/threat/normal classification |
| `TestAlertEngine` | Rule evaluation, severity, time-based triggering |
| `TestDatabase` | Insert/query by object, time range, event type |
| `TestIntegration` | Full end-to-end pipeline with Q&A verification |

Run: `python -m pytest tests/ -v`
