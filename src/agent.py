"""
Drone Security Analyst Agent
Orchestrates detection, alerting, logging, and Q&A.
"""

import uuid
import json
import os
from datetime import datetime
from typing import List

from src.models import VideoFrame, TelemetryData, SessionContext
from src.detector import ObjectDetector
from src.alert_engine import AlertEngine
from src.database import FrameIndexDB

# ANSI colors for CLI
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

SEVERITY_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
}


class DroneSecurityAgent:
    """
    Core agent: processes frames, triggers alerts, answers queries.
    Bonus: video summarization + follow-up Q&A.
    """

    def __init__(self, db: FrameIndexDB, use_llm: bool = False):
        self.db = db
        self.detector = ObjectDetector(use_llm=use_llm)
        self.alert_engine = AlertEngine()
        self.context = SessionContext(
            session_id=str(uuid.uuid4())[:8],
            start_time=datetime.now(),
        )
        self._log_lines: List[str] = []
        self.use_llm = use_llm


    def process_frame(self, frame: VideoFrame, telemetry: TelemetryData):
        """Process one frame: detect → log → alert → index."""
    
        event = self.detector.analyze_frame(frame, telemetry)

        self.context.add_event(event)

        log_line = (
            f"[Frame {event.frame_id:02d}] {event.timestamp}  "
            f"{event.location:<22} | {event.event_type:<20} | "
            f"Objects: {', '.join(event.objects)}"
        )
        print(f"{CYAN}{log_line}{RESET}")
        self._log_lines.append(log_line)

        if event.llm_analysis:
            print(f"  {BOLD}LLM:{RESET} {event.llm_analysis}")


        alerts = self.alert_engine.evaluate(event, self.context)
        for alert in alerts:
            self.context.add_alert(alert)
            color = SEVERITY_COLOR.get(alert.severity, "")
            alert_line = (
                f"  {color}[ALERT {alert.severity}]{RESET} "
                f"Rule {alert.rule_triggered}: {alert.message}"
            )
            print(alert_line)
            self._log_lines.append(f"  [ALERT {alert.severity}] {alert.message}")
            self.db.insert_alert(alert)

        self.db.insert_frame(event)


    def print_summary(self):
        """Print session summary."""
        ctx = self.context
        stats = self.db.get_stats()
        print(f"\n{BOLD}Session ID:{RESET}    {ctx.session_id}")
        print(f"{BOLD}Frames processed:{RESET} {stats['total_frames']}")
        print(f"{BOLD}Alerts triggered:{RESET} {stats['total_alerts']}")
        print(f"{BOLD}Object counts:{RESET}    {ctx.object_counts}")
        print(f"\n{BOLD}Events by type:{RESET}")
        for etype, cnt in stats["by_event_type"].items():
            print(f"  {etype}: {cnt}")

        high_alerts = self.db.get_high_severity_alerts()
        if high_alerts:
            print(f"\n{RED}{BOLD}High-severity alerts:{RESET}")
            for a in high_alerts:
                print(f"  [{a['severity']}] {a['message']}")

        print(f"\n{BOLD}Video Summary:{RESET}")
        print(f"  {self._generate_video_summary()}")

    def _generate_video_summary(self) -> str:
        """
        Bonus feature: generate a one-sentence summary of the entire session.
        Uses LLM if available, otherwise builds from context.
        """
        if self.use_llm:
            try:
                return self._llm_summarize()
            except Exception:
                pass

        ctx = self.context
        n_events = len(ctx.events)
        n_alerts = len(ctx.alerts)
        top_objs = sorted(ctx.object_counts.items(), key=lambda x: -x[1])[:3]
        obj_str = ", ".join(f"{k} (×{v})" for k, v in top_objs) or "no specific objects"
        active_locs = sorted(ctx.location_activity.items(), key=lambda x: -x[1])[:2]
        loc_str = " and ".join(l for l, _ in active_locs) or "various locations"
        return (
            f"Monitored {n_events} events across the property; "
            f"detected {obj_str}; most activity at {loc_str}; "
            f"{n_alerts} security alert(s) triggered."
        )

    def _llm_summarize(self) -> str:
        """LLM-generated summary (requires LangChain + API key)."""
        from langchain.prompts import PromptTemplate
        from langchain.chains import LLMChain
        import os

        ctx = self.context
        events_text = "\n".join(
            f"- Frame {e.frame_id}: {e.timestamp}, {e.location}, {e.event_type}, {e.description[:60]}"
            for e in ctx.events[:20]
        )
        alerts_text = "\n".join(
            f"- [{a.severity}] {a.message}" for a in ctx.alerts[:10]
        )

        anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
        openai_key = os.environ.get("OPENAI_API_KEY")

        if anthropic_key:
            from langchain_anthropic import ChatAnthropic
            llm = ChatAnthropic(model="claude-3-haiku-20240307", temperature=0, max_tokens=150)
        elif openai_key:
            from langchain_openai import ChatOpenAI
            llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0, max_tokens=150)
        else:
            raise RuntimeError("No API key")

        prompt = PromptTemplate(
            input_variables=["events", "alerts"],
            template="""Summarize this drone security session in ONE sentence for a property owner.

Events:
{events}

Alerts:
{alerts}

One-sentence summary:"""
        )
        chain = LLMChain(llm=llm, prompt=prompt)
        return chain.run(events=events_text, alerts=alerts_text).strip()



    def answer_query(self, question: str) -> str:
        """
        Bonus feature: answer follow-up questions about session data.
        Uses DB queries + optional LLM synthesis.
        """
        q_lower = question.lower()

        results = []

        if any(kw in q_lower for kw in ["vehicle", "truck", "car", "suv", "van"]):
            results = self.db.query_by_event_type("vehicle")
            if not results:
                results = self.db.query_by_object("truck")
        elif any(kw in q_lower for kw in ["person", "people", "loitering", "individual"]):
            results = self.db.query_by_event_type("person")
            if not results:
                results = self.db.search_frames("person")
        elif "midnight" in q_lower or "night" in q_lower or "00:" in q_lower:
            night_frames = [
                r for r in self.db.get_all_frames()
                if self._is_night_ts(r["timestamp"])
            ]
            results = night_frames
        elif "gate" in q_lower:
            results = self.db.query_by_location("gate")
        elif "alert" in q_lower or "warning" in q_lower:
            results = self.db.get_all_alerts()
            if results:
                return "\n".join(
                    f"[{r['severity']}] {r['timestamp']} {r['location']}: {r['message']}"
                    for r in results
                )
        elif "summar" in q_lower:
            return self._generate_video_summary()
        elif "object" in q_lower or "detected" in q_lower or "what" in q_lower:
            results = self.db.get_all_frames()
        else:
            words = [w for w in q_lower.split() if len(w) > 3]
            for word in words:
                r = self.db.search_frames(word)
                if r:
                    results = r
                    break
            if not results:
                results = self.db.get_all_frames()

        if not results:
            return "No matching events found in the index for that query."


        lines = []
        for r in results[:8]:
            if "objects" in r:
                objs = r["objects"]
                if isinstance(objs, str):
                    try:
                        objs = json.loads(objs)
                    except Exception:
                        pass
                objs_str = ", ".join(objs) if isinstance(objs, list) else str(objs)
                lines.append(
                    f"Frame {r['frame_id']} @ {r['timestamp']} — {r['location']}: "
                    f"{objs_str} [{r['event_type']}]"
                )
            else:
                lines.append(str(r))

        header = f"Found {len(results)} result(s):"
        return header + "\n" + "\n".join(lines)

    @staticmethod
    def _is_night_ts(ts: str) -> bool:
        try:
            h = int(ts.split(":")[0])
            return h >= 22 or h < 6
        except Exception:
            return False

    def save_log(self, path: str = "logs/session.log"):
        """Save session log to file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(f"Drone Security Agent Session — {self.context.start_time}\n")
            f.write("=" * 60 + "\n")
            f.write("\n".join(self._log_lines))
            f.write("\n\n--- SUMMARY ---\n")
            f.write(self.context.get_summary_text())
