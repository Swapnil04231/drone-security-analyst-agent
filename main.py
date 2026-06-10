"""
Drone Security Analyst Agent - Main Entry Point
Processes simulated telemetry + video frames and generates security alerts.
"""

import argparse
import sys
from src.agent import DroneSecurityAgent
from src.simulator import DroneSimulator
from src.database import FrameIndexDB


def run_demo(use_llm: bool = False):
    """Run the full demo pipeline."""
    print("\n" + "="*60)
    print("  DRONE SECURITY ANALYST AGENT - DEMO")
    print("="*60 + "\n")

    # Initialize components
    db = FrameIndexDB("data/frames.db")
    simulator = DroneSimulator()
    agent = DroneSecurityAgent(db=db, use_llm=use_llm)

    # Generate simulated data
    frames = simulator.generate_frames(count=15)
    telemetry_stream = simulator.generate_telemetry(count=15)

    print(f"[SIM] Generated {len(frames)} video frames and {len(telemetry_stream)} telemetry records\n")

    for frame, telemetry in zip(frames, telemetry_stream):
        agent.process_frame(frame, telemetry)

    print("\n" + "="*60)
    print("  SESSION SUMMARY")
    print("="*60)
    agent.print_summary()

    print("\n" + "="*60)
    print("  FOLLOW-UP QUERY DEMO")
    print("="*60)
    demo_queries = [
        "Show all events involving vehicles",
        "Were there any person detections after midnight?",
        "What objects were detected near the main gate?",
        "Give me a summary of today's security events",
    ]
    for q in demo_queries:
        print(f"\nQ: {q}")
        answer = agent.answer_query(q)
        print(f"A: {answer}")

    db.close()


def run_interactive(use_llm: bool = False):
    """Interactive Q&A mode after processing."""
    db = FrameIndexDB("data/frames.db")
    simulator = DroneSimulator()
    agent = DroneSecurityAgent(db=db, use_llm=use_llm)

    frames = simulator.generate_frames(count=20)
    telemetry_stream = simulator.generate_telemetry(count=20)

    print("[*] Processing frames...\n")
    for frame, telemetry in zip(frames, telemetry_stream):
        agent.process_frame(frame, telemetry)

    agent.print_summary()

    print("\n[*] Enter follow-up questions (type 'exit' to quit):")
    while True:
        try:
            query = input("\nYou: ").strip()
            if query.lower() in ("exit", "quit", "q"):
                break
            if query:
                answer = agent.answer_query(query)
                print(f"Agent: {answer}")
        except (KeyboardInterrupt, EOFError):
            break

    db.close()
    print("\n[*] Session ended.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Drone Security Analyst Agent")
    parser.add_argument("--mode", choices=["demo", "interactive"], default="demo",
                        help="Run mode: demo (default) or interactive Q&A")
    parser.add_argument("--llm", action="store_true",
                        help="Use LLM API for enhanced analysis (requires OPENAI_API_KEY or ANTHROPIC_API_KEY)")
    args = parser.parse_args()

    import os
    os.makedirs("data", exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    if args.mode == "interactive":
        run_interactive(use_llm=args.llm)
    else:
        run_demo(use_llm=args.llm)
