"""Replay integration with the copied server-v1 adapter; no live-health claims."""

import asyncio
import json
import stat
import sys
import time
from pathlib import Path

from ais.sender import Outbox, Sender


def read_token(path):
    path = Path(path)
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("Token file must be private (chmod 600)")
    token = path.read_text().strip()
    if not token or len(token) > 4096 or any(c.isspace() for c in token):
        raise ValueError("Invalid credential file")
    return token


async def replay(assessments, destination, model, args, sender_factory=Sender):
    """Process a finite file; delivery and heartbeats run independently.

    The run stays explicitly replay/demo. EOF reports collector stopped. A
    finite linger permits dashboard inspection without pretending collection
    continues. Unacknowledged records remain on disk and yield exit code 3.
    """
    token = read_token(args.token_file)
    outbox = Outbox(args.outbox)
    run = outbox.new_run(args.transport_boot_id, mode=args.transport_mode)
    sender = sender_factory(
        outbox, args.server_url, token, allow_tailscale_http=args.allow_tailscale_http
    )
    stop = asyncio.Event()
    collector = {
        "mode": "replay",
        "state": "healthy",
        "last_successful_poll": None,
        "last_observed_event": None,
        "collected": 0,
        "lost": 0,
    }

    def health():
        return {
            "collector": dict(collector),
            "detector": {
                "state": "running",
                "model_version": model.version,
                "profile_count": len(model.profiles),
                "experimental": True,
                "deployment_ready": False,
            },
        }

    task = asyncio.create_task(sender.supervise(run, health, stop))
    try:
        for assessment in assessments:
            if task.done():
                await task
            if assessment["host"] != args.expected_host:
                raise ValueError("Assessment host differs from registered host")
            if assessment["boot_id"] != args.transport_boot_id:
                raise ValueError("Assessment boot differs from run")
            collector["last_successful_poll"] = time.time()
            collector["last_observed_event"] = assessment["timestamp"]
            collector["collected"] += 1
            record_id = sender.enqueue(assessment, run.run_id)
            if record_id is None and assessment["status"] != "duplicate":
                raise ValueError("Assessment rejected by transport contract")
            destination.write(json.dumps(assessment, allow_nan=False) + "\n")
            destination.flush()
            # Enqueue on the supervisor's loop so wakeups are thread safe.
            await asyncio.sleep(0)
        collector["state"] = "stopped"
        # Keep the supervisor active for flushing and a final health report.
        done, _ = await asyncio.wait({task}, timeout=args.transport_linger)
        if done:
            await task
    finally:
        collector["state"] = "stopped"
        stop.set()
        if sender._wake:
            sender._wake.set()
        try:
            await task
        finally:
            sender.client.close()
    status = outbox.health()
    print(json.dumps({"transport_mode": run.mode, "delivery": status}), file=sys.stderr)
    return 0 if status["queue_depth"] == 0 and status["state"] == "healthy" else 3
