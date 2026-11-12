# AIS monitoring server prototype

This is the `monitoring-server` branch of `Heatbless/ais_linux_command_monitor`. The `main` branch contains the detector app; this branch contains the central monitoring server and sender adapter.

Implementation of the v1 scope in [SERVER_PLAN.md](SERVER_PLAN.md). This checkout originally contained only that document. The referenced detector (`ais/engine.py`, `ais/events.py`, `ais/cli.py`), detector tests and synthetic event stream were **not supplied**. The transport demonstration uses handoff-derived fixtures, not real detector output. Nested score/quality shapes must be reconciled with actual engine fixtures before integration; do not treat this prototype as deployment-ready.

## Local use

Requires Python 3.12+. Install into a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
.venv/bin/python -m ais.server.demo
```

Generate independent server/operator secrets into a private environment file, load it, and provision an agent:

```sh
umask 077
.venv/bin/ais-server secrets > .env
set -a
. ./.env
set +a
.venv/bin/ais-server register 'My VM' vm-01
.venv/bin/ais-server serve
```

The server binds `127.0.0.1:8000`, with one worker and access logs disabled. Open that URL and sign in with `AIS_OPERATOR_TOKEN`. For a remote server, use `ssh -L 8000:127.0.0.1:8000 your-server`, then open the same local URL. The operator origin must exactly match the browser origin. Tokens never authorize dashboard access. Dashboard sessions expire after eight hours; sign in again to refresh the CSRF token.

To also accept connections from your Tailscale network, with the same environment
and database as your normal launch, run:

```sh
.venv/bin/ais-server serve --tailscale
```

This detects the machine's Tailscale IPv4 address and binds both that address and
`127.0.0.1` on port 8000. Visit `http://TAILSCALE-IP:8000` from an authorized
Tailscale device. The detected IP is added to the host and browser-origin
allowlists; operator login, session and CSRF checks still apply. HTTP here travels
inside Tailscale's encrypted connection. No public-interface listener is added.
Tailscale must be running before startup; restart the app if its Tailscale IP
changes. You can supply a specific address with `--tailscale 100.x.y.z`, or set
`AIS_TAILSCALE_IP=auto` in the launch environment. An existing HTTPS operator origin
requires an HTTPS proxy instead, preserving Secure session cookies.

`ais-server --database PATH rotate AGENT_ID`, `disable AGENT_ID` and `backup DESTINATION` provide operator maintenance. Registration and rotation print an agent secret once; keep it in a mode-0600 file. Backups use SQLite's backup API. Store the database in a mode-0700 directory; the CLI sets umask 077.

The dashboard's Detection log is a table of sanitized activity, with observation
or receipt time, host/account, program/source, detector status, AIS score/threshold,
separate Markov comparison, warning reasons and expandable event details. Red and
amber rows indicate explicit AIS flags, warning severity or failed execution;
purple indicates a separate Markov comparison flag. Text labels accompany colors.
Warm-up, missing profiles/features and missing decisions remain unassessed.
The display uses explicit detector alert decisions, not a guessed threshold
direction. A policy warning can highlight an event even without an AIS score.
The flagged-only filter applies to loaded activity; older activity is paginated.
Frontend display checks can be run with `node --test tests/dashboard.test.cjs`.

## Transport integration

`Outbox.new_run()` creates a fresh process run; `Sender.register(run)` registers it. Pass already sanitized `Engine.process()` results to `Sender.enqueue(assessment, run.run_id)`. The explicit mapper drops unlisted top-level fields; nested contracts reject extras. Invalid mappings retain only a generated record ID, static error code and rejection time, never the payload. Inspect `Outbox.health()` to surface persistent faults. A duplicate assessment is omitted.

`Sender.supervise(run, health_provider, stop_event)` runs independent delivery and heartbeat loops. A health provider must supply `collector` and `detector` dictionaries backed by actual supervision, including successful poll evidence for live collectors. Do not label quiet stdin healthy. Run enqueue from the same asyncio loop for immediate warning/size-triggered wakeups. Collector checkpoints have their own persistence API and must be advanced according to collector semantics, independently of HTTP acknowledgement. Queued envelopes retain origin run IDs across restarts; previously registered retired runs can still deliver. Use HTTPS with certificate verification; injected HTTP clients are reserved for local tests.

Temporary network/capacity failures retain records and use jittered backoff. HTTP 401 pauses delivery until `credentials()` supplies corrected credentials. HTTP 409/413/422 quarantines a batch with bounded rejection metadata; inspect and correct configuration before resuming normal operation. Queue loss and rejections remain visible after reconnect. There is no automatic clearing of loss history. The server retains dedup receipts for 90 days, so retries beyond that boundary can be stored again.

## Deployment and remaining acceptance

Review the examples in `deploy/`; they are not installed or activated. Configure an explicit ingest hostname, real TLS certificate, private database volume and service user. The TLS proxy exposes only the three POST ingestion routes; dashboard and operator routes are reached through the SSH tunnel. No VPS settings were changed.

The suite uses temporary databases and controlled clocks for ingestion, grouping, authentication, heartbeat expiry, outbox persistence, retention and backup. The demo asserts three delivered assessments, one grouped warning, replay heartbeat, a demo-labeled run and dashboard access, without executing listed programs. Model training/activation, learning controls, remote execution, notifications and automatic blocking are unavailable.

Pending supplied detector source: validate every actual output variant, run its existing suite before/after integration, connect its demo stream, and build the replay CLI adapter around its real interfaces. Pending a real VM: live collection/checkpoint integration, representative normal audit recordings, and agent termination, collector failure and network interruption demonstrations. Replay results establish no live collector capability or model accuracy.
