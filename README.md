# AIS Linux command monitor

Experimental Linux command monitoring using variable-radius negative selection,
contextual attention rules and an independent first-order Markov baseline.
Includes a local Bash/Zsh collector and a durable sender for a compatible
monitoring server. Python execution produces a review warning independently of
learned normality.

This repository contains implementation code, tests, a [command reference catalogue](commands/README.md),
a [synthetic benchmark](benchmarks/synthetic/README.md), generic examples and
synthetic-data generation code. Personal histories, downloaded external datasets,
trained models, credentials, server addresses, the paper and the separate
dashboard implementation are excluded. Neither Bash history nor data derived
from personal histories is included in the published benchmark.

## Setup and synthetic demonstration

Requires Linux/WSL, Python 3.12+ and uv.

```sh
uv sync --locked
uv run python -m ais demo --host demo-host \
  --output private-data/demo --report private-data/demo/report.md
uv run python -m ais score \
  --model private-data/demo/model.json \
  --input private-data/demo/evaluation-events.jsonl \
  --config examples/contextual-config.json
```

The generator creates separate synthetic normal training/calibration workflows
and evaluation scenarios. It executes none of the example commands. These are
correctness fixtures, not evidence of operational attack-detection accuracy.
The default examples in `examples/synthetic-events.jsonl` use `demo-vm` and a
different boot identity; use the generated evaluation file with its matching
model as above.

## Live local monitoring

In terminal 1:

```sh
uv run python -m ais monitor \
  --model private-data/demo/model.json \
  --config examples/contextual-config.json \
  --host demo-host
```

After the receiver reports ready, enable the hook in terminal 2 from this
project directory:

```sh
# Select the shell actually running in this terminal:
source <(uv run python -m ais hook bash)
# For Zsh, use: source <(uv run python -m ais hook zsh)
```

Run `python3 -c 'print("AIS test")'` to produce Python attention. Sanitized
assessments appear in terminal 1. The collector uses a private Linux directory
at `/tmp/ais-live-UID`, where UID is your numeric user ID. Supply `--state-dir`
and the hook's `--socket` option to select persistent private Linux storage.

The hook observes command intentions in participating shells, not confirmed
machine-wide executions. Unhooked terminals, internal script commands, cron,
services and other users are outside scope. Dynamic/compound syntax can reduce
visibility; rejected observations increment loss counters. Same-user attackers
can disable or forge hook observations. This is a demonstration collector, not
a security boundary. Healthy receiver status does not prove all hooks remain
installed. Remove hooks with `trap - DEBUG` in Bash or
`add-zsh-hook -d preexec _ais_preexec` in Zsh, then stop the monitor with Ctrl+C.

The synthetic model has execution-source profiles. New live shell/account
profiles report `no_profile` until approved matching normal workflows are
trained. Rules still warn. No automatic live learning occurs.

## Train AIS

Use the structure in `examples/workflows-template.json`. Each normal workflow
needs explicit approval, its actual host/account/source context and a partition
of `train` or `calibration`. Keep evaluation sessions separate. Each fitting
profile requires ten-event windows in separate normal sessions for training
and calibration. Do not treat a reference vocabulary or attack fixture as normal.

```sh
uv run python -m ais train YOUR_APPROVED_WORKFLOWS.json \
  --output private-data/model.json
```

Training maps ten-command windows to bounded features and samples 1,024
candidate detector centers. Each radius is its nearest normal-vector distance
minus 0.02. Up to 256 positive-radius detectors are retained after checking
normal-sample exclusion. Separate normal calibration sessions set an empirical
99th-percentile threshold, with a strict greater-than alert comparison.

AIS scores are not attack probabilities. Markov scores are a separately
calibrated transition baseline; their numerical scale is not directly comparable
to AIS. Missing profiles/features or short sequences mean not assessed, not
normal. The fixed-budget detector does not certify nonself coverage, and small
synthetic calibration sets cannot establish future false-alert rates.

## Optional monitoring server delivery

The compatible ingestion server is a separate project. Provision an agent
whose registered host exactly matches the detector's `--host`. Store its token
in a private mode-600 file on a Linux filesystem. Then add these options to
`monitor`:

```text
--server-url https://YOUR_INGEST_HOST
--token-file /YOUR_PRIVATE_LINUX_PATH/agent.token
```

The copied v1 contracts in `ais/contracts.py` define run registration,
assessments and heartbeats. The sender uploads sanitized assessments, not raw
command lines, histories or model files. A private SQLite outbox preserves
retry identities across restarts. Heartbeats run independently every 30 seconds.
For HTTP over an existing Tailscale route, `--allow-tailscale-http` explicitly
permits only a literal address in `100.64.0.0/10`; it does not create or verify
that route. HTTPS certificate checks remain enabled by default.

## Validation and historical experiments

```sh
uv run python -m pytest -q
uv run ruff check ais experiments tests
```

The `experiments/` package retains earlier history/dataset experiments and
bounded external fetchers. Their private inputs are not included. Historical
categorical models differ from the current contextual numerical model and
must not be presented as the same algorithm's validation. Dataset fetchers
retain source URLs and integrity checks; check each source's license and
attribution requirements before redistribution. No dataset contents are run
as shell commands.

The current contextual synthetic evaluation contains 25 scenarios and 157
events, with 72 normal training and 72 normal calibration events. Only eight
evaluation scenarios support learned scoring. Real operational reliability
and superiority over Markov have not been established.
