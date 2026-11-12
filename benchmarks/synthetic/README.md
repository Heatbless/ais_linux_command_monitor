# Synthetic contextual benchmark

All events are generated examples from `ais.demo.document(host="demo-host")`.
No personal Bash history, filtered history, real session recordings or models
trained from those histories were used to create these files. The command
catalogue is separate reference material and is not used as normal training.

| Partition | Workflows | Events |
|---|---:|---:|
| Normal training | 6 | 72 |
| Normal calibration | 6 | 72 |
| Evaluation | 25 | 157 |

Evaluation comprises seven normal scenarios, 17 unusual scenarios and one
same-command-names/different-intent control. Sources include supplied execution,
shell and authentication examples; they are not real sensor recordings.

Files:

- `synthetic-workflows.json`: all workflows with explicit partitions and synthetic markers.
- `evaluation-events.jsonl`: only evaluation input events.
- `results.json`: per-scenario checks, scoring availability and provenance.
- `assessments.jsonl`: sanitized reference detector outputs, with scenario IDs.
- `REPORT.md`: generated readable scenario report.
- `manifest.json`: generation settings and checksums.

Reproduce from the repository root:

```sh
uv run python -m ais demo --host demo-host \
  --output private-data/demo --report private-data/demo/REPORT.md
uv run python -m ais score \
  --model private-data/demo/model.json \
  --input benchmarks/synthetic/evaluation-events.jsonl \
  --config examples/contextual-config.json
```

Or train directly from the released workflows:

```sh
uv run python -m ais train benchmarks/synthetic/synthetic-workflows.json \
  --allow-synthetic --output private-data/synthetic-model.json
```

The trainer uses only explicitly normal training/calibration partitions;
evaluation events never enter fitting. `approved_by: demo_fixture` is fixture
authorization, not an operator's approval of genuine normal activity. Model
artifacts are generated locally and are not included in this release.

All 25 expected scenario checks pass. Only eight scenarios support learned
AIS/Markov scoring; 17 lack sufficient successful context or window length.
Across 26 scorable windows, five exceed each learned threshold. The replay
contains 47 warning-bearing assessments, including independent policy rules.
This is not 47 AIS detections or an operational accuracy estimate. Current
synthetic calibration scores are constant and thresholds are zero. The small,
constructed fixture does not establish generalization or superiority to Markov.

The generated examples include sensitive command strings, but none are run by
replay or training. Treat them as dataset contents, not instructions to execute.
