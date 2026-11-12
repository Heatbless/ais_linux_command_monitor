# Command reference catalogue

This folder contains 15 categorized reference files with 730 command-example
lines. It is a vocabulary reference, not a recorded user session, a Bash history,
a malicious-command blacklist, or an approved normal training dataset. File
order must not be interpreted as chronological activity.

Entries include ordinary commands and sensitive administration. Familiarity
does not establish that a command is safe or normal for an account. Credential-
like literals such as `API_KEY=abc123`, `mypass`, and `me@example.com` are
illustrative placeholders. The examples are data, not batch scripts to execute.

Import recognized vocabulary with:

```sh
uv run python -m ais catalogue --directory commands
```

Or use it as optional recognition context while scoring:

```sh
uv run python -m ais score \
  --model private-data/demo/model.json \
  --input benchmarks/synthetic/evaluation-events.jsonl \
  --reference-dir commands
```

This sets recognition metadata; it does not fit normality, suppress Python
attention, or approve catalogue entries as normal. The published synthetic
benchmark was generated separately and does not train on catalogue-file order.
