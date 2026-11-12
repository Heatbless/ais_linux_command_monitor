# Contextual monitoring demonstration

This is a deterministic synthetic correctness demonstration, not a reliability benchmark or evidence of real attack detection. Normal training/calibration workflows are separate from evaluation scenarios. The reference command catalogue is not normal training data.

Profiles: 3. Expected rule checks passed: True.

| Scenario | Synthetic label | AIS alert | Markov baseline alert | Rules | Checks |
|---|---|---|---|---|---|
| normal_developer | normal | False | False | python_attention | True |
| normal_admin | normal | False | False | none | True |
| normal_backup | normal | False | False | none | True |
| normal_service | normal | False | False | none | True |
| normal_service_worker | normal | False | False | python_attention | True |
| normal_fast_automation | normal | False | False | none | True |
| service_orientation | unusual | not scored | not scored | orientation_burst | True |
| service_shell | unusual | not scored | not scored | python_attention, service_interpreter, shell_stabilization | True |
| host_discovery | unusual | not scored | not scored | discovery_burst | True |
| delivery_cleanup | unusual | not scored | not scored | delivery_cleanup, delivery_execution | True |
| compile_elevation | unusual | not scored | not scored | compile_execute | True |
| persistence | unusual | not scored | not scored | persistence_chain | True |
| credential_read | unusual | not scored | not scored | credential_read | True |
| credential_tool | unusual | not scored | not scored | credential_tool_context | True |
| account_persistence | unusual | not scored | not scored | account_change_chain | True |
| security_tamper | unusual | not scored | not scored | monitor_tamper, security_disabled | True |
| lateral | unusual | not scored | not scored | outgoing_remote_burst | True |
| collection | unusual | not scored | not scored | collection_transfer | True |
| impact | unusual | not scored | not scored | bulk_crypto_chain | True |
| device_overwrite | unusual | not scored | not scored | destructive_device_write | True |
| history_controls | unusual | not scored | not scored | history_cleared, history_setting_changed | True |
| auth_failures | unusual | not scored | not scored | repeated_auth_failure | True |
| same_names_different_intent | intent_control | False | False | python_attention | True |
| post_compromise_session | unusual | True | True | behavioral_anomaly, delivery_cleanup, delivery_execution, orientation_burst, outgoing_remote_burst, rapid_distinct_commands | True |
| relative_program_alone | normal | not scored | not scored | none | True |

The always-warn Python policy is intentional attention during normal developer work; it is not counted as evidence that AIS detected malicious intent. The same-name/different-intent control illustrates that command names cannot reveal changed arguments or purpose.

Burst thresholds and stage correlations are configurable hypotheses. Legitimate administration can trigger them. Unknown context is never replaced with fabricated timestamps, roles or source IPs. Shell history-control cases explicitly require shell telemetry; raw exec auditing cannot observe built-ins.

The local and VPS history experiments remain unvalidated. This new layer has not been trained on raw histories with invented roles/timing or tuned using Cowrie/AIT outcomes. Live audit recordings from the intended account remain necessary.

Run `uv run python -m ais demo`. See [usage and schema](../contextual-monitoring.md).
