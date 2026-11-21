# Test Suite Verification Report

- **Test Suite**: `tests/test_wrap_m2.py`
- **Total Tests**: 21
- **Passed**: 21 (100%)
- **Failed**: 0
- **Duration**: 0.23 seconds

## Test Breakdown

1. `test_effective_annotations_defaults`: Verifies safety annotation defaults match MCP spec when unspecified (`readOnlyHint=false`, `destructiveHint=true`, `idempotentHint=false`, `openWorldHint=true`).
2. `test_annotation_relaxation_and_escalation`: Verifies bidirectional annotation diffing: relaxation flagged `HIGH`/`would_block=True`; escalation flagged `HIGH`/`would_block=True`.
3. `test_schema_constraint_relaxation`: Verifies required property removal, enum widening, pattern regex removal, and maxLength loosening.
4. `test_tool_rename_detection`: Verifies that identical schema and annotations under a new name are classified as a rename (`DRIFT_REMOVAL_OR_RENAME`, `is_rename=True`, `MEDIUM`).
5. `test_prompt_injection_heuristics`: Verifies instruction override, role hijacking, and fake system tags are detected in instructions and tool descriptions.
6. `test_non_fingerprintable_probe_ids`: Verifies probe IDs mimic client style (high int vs hex) without fixed markers and exclude active client IDs.
7. `test_single_serialized_writer_with_1mb_streaming`: Verifies synthetic probe injected during 1 MB streaming client message causes zero byte splicing or interleaving.
8. `test_active_reverify_catches_covert_drift`: Verifies probe triggered on tool call catches covert injection and drops probe response from client stdout.
9. `test_paginated_manifest_aggregation`: Verifies proxy follows `nextCursor` until exhausted and establishes complete aggregated baseline.
10. `test_cross_session_drift_and_untrusted_isolation`: Verifies append-only `manifest_history` in SQLite isolates high-drift sessions as untrusted.
11. `test_probe_error_handling_graceful`: Verifies server returning error on synthetic `tools/list` is logged as `INFO` and ignored without client disruption.
12. `test_stderr_alert_safety`: Verifies high-severity drift warnings print exclusively to stderr while stdout remains empty for JSON-RPC transport.
13. `test_heuristics_false_positive_corpus`: Verifies 82 real descriptions from `server-everything`, `filesystem`, `git`, `fetch`, and `vps-mcp` produce 0 false positives.
14. `test_instructions_drift_with_and_without_injection`: Verifies instruction mutation without injection is `MEDIUM`/`observed`/non-blocking, while with injection is `HIGH`/`correlated`/`would_block`.
15. `test_probe_coalescing`: Verifies at most 1 probe in flight and minimum 10-second cooldown interval between probes.
16. `test_probes_never_delay_client_forwarding`: Verifies client messages enqueued behind active probes forward immediately (< 5 ms latency).
17. `test_client_pagination_timeout_finalizes_partial`: Verifies 50ms timeout finalizes baseline with `is_partial=True` when client abandons pagination.
18. `test_additive_version_bump_cross_session_medium`: Verifies additive tool additions under version bumps yield `SEVERITY_MEDIUM` and `would_block=False`.
19. `test_e2e_id_safety_string_client`: Verifies client UUID format is detected and matched by probe generator without collision.
20. `test_late_probe_response_dropped`: Verifies late probe response arriving within 600s window is dropped and never forwarded to client stdout.
21. `test_schema_capability_expansion_and_constraint_relaxation`: Verifies `additionalProperties` relaxation, loosened `minimum`, loosened `maximum`, and removed `format`.
