# Legacy History Compatibility for MCR Core v0.1

## Conclusion

MCR Core v0.1 should ship one read-only legacy codec. It must load accepted JSONL histories without rewriting them, preserve every original event and payload, reduce only facts that satisfy Core's invariants, and retain the rest as Opaque Facts. A fully sealed valid chain is cryptographically verifiable; a fully unsealed history is structurally replayable but must be reported as `unsealed`, never as hash-valid. Partially sealed or hash-invalid histories are invalid and must not be repaired in place.

`state.json` is a non-authoritative legacy cache. Event IDs and all fact IDs are workspace-local opaque strings: they must be preserved, not parsed, inferred, or renumbered.

All source references below are repository-relative paths in
`Notyet1307/agent-lab`.

## Source set

- All cited tracked Agent-lab sources were inspected at commit
  `eab6efdbd8e299262617361aa615890e3fa6102e`. The two untracked local
  customer-evaluation directories were excluded.
- Accepted-state ledger: `docs/project_state.md:1-17,1135-1158`.
- Accepted static histories/caches: `examples/exposure_governance_case_001/.mcr/events.jsonl:1-65`, `examples/exposure_governance_case_001/.mcr/state.json:1-798`, `examples/alert_triage_case_001/.mcr/events.jsonl:1-12`, and `examples/alert_triage_case_001/.mcr/state.json:1-159`.
- Accepted sealed result: `examples/exposure_governance_case_001/.mcr/audit/verify_result.json:1-14` and `examples/exposure_governance_case_001/.mcr/audit/verify_report.md:1-16`.
- Implementation: `mcr-cli/types.go:15-23,486-504`; `mcr-cli/main.go:3423-3531`; `mcr-cli/state.go:13-148`; `mcr-cli/audit.go:163-265`.
- Tests: `mcr-cli/main_test.go:2373-2405,2502-2575`; `mcr-cli/serve_test.go:1572-1609,1790-1833`.
- Later accepted forms: `docs/adr/0002-generic-input-registered-event.md:1-5`; `docs/project_state.md:1176-1193`.

Excluded: real-customer evaluation directories, archived histories, untracked workspaces, and customer data.

## Observed forms

### Event envelope and JSONL

The legacy log is one JSON object per non-empty line. The decoded envelope is:

```text
event_id, event_type, timestamp, actor { type, id },
optional prev_hash, optional event_hash, payload
```

The reader skips empty lines, rejects malformed JSON, and otherwise decodes through a typed Event with `payload` retained as raw JSON (`mcr-cli/main.go:3423-3446`; `mcr-cli/types.go:15-23`). Accepted timestamps are RFC3339 UTC; accepted actors use `human` or `executor`, but remain opaque because Core does not authenticate them.

The two accepted static logs intentionally differ:

- Exposure governance has 65 events, `evt_001` through `evt_065`, all with both hash fields (`examples/exposure_governance_case_001/.mcr/events.jsonl:1-65`). Its tracked result reports complete fields and a valid chain (`examples/exposure_governance_case_001/.mcr/audit/verify_result.json:2-10`).
- Alert triage has 12 events, `evt_001` through `evt_012`, with neither hash field (`examples/alert_triage_case_001/.mcr/events.jsonl:1-12`). It is accepted, not corrupt; the ledger freezes counts at 65/12 (`docs/project_state.md:1165-1169`).

### Payload families

The accepted static logs contain fourteen Event types. Their payloads evolved
additively, so a compatibility codec cannot select one rigid payload version.

| Event family | Observed payload form and Core relevance | Evidence |
|---|---|---|
| `McrInitialized` | `workspace`, `workspace_id`; identifies the ledger boundary. | `examples/exposure_governance_case_001/.mcr/events.jsonl:1` |
| `TaskCreated` | Initial task contract. The early form has task fields only; the Pack form adds `pack_*`, paths, plans, and output templates. `status` is adapter data, not a Core lifecycle. | `examples/exposure_governance_case_001/.mcr/events.jsonl:2,16` |
| `RunStarted`, `RunCompleted` | Start is a small observation; completion adds timestamps, workspace, logs, outputs, prompt, mode, and role. Core can retain a Run observation while treating runtime detail as opaque. | `examples/exposure_governance_case_001/.mcr/events.jsonl:3-4,17-18,36-37` |
| `ArtifactAdded` | `artifact_id`, task/run references, kind, path, content hash, producer, time; later versions add version/replacement/review fields. | `examples/exposure_governance_case_001/.mcr/events.jsonl:5-6,19-20,38` |
| `EvidenceLinked` | Nested Claim and Evidence records; the source carries path, anchor, and hash. | `mcr-cli/types.go:166-196`; `examples/exposure_governance_case_001/.mcr/events.jsonl:7-8` |
| `ReviewSubmitted` | Legacy records bind only a task, reviewer, verdict, findings, and time. The type now has optional difference-artifact ID/hash fields, but the frozen events do not carry them. | `mcr-cli/types.go:241-252`; `examples/exposure_governance_case_001/.mcr/events.jsonl:9,35,53` |
| `ApprovalGranted` | Legacy records have task, actor, decision, scope, note, and time. Only newer report approvals can add an exact report fingerprint. | `mcr-cli/types.go:254-263`; `examples/exposure_governance_case_001/.mcr/events.jsonl:10,54,60` |
| `DeliveryRecorded` | Legacy path/format record, optionally with HTML and manifest paths; it does not enumerate exact Artifact versions, target, or delivery scope. | `mcr-cli/types.go:299-307`; `examples/exposure_governance_case_001/.mcr/events.jsonl:11,55` |
| `HerdrSessionPrepared`, `RunLogCaptured` | Nested Herdr session, pane, log, and Run data. These are runtime-specific and outside Core semantics. | `mcr-cli/types.go:92-137`; `examples/exposure_governance_case_001/.mcr/events.jsonl:14-15` |
| `CapabilityGranted`, `ToolCallRecorded` | Capability and execution/tool details. They are policy/runtime extensions, not Core authorization or Run semantics. | `mcr-cli/types.go:347-380`; `examples/exposure_governance_case_001/.mcr/events.jsonl:56-58,62-63,65` |
| `PolicyDecisionRecorded` | Task/run/method/result/rule and optional approval reference. It has no exact tool-call reference or input hash, so frozen records do not identify the exact evaluated action. | `mcr-cli/types.go:404-415`; `examples/exposure_governance_case_001/.mcr/events.jsonl:59,61,64` |

Three accepted later forms are absent from the frozen 65/12 logs:

- `InputRegistered` carries input/task IDs, kind, filename, SHA256, row count, field mapping, version, and optional stored path (`mcr-cli/types.go:583-605`). Changed content creates a new `input_NNN` version; identical content is idempotent (`mcr-cli/input_test.go:294-325,359-396`).
- `NarrativeDraftReviewed` binds task, exact Artifact ID/hash, reviewer, decision, and time, so it can reduce to Review (`mcr-cli/types.go:265-273`; `mcr-cli/serve_test.go:1572-1609`).
- `CustomerReportPublished` binds scenario-specific exact references and an audit-result hash. It remains a Customer Report extension (`mcr-cli/types.go:275-288`; `docs/project_state.md:1184-1200`).

### `state.json`

Both caches declare `mcr_version: 0.1.0`, workspace ID/status, ID-keyed maps, and `last_event_id`. Exposure has capability/tool/policy maps; alert omits those empty maps (`examples/exposure_governance_case_001/.mcr/state.json:1-5,658-797`; `examples/alert_triage_case_001/.mcr/state.json:1-5,125-158`). Absence means empty.

The log is authoritative: `readWorkspaceView` derives from events and never reads `state.json` (`mcr-cli/main.go:483-495`). The old reducer replaces Runs from Herdr/log events, stores capability/tool maps, and changes status only for hard-coded task IDs (`mcr-cli/state.go:9-11,65-74,85-128`). Thus `task_001` remains `created`, while `task_002/003` become `approved` (`examples/exposure_governance_case_001/.mcr/state.json:6-58`; `examples/alert_triage_case_001/.mcr/state.json:6-33`).

### IDs and hashes

- IDs are local to a Workspace. Both logs start at `evt_001`; both reuse
  `artifact_001`, `evidence_001`, `review_001`, `approval_001`, and
  `delivery_001` (`examples/exposure_governance_case_001/.mcr/events.jsonl:1,5,7,9-11`;
  `examples/alert_triage_case_001/.mcr/events.jsonl:1,5-6,10-12`). Alert triage's
  only Run is `run_005`, proving that a numeric suffix is not an ordinal within
  that Workspace (`examples/alert_triage_case_001/.mcr/state.json:48-61`).
- The writer currently generates `evt_%03d` from event count, but the verifier
  requires only non-empty uniqueness; it does not validate that grammar or
  sequence (`mcr-cli/main.go:3580-3582`; `mcr-cli/audit.go:179-190`). Therefore
  generation policy is not an identity invariant.
- Legacy event-chain, Artifact, and Evidence hashes use
  `sha256:<64 lowercase hex>`. `InputRegistered.sha256` stores the bare 64-hex
  digest (`mcr-cli/audit.go:251-265`; `mcr-cli/input.go:47-50,314-325`). Core may
  normalize these for comparison but must preserve the original spelling.
- The legacy event hash is SHA256 over JSON of
  `event_id,event_type,timestamp,actor,payload`, followed by one newline and the
  previous hash. The first `prev_hash` is
  `sha256:` plus 64 zeroes (`mcr-cli/types.go:478-484`;
  `mcr-cli/audit.go:163-176,211-224,251-253`). This is a legacy Go JSON codec,
  not a published canonical-JSON standard.

## Classification matrix

"Opaque" always means preserve the original record and payload exactly; it
does not mean ignore or discard it.

| Legacy form | Recognize | Core-reduce | Preserve opaquely | Reject |
|---|---:|---:|---:|---:|
| Valid Event envelope and `McrInitialized` | Yes | Workspace bootstrap | Unknown fields | Missing/invalid required envelope |
| `TaskCreated` | Yes | Task initial contract; ignore lifecycle meaning of `status` | Pack/scenario fields | Missing task identity or conflicting reuse within the Workspace |
| `RunStarted` / `RunCompleted` | Yes | Immutable legacy Run observations, optionally grouped by opaque `run_id` | Executor, prompt, status, workspace, logs, Herdr metadata | Missing task/run identity or invalid task reference |
| `ArtifactAdded` | Yes | Artifact when ID, task, locator, and content hash are valid | Kind/producer/version extensions | Invalid hash/reference or conflicting identity |
| `EvidenceLinked` | Yes | Claim + Source Reference + Evidence Link when all bindings exist | Scenario classifications and notes | Broken task/artifact/source binding |
| `InputRegistered` | Yes | Registered Input | Kind, mapping, stored-path details | Invalid hash/reference or conflicting identity |
| `NarrativeDraftReviewed` | Yes | Review because exact Artifact ID/hash is present | Narrative-specific meaning | Broken exact binding |
| `ReviewSubmitted` with exact subject ID/version or hash | Yes | Review | Verdict/findings vocabulary | Broken exact binding |
| Frozen `ReviewSubmitted` without exact subject/version | Yes | No | Entire legacy review | No; accepted but under-bound |
| `ApprovalGranted` with exact subject/fingerprint and scope | Yes | Approval | Scenario decision vocabulary | Broken exact binding |
| Frozen `ApprovalGranted` with task/scope only | Yes | No | Entire legacy approval | No; accepted but under-bound |
| `PolicyDecisionRecorded` without exact action reference | Yes | No | Entire legacy policy decision | No; accepted but under-bound |
| Frozen `DeliveryRecorded` without Artifact versions, target, and scope | Yes | No | Entire legacy delivery | No; accepted but under-bound |
| `HerdrSessionPrepared`, `RunLogCaptured`, `CapabilityGranted`, `ToolCallRecorded`, `CustomerReportPublished`, or an unknown Event type | Yes | No | Entire extension fact | Invalid envelope/hash only; opaque payload references are not interpreted |
| `state.json` | Yes, as optional cache | No facts imported; compare only as a diagnostic | Whole legacy cache if retained | Reject the cache, not the Event history, when stale/malformed |
| Fully sealed, valid chain | Yes | Yes, subject to rows above | Exact source bytes | Hash mismatch, duplicate ID, or malformed hash |
| Fully unsealed history | Yes | Yes, subject to rows above | Exact source bytes | Do not call it hash-valid |
| Mixed/partially sealed history | Diagnose | No | Raw bytes for diagnostics | Yes; never auto-complete |
| Fully sealed but invalid history | Diagnose | No | Raw bytes for diagnostics | Yes; never auto-repair |

The under-bound Review/Approval/Policy/Delivery rows are essential. Upcasting
them by guessing a subject would violate the agreed Core invariant; rejecting
them would break accepted-history compatibility. Opaque preservation is the
only option that satisfies both constraints.

## Recommended v0.1 compatibility contract

1. **Read-only input.** Loading, replaying, verifying, or comparing a legacy
   Workspace must not write `events.jsonl`, `state.json`, audit output, or any
   adjacent file. The old mutating verifier seals an all-unsealed log in place
   (`mcr-cli/audit.go:13-45`); Core must not copy that behavior.
2. **Events are the source.** Require exactly one usable `McrInitialized` as
   the first Event and derive a fresh Core projection from ordered Event
   records. Treat manifest and `state.json` workspace/last-event fields as
   consistency diagnostics only.
3. **Opaque, workspace-local identity.** Key all Event and fact identities by
   `(workspace_id, local_id)`. Require non-empty IDs and unique Event IDs within
   a Workspace, but do not parse prefixes, numeric widths, or sequence and do
   not generate replacements.
4. **Exact preservation.** Retain every raw JSONL record and raw payload,
   including unknown fields and unknown Event types. Typed decoding is a view
   over the preserved bytes, not a replacement serialization.
5. **Conditional typed reduction.** Reduce a recognized legacy record only
   when it contains the IDs, task/workspace scope, exact subject/version, and
   hashes required by the relevant Core concept. Otherwise emit an Opaque Fact
   with a diagnostic such as `legacy_underbound`, not a guessed Core fact.
6. **No legacy workflow projection in Core.** Do not port hard-coded task
   status transitions, Herdr/log state replacement, capability grants, or
   tool-call projections. Core exposes deterministic fact views, not the old
   product workflow state.
7. **Validate structure before hashes.** Reject malformed required envelope
   fields, duplicate Event IDs within a Workspace, and invalid references in
   recognized facts before assigning a hash-integrity outcome. This applies to
   sealed and unsealed histories alike.
8. **Four hash-integrity outcomes.** For a structurally valid history, report
   exactly:
   - `sealed_valid`: every Event has both hashes and the chain verifies;
   - `unsealed`: no Event has either hash; structural replay is allowed, but
     there is no cryptographic integrity claim;
   - `partial_invalid`: any mixture, or either field missing on any Event;
   - `sealed_invalid`: complete fields but malformed hashes, wrong
     `prev_hash`, or wrong `event_hash`.
9. **No projection from invalid integrity states.** `partial_invalid` and
   `sealed_invalid` may return diagnostics and preserved bytes, but must not
   produce an accepted Core projection or allow appends. The existing append
   path already rejects partial and invalid sealed histories
   (`mcr-cli/main.go:3477-3504`), and the tests cover invalid-chain rejection
   (`mcr-cli/main_test.go:2558-2574`).
10. **State-cache mismatch is non-destructive.** Missing, malformed, or stale
   `state.json` invalidates that cache only. Never rewrite it during legacy
   load; return a mismatch diagnostic if a consumer asks for comparison.

Acceptance examples for the later implementation are therefore simple:

- exposure history loads byte-for-byte unchanged as `sealed_valid`, verifies
  through `evt_065`, and produces a deterministic Core projection plus opaque
  extensions;
- alert history loads byte-for-byte unchanged as `unsealed`, structurally
  replays through `evt_012`, and makes no hash-valid claim;
- a partially hashed or tampered copy is rejected without any repair; and
- deleting or corrupting only `state.json` does not change Event replay.

## Prototype decision

No prototype is needed. The two accepted static logs already supply both valid
compatibility modes, the tracked audit result supplies a sealed golden outcome,
and existing tests exercise sealing, sealed append continuation, legacy
unsealed append, and invalid-chain rejection
(`mcr-cli/main_test.go:2373-2405,2502-2575`). A throwaway parser would merely
repeat known behavior. The implementation phase should start with golden
read-only tests against these exact histories and the contract above.

## Risks and open edges

- **Legacy hash portability.** The hash input depends on Go's JSON encoding and
  field order, not a formal canonical-JSON spec. Cross-language ports need
  golden vectors; v0.1 should keep one small compatibility codec rather than
  redefine the hash.
- **Unsealed does not mean trustworthy.** Alert triage can be replayed, but its
  contents are not tamper-evident. UI/API wording must not collapse
  `structurally replayed` into `audit verified`.
- **Unknown envelope fields are not hash-covered.** The legacy hash core lists
  only five fields (`mcr-cli/types.go:478-484`). Preserve any extra envelope
  fields, but mark them unauthenticated under the legacy chain.
- **Under-bound governance events.** Frozen Review, Approval, Policy Decision,
  and Delivery payloads cannot satisfy modern exact-subject invariants. They
  remain Opaque Facts permanently; adding guessed links later would be a
  history migration.
- **Hash spelling differs by payload family.** Bare input digests and prefixed
  Event/Artifact digests need one internal comparison representation without
  rewriting source values.
- **State parity is intentionally limited.** A Core projection will not
  reproduce adapter-specific task statuses, Herdr fields, capability maps, or
  Customer Report state. Consumers needing the old product view must keep that
  projection in the adapter, outside MCR Core.
