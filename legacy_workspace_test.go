package mcr_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	mcr "github.com/Notyet1307/MCR-Core"
)

const firstLegacyEventHash = "sha256:a248bf58a7d763bd2030429a5af3bd8f78bf97a9af700055804f153886abc255"

func TestSealedLegacyVerifyUsesLiteralHashVector(t *testing.T) {
	workspacePath := copyLegacyWorkspace(t)
	workspace, err := mcr.Open(workspacePath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	verification, err := workspace.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	assertJSONGolden(t, "testdata/legacy/sealed-valid.verify.json", verification)

	ledger, err := os.ReadFile(filepath.Join(workspacePath, ".mcr", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var first struct {
		PrevHash  string `json:"prev_hash"`
		EventHash string `json:"event_hash"`
	}
	if err := json.Unmarshal(bytes.SplitN(ledger, []byte{'\n'}, 2)[0], &first); err != nil {
		t.Fatal(err)
	}
	if first.PrevHash != "sha256:0000000000000000000000000000000000000000000000000000000000000000" || first.EventHash != firstLegacyEventHash {
		t.Fatalf("literal hash vector mismatch: %#v", first)
	}

	var vectors []struct {
		EventID        string `json:"event_id"`
		PreviousHash   string `json:"previous_hash"`
		ExpectedDigest string `json:"expected_digest"`
	}
	readJSONFile(t, "testdata/hashes/legacy-events.json", &vectors)
	if len(vectors) == 0 || vectors[0].PreviousHash != first.PrevHash || vectors[0].ExpectedDigest != firstLegacyEventHash {
		t.Fatalf("checked-in hash vector does not contain the literal first digest")
	}
}

func TestLegacyHeaderAdditiveNativeFieldDoesNotChangeFormat(t *testing.T) {
	sealed, err := os.ReadFile("testdata/legacy/sealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	headerEnd := bytes.IndexByte(sealed, '\n')
	mutated := append([]byte(nil), sealed[:headerEnd-1]...)
	mutated = append(mutated, []byte(`,"record_type":"ignored-additive"}`)...)
	mutated = append(mutated, '\n')
	mutated = append(mutated, sealed[headerEnd+1:]...)
	workspacePath := writeLegacyWorkspace(t, mutated, []byte(`{"workspace_id":"workspace/opaque","last_event_id":"unknown+extension"}`))
	before := snapshotFiles(t, workspacePath)
	workspace, err := mcr.Open(workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := workspace.Verify()
	if err != nil || verification.Format != "legacy" || verification.Integrity != mcr.IntegritySealedValid {
		t.Fatalf("Verify additive legacy header = %#v, %v", verification, err)
	}
	facts, err := workspace.Query(mcr.FactQuery{})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONGolden(t, "testdata/legacy/sealed-valid.query.json", facts)
	projection, err := workspace.Replay()
	if err != nil {
		t.Fatal(err)
	}
	assertJSONGolden(t, "testdata/legacy/sealed-valid.replay.json", projection)
	if after := snapshotFiles(t, workspacePath); !reflect.DeepEqual(after, before) {
		t.Fatal("legacy files changed")
	}
}

func TestSealedLegacyQueryPreservesTimelineAndExactFilters(t *testing.T) {
	ws, err := mcr.Open(copyLegacyWorkspace(t))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := ws.Query(mcr.FactQuery{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	assertJSONGolden(t, "testdata/legacy/sealed-valid.query.json", facts)
	if !bytes.Contains(facts[0].Payload, []byte(`"additive":"visible"`)) || !bytes.Contains(facts[2].Payload, []byte(`"additive_review":true`)) {
		t.Fatal("source payload additive fields were not retained")
	}

	matched, err := ws.Query(mcr.FactQuery{FactID: "review?under", TaskID: "task/non-numeric", Kind: mcr.KindOpaqueRecorded})
	if err != nil || len(matched) != 1 || matched[0].FactID != "review?under" {
		t.Fatalf("exact AND query = %#v, %v", matched, err)
	}
	for _, query := range []mcr.FactQuery{
		{FactID: "review"},
		{FactID: "review?under", TaskID: "task"},
		{FactID: "review?under", TaskID: "task/non-numeric", Kind: "ReviewSubmitted"},
	} {
		matched, err = ws.Query(query)
		if err != nil || len(matched) != 0 {
			t.Fatalf("non-exact query %#v unexpectedly matched %#v: %v", query, matched, err)
		}
	}
}

func TestSealedLegacyArtifactRunClaimRequiresExactFactRef(t *testing.T) {
	sealed, err := os.ReadFile("testdata/legacy/sealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(sealed, []byte("\n")), []byte("\n"))
	if len(lines) < 3 {
		t.Fatalf("sealed legacy fixture has %d records, want at least 3", len(lines))
	}
	var run struct {
		EventID   string `json:"event_id"`
		EventHash string `json:"event_hash"`
	}
	if err := json.Unmarshal(lines[2], &run); err != nil {
		t.Fatal(err)
	}

	type artifactEvent struct {
		EventID   string          `json:"event_id"`
		EventType string          `json:"event_type"`
		Timestamp string          `json:"timestamp"`
		Actor     mcr.Actor       `json:"actor"`
		PrevHash  string          `json:"prev_hash"`
		EventHash string          `json:"event_hash"`
		Payload   json.RawMessage `json:"payload"`
	}
	makeLedger := func(t *testing.T, eventID string, payload map[string]any) ([]byte, artifactEvent) {
		t.Helper()
		rawPayload, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		event := artifactEvent{
			EventID:   eventID,
			EventType: "ArtifactAdded",
			Timestamp: "2025-01-02T03:04:05Z",
			Actor:     mcr.Actor{Type: "human", ID: "tester"},
			PrevHash:  run.EventHash,
			Payload:   rawPayload,
		}
		core, err := json.Marshal(struct {
			EventID   string          `json:"event_id"`
			EventType string          `json:"event_type"`
			Timestamp string          `json:"timestamp"`
			Actor     mcr.Actor       `json:"actor"`
			Payload   json.RawMessage `json:"payload"`
		}{event.EventID, event.EventType, event.Timestamp, event.Actor, event.Payload})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(append(append(core, '\n'), event.PrevHash...))
		event.EventHash = "sha256:" + hex.EncodeToString(digest[:])
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		ledger := append(bytes.Join(lines[:3], []byte("\n")), '\n')
		ledger = append(ledger, encoded...)
		return append(ledger, '\n'), event
	}

	content := map[string]any{
		"locator": "out/report.txt",
		"sha256":  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	tests := []struct {
		name           string
		eventID        string
		runSource      map[string]any
		wantOpaque     bool
		invalidHistory bool
	}{
		{name: "run_id only", eventID: "artifact@run-id", runSource: map[string]any{"run_id": "legacy-run"}, wantOpaque: true},
		{name: "run_fact_id only", eventID: "artifact@run-fact-id", runSource: map[string]any{"run_fact_id": run.EventID}, wantOpaque: true},
		{name: "run_record_hash only", eventID: "artifact@run-record-hash", runSource: map[string]any{"run_record_hash": run.EventHash}, wantOpaque: true},
		{name: "complete valid exact flattened binding", eventID: "artifact@valid-run", runSource: map[string]any{"run_fact_id": run.EventID, "run_record_hash": run.EventHash}},
		{name: "complete invalid exact flattened binding", eventID: "artifact@missing-run", runSource: map[string]any{"run_fact_id": "missing-run", "run_record_hash": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}, invalidHistory: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := map[string]any{
				"task_id":           "task/non-numeric",
				"content":           content,
				"additive_artifact": true,
			}
			for key, value := range test.runSource {
				payload[key] = value
			}
			ledger, source := makeLedger(t, test.eventID, payload)
			workspace := writeLegacyWorkspace(t, ledger, []byte("{}\n"))
			ws, err := mcr.Open(workspace)
			if err != nil {
				t.Fatal(err)
			}

			verification, err := ws.Verify()
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if test.invalidHistory {
				if verification.StructuralValid || len(verification.Diagnostics) != 1 || verification.Diagnostics[0].Code != "invalid_payload" {
					t.Fatalf("Verify = %#v, want one invalid_payload diagnostic", verification)
				}
				if _, err := ws.Query(mcr.FactQuery{}); !errors.Is(err, mcr.ErrInvalidHistory) {
					t.Fatalf("Query error = %v, want ErrInvalidHistory", err)
				}
				if _, err := ws.Replay(); !errors.Is(err, mcr.ErrInvalidHistory) {
					t.Fatalf("Replay error = %v, want ErrInvalidHistory", err)
				}
				if _, err := ws.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrInvalidHistory) {
					t.Fatalf("Submit error = %v, want ErrInvalidHistory", err)
				}
				return
			}
			if !verification.StructuralValid || verification.Integrity != mcr.IntegritySealedValid || len(verification.Diagnostics) != 0 {
				t.Fatalf("Verify = %#v, want structurally valid sealed history", verification)
			}

			facts, err := ws.Query(mcr.FactQuery{})
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(facts) != 3 || facts[2].FactID != source.EventID {
				t.Fatalf("timeline = %#v, want Artifact at third fact", facts)
			}
			artifact := facts[2]
			if artifact.TaskID != "task/non-numeric" || !reflect.DeepEqual(artifact.Actor, source.Actor) || artifact.RecordedAt.Format(time.RFC3339Nano) != source.Timestamp || artifact.PrevHash != source.PrevHash || artifact.RecordHash != source.EventHash || !bytes.Equal(artifact.Payload, source.Payload) {
				t.Fatalf("Artifact source identity changed: %#v, source = %#v", artifact, source)
			}

			projection, err := ws.Replay()
			if err != nil {
				t.Fatalf("Replay: %v", err)
			}
			if len(projection.Tasks) != 1 {
				t.Fatalf("Replay tasks = %#v", projection.Tasks)
			}
			task := projection.Tasks[0]
			if test.wantOpaque {
				if artifact.Kind != mcr.KindOpaqueRecorded || !artifact.Opaque || artifact.OpaqueReason != "legacy_underbound" {
					t.Fatalf("partial Run source = %#v, want legacy_underbound opaque", artifact)
				}
				if len(task.Artifacts) != 0 || len(task.OpaqueFacts) != 1 {
					t.Fatalf("partial Artifact replay = %#v", task)
				}
				opaque := task.OpaqueFacts[0]
				if opaque.SourceFactID != source.EventID || opaque.Kind != source.EventType || !bytes.Equal(opaque.Data, source.Payload) {
					t.Fatalf("opaque replay = %#v, source = %#v", opaque, source)
				}
				return
			}

			if artifact.Kind != mcr.KindArtifactRecorded || artifact.Opaque {
				t.Fatalf("complete Run source = %#v, want typed Artifact", artifact)
			}
			if len(task.OpaqueFacts) != 0 || len(task.Artifacts) != 1 {
				t.Fatalf("typed Artifact replay = %#v", task)
			}
			typed := task.Artifacts[0]
			if typed.SourceFactID != source.EventID || typed.Run == nil || typed.Run.FactID != run.EventID || typed.Run.RecordHash != run.EventHash {
				t.Fatalf("typed Artifact = %#v, want Run %#v", typed, run)
			}
			if bytes.Contains(artifact.Payload, []byte(`"run"`)) || !bytes.Contains(artifact.Payload, []byte(`"additive_artifact":true`)) {
				t.Fatalf("source payload changed: %s", artifact.Payload)
			}
		})
	}
}

func TestSealedLegacyReplayIsDeterministicAndShared(t *testing.T) {
	ws, err := mcr.Open(copyLegacyWorkspace(t))
	if err != nil {
		t.Fatal(err)
	}
	first, err := ws.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	second, err := ws.Replay()
	if err != nil {
		t.Fatalf("second Replay: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated Replay differs")
	}
	assertJSONGolden(t, "testdata/legacy/sealed-valid.replay.json", first)
}

func TestUnsealedLegacyPublicOperations(t *testing.T) {
	workspace := copyLegacyFixtureWorkspace(t, "unsealed-valid.jsonl", []byte("{\"workspace_id\":\"workspace/unsealed\",\"last_event_id\":\"extension+opaque\"}\n"))
	before := snapshotFiles(t, workspace)
	ws, err := mcr.Open(workspace)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	verification, err := ws.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	assertJSONGolden(t, "testdata/legacy/unsealed-valid.verify.json", verification)
	facts, err := ws.Query(mcr.FactQuery{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	assertJSONGolden(t, "testdata/legacy/unsealed-valid.query.json", facts)
	if len(facts) != 3 || !bytes.Contains(facts[1].Payload, []byte(`"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`)) {
		t.Fatalf("bare source digest was not preserved: %#v", facts)
	}
	projection, err := ws.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	assertJSONGolden(t, "testdata/legacy/unsealed-valid.replay.json", projection)
	if _, err := ws.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrReadOnly) {
		t.Fatalf("Submit error = %v, want ErrReadOnly", err)
	}
	if after := snapshotFiles(t, workspace); !reflect.DeepEqual(before, after) {
		t.Fatalf("unsealed workspace files changed\nbefore: %#v\nafter: %#v", before, after)
	}
}

func TestSealedLegacyOperationsAreReadOnly(t *testing.T) {
	workspace := copyLegacyWorkspace(t)
	before := snapshotFiles(t, workspace)
	ws, err := mcr.Open(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Verify(); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Query(mcr.FactQuery{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Replay(); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Replay(); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrReadOnly) {
		t.Fatalf("Submit error = %v, want ErrReadOnly", err)
	}
	after := snapshotFiles(t, workspace)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("workspace files changed\nbefore: %#v\nafter: %#v", before, after)
	}
}

func TestLegacyIntegrityClassificationAndOperationGates(t *testing.T) {
	sealed, err := os.ReadFile("testdata/legacy/sealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	firstHash := []byte(`"event_hash":"` + firstLegacyEventHash + `"`)
	wrongHash := `sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`
	tests := []struct {
		name        string
		ledger      []byte
		integrity   string
		diagnostics []mcr.Diagnostic
	}{
		{name: "partial-one-field", ledger: mutateLegacyRecord(t, sealed, 2, func(values map[string]any) { delete(values, "event_hash") }), integrity: mcr.IntegrityPartialInvalid, diagnostics: []mcr.Diagnostic{{Code: "missing_event_hash", RecordNumber: 2, RecordID: "task:alpha", Message: "legacy event is missing event_hash"}}},
		{name: "partial-mixed", ledger: mutateLegacyRecord(t, sealed, 2, func(values map[string]any) { delete(values, "prev_hash"); delete(values, "event_hash") }), integrity: mcr.IntegrityPartialInvalid, diagnostics: []mcr.Diagnostic{{Code: "missing_previous_hash", RecordNumber: 2, RecordID: "task:alpha", Message: "legacy event is missing prev_hash"}, {Code: "missing_event_hash", RecordNumber: 2, RecordID: "task:alpha", Message: "legacy event is missing event_hash"}}},
		{name: "sealed-spelling", ledger: bytes.Replace(sealed, []byte(`"prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"`), []byte(`"prev_hash":"SHA256:0000000000000000000000000000000000000000000000000000000000000000"`), 1), integrity: mcr.IntegritySealedInvalid, diagnostics: []mcr.Diagnostic{{Code: "invalid_previous_hash", RecordNumber: 1, RecordID: "header@sealed", Message: "legacy previous hash spelling is invalid"}}},
		{name: "sealed-link", ledger: bytes.Replace(sealed, []byte(`"prev_hash":"`+firstLegacyEventHash+`"`), []byte(`"prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"`), 1), integrity: mcr.IntegritySealedInvalid, diagnostics: []mcr.Diagnostic{{Code: "previous_hash_mismatch", RecordNumber: 2, RecordID: "task:alpha", Message: "previous hash does not match"}, {Code: "event_hash_mismatch", RecordNumber: 2, RecordID: "task:alpha", Message: "legacy event hash does not match"}}},
		{name: "sealed-digest", ledger: bytes.Replace(sealed, firstHash, []byte(`"event_hash":"`+wrongHash+`"`), 1), integrity: mcr.IntegritySealedInvalid, diagnostics: []mcr.Diagnostic{{Code: "event_hash_mismatch", RecordNumber: 1, RecordID: "header@sealed", Message: "legacy event hash does not match"}, {Code: "previous_hash_mismatch", RecordNumber: 2, RecordID: "task:alpha", Message: "previous hash does not match"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := writeLegacyWorkspace(t, test.ledger, []byte("{\"legacy_cache\":true}\n"))
			before := snapshotFiles(t, workspace)
			ws, err := mcr.Open(workspace)
			if err != nil {
				t.Fatal(err)
			}
			first, err := ws.Verify()
			if err != nil {
				t.Fatal(err)
			}
			second, err := ws.Verify()
			if err != nil || !reflect.DeepEqual(first, second) {
				t.Fatalf("repeated Verify differs: %#v / %#v / %v", first, second, err)
			}
			if !first.StructuralValid || first.Integrity != test.integrity || !reflect.DeepEqual(first.Diagnostics, test.diagnostics) {
				t.Fatalf("Verify = %#v, want integrity %q diagnostics %#v", first, test.integrity, test.diagnostics)
			}
			if _, err := ws.Query(mcr.FactQuery{}); !errors.Is(err, mcr.ErrInvalidHistory) {
				t.Fatalf("Query error = %v", err)
			}
			if _, err := ws.Replay(); !errors.Is(err, mcr.ErrInvalidHistory) {
				t.Fatalf("Replay error = %v", err)
			}
			if _, err := ws.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrInvalidHistory) {
				t.Fatalf("Submit error = %v", err)
			}
			if after := snapshotFiles(t, workspace); !reflect.DeepEqual(before, after) {
				t.Fatal("invalid legacy history was modified")
			}
		})
	}
}

func TestLegacyDualFixtureMutationMatrix(t *testing.T) {
	sealed, err := os.ReadFile("testdata/legacy/sealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	unsealed, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	wrongHash := "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	tests := []struct {
		name        string
		ledger      []byte
		structural  bool
		integrity   string
		diagnostics []mcr.Diagnostic
	}{
		{
			name:       "sealed-missing-previous-hash",
			ledger:     mutateLegacyRecord(t, sealed, 2, func(values map[string]any) { delete(values, "prev_hash") }),
			structural: true,
			integrity:  mcr.IntegrityPartialInvalid,
			diagnostics: []mcr.Diagnostic{
				{Code: "missing_previous_hash", RecordNumber: 2, RecordID: "task:alpha", Message: "legacy event is missing prev_hash"},
			},
		},
		{
			name:       "unsealed-single-present-field",
			ledger:     mutateLegacyRecord(t, unsealed, 1, func(values map[string]any) { values["event_hash"] = wrongHash }),
			structural: true,
			integrity:  mcr.IntegrityPartialInvalid,
			diagnostics: []mcr.Diagnostic{
				{Code: "missing_previous_hash", RecordNumber: 1, RecordID: "header@sealed", Message: "legacy event is missing prev_hash"},
				{Code: "missing_previous_hash", RecordNumber: 2, RecordID: "task@u-9", Message: "legacy event is missing prev_hash"},
				{Code: "missing_event_hash", RecordNumber: 2, RecordID: "task@u-9", Message: "legacy event is missing event_hash"},
				{Code: "missing_previous_hash", RecordNumber: 3, RecordID: "input#bare", Message: "legacy event is missing prev_hash"},
				{Code: "missing_event_hash", RecordNumber: 3, RecordID: "input#bare", Message: "legacy event is missing event_hash"},
				{Code: "missing_previous_hash", RecordNumber: 4, RecordID: "extension+opaque", Message: "legacy event is missing prev_hash"},
				{Code: "missing_event_hash", RecordNumber: 4, RecordID: "extension+opaque", Message: "legacy event is missing event_hash"},
			},
		},
		{
			name:       "sealed-invalid-event-spelling",
			ledger:     bytes.Replace(sealed, []byte(`"event_hash":"`+firstLegacyEventHash+`"`), []byte(`"event_hash":"SHA256:`+firstLegacyEventHash[len("sha256:"):]+`"`), 1),
			structural: true,
			integrity:  mcr.IntegritySealedInvalid,
			diagnostics: []mcr.Diagnostic{
				{Code: "invalid_event_hash", RecordNumber: 1, RecordID: "header@sealed", Message: "legacy event hash spelling is invalid"},
				{Code: "previous_hash_mismatch", RecordNumber: 2, RecordID: "task:alpha", Message: "previous hash does not match"},
			},
		},
		{
			name:       "sealed-invalid-link",
			ledger:     bytes.Replace(sealed, []byte(`"prev_hash":"`+firstLegacyEventHash+`"`), []byte(`"prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"`), 1),
			structural: true,
			integrity:  mcr.IntegritySealedInvalid,
			diagnostics: []mcr.Diagnostic{
				{Code: "previous_hash_mismatch", RecordNumber: 2, RecordID: "task:alpha", Message: "previous hash does not match"},
				{Code: "event_hash_mismatch", RecordNumber: 2, RecordID: "task:alpha", Message: "legacy event hash does not match"},
			},
		},
		{
			name:       "sealed-invalid-digest",
			ledger:     bytes.Replace(sealed, []byte(`"event_hash":"`+firstLegacyEventHash+`"`), []byte(`"event_hash":"`+wrongHash+`"`), 1),
			structural: true,
			integrity:  mcr.IntegritySealedInvalid,
			diagnostics: []mcr.Diagnostic{
				{Code: "event_hash_mismatch", RecordNumber: 1, RecordID: "header@sealed", Message: "legacy event hash does not match"},
				{Code: "previous_hash_mismatch", RecordNumber: 2, RecordID: "task:alpha", Message: "previous hash does not match"},
			},
		},
		{
			name:        "sealed-required-envelope-before-integrity",
			ledger:      mutateLegacyRecord(t, sealed, 2, func(values map[string]any) { delete(values, "actor") }),
			structural:  false,
			diagnostics: []mcr.Diagnostic{{Code: "invalid_event_envelope", RecordNumber: 2, Message: "legacy event is missing required envelope fields"}},
		},
		{
			name:        "sealed-duplicate-before-integrity",
			ledger:      mutateLegacyRecord(t, sealed, 2, func(values map[string]any) { values["event_id"] = "header@sealed" }),
			structural:  false,
			diagnostics: []mcr.Diagnostic{{Code: "duplicate_event_id", RecordNumber: 2, RecordID: "header@sealed", Message: "legacy event ID is not unique"}},
		},
		{
			name: "unsealed-reference-before-integrity",
			ledger: mutateLegacyRecord(t, unsealed, 4, func(values map[string]any) {
				values["event_type"] = "ArtifactAdded"
				values["payload"] = map[string]any{
					"task_id": "task/u?opaque",
					"content": map[string]any{"locator": "out.txt", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
					"run":     map[string]any{"fact_id": "missing-run", "record_hash": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
				}
			}),
			structural:  false,
			diagnostics: []mcr.Diagnostic{{Code: "invalid_payload", RecordNumber: 4, RecordID: "extension+opaque", Message: "artifact run does not reference an earlier Fact"}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := writeLegacyWorkspace(t, test.ledger, []byte("{}\n"))
			before := snapshotFiles(t, workspace)
			ws, err := mcr.Open(workspace)
			if err != nil {
				t.Fatal(err)
			}
			first, err := ws.Verify()
			if err != nil {
				t.Fatal(err)
			}
			second, err := ws.Verify()
			if err != nil || !reflect.DeepEqual(first, second) {
				t.Fatalf("repeated Verify differs: %#v / %#v / %v", first, second, err)
			}
			if first.StructuralValid != test.structural || first.Integrity != test.integrity || !reflect.DeepEqual(first.Diagnostics, test.diagnostics) {
				t.Fatalf("Verify = %#v, want structural %v integrity %q diagnostics %#v", first, test.structural, test.integrity, test.diagnostics)
			}
			if _, err := ws.Query(mcr.FactQuery{}); !errors.Is(err, mcr.ErrInvalidHistory) {
				t.Fatalf("Query error = %v, want ErrInvalidHistory", err)
			}
			if _, err := ws.Replay(); !errors.Is(err, mcr.ErrInvalidHistory) {
				t.Fatalf("Replay error = %v, want ErrInvalidHistory", err)
			}
			if _, err := ws.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrInvalidHistory) {
				t.Fatalf("Submit error = %v, want ErrInvalidHistory", err)
			}
			if after := snapshotFiles(t, workspace); !reflect.DeepEqual(before, after) {
				t.Fatalf("workspace changed\nbefore: %#v\nafter: %#v", before, after)
			}
		})
	}
}

func TestLegacyStructurePrecedesIntegrity(t *testing.T) {
	sealed, err := os.ReadFile("testdata/legacy/sealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data []byte
		code string
	}{
		{name: "required-envelope", data: mutateLegacyRecord(t, sealed, 2, func(values map[string]any) { delete(values, "actor") }), code: "invalid_event_envelope"},
		{name: "duplicate-id-before-broken-hash", data: mutateLegacyRecord(t, sealed, 2, func(values map[string]any) { values["event_id"] = "header@sealed" }), code: "duplicate_event_id"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := writeLegacyWorkspace(t, test.data, []byte("{}\n"))
			ws, err := mcr.Open(workspace)
			if err != nil {
				t.Fatal(err)
			}
			verification, err := ws.Verify()
			if err != nil || verification.StructuralValid || verification.Integrity != "" || len(verification.Diagnostics) != 1 || verification.Diagnostics[0].Code != test.code {
				t.Fatalf("Verify = %#v, %v", verification, err)
			}
			if _, err := ws.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrInvalidHistory) {
				t.Fatalf("Submit error = %v", err)
			}
		})
	}
}

func TestLegacyExactReferenceDoesNotFallback(t *testing.T) {
	unsealed, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	mutated := mutateLegacyRecord(t, unsealed, 4, func(values map[string]any) {
		values["event_type"] = "ArtifactAdded"
		values["payload"] = map[string]any{
			"task_id": "task/u?opaque",
			"content": map[string]any{"locator": "out.txt", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
			"run":     map[string]any{"fact_id": "missing-run", "record_hash": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		}
	})
	workspace := writeLegacyWorkspace(t, mutated, []byte("{}\n"))
	ws, err := mcr.Open(workspace)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := ws.Verify()
	if err != nil || verification.StructuralValid || len(verification.Diagnostics) != 1 || verification.Diagnostics[0].Code != "invalid_payload" {
		t.Fatalf("Verify = %#v, %v", verification, err)
	}
}

func TestLegacyGovernanceUnderboundRemainsOpaque(t *testing.T) {
	unsealed, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	exactSubject := map[string]any{
		"fact_id":     "task@u-9",
		"record_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	tests := []struct {
		name          string
		eventType     string
		payload       map[string]any
		missingTaskID bool
	}{
		{name: "review missing task ID", eventType: "ReviewSubmitted", payload: map[string]any{"subject": exactSubject, "outcome": "accepted", "additive": "retained"}, missingTaskID: true},
		{name: "review missing required outcome", eventType: "ReviewSubmitted", payload: map[string]any{"task_id": "task/u?opaque", "subject": exactSubject, "additive": "retained"}},
		{name: "review alias flattened half reference", eventType: "NarrativeDraftReviewed", payload: map[string]any{"task_id": "task/u?opaque", "subject_fact_id": "task@u-9", "outcome": "accepted", "additive": "retained"}},
		{name: "review nested incomplete precedes flattened", eventType: "ReviewSubmitted", payload: map[string]any{"task_id": "task/u?opaque", "subject": map[string]any{"fact_id": "task@u-9"}, "subject_fact_id": "task@u-9", "subject_record_hash": exactSubject["record_hash"], "outcome": "accepted", "additive": "retained"}},
		{name: "approval missing required scope", eventType: "ApprovalGranted", payload: map[string]any{"task_id": "task/u?opaque", "subject": exactSubject, "decision": "approved", "additive": "retained"}},
		{name: "approval flattened half reference", eventType: "ApprovalGranted", payload: map[string]any{"task_id": "task/u?opaque", "subject_record_hash": exactSubject["record_hash"], "scope": "release", "decision": "approved", "additive": "retained"}},
		{name: "policy missing required result", eventType: "PolicyDecisionRecorded", payload: map[string]any{"task_id": "task/u?opaque", "subject": exactSubject, "action": "allow", "policy": "release", "additive": "retained"}},
		{name: "policy nested incomplete binding", eventType: "PolicyDecisionRecorded", payload: map[string]any{"task_id": "task/u?opaque", "subject": map[string]any{"record_hash": exactSubject["record_hash"]}, "action": "allow", "policy": "release", "result": "passed", "additive": "retained"}},
		{name: "delivery missing artifacts", eventType: "DeliveryRecorded", payload: map[string]any{"task_id": "task/u?opaque", "format": "archive", "scope": "release", "target": "customer", "additive": "retained"}},
		{name: "delivery artifact incomplete binding", eventType: "DeliveryRecorded", payload: map[string]any{"task_id": "task/u?opaque", "artifacts": []any{map[string]any{"fact_id": "input#bare"}}, "format": "archive", "scope": "release", "target": "customer", "additive": "retained"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := mutateLegacyRecord(t, unsealed, 4, func(values map[string]any) {
				values["event_type"] = test.eventType
				values["payload"] = test.payload
			})
			workspace := writeLegacyWorkspace(t, mutated, []byte("{}\n"))
			ws, err := mcr.Open(workspace)
			if err != nil {
				t.Fatal(err)
			}

			facts, err := ws.Query(mcr.FactQuery{})
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(facts) != 3 || facts[0].FactID != "task@u-9" || facts[1].FactID != "input#bare" || facts[2].FactID != "extension+opaque" {
				t.Fatalf("Query timeline = %#v", facts)
			}
			fact := facts[2]
			expectedPayload, err := json.Marshal(test.payload)
			if err != nil {
				t.Fatal(err)
			}
			expectedTaskID := "task/u?opaque"
			if test.missingTaskID {
				expectedTaskID = ""
			}
			if fact.TaskID != expectedTaskID || fact.Kind != mcr.KindOpaqueRecorded || !fact.Opaque || fact.OpaqueReason != "legacy_underbound" || fact.Actor != (mcr.Actor{Type: "service", ID: "legacy-extension"}) || fact.RecordedAt.Format("2006-01-02T15:04:05Z07:00") != "2025-02-03T04:05:09Z" || fact.PrevHash != "" || fact.RecordHash != "" || !bytes.Equal(fact.Payload, expectedPayload) {
				t.Fatalf("under-bound Fact = %#v, payload = %s, want payload = %s", fact, fact.Payload, expectedPayload)
			}

			projection, err := ws.Replay()
			if err != nil {
				t.Fatalf("Replay: %v", err)
			}
			expectedOpaqueFacts := 1
			if test.missingTaskID {
				expectedOpaqueFacts = 0
			}
			if len(projection.Tasks) != 1 || len(projection.Tasks[0].OpaqueFacts) != expectedOpaqueFacts {
				t.Fatalf("Replay tasks = %#v", projection.Tasks)
			}
			if expectedOpaqueFacts != 0 {
				opaque := projection.Tasks[0].OpaqueFacts[0]
				if opaque.SourceFactID != fact.FactID || opaque.Kind != test.eventType || !bytes.Equal(opaque.Data, expectedPayload) {
					t.Fatalf("Replay opaque = %#v, want source payload %s", opaque, expectedPayload)
				}
			}
		})
	}
}

func TestLegacyContentUnderboundRemainsOpaque(t *testing.T) {
	unsealed, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []string{"InputRegistered", "ArtifactAdded"} {
		t.Run(eventType, func(t *testing.T) {
			payload := map[string]any{
				"task_id":  "task/u?opaque",
				"content":  map[string]any{"locator": "inputs/incomplete.txt"},
				"additive": "retained",
			}
			mutated := mutateLegacyRecord(t, unsealed, 3, func(values map[string]any) {
				values["event_type"] = eventType
				values["payload"] = payload
			})
			workspacePath := writeLegacyWorkspace(t, mutated, []byte("{}\n"))
			before := snapshotFiles(t, workspacePath)
			workspace, err := mcr.Open(workspacePath)
			if err != nil {
				t.Fatal(err)
			}
			verification, err := workspace.Verify()
			if err != nil || !verification.StructuralValid || verification.Integrity != mcr.IntegrityUnsealed {
				t.Fatalf("Verify under-bound content = %#v, %v", verification, err)
			}
			facts, err := workspace.Query(mcr.FactQuery{FactID: "input#bare"})
			if err != nil || len(facts) != 1 {
				t.Fatalf("Query under-bound content = %#v, %v", facts, err)
			}
			expectedPayload, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			fact := facts[0]
			if fact.Kind != mcr.KindOpaqueRecorded || !fact.Opaque || fact.OpaqueReason != "legacy_underbound" || !bytes.Equal(fact.Payload, expectedPayload) {
				t.Fatalf("under-bound content Fact = %#v, payload = %s", fact, fact.Payload)
			}
			projection, err := workspace.Replay()
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, opaque := range projection.Tasks[0].OpaqueFacts {
				if opaque.SourceFactID == fact.FactID && opaque.Kind == eventType && bytes.Equal(opaque.Data, expectedPayload) {
					found = true
				}
			}
			if !found {
				t.Fatalf("Replay omitted under-bound content: %#v", projection.Tasks[0].OpaqueFacts)
			}
			if after := snapshotFiles(t, workspacePath); !reflect.DeepEqual(after, before) {
				t.Fatal("legacy files changed")
			}
		})
	}
}

func TestLegacyContentCompleteInvalidDigestFailsClosed(t *testing.T) {
	unsealed, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	mutated := mutateLegacyRecord(t, unsealed, 3, func(values map[string]any) {
		values["payload"] = map[string]any{
			"task_id": "task/u?opaque",
			"content": map[string]any{"locator": "inputs/invalid.txt", "sha256": "not-a-hash"},
		}
	})
	workspacePath := writeLegacyWorkspace(t, mutated, []byte("{}\n"))
	workspace, err := mcr.Open(workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := workspace.Verify()
	if err != nil || verification.StructuralValid || len(verification.Diagnostics) == 0 || verification.Diagnostics[0].Code != "invalid_payload" {
		t.Fatalf("Verify complete invalid content = %#v, %v", verification, err)
	}
}

func TestLegacyTaskAndRunUnderboundRemainOpaque(t *testing.T) {
	unsealed, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, eventType, factID string
		recordNumber, keep      int
		payload                 map[string]any
		taskScoped              bool
	}{
		{
			name: "Task missing Definition digest", eventType: "TaskCreated", factID: "task@u-9", recordNumber: 2, keep: 2,
			payload: map[string]any{"task_id": "task/u?opaque", "definition": map[string]any{
				"namespace": "example", "id": "unsealed-task", "version": "1.0.0", "locator": "defs/unsealed.json",
			}, "additive": "retained"},
		},
		{
			name: "Run missing outcome", eventType: "RunCompleted", factID: "input#bare", recordNumber: 3, keep: 3, taskScoped: true,
			payload: map[string]any{"task_id": "task/u?opaque", "started_at": "2025-02-03T04:05:07Z", "ended_at": "2025-02-03T04:05:08Z", "additive": "retained"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := mutateLegacyRecord(t, unsealed, test.recordNumber, func(values map[string]any) {
				values["event_type"] = test.eventType
				values["payload"] = test.payload
			})
			lines := bytes.Split(bytes.TrimSuffix(mutated, []byte("\n")), []byte("\n"))
			mutated = append(bytes.Join(lines[:test.keep], []byte("\n")), '\n')
			workspacePath := writeLegacyWorkspace(t, mutated, []byte("{}\n"))
			before := snapshotFiles(t, workspacePath)
			workspace, err := mcr.Open(workspacePath)
			if err != nil {
				t.Fatal(err)
			}
			verification, err := workspace.Verify()
			if err != nil || !verification.StructuralValid || verification.Integrity != mcr.IntegrityUnsealed {
				t.Fatalf("Verify under-bound %s = %#v, %v", test.eventType, verification, err)
			}
			facts, err := workspace.Query(mcr.FactQuery{FactID: test.factID})
			if err != nil || len(facts) != 1 {
				t.Fatalf("Query under-bound %s = %#v, %v", test.eventType, facts, err)
			}
			expectedPayload, err := json.Marshal(test.payload)
			if err != nil {
				t.Fatal(err)
			}
			fact := facts[0]
			if fact.TaskID != "task/u?opaque" || fact.Kind != mcr.KindOpaqueRecorded || !fact.Opaque || fact.OpaqueReason != "legacy_underbound" || !bytes.Equal(fact.Payload, expectedPayload) {
				t.Fatalf("under-bound %s Fact = %#v, payload = %s", test.eventType, fact, fact.Payload)
			}
			projection, err := workspace.Replay()
			if err != nil {
				t.Fatal(err)
			}
			var opaqueFacts []mcr.OpaqueFactProjection
			if test.taskScoped {
				if len(projection.Tasks) != 1 {
					t.Fatalf("Replay Tasks = %#v", projection.Tasks)
				}
				opaqueFacts = projection.Tasks[0].OpaqueFacts
			} else {
				if len(projection.Tasks) != 0 {
					t.Fatalf("under-bound Task created a typed projection: %#v", projection.Tasks)
				}
				opaqueFacts = projection.OpaqueFacts
			}
			if len(opaqueFacts) != 1 || opaqueFacts[0].SourceFactID != fact.FactID || opaqueFacts[0].Kind != test.eventType || !bytes.Equal(opaqueFacts[0].Data, expectedPayload) {
				t.Fatalf("Replay under-bound %s = %#v", test.eventType, opaqueFacts)
			}
			if after := snapshotFiles(t, workspacePath); !reflect.DeepEqual(after, before) {
				t.Fatal("legacy files changed")
			}
		})
	}
}

func TestLegacyTaskAndRunCompleteInvalidValuesFailClosed(t *testing.T) {
	unsealed, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, eventType string
		recordNumber    int
		payload         map[string]any
	}{
		{
			name: "Task invalid Definition digest", eventType: "TaskCreated", recordNumber: 2,
			payload: map[string]any{"task_id": "task/u?opaque", "definition": map[string]any{
				"namespace": "example", "id": "unsealed-task", "version": "1.0.0", "locator": "defs/unsealed.json", "sha256": "not-a-hash",
			}},
		},
		{
			name: "Run reversed interval", eventType: "RunCompleted", recordNumber: 3,
			payload: map[string]any{"task_id": "task/u?opaque", "started_at": "2025-02-03T04:05:09Z", "ended_at": "2025-02-03T04:05:08Z", "outcome": "completed"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := mutateLegacyRecord(t, unsealed, test.recordNumber, func(values map[string]any) {
				values["event_type"] = test.eventType
				values["payload"] = test.payload
			})
			workspacePath := writeLegacyWorkspace(t, mutated, []byte("{}\n"))
			workspace, err := mcr.Open(workspacePath)
			if err != nil {
				t.Fatal(err)
			}
			verification, err := workspace.Verify()
			if err != nil || verification.StructuralValid || len(verification.Diagnostics) == 0 || verification.Diagnostics[0].Code != "invalid_payload" {
				t.Fatalf("Verify complete invalid %s = %#v, %v", test.eventType, verification, err)
			}
		})
	}
}

func TestLegacyGovernanceCompleteInvalidReferencesFailClosed(t *testing.T) {
	unsealed, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	hash := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	exactSubject := map[string]any{"fact_id": "task@u-9", "record_hash": hash}
	tests := []struct {
		name      string
		eventType string
		prepare   func([]byte) []byte
		payload   map[string]any
	}{
		{name: "review task ID wrong type", eventType: "ReviewSubmitted", payload: map[string]any{"task_id": 7, "subject": exactSubject, "outcome": "accepted"}},
		{name: "review nested missing subject", eventType: "ReviewSubmitted", payload: map[string]any{"task_id": "task/u?opaque", "subject": map[string]any{"fact_id": "missing", "record_hash": hash}, "outcome": "accepted", "additive": true}},
		{name: "review nested malformed hash", eventType: "ReviewSubmitted", payload: map[string]any{"task_id": "task/u?opaque", "subject": map[string]any{"fact_id": "task@u-9", "record_hash": "not-a-hash"}, "outcome": "accepted"}},
		{name: "review nested malformed precedes flattened", eventType: "ReviewSubmitted", payload: map[string]any{"task_id": "task/u?opaque", "subject": "wrong-shape", "subject_fact_id": "task@u-9", "subject_record_hash": hash, "outcome": "accepted"}},
		{name: "review flattened malformed hash", eventType: "NarrativeDraftReviewed", payload: map[string]any{"task_id": "task/u?opaque", "subject_fact_id": "task@u-9", "subject_record_hash": "not-a-hash", "outcome": "accepted"}},
		{name: "review flattened fact ID wrong type", eventType: "ReviewSubmitted", payload: map[string]any{"task_id": "task/u?opaque", "subject_fact_id": 7, "subject_record_hash": hash, "outcome": "accepted"}},
		{name: "review flattened empty fact ID", eventType: "ReviewSubmitted", payload: map[string]any{"task_id": "task/u?opaque", "subject_fact_id": "", "subject_record_hash": hash, "outcome": "accepted"}},
		{name: "review flattened null hash", eventType: "ReviewSubmitted", payload: map[string]any{"task_id": "task/u?opaque", "subject_fact_id": "task@u-9", "subject_record_hash": nil, "outcome": "accepted"}},
		{name: "review invalid optional findings", eventType: "ReviewSubmitted", payload: map[string]any{"task_id": "task/u?opaque", "subject": exactSubject, "outcome": "accepted", "findings": 7}},
		{name: "approval empty required scope", eventType: "ApprovalGranted", payload: map[string]any{"task_id": "task/u?opaque", "subject": exactSubject, "scope": "", "decision": "approved"}},
		{name: "approval wrong shaped subject", eventType: "ApprovalGranted", payload: map[string]any{"task_id": "task/u?opaque", "subject": "task@u-9", "scope": "release", "decision": "approved"}},
		{name: "approval invalid optional note", eventType: "ApprovalGranted", payload: map[string]any{"task_id": "task/u?opaque", "subject": exactSubject, "scope": "release", "decision": "approved", "note": ""}},
		{name: "approval flattened cross task subject", eventType: "ApprovalGranted", prepare: func(ledger []byte) []byte {
			return mutateLegacyRecord(t, ledger, 3, func(values map[string]any) {
				values["event_type"] = "TaskCreated"
				values["payload"] = map[string]any{"task_id": "task/other", "definition": map[string]any{"namespace": "example", "id": "other", "version": "1.0.0", "locator": "defs/other.json", "sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
			})
		}, payload: map[string]any{"task_id": "task/u?opaque", "subject_fact_id": "input#bare", "subject_record_hash": hash, "scope": "release", "decision": "approved", "additive": true}},
		{name: "policy subject hash mismatch", eventType: "PolicyDecisionRecorded", payload: map[string]any{"task_id": "task/u?opaque", "subject": map[string]any{"fact_id": "task@u-9", "record_hash": hash}, "action": "allow", "policy": "release", "result": "passed", "additive": true}},
		{name: "policy required result null", eventType: "PolicyDecisionRecorded", payload: map[string]any{"task_id": "task/u?opaque", "subject": exactSubject, "action": "allow", "policy": "release", "result": nil}},
		{name: "delivery artifacts non array", eventType: "DeliveryRecorded", payload: map[string]any{"task_id": "task/u?opaque", "artifacts": "input#bare", "format": "archive", "scope": "release", "target": "customer"}},
		{name: "delivery artifacts empty", eventType: "DeliveryRecorded", payload: map[string]any{"task_id": "task/u?opaque", "artifacts": []any{}, "format": "archive", "scope": "release", "target": "customer"}},
		{name: "delivery artifact non object", eventType: "DeliveryRecorded", payload: map[string]any{"task_id": "task/u?opaque", "artifacts": []any{"input#bare"}, "format": "archive", "scope": "release", "target": "customer"}},
		{name: "delivery artifact malformed reference", eventType: "DeliveryRecorded", payload: map[string]any{"task_id": "task/u?opaque", "artifacts": []any{map[string]any{"fact_id": 7, "record_hash": hash}}, "format": "archive", "scope": "release", "target": "customer"}},
		{name: "delivery artifact malformed hash", eventType: "DeliveryRecorded", payload: map[string]any{"task_id": "task/u?opaque", "artifacts": []any{map[string]any{"fact_id": "input#bare", "record_hash": "not-a-hash"}}, "format": "archive", "scope": "release", "target": "customer"}},
		{name: "delivery duplicate artifacts", eventType: "DeliveryRecorded", payload: map[string]any{"task_id": "task/u?opaque", "artifacts": []any{exactSubject, exactSubject}, "format": "archive", "scope": "release", "target": "customer"}},
		{name: "delivery artifact wrong kind", eventType: "DeliveryRecorded", payload: map[string]any{"task_id": "task/u?opaque", "artifacts": []any{map[string]any{"fact_id": "input#bare", "record_hash": hash}}, "format": "archive", "scope": "release", "target": "customer", "additive": true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ledger := unsealed
			if test.prepare != nil {
				ledger = test.prepare(ledger)
			}
			mutated := mutateLegacyRecord(t, ledger, 4, func(values map[string]any) {
				values["event_type"] = test.eventType
				values["payload"] = test.payload
			})
			workspace := writeLegacyWorkspace(t, mutated, []byte("{}\n"))
			ws, err := mcr.Open(workspace)
			if err != nil {
				t.Fatal(err)
			}
			verification, err := ws.Verify()
			if err != nil || verification.StructuralValid || len(verification.Diagnostics) != 1 || verification.Diagnostics[0].Code != "invalid_payload" {
				t.Fatalf("Verify = %#v, %v", verification, err)
			}
			if _, err := ws.Query(mcr.FactQuery{}); !errors.Is(err, mcr.ErrInvalidHistory) {
				t.Fatalf("Query error = %v, want ErrInvalidHistory", err)
			}
			if _, err := ws.Replay(); !errors.Is(err, mcr.ErrInvalidHistory) {
				t.Fatalf("Replay error = %v, want ErrInvalidHistory", err)
			}
			if _, err := ws.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrInvalidHistory) {
				t.Fatalf("Submit error = %v, want ErrInvalidHistory", err)
			}
		})
	}
}

func TestLegacyCacheDiagnosticsAreNonAuthoritative(t *testing.T) {
	ledger, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	baseline := writeLegacyWorkspace(t, ledger, []byte("{\"workspace_id\":\"workspace/unsealed\",\"last_event_id\":\"extension+opaque\"}\n"))
	baselineWS, _ := mcr.Open(baseline)
	baselineProjection, err := baselineWS.Replay()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		state []byte
		code  string
	}{
		{name: "missing", state: nil, code: "legacy_cache_missing"},
		{name: "malformed", state: []byte("{\n"), code: "legacy_cache_invalid_json"},
		{name: "non-object", state: []byte("[]\n"), code: "legacy_cache_not_object"},
		{name: "mismatch", state: []byte("{\"workspace_id\":\"other\",\"last_event_id\":\"stale\"}\n"), code: "legacy_cache_workspace_mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := writeLegacyWorkspace(t, ledger, test.state)
			ws, err := mcr.Open(workspace)
			if err != nil {
				t.Fatal(err)
			}
			verification, err := ws.Verify()
			if err != nil || !verification.StructuralValid || verification.Integrity != mcr.IntegrityUnsealed || len(verification.Diagnostics) == 0 || verification.Diagnostics[0].Code != test.code {
				t.Fatalf("Verify = %#v, %v", verification, err)
			}
			projection, err := ws.Replay()
			if err != nil || !reflect.DeepEqual(projection, baselineProjection) {
				t.Fatalf("Replay changed with cache: %#v, %v", projection, err)
			}
		})
	}
	for _, name := range []string{"symlink", "directory", "fifo"} {
		t.Run(name, func(t *testing.T) {
			workspace := writeLegacyWorkspace(t, ledger, nil)
			statePath := filepath.Join(workspace, ".mcr", "state.json")
			switch name {
			case "symlink":
				target := filepath.Join(workspace, "cache-target.json")
				if err := os.WriteFile(target, []byte("{}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, statePath); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(statePath, 0o755); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(statePath, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ws, err := mcr.Open(workspace)
			if err != nil {
				t.Fatal(err)
			}
			verification, err := ws.Verify()
			if err != nil || !verification.StructuralValid || verification.Integrity != mcr.IntegrityUnsealed || len(verification.Diagnostics) != 1 || verification.Diagnostics[0].Code != "legacy_cache_not_regular" {
				t.Fatalf("Verify = %#v, %v", verification, err)
			}
			projection, err := ws.Replay()
			if err != nil || !reflect.DeepEqual(projection, baselineProjection) {
				t.Fatalf("Replay changed with %s cache: %#v, %v", name, projection, err)
			}
		})
	}
}

func mutateLegacyRecord(t *testing.T, ledger []byte, record int, mutate func(map[string]any)) []byte {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(ledger, []byte("\n")), []byte("\n"))
	var values map[string]any
	if err := json.Unmarshal(lines[record-1], &values); err != nil {
		t.Fatal(err)
	}
	mutate(values)
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	lines[record-1] = encoded
	return append(bytes.Join(lines, []byte("\n")), '\n')
}

func writeLegacyWorkspace(t *testing.T, ledger, state []byte) string {
	t.Helper()
	root := t.TempDir()
	mcrDir := filepath.Join(root, ".mcr")
	if err := os.Mkdir(mcrDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mcrDir, "events.jsonl"), ledger, 0o644); err != nil {
		t.Fatal(err)
	}
	if state != nil {
		if err := os.WriteFile(filepath.Join(mcrDir, "state.json"), state, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func copyLegacyWorkspace(t *testing.T) string {
	t.Helper()
	return copyLegacyFixtureWorkspace(t, "sealed-valid.jsonl", []byte("{\"legacy_cache\":true}\n"))
}

func copyLegacyFixtureWorkspace(t *testing.T, fixture string, state []byte) string {
	t.Helper()
	root := t.TempDir()
	mcrDir := filepath.Join(root, ".mcr")
	if err := os.Mkdir(mcrDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ledger, err := os.ReadFile(filepath.Join("testdata/legacy", fixture))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"events.jsonl": ledger,
		"state.json":   state,
		"marker.audit": []byte("adjacent marker\n"),
	} {
		if err := os.WriteFile(filepath.Join(mcrDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func snapshotFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	snapshot := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		snapshot[relative] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertJSONGolden(t *testing.T, path string, actual any) {
	t.Helper()
	var expected any
	readJSONFile(t, path, &expected)
	encoded, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, decoded) {
		expectedJSON, _ := json.MarshalIndent(expected, "", "  ")
		actualJSON, _ := json.MarshalIndent(decoded, "", "  ")
		t.Fatalf("JSON differs from %s\nexpected:\n%s\nactual:\n%s", path, expectedJSON, actualJSON)
	}
}

func readJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}
