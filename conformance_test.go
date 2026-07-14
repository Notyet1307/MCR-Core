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
	"strings"
	"testing"

	mcr "github.com/Notyet1307/MCR-Core"
)

const nativeZeroHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
const nativeWrongHash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

type nativeTestHeader struct {
	RecordType    string `json:"record_type"`
	FormatVersion string `json:"format_version"`
	WorkspaceID   string `json:"workspace_id"`
	RecordedAt    string `json:"recorded_at"`
	PrevHash      string `json:"prev_hash"`
	RecordHash    string `json:"record_hash"`
}

type nativeTestFact struct {
	RecordType string          `json:"record_type"`
	FactID     string          `json:"fact_id"`
	TaskID     string          `json:"task_id"`
	Kind       string          `json:"kind"`
	Actor      mcr.Actor       `json:"actor"`
	RecordedAt string          `json:"recorded_at"`
	Payload    json.RawMessage `json:"payload"`
	PrevHash   string          `json:"prev_hash"`
	RecordHash string          `json:"record_hash"`
}

func TestMalformedHistoryRecordCounts(t *testing.T) {
	native, err := os.ReadFile("testdata/native-task.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, code string
		ledger     []byte
		count      int
	}{
		{"native BOM", "invalid_encoding", append([]byte{0xef, 0xbb, 0xbf}, native...), 15},
		{"native invalid UTF-8", "invalid_encoding", append([]byte{0xff}, native...), 15},
		{"native missing final newline", "missing_newline", bytes.TrimSuffix(native, []byte("\n")), 15},
		{"legacy BOM", "invalid_encoding", append([]byte{0xef, 0xbb, 0xbf}, legacy...), 4},
		{"legacy invalid UTF-8", "invalid_encoding", append([]byte{0xff}, legacy...), 4},
		{"legacy missing final newline", "missing_newline", bytes.TrimSuffix(legacy, []byte("\n")), 4},
		{"empty", "missing_newline", []byte{}, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspacePath := writeLegacyWorkspace(t, test.ledger, nil)
			workspace, err := mcr.Open(workspacePath)
			if err != nil {
				t.Fatal(err)
			}
			verification, err := workspace.Verify()
			if err != nil || verification.RecordCount != test.count || len(verification.Diagnostics) == 0 || verification.Diagnostics[0].Code != test.code {
				t.Fatalf("Verify malformed history = %#v, %v; want count=%d code=%s", verification, err, test.count, test.code)
			}
		})
	}
}

func TestNativeStrictKindConformanceMatrix(t *testing.T) {
	type invalidCase struct {
		name   string
		kind   string
		code   string
		mutate func(*testing.T, []nativeTestFact)
	}
	var invalid []invalidCase
	addObject := func(kind, label string, path, fields, required []string, absentDefaults map[string]any) {
		for _, field := range required {
			field := field
			invalid = append(invalid, invalidCase{
				name: label + "/missing-" + field, kind: kind, code: "invalid_payload",
				mutate: func(t *testing.T, facts []nativeTestFact) {
					index := nativeFactIndex(t, facts, kind)
					facts[index].Payload = mutateNativeObjectAt(t, facts[index].Payload, path, func(values map[string]any) { delete(values, field) })
				},
			})
		}
		for _, field := range fields {
			field := field
			invalid = append(invalid,
				invalidCase{
					name: label + "/wrong-type-" + field, kind: kind, code: "invalid_payload",
					mutate: func(t *testing.T, facts []nativeTestFact) {
						index := nativeFactIndex(t, facts, kind)
						facts[index].Payload = mutateNativeObjectAt(t, facts[index].Payload, path, func(values map[string]any) { values[field] = 1 })
					},
				},
				invalidCase{
					name: label + "/duplicate-" + field, kind: kind, code: "invalid_fact_envelope",
					mutate: func(t *testing.T, facts []nativeTestFact) {
						index := nativeFactIndex(t, facts, kind)
						payload := facts[index].Payload
						if value, ok := absentDefaults[field]; ok {
							payload = mutateNativeObjectAt(t, payload, path, func(values map[string]any) { values[field] = value })
						}
						facts[index].Payload = duplicateNativeObjectFieldAt(t, payload, path, field)
					},
				},
			)
		}
		invalid = append(invalid, invalidCase{
			name: label + "/unknown-field", kind: kind, code: "invalid_payload",
			mutate: func(t *testing.T, facts []nativeTestFact) {
				index := nativeFactIndex(t, facts, kind)
				facts[index].Payload = mutateNativeObjectAt(t, facts[index].Payload, path, func(values map[string]any) { values["unexpected"] = true })
			},
		})
	}
	addValue := func(kind, name string, path []string, field string, value any) {
		invalid = append(invalid, invalidCase{
			name: name, kind: kind, code: "invalid_payload",
			mutate: func(t *testing.T, facts []nativeTestFact) {
				index := nativeFactIndex(t, facts, kind)
				facts[index].Payload = mutateNativeObjectAt(t, facts[index].Payload, path, func(values map[string]any) { values[field] = value })
			},
		})
	}

	addObject(mcr.KindTaskCreated, "payload", nil, []string{"definition"}, []string{"definition"}, nil)
	addObject(mcr.KindRunRecorded, "payload", nil, []string{"started_at", "ended_at", "outcome"}, []string{"started_at", "ended_at", "outcome"}, nil)
	addObject(mcr.KindInputRegistered, "payload", nil, []string{"content"}, []string{"content"}, nil)
	addObject(mcr.KindArtifactRecorded, "payload", nil, []string{"content", "run"}, []string{"content"}, nil)
	addObject(mcr.KindClaimRecorded, "payload", nil, []string{"statement", "origin_artifact"}, []string{"statement"}, nil)
	addObject(mcr.KindSourceReferenceRecorded, "payload", nil, []string{"content", "anchor"}, []string{"content", "anchor"}, nil)
	addObject(mcr.KindEvidenceLinked, "payload", nil, []string{"claim", "source"}, []string{"claim", "source"}, nil)
	addObject(mcr.KindReviewRecorded, "payload", nil, []string{"subject", "outcome", "findings"}, []string{"subject", "outcome"}, nil)
	addObject(mcr.KindApprovalRecorded, "payload", nil, []string{"subject", "scope", "decision", "note"}, []string{"subject", "scope", "decision"}, map[string]any{"note": "fixture note"})
	addObject(mcr.KindPolicyDecisionRecorded, "payload", nil, []string{"subject", "action", "policy", "result"}, []string{"subject", "action", "policy", "result"}, nil)
	addObject(mcr.KindDeliveryRecorded, "payload", nil, []string{"artifacts", "format", "scope", "target"}, []string{"artifacts", "format", "scope", "target"}, nil)
	addObject(mcr.KindOpaqueRecorded, "payload", nil, []string{"kind", "data"}, []string{"kind", "data"}, nil)

	addObject(mcr.KindTaskCreated, "definition", []string{"definition"}, []string{"namespace", "id", "version", "locator", "sha256"}, []string{"namespace", "id", "version", "locator", "sha256"}, nil)
	for _, field := range []string{"namespace", "id", "version", "locator"} {
		addValue(mcr.KindTaskCreated, "definition/empty-"+field, []string{"definition"}, field, "")
	}

	type objectLocation struct {
		name string
		kind string
		path []string
	}
	contentRefs := []objectLocation{
		{name: "input-content", kind: mcr.KindInputRegistered, path: []string{"content"}},
		{name: "artifact-content", kind: mcr.KindArtifactRecorded, path: []string{"content"}},
		{name: "source-content", kind: mcr.KindSourceReferenceRecorded, path: []string{"content"}},
	}
	for _, ref := range contentRefs {
		addObject(ref.kind, ref.name, ref.path, []string{"locator", "sha256"}, []string{"locator", "sha256"}, nil)
		addValue(ref.kind, ref.name+"/empty-locator", ref.path, "locator", "")
	}

	factRefs := []objectLocation{
		{name: "artifact-run", kind: mcr.KindArtifactRecorded, path: []string{"run"}},
		{name: "claim-origin-artifact", kind: mcr.KindClaimRecorded, path: []string{"origin_artifact"}},
		{name: "evidence-claim", kind: mcr.KindEvidenceLinked, path: []string{"claim"}},
		{name: "evidence-source", kind: mcr.KindEvidenceLinked, path: []string{"source"}},
		{name: "review-subject", kind: mcr.KindReviewRecorded, path: []string{"subject"}},
		{name: "approval-subject", kind: mcr.KindApprovalRecorded, path: []string{"subject"}},
		{name: "policy-subject", kind: mcr.KindPolicyDecisionRecorded, path: []string{"subject"}},
	}
	for _, ref := range factRefs {
		addObject(ref.kind, ref.name, ref.path, []string{"fact_id", "record_hash"}, []string{"fact_id", "record_hash"}, nil)
		addValue(ref.kind, ref.name+"/empty-fact-id", ref.path, "fact_id", "")
	}

	hashLocations := []struct {
		name  string
		kind  string
		path  []string
		field string
	}{
		{name: "definition-sha256", kind: mcr.KindTaskCreated, path: []string{"definition"}, field: "sha256"},
		{name: "input-content-sha256", kind: mcr.KindInputRegistered, path: []string{"content"}, field: "sha256"},
		{name: "artifact-content-sha256", kind: mcr.KindArtifactRecorded, path: []string{"content"}, field: "sha256"},
		{name: "source-content-sha256", kind: mcr.KindSourceReferenceRecorded, path: []string{"content"}, field: "sha256"},
	}
	for _, ref := range factRefs {
		hashLocations = append(hashLocations, struct {
			name  string
			kind  string
			path  []string
			field string
		}{name: ref.name + "-record-hash", kind: ref.kind, path: ref.path, field: "record_hash"})
	}
	invalidHashes := []struct {
		name  string
		value string
	}{
		{name: "wrong-prefix", value: "SHA256:" + strings.Repeat("0", 64)},
		{name: "wrong-length", value: "sha256:" + strings.Repeat("0", 63)},
		{name: "non-hex", value: "sha256:" + strings.Repeat("0", 63) + "g"},
		{name: "uppercase-hex", value: "sha256:" + strings.Repeat("A", 64)},
	}
	for _, location := range hashLocations {
		for _, hash := range invalidHashes {
			addValue(location.kind, location.name+"/"+hash.name, location.path, location.field, hash.value)
		}
	}

	for _, timestamp := range []string{"started_at", "ended_at"} {
		addValue(mcr.KindRunRecorded, "run/invalid-"+timestamp, nil, timestamp, "not-a-time")
		addValue(mcr.KindRunRecorded, "run/non-utc-"+timestamp, nil, timestamp, "2026-01-02T04:00:00+01:00")
	}
	addValue(mcr.KindRunRecorded, "run/empty-outcome", nil, "outcome", "")
	invalid = append(invalid, invalidCase{
		name: "run/end-before-start", kind: mcr.KindRunRecorded, code: "invalid_payload",
		mutate: func(t *testing.T, facts []nativeTestFact) {
			index := nativeFactIndex(t, facts, mcr.KindRunRecorded)
			facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) {
				values["started_at"] = "2026-01-02T03:04:00Z"
				values["ended_at"] = "2026-01-02T03:03:59Z"
			})
		},
	})

	for _, scalar := range []struct {
		kind  string
		field string
	}{
		{mcr.KindClaimRecorded, "statement"},
		{mcr.KindSourceReferenceRecorded, "anchor"},
		{mcr.KindReviewRecorded, "outcome"},
		{mcr.KindApprovalRecorded, "scope"},
		{mcr.KindApprovalRecorded, "decision"},
		{mcr.KindPolicyDecisionRecorded, "action"},
		{mcr.KindPolicyDecisionRecorded, "policy"},
		{mcr.KindPolicyDecisionRecorded, "result"},
		{mcr.KindDeliveryRecorded, "format"},
		{mcr.KindDeliveryRecorded, "scope"},
		{mcr.KindDeliveryRecorded, "target"},
		{mcr.KindOpaqueRecorded, "kind"},
	} {
		addValue(scalar.kind, "payload/empty-"+scalar.field, nil, scalar.field, "")
	}
	for _, optional := range []struct {
		kind  string
		field string
	}{
		{mcr.KindArtifactRecorded, "run"},
		{mcr.KindClaimRecorded, "origin_artifact"},
		{mcr.KindReviewRecorded, "findings"},
		{mcr.KindApprovalRecorded, "note"},
	} {
		addValue(optional.kind, "payload/null-"+optional.field, nil, optional.field, nil)
	}
	addValue(mcr.KindReviewRecorded, "payload/empty-findings", nil, "findings", "")
	addValue(mcr.KindApprovalRecorded, "payload/empty-note", nil, "note", "")

	invalid = append(invalid,
		invalidCase{
			name: "delivery/empty-artifacts", kind: mcr.KindDeliveryRecorded, code: "invalid_payload",
			mutate: func(t *testing.T, facts []nativeTestFact) {
				index := nativeFactIndex(t, facts, mcr.KindDeliveryRecorded)
				facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) { values["artifacts"] = []any{} })
			},
		},
		invalidCase{
			name: "delivery/invalid-artifact-item", kind: mcr.KindDeliveryRecorded, code: "invalid_payload",
			mutate: func(t *testing.T, facts []nativeTestFact) {
				index := nativeFactIndex(t, facts, mcr.KindDeliveryRecorded)
				facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) { values["artifacts"].([]any)[0] = 1 })
			},
		},
		invalidCase{
			name: "delivery/duplicate-artifact-id", kind: mcr.KindDeliveryRecorded, code: "invalid_payload",
			mutate: func(t *testing.T, facts []nativeTestFact) {
				index := nativeFactIndex(t, facts, mcr.KindDeliveryRecorded)
				facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) {
					artifacts := values["artifacts"].([]any)
					artifacts[1].(map[string]any)["fact_id"] = artifacts[0].(map[string]any)["fact_id"]
				})
			},
		},
	)
	addArrayObject := func(label string) {
		for _, field := range []string{"fact_id", "record_hash"} {
			field := field
			invalid = append(invalid,
				invalidCase{
					name: label + "/missing-" + field, kind: mcr.KindDeliveryRecorded, code: "invalid_payload",
					mutate: func(t *testing.T, facts []nativeTestFact) {
						index := nativeFactIndex(t, facts, mcr.KindDeliveryRecorded)
						facts[index].Payload = mutateNativeArrayObjectAt(t, facts[index].Payload, "artifacts", 0, func(values map[string]any) { delete(values, field) })
					},
				},
				invalidCase{
					name: label + "/wrong-type-" + field, kind: mcr.KindDeliveryRecorded, code: "invalid_payload",
					mutate: func(t *testing.T, facts []nativeTestFact) {
						index := nativeFactIndex(t, facts, mcr.KindDeliveryRecorded)
						facts[index].Payload = mutateNativeArrayObjectAt(t, facts[index].Payload, "artifacts", 0, func(values map[string]any) { values[field] = 1 })
					},
				},
				invalidCase{
					name: label + "/duplicate-" + field, kind: mcr.KindDeliveryRecorded, code: "invalid_fact_envelope",
					mutate: func(t *testing.T, facts []nativeTestFact) {
						index := nativeFactIndex(t, facts, mcr.KindDeliveryRecorded)
						facts[index].Payload = duplicateNativeArrayObjectField(t, facts[index].Payload, "artifacts", 0, field)
					},
				},
			)
		}
		invalid = append(invalid, invalidCase{
			name: label + "/unknown-field", kind: mcr.KindDeliveryRecorded, code: "invalid_payload",
			mutate: func(t *testing.T, facts []nativeTestFact) {
				index := nativeFactIndex(t, facts, mcr.KindDeliveryRecorded)
				facts[index].Payload = mutateNativeArrayObjectAt(t, facts[index].Payload, "artifacts", 0, func(values map[string]any) { values["unexpected"] = true })
			},
		})
		addArrayValue := func(name, field string, value any) {
			invalid = append(invalid, invalidCase{
				name: label + "/" + name, kind: mcr.KindDeliveryRecorded, code: "invalid_payload",
				mutate: func(t *testing.T, facts []nativeTestFact) {
					index := nativeFactIndex(t, facts, mcr.KindDeliveryRecorded)
					facts[index].Payload = mutateNativeArrayObjectAt(t, facts[index].Payload, "artifacts", 0, func(values map[string]any) { values[field] = value })
				},
			})
		}
		addArrayValue("empty-fact-id", "fact_id", "")
		for _, hash := range invalidHashes {
			addArrayValue("record-hash-"+hash.name, "record_hash", hash.value)
		}
	}
	addArrayObject("delivery-artifact")

	nativeKinds := []string{
		mcr.KindTaskCreated, mcr.KindRunRecorded, mcr.KindInputRegistered, mcr.KindArtifactRecorded,
		mcr.KindClaimRecorded, mcr.KindSourceReferenceRecorded, mcr.KindEvidenceLinked, mcr.KindReviewRecorded,
		mcr.KindApprovalRecorded, mcr.KindPolicyDecisionRecorded, mcr.KindDeliveryRecorded, mcr.KindOpaqueRecorded,
	}
	for _, kind := range nativeKinds {
		addValue(mcr.KindOpaqueRecorded, "opaque/native-kind-"+kind, nil, "kind", kind)
	}
	for _, data := range []struct {
		name  string
		value any
	}{
		{name: "null-data", value: nil},
		{name: "array-data", value: []any{}},
		{name: "string-data", value: "external"},
		{name: "number-data", value: 1},
		{name: "boolean-data", value: true},
	} {
		addValue(mcr.KindOpaqueRecorded, "opaque/"+data.name, nil, "data", data.value)
	}

	for _, test := range invalid {
		t.Run(test.kind+"/"+test.name, func(t *testing.T) {
			header, facts := readNativeFixture(t)
			test.mutate(t, facts)
			assertNativeHistoryRejected(t, sealNativeLedger(t, header, facts), test.code)
		})
	}

	valid := []struct {
		name     string
		kind     string
		truncate bool
		mutate   func(*testing.T, []nativeTestFact)
	}{
		{name: "run/equal-timestamps", kind: mcr.KindRunRecorded, truncate: true, mutate: func(t *testing.T, facts []nativeTestFact) {
			index := nativeFactIndex(t, facts, mcr.KindRunRecorded)
			facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) { values["ended_at"] = values["started_at"] })
		}},
		{name: "artifact/omitted-run", kind: mcr.KindArtifactRecorded, truncate: true, mutate: func(t *testing.T, facts []nativeTestFact) {
			index := nativeFactIndex(t, facts, mcr.KindArtifactRecorded)
			facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) { delete(values, "run") })
		}},
		{name: "claim/omitted-origin-artifact", kind: mcr.KindClaimRecorded, truncate: true, mutate: func(t *testing.T, facts []nativeTestFact) {
			index := nativeFactIndex(t, facts, mcr.KindClaimRecorded)
			facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) { delete(values, "origin_artifact") })
		}},
		{name: "review/omitted-findings", kind: mcr.KindReviewRecorded, truncate: true, mutate: func(t *testing.T, facts []nativeTestFact) {
			index := nativeFactIndex(t, facts, mcr.KindReviewRecorded)
			facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) { delete(values, "findings") })
		}},
		{name: "approval/omitted-note", kind: mcr.KindApprovalRecorded, truncate: true, mutate: func(*testing.T, []nativeTestFact) {}},
		{name: "approval/present-note", kind: mcr.KindApprovalRecorded, truncate: true, mutate: func(t *testing.T, facts []nativeTestFact) {
			index := nativeFactIndex(t, facts, mcr.KindApprovalRecorded)
			facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) { values["note"] = "fixture note" })
		}},
		{name: "opaque/empty-object-data", kind: mcr.KindOpaqueRecorded, truncate: true, mutate: func(t *testing.T, facts []nativeTestFact) {
			index := nativeFactIndex(t, facts, mcr.KindOpaqueRecorded)
			facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) { values["data"] = map[string]any{} })
		}},
		{name: "opaque/open-object-data", kind: mcr.KindOpaqueRecorded, truncate: true, mutate: func(t *testing.T, facts []nativeTestFact) {
			index := nativeFactIndex(t, facts, mcr.KindOpaqueRecorded)
			facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) {
				values["kind"] = "vendor.custom"
				values["data"] = map[string]any{"native_kind": mcr.KindTaskCreated, "nested": map[string]any{"unexpected": true}}
			})
		}},
	}
	for _, test := range valid {
		t.Run("valid/"+test.name, func(t *testing.T) {
			header, facts := readNativeFixture(t)
			test.mutate(t, facts)
			if test.truncate {
				facts = facts[:nativeFactIndex(t, facts, test.kind)+1]
			}
			assertNativeHistoryAccepted(t, sealNativeLedger(t, header, facts))
		})
	}
}

func mutateNativeObjectAt(t *testing.T, payload json.RawMessage, path []string, mutate func(map[string]any)) json.RawMessage {
	t.Helper()
	if len(path) == 0 {
		return mutateNativePayload(t, payload, mutate)
	}
	return mutateNativePayload(t, payload, func(values map[string]any) {
		object, ok := values[path[0]].(map[string]any)
		if !ok {
			t.Fatalf("payload path %q is not an object", path[0])
		}
		mutateNativeObjectValueAt(t, object, path[1:], mutate)
	})
}

func mutateNativeObjectValueAt(t *testing.T, object map[string]any, path []string, mutate func(map[string]any)) {
	t.Helper()
	if len(path) == 0 {
		mutate(object)
		return
	}
	nested, ok := object[path[0]].(map[string]any)
	if !ok {
		t.Fatalf("payload path %q is not an object", path[0])
	}
	mutateNativeObjectValueAt(t, nested, path[1:], mutate)
}

func duplicateNativeObjectFieldAt(t *testing.T, payload json.RawMessage, path []string, field string) json.RawMessage {
	t.Helper()
	if len(path) == 0 {
		return duplicateNativePayloadField(t, payload, field)
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(payload, &values); err != nil {
		t.Fatal(err)
	}
	nested, ok := values[path[0]]
	if !ok {
		t.Fatalf("payload has no object %q", path[0])
	}
	values[path[0]] = duplicateNativeObjectFieldAt(t, nested, path[1:], field)
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mutateNativeArrayObjectAt(t *testing.T, payload json.RawMessage, field string, index int, mutate func(map[string]any)) json.RawMessage {
	t.Helper()
	return mutateNativePayload(t, payload, func(values map[string]any) {
		items, ok := values[field].([]any)
		if !ok || index >= len(items) {
			t.Fatalf("payload field %q has no item %d", field, index)
		}
		object, ok := items[index].(map[string]any)
		if !ok {
			t.Fatalf("payload field %q item %d is not an object", field, index)
		}
		mutate(object)
	})
}

func duplicateNativeArrayObjectField(t *testing.T, payload json.RawMessage, field string, index int, duplicate string) json.RawMessage {
	t.Helper()
	var values map[string]json.RawMessage
	if err := json.Unmarshal(payload, &values); err != nil {
		t.Fatal(err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(values[field], &items); err != nil || index >= len(items) {
		t.Fatalf("payload field %q has no item %d", field, index)
	}
	items[index] = duplicateNativePayloadField(t, items[index], duplicate)
	encodedItems, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	values[field] = encodedItems
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestNativeReferenceForwardAndCrossWorkspaceCollisionMatrix(t *testing.T) {
	type referenceCase struct {
		name      string
		kind      string
		field     string
		localID   string
		arrayItem bool
	}
	references := []referenceCase{
		{name: "artifact-run", kind: mcr.KindArtifactRecorded, field: "run", localID: "fact_fixture_02"},
		{name: "claim-origin", kind: mcr.KindClaimRecorded, field: "origin_artifact", localID: "fact_fixture_04"},
		{name: "evidence-claim", kind: mcr.KindEvidenceLinked, field: "claim", localID: "fact_fixture_05"},
		{name: "evidence-source", kind: mcr.KindEvidenceLinked, field: "source", localID: "fact_fixture_06"},
		{name: "review-subject", kind: mcr.KindReviewRecorded, field: "subject", localID: "fact_fixture_07"},
		{name: "approval-subject", kind: mcr.KindApprovalRecorded, field: "subject", localID: "fact_fixture_09"},
		{name: "policy-subject", kind: mcr.KindPolicyDecisionRecorded, field: "subject", localID: "fact_fixture_10"},
		{name: "delivery-artifact", kind: mcr.KindDeliveryRecorded, field: "artifacts", localID: "fact_fixture_04", arrayItem: true},
	}
	for _, reference := range references {
		reference := reference
		for _, mode := range []string{"forward", "cross-workspace-id-collision"} {
			mode := mode
			t.Run(reference.name+"/"+mode, func(t *testing.T) {
				header, facts := readNativeFixture(t)
				index := nativeFactIndex(t, facts, reference.kind)
				factID := "fact_fixture_14"
				if mode == "cross-workspace-id-collision" {
					factID = reference.localID
				}
				facts[index].Payload = mutateNativePayload(t, facts[index].Payload, func(values map[string]any) {
					ref := map[string]any{"fact_id": factID, "record_hash": nativeWrongHash}
					if reference.arrayItem {
						values[reference.field] = []any{ref}
					} else {
						values[reference.field] = ref
					}
				})
				ledger := sealNativeLedger(t, header, facts)
				assertNativeHistoryRejected(t, ledger, "invalid_payload")
			})
		}
	}
}

func TestNativeIdentityAndChainTamperMatrix(t *testing.T) {
	tests := []struct {
		name string
		code string
		make func(*nativeTestHeader, []nativeTestFact) []byte
	}{
		{
			name: "header-previous-hash",
			code: "invalid_header",
			make: func(header *nativeTestHeader, facts []nativeTestFact) []byte {
				header.PrevHash = nativeWrongHash
				return encodeNativeLedger(t, *header, facts)
			},
		},
		{
			name: "header-record-hash",
			code: "record_hash_mismatch",
			make: func(header *nativeTestHeader, facts []nativeTestFact) []byte {
				header.RecordHash = nativeWrongHash
				return encodeNativeLedger(t, *header, facts)
			},
		},
		{
			name: "fact-previous-hash",
			code: "previous_hash_mismatch",
			make: func(header *nativeTestHeader, facts []nativeTestFact) []byte {
				facts[1].PrevHash = nativeWrongHash
				return encodeNativeLedger(t, *header, facts)
			},
		},
		{
			name: "fact-record-hash",
			code: "record_hash_mismatch",
			make: func(header *nativeTestHeader, facts []nativeTestFact) []byte {
				facts[0].RecordHash = nativeWrongHash
				return encodeNativeLedger(t, *header, facts)
			},
		},
		{
			name: "fact-payload",
			code: "record_hash_mismatch",
			make: func(header *nativeTestHeader, facts []nativeTestFact) []byte {
				facts[0].Payload = bytes.Replace(facts[0].Payload, []byte("neutral-task"), []byte("altered-task"), 1)
				return encodeNativeLedger(t, *header, facts)
			},
		},
		{
			name: "fact-actor",
			code: "record_hash_mismatch",
			make: func(header *nativeTestHeader, facts []nativeTestFact) []byte {
				facts[0].Actor.ID = "tampered-host"
				return encodeNativeLedger(t, *header, facts)
			},
		},
		{
			name: "empty-fact-id-before-chain",
			code: "invalid_fact_envelope",
			make: func(header *nativeTestHeader, facts []nativeTestFact) []byte {
				facts[0].FactID = ""
				return sealNativeLedger(t, *header, facts)
			},
		},
		{
			name: "empty-task-id-before-chain",
			code: "invalid_fact_envelope",
			make: func(header *nativeTestHeader, facts []nativeTestFact) []byte {
				facts[0].TaskID = ""
				return sealNativeLedger(t, *header, facts)
			},
		},
		{
			name: "non-task-before-task-created",
			code: "invalid_payload",
			make: func(header *nativeTestHeader, facts []nativeTestFact) []byte {
				facts[1].TaskID = "task-not-created"
				return sealNativeLedger(t, *header, facts)
			},
		},
		{
			name: "duplicate-task-id",
			code: "duplicate_task",
			make: func(header *nativeTestHeader, facts []nativeTestFact) []byte {
				facts[len(facts)-1].TaskID = facts[0].TaskID
				return sealNativeLedger(t, *header, facts)
			},
		},
		{
			name: "duplicate-fact-id-before-chain",
			code: "duplicate_fact_id",
			make: func(header *nativeTestHeader, facts []nativeTestFact) []byte {
				facts[1].FactID = facts[0].FactID
				return sealNativeLedger(t, *header, facts)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header, facts := readNativeFixture(t)
			ledger := test.make(&header, facts)
			assertNativeHistoryRejected(t, ledger, test.code)
		})
	}
}

func readNativeFixture(t *testing.T) (nativeTestHeader, []nativeTestFact) {
	t.Helper()
	ledger, err := os.ReadFile("testdata/native-task.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(ledger, []byte("\n")), []byte("\n"))
	var header nativeTestHeader
	if err := json.Unmarshal(lines[0], &header); err != nil {
		t.Fatal(err)
	}
	facts := make([]nativeTestFact, len(lines)-1)
	for index := range facts {
		if err := json.Unmarshal(lines[index+1], &facts[index]); err != nil {
			t.Fatal(err)
		}
	}
	return header, facts
}

func nativeFactIndex(t *testing.T, facts []nativeTestFact, kind string) int {
	t.Helper()
	for index := range facts {
		if facts[index].Kind == kind {
			return index
		}
	}
	t.Fatalf("fixture has no Fact of Kind %q", kind)
	return -1
}

func mutateNativePayload(t *testing.T, payload json.RawMessage, mutate func(map[string]any)) json.RawMessage {
	t.Helper()
	var values map[string]any
	if err := json.Unmarshal(payload, &values); err != nil {
		t.Fatal(err)
	}
	mutate(values)
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func duplicateNativePayloadField(t *testing.T, payload json.RawMessage, field string) json.RawMessage {
	t.Helper()
	var values map[string]json.RawMessage
	if err := json.Unmarshal(payload, &values); err != nil {
		t.Fatal(err)
	}
	value, ok := values[field]
	if !ok {
		t.Fatalf("payload has no field %q", field)
	}
	duplicate := append([]byte(`{"`+field+`":`), value...)
	duplicate = append(duplicate, ',')
	duplicate = append(duplicate, payload[1:]...)
	return duplicate
}

func sealNativeLedger(t *testing.T, header nativeTestHeader, facts []nativeTestFact) []byte {
	t.Helper()
	header.PrevHash = nativeZeroHash
	header.RecordHash = nativeTestDigest(t, struct {
		RecordType    string `json:"record_type"`
		FormatVersion string `json:"format_version"`
		WorkspaceID   string `json:"workspace_id"`
		RecordedAt    string `json:"recorded_at"`
		PrevHash      string `json:"prev_hash"`
	}{header.RecordType, header.FormatVersion, header.WorkspaceID, header.RecordedAt, header.PrevHash})
	previous := header.RecordHash
	for index := range facts {
		facts[index].PrevHash = previous
		facts[index].RecordHash = nativeTestDigest(t, struct {
			RecordType string          `json:"record_type"`
			FactID     string          `json:"fact_id"`
			TaskID     string          `json:"task_id"`
			Kind       string          `json:"kind"`
			Actor      mcr.Actor       `json:"actor"`
			RecordedAt string          `json:"recorded_at"`
			Payload    json.RawMessage `json:"payload"`
			PrevHash   string          `json:"prev_hash"`
		}{facts[index].RecordType, facts[index].FactID, facts[index].TaskID, facts[index].Kind, facts[index].Actor, facts[index].RecordedAt, facts[index].Payload, facts[index].PrevHash})
		previous = facts[index].RecordHash
	}
	return encodeNativeLedger(t, header, facts)
}

func nativeTestDigest(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func encodeNativeLedger(t *testing.T, header nativeTestHeader, facts []nativeTestFact) []byte {
	t.Helper()
	var ledger bytes.Buffer
	encoder := json.NewEncoder(&ledger)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(header); err != nil {
		t.Fatal(err)
	}
	for _, fact := range facts {
		if err := encoder.Encode(fact); err != nil {
			t.Fatal(err)
		}
	}
	return ledger.Bytes()
}

func assertNativeHistoryAccepted(t *testing.T, ledger []byte) {
	t.Helper()
	root := t.TempDir()
	mcrDir := filepath.Join(root, ".mcr")
	if err := os.Mkdir(mcrDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(mcrDir, "events.jsonl")
	if err := os.WriteFile(ledgerPath, ledger, 0o600); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), ledger...)
	workspace, err := mcr.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := workspace.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if !verification.StructuralValid || verification.Integrity != mcr.IntegritySealedValid || len(verification.Diagnostics) != 0 {
		t.Fatalf("Verify = %#v, want accepted sealed native history", verification)
	}
	if _, err := workspace.Query(mcr.FactQuery{}); err != nil {
		t.Fatalf("Query valid history: %v", err)
	}
	if _, err := workspace.Replay(); err != nil {
		t.Fatalf("Replay valid history: %v", err)
	}
	after, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("valid native history was rewritten")
	}
}

func assertNativeHistoryRejected(t *testing.T, ledger []byte, code string) {
	t.Helper()
	root := t.TempDir()
	mcrDir := filepath.Join(root, ".mcr")
	if err := os.Mkdir(mcrDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(mcrDir, "events.jsonl")
	if err := os.WriteFile(ledgerPath, ledger, 0o600); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), ledger...)
	workspace, err := mcr.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	first, err := workspace.Verify()
	if err != nil {
		t.Fatal(err)
	}
	second, err := workspace.Verify()
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated Verify differs: %#v / %#v / %v", first, second, err)
	}
	if first.StructuralValid || first.Integrity != "" || len(first.Diagnostics) != 1 || first.Diagnostics[0].Code != code {
		t.Fatalf("Verify = %#v, want structural rejection code %q", first, code)
	}
	if _, err := workspace.Query(mcr.FactQuery{}); !errors.Is(err, mcr.ErrInvalidHistory) {
		t.Fatalf("Query error = %v, want ErrInvalidHistory", err)
	}
	if _, err := workspace.Replay(); !errors.Is(err, mcr.ErrInvalidHistory) {
		t.Fatalf("Replay error = %v, want ErrInvalidHistory", err)
	}
	if _, err := workspace.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrInvalidHistory) {
		t.Fatalf("Submit error = %v, want ErrInvalidHistory", err)
	}
	after, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("invalid native history was repaired or rewritten")
	}
}
