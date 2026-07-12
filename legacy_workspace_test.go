package mcr_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	mcr "github.com/Notyet1307/MCR-Core"
)

const firstLegacyEventHash = "sha256:a248bf58a7d763bd2030429a5af3bd8f78bf97a9af700055804f153886abc255"

func TestSealedLegacyVerifyUsesLiteralHashVector(t *testing.T) {
	workspace := copyLegacyWorkspace(t)
	ws, err := mcr.Open(workspace)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	verification, err := ws.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	assertJSONGolden(t, "testdata/legacy/sealed-valid.verify.json", verification)

	ledger, err := os.ReadFile(filepath.Join(workspace, ".mcr", "events.jsonl"))
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
	workspace := copyLegacyWorkspace(t)
	ledger, err := os.ReadFile("testdata/legacy/sealed-artifact-empty-run-id.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".mcr", "events.jsonl"), ledger, 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := mcr.Open(workspace)
	if err != nil {
		t.Fatal(err)
	}

	facts, err := ws.Query(mcr.FactQuery{FactID: "artifact@empty-run-id"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(facts) != 1 || facts[0].Kind != mcr.KindOpaqueRecorded || !facts[0].Opaque || facts[0].OpaqueReason != "legacy_underbound" {
		t.Fatalf("artifact with claimed but unbound run = %#v, want legacy_underbound opaque", facts)
	}
	if !bytes.Contains(facts[0].Payload, []byte(`"run_id":""`)) || !bytes.Contains(facts[0].Payload, []byte(`"additive_artifact":true`)) {
		t.Fatalf("source payload not preserved: %s", facts[0].Payload)
	}

	projection, err := ws.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(projection.Tasks) != 1 || len(projection.Tasks[0].Artifacts) != 0 || len(projection.Tasks[0].OpaqueFacts) != 1 {
		t.Fatalf("artifact replay projection = %#v", projection.Tasks)
	}
	opaque := projection.Tasks[0].OpaqueFacts[0]
	if opaque.SourceFactID != "artifact@empty-run-id" || opaque.Kind != "ArtifactAdded" || !bytes.Equal(opaque.Data, facts[0].Payload) {
		t.Fatalf("opaque replay = %#v, query payload = %s", opaque, facts[0].Payload)
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

func copyLegacyWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mcrDir := filepath.Join(root, ".mcr")
	if err := os.Mkdir(mcrDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ledger, err := os.ReadFile("testdata/legacy/sealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"events.jsonl": ledger,
		"state.json":   []byte("{\"legacy_cache\":true}\n"),
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
