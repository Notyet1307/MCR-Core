package mcr

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSubmitFailureBeforeReplacePreservesLedger(t *testing.T) {
	root := t.TempDir()
	workspace, err := Create(root, "workspace-failure")
	if err != nil {
		t.Fatal(err)
	}
	taskPayload, err := json.Marshal(map[string]any{"definition": map[string]string{
		"namespace": "example.test", "id": "neutral-task", "version": "v1", "locator": "urn:example:neutral-task:v1",
		"sha256": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Submit(Submission{TaskID: "task-1", Actor: Actor{Type: "integration", ID: "test-host"}, Kind: KindTaskCreated, Payload: taskPayload}); err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(root, ".mcr", "events.jsonl")
	before, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected pre-replace failure")
	beforeLedgerReplace = func() error { return injected }
	defer func() { beforeLedgerReplace = func() error { return nil } }()
	payload := json.RawMessage(`{"kind":"test.failure","data":{"value":1}}`)
	if _, err := workspace.Submit(Submission{TaskID: "task-1", Actor: Actor{Type: "integration", ID: "test-host"}, Kind: KindOpaqueRecorded, Payload: payload}); !errors.Is(err, injected) {
		t.Fatalf("Submit injected failure error = %v", err)
	}
	after, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("pre-replace failure changed authoritative ledger bytes")
	}
	entries, err := os.ReadDir(filepath.Dir(ledgerPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "events.jsonl" {
		t.Fatalf("pre-replace failure left storage artifacts: %+v", entries)
	}
}
