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

func TestWorkspaceOperationsRejectRootReplacementAfterLock(t *testing.T) {
	taskPayload := json.RawMessage(`{"definition":{"namespace":"example.test","id":"neutral-task","version":"v1","locator":"urn:example:neutral-task:v1","sha256":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}`)
	operations := []struct {
		name string
		run  func(*Workspace) error
	}{
		{"Submit", func(workspace *Workspace) error {
			_, err := workspace.Submit(Submission{TaskID: "task-1", Actor: Actor{Type: "integration", ID: "test-host"}, Kind: KindTaskCreated, Payload: taskPayload})
			return err
		}},
		{"Query", func(workspace *Workspace) error { _, err := workspace.Query(FactQuery{}); return err }},
		{"Replay", func(workspace *Workspace) error { _, err := workspace.Replay(); return err }},
		{"Verify", func(workspace *Workspace) error { _, err := workspace.Verify(); return err }},
	}
	phases := []struct {
		name    string
		install func(func() error)
		reset   func()
	}{
		{"after lock", func(mutate func() error) { afterWorkspaceLock = mutate }, func() { afterWorkspaceLock = func() error { return nil } }},
		{"before IO", func(mutate func() error) { beforeWorkspaceIO = mutate }, func() { beforeWorkspaceIO = func() error { return nil } }},
		{"during final open", func(mutate func() error) {
			beforeRootRegularOpen = func(name string) error {
				if name == "events.jsonl" {
					return mutate()
				}
				return nil
			}
		}, func() { beforeRootRegularOpen = func(string) error { return nil } }},
	}
	for _, phase := range phases {
		t.Run(phase.name, func(t *testing.T) {
			for _, operation := range operations {
				t.Run(operation.name, func(t *testing.T) {
					parent := t.TempDir()
					root := filepath.Join(parent, "workspace")
					target := filepath.Join(parent, "target")
					if err := os.Mkdir(root, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(target, 0o700); err != nil {
						t.Fatal(err)
					}
					workspace, err := Create(root, "workspace-original")
					if err != nil {
						t.Fatal(err)
					}
					if _, err := Create(target, "workspace-target"); err != nil {
						t.Fatal(err)
					}
					targetLedger := filepath.Join(target, ".mcr", "events.jsonl")
					before, err := os.ReadFile(targetLedger)
					if err != nil {
						t.Fatal(err)
					}
					phase.install(func() error {
						if err := os.Rename(root, filepath.Join(parent, "moved")); err != nil {
							return err
						}
						return os.Symlink(target, root)
					})
					defer phase.reset()

					if err := operation.run(workspace); !errors.Is(err, ErrConflict) {
						t.Fatalf("%s %s root replacement = %v, want ErrConflict", operation.name, phase.name, err)
					}
					after, err := os.ReadFile(targetLedger)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(after, before) {
						t.Fatal("replacement target ledger changed")
					}
				})
			}
		})
	}
}

func TestWorkspaceOperationsRejectLedgerSymlinkRace(t *testing.T) {
	root := t.TempDir()
	workspace, err := Create(root, "workspace-original")
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(root, ".mcr", "events.jsonl")
	before, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	mutated := false
	beforeRootRegularOpen = func(name string) error {
		if name != "events.jsonl" || mutated {
			return nil
		}
		mutated = true
		moved := filepath.Join(root, ".mcr", "moved-events.jsonl")
		if err := os.Rename(ledgerPath, moved); err != nil {
			return err
		}
		return os.Symlink("moved-events.jsonl", ledgerPath)
	}
	defer func() { beforeRootRegularOpen = func(string) error { return nil } }()

	if _, err := workspace.Verify(); !errors.Is(err, ErrConflict) {
		t.Fatalf("Verify ledger symlink race = %v, want ErrConflict", err)
	}
	after, err := os.ReadFile(filepath.Join(root, ".mcr", "moved-events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("ledger changed during symlink race")
	}
}

func TestSubmitRejectsWorkspaceReplacementBeforeRename(t *testing.T) {
	taskPayload := json.RawMessage(`{"definition":{"namespace":"example.test","id":"neutral-task","version":"v1","locator":"urn:example:neutral-task:v1","sha256":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}`)
	for _, replace := range []string{"root", "storage"} {
		t.Run(replace, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "workspace")
			target := filepath.Join(parent, "target")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			workspace, err := Create(root, "workspace-original")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Create(target, "workspace-target"); err != nil {
				t.Fatal(err)
			}
			targetLedger := filepath.Join(target, ".mcr", "events.jsonl")
			before, err := os.ReadFile(targetLedger)
			if err != nil {
				t.Fatal(err)
			}
			beforeLedgerReplace = func() error {
				if replace == "root" {
					if err := os.Rename(root, filepath.Join(parent, "moved")); err != nil {
						return err
					}
					return os.Symlink(target, root)
				}
				storage := filepath.Join(root, ".mcr")
				if err := os.Rename(storage, filepath.Join(root, "moved-storage")); err != nil {
					return err
				}
				return os.Symlink(filepath.Join(target, ".mcr"), storage)
			}
			defer func() { beforeLedgerReplace = func() error { return nil } }()

			_, err = workspace.Submit(Submission{TaskID: "task-1", Actor: Actor{Type: "integration", ID: "test-host"}, Kind: KindTaskCreated, Payload: taskPayload})
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("Submit after %s replacement = %v, want ErrConflict", replace, err)
			}
			after, err := os.ReadFile(targetLedger)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("replacement target ledger changed")
			}
		})
	}
}

func TestWorkspaceOperationsRejectEscapingLedgerSymlinkRace(t *testing.T) {
	root := t.TempDir()
	workspace, err := Create(root, "workspace-original")
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(root, ".mcr", "events.jsonl")
	moved := filepath.Join(root, ".mcr", "moved-events.jsonl")
	outside := filepath.Join(t.TempDir(), "outside-events.jsonl")
	if err := os.WriteFile(outside, []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mutated := false
	beforeRootRegularOpen = func(name string) error {
		if name != "events.jsonl" || mutated {
			return nil
		}
		mutated = true
		if err := os.Rename(ledgerPath, moved); err != nil {
			return err
		}
		return os.Symlink(outside, ledgerPath)
	}
	defer func() { beforeRootRegularOpen = func(string) error { return nil } }()

	if _, err := workspace.Verify(); !errors.Is(err, ErrConflict) {
		t.Fatalf("Verify escaping ledger symlink race = %v, want ErrConflict", err)
	}
}

func TestWorkspaceOperationsPreserveDanglingLedgerCause(t *testing.T) {
	root := t.TempDir()
	workspace, err := Create(root, "workspace-original")
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(root, ".mcr", "events.jsonl")
	mutated := false
	beforeRootRegularOpen = func(name string) error {
		if name != "events.jsonl" || mutated {
			return nil
		}
		mutated = true
		if err := os.Rename(ledgerPath, filepath.Join(root, ".mcr", "moved-events.jsonl")); err != nil {
			return err
		}
		return os.Symlink("missing-events.jsonl", ledgerPath)
	}
	defer func() { beforeRootRegularOpen = func(string) error { return nil } }()

	_, err = workspace.Verify()
	if !errors.Is(err, ErrConflict) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Verify dangling ledger race = %v, want ErrConflict and os.ErrNotExist", err)
	}
}

func TestLegacyCacheReplacementRaceIsUnreadable(t *testing.T) {
	rootPath := t.TempDir()
	statePath := filepath.Join(rootPath, "state.json")
	if err := os.WriteFile(statePath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	mutated := false
	beforeRootRegularOpen = func(name string) error {
		if name != "state.json" || mutated {
			return nil
		}
		mutated = true
		if err := os.Rename(statePath, filepath.Join(rootPath, "old-state.json")); err != nil {
			return err
		}
		return os.WriteFile(statePath, []byte("{}\n"), 0o600)
	}
	defer func() { beforeRootRegularOpen = func(string) error { return nil } }()

	diagnostics := inspectLegacyCache(root, history{}, Verification{})
	if len(diagnostics) != 1 || diagnostics[0].Code != "legacy_cache_unreadable" {
		t.Fatalf("cache replacement diagnostics = %#v", diagnostics)
	}
}

func TestRootEntryErrorPreservesOSCause(t *testing.T) {
	err := rootEntryError("events.jsonl", os.ErrPermission)
	if !errors.Is(err, os.ErrPermission) || errors.Is(err, ErrConflict) {
		t.Fatalf("permission error classification = %v", err)
	}
}
