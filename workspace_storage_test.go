package mcr_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	mcr "github.com/Notyet1307/MCR-Core"
)

func TestWorkspaceStorageContainmentAndPermissions(t *testing.T) {
	t.Run("create uses canonical private storage", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "workspace")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(parent, "workspace-link")
		if err := os.Symlink(root, alias); err != nil {
			t.Fatal(err)
		}
		workspace, err := mcr.Create(alias, "workspace-storage")
		if err != nil {
			t.Fatalf("Create through canonical alias: %v", err)
		}
		if _, err := workspace.Verify(); err != nil {
			t.Fatalf("Verify: %v", err)
		}
		assertMode(t, filepath.Join(root, ".mcr"), 0o700)
		assertMode(t, filepath.Join(root, ".mcr", "events.jsonl"), 0o600)
	})

	t.Run("half initialized storage conflicts", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Mkdir(filepath.Join(root, ".mcr"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := mcr.Create(root, "workspace-storage"); !errors.Is(err, mcr.ErrConflict) {
			t.Fatalf("Create half initialized storage error = %v", err)
		}
	})

	t.Run("symlinks and non regular ledgers reject", func(t *testing.T) {
		outside := t.TempDir()
		outsideLedger := filepath.Join(outside, "events.jsonl")
		if err := os.WriteFile(outsideLedger, []byte("outside\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		rootWithLinkedStorage := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(rootWithLinkedStorage, ".mcr")); err != nil {
			t.Fatal(err)
		}
		if _, err := mcr.Open(rootWithLinkedStorage); !errors.Is(err, mcr.ErrConflict) {
			t.Fatalf("Open linked .mcr error = %v", err)
		}

		rootWithLinkedLedger := t.TempDir()
		mcrDir := filepath.Join(rootWithLinkedLedger, ".mcr")
		if err := os.Mkdir(mcrDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideLedger, filepath.Join(mcrDir, "events.jsonl")); err != nil {
			t.Fatal(err)
		}
		if _, err := mcr.Open(rootWithLinkedLedger); !errors.Is(err, mcr.ErrConflict) {
			t.Fatalf("Open linked ledger error = %v", err)
		}

		rootWithDirectoryLedger := t.TempDir()
		mcrDir = filepath.Join(rootWithDirectoryLedger, ".mcr")
		if err := os.MkdirAll(filepath.Join(mcrDir, "events.jsonl"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := mcr.Open(rootWithDirectoryLedger); !errors.Is(err, mcr.ErrConflict) {
			t.Fatalf("Open directory ledger error = %v", err)
		}

		rootReplacedAfterOpen := t.TempDir()
		workspace, err := mcr.Create(rootReplacedAfterOpen, "workspace-storage")
		if err != nil {
			t.Fatal(err)
		}
		ledgerPath := filepath.Join(rootReplacedAfterOpen, ".mcr", "events.jsonl")
		if err := os.Remove(ledgerPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideLedger, ledgerPath); err != nil {
			t.Fatal(err)
		}
		if _, err := workspace.Verify(); !errors.Is(err, mcr.ErrConflict) {
			t.Fatalf("Verify replaced linked ledger error = %v", err)
		}
	})

	t.Run("canonical root replacement rejects every operation", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "workspace")
		target := filepath.Join(parent, "target")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		workspace, err := mcr.Create(root, "workspace-storage")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mcr.Create(target, "workspace-target"); err != nil {
			t.Fatal(err)
		}
		targetLedger := filepath.Join(target, ".mcr", "events.jsonl")
		before, err := os.ReadFile(targetLedger)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(root, filepath.Join(parent, "moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, root); err != nil {
			t.Fatal(err)
		}

		operations := []struct {
			name string
			run  func() error
		}{
			{"Submit", func() error { _, err := workspace.Submit(validTaskSubmission("escape-task")); return err }},
			{"Query", func() error { _, err := workspace.Query(mcr.FactQuery{}); return err }},
			{"Replay", func() error { _, err := workspace.Replay(); return err }},
			{"Verify", func() error { _, err := workspace.Verify(); return err }},
		}
		for _, operation := range operations {
			if err := operation.run(); !errors.Is(err, mcr.ErrConflict) {
				t.Errorf("%s after root replacement = %v, want ErrConflict", operation.name, err)
			}
		}
		after, err := os.ReadFile(targetLedger)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Fatal("replacement target ledger changed")
		}
	})

	t.Run("open preserves existing permissions", func(t *testing.T) {
		root := t.TempDir()
		workspace, err := mcr.Create(root, "workspace-storage")
		if err != nil {
			t.Fatal(err)
		}
		ledgerPath := filepath.Join(root, ".mcr", "events.jsonl")
		if err := os.Chmod(ledgerPath, 0o640); err != nil {
			t.Fatal(err)
		}
		opened, err := mcr.Open(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := opened.Verify(); err != nil {
			t.Fatal(err)
		}
		if _, err := workspace.Verify(); err != nil {
			t.Fatal(err)
		}
		assertMode(t, ledgerPath, 0o640)
	})
}

func TestWorkspaceStorageLocksFreshnessAndAtomicReplacement(t *testing.T) {
	lockedRoot := t.TempDir()
	rootLock := lockTestDirectory(t, lockedRoot, syscall.LOCK_SH)
	if _, err := mcr.Create(lockedRoot, "workspace-busy"); !errors.Is(err, mcr.ErrBusy) {
		t.Fatalf("Create under shared root lock error = %v", err)
	}
	unlockTestDirectory(t, rootLock)

	root := t.TempDir()
	first, err := mcr.Create(root, "workspace-storage")
	if err != nil {
		t.Fatal(err)
	}
	second, err := mcr.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Submit(validTaskSubmission("task-1")); err != nil {
		t.Fatal(err)
	}
	if facts, err := second.Query(mcr.FactQuery{}); err != nil || len(facts) != 1 {
		t.Fatalf("second handle did not observe completed write: %+v, %v", facts, err)
	}

	mcrDir := filepath.Join(root, ".mcr")
	shared := lockTestDirectory(t, mcrDir, syscall.LOCK_SH)
	if _, err := second.Query(mcr.FactQuery{}); err != nil {
		t.Fatalf("Query under another shared lock: %v", err)
	}
	if _, err := first.Submit(submission("task-1", mcr.KindOpaqueRecorded, map[string]any{"kind": "test.busy", "data": map[string]any{"value": 1}})); !errors.Is(err, mcr.ErrBusy) {
		t.Fatalf("Submit under shared lock error = %v", err)
	}
	unlockTestDirectory(t, shared)

	exclusive := lockTestDirectory(t, mcrDir, syscall.LOCK_EX)
	if _, err := second.Query(mcr.FactQuery{}); !errors.Is(err, mcr.ErrBusy) {
		t.Fatalf("Query under exclusive lock error = %v", err)
	}
	unlockTestDirectory(t, exclusive)

	ledgerPath := filepath.Join(mcrDir, "events.jsonl")
	if err := os.Chmod(ledgerPath, 0o640); err != nil {
		t.Fatal(err)
	}
	oldLedger, err := os.Open(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	before, err := io.ReadAll(oldLedger)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldLedger.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Submit(submission("task-1", mcr.KindOpaqueRecorded, map[string]any{"kind": "test.atomic", "data": map[string]any{"value": 2}})); err != nil {
		t.Fatal(err)
	}
	oldView, err := io.ReadAll(oldLedger)
	if closeErr := oldLedger.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldView, before) || bytes.Equal(after, before) || !bytes.HasPrefix(after, before) {
		t.Fatal("Submit did not expose atomic exact-old-or-new ledger views")
	}
	assertMode(t, ledgerPath, 0o640)
}

func TestWorkspaceStorageLockReleasedOnProcessExit(t *testing.T) {
	root := t.TempDir()
	workspace, err := mcr.Create(root, "workspace-storage")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestWorkspaceStorageLockHelper$")
	command.Env = append(os.Environ(), "MCR_TEST_LOCK_DIR="+filepath.Join(root, ".mcr"))
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("lock helper readiness = %q, %v", line, err)
	}
	if _, err := workspace.Verify(); !errors.Is(err, mcr.ErrBusy) {
		t.Fatalf("Verify while helper holds exclusive lock error = %v", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	if _, err := workspace.Verify(); err != nil {
		t.Fatalf("Verify after lock holder exit: %v", err)
	}
}

func TestWorkspaceConcurrentWritersAndLargeRecords(t *testing.T) {
	root := t.TempDir()
	workspace, err := mcr.Create(root, "workspace-concurrent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Submit(validTaskSubmission("task-1")); err != nil {
		t.Fatal(err)
	}

	largeValue := strings.Repeat("x", 1024*1024)
	if _, err := workspace.Submit(submission("task-1", mcr.KindOpaqueRecorded, map[string]any{"kind": "test.large", "data": map[string]any{"value": largeValue}})); err != nil {
		t.Fatalf("Submit large record: %v", err)
	}
	facts, err := workspace.Query(mcr.FactQuery{Kind: mcr.KindOpaqueRecorded})
	if err != nil || len(facts) != 1 || len(facts[0].Payload) < len(largeValue) {
		t.Fatalf("Query large record = %d Facts, payload bytes %d, %v", len(facts), len(facts[0].Payload), err)
	}

	const goroutineWriters = 6
	var wait sync.WaitGroup
	errorsByWriter := make(chan error, goroutineWriters)
	for i := range goroutineWriters {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			handle, err := mcr.Open(root)
			if err != nil {
				errorsByWriter <- err
				return
			}
			errorsByWriter <- submitWithBusyRetry(handle, "test.goroutine", index)
		}(i)
	}
	wait.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Fatalf("concurrent goroutine Submit: %v", err)
		}
	}

	const processWriters = 4
	commands := make([]*exec.Cmd, processWriters)
	for i := range commands {
		command := exec.Command(os.Args[0], "-test.run=^TestWorkspaceConcurrentSubmitHelper$")
		command.Env = append(os.Environ(), "MCR_TEST_SUBMIT_ROOT="+root, fmt.Sprintf("MCR_TEST_SUBMIT_INDEX=%d", i))
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		commands[i] = command
	}
	for _, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("concurrent process Submit: %v", err)
		}
	}

	facts, err = workspace.Query(mcr.FactQuery{})
	if err != nil {
		t.Fatal(err)
	}
	wantFacts := 2 + goroutineWriters + processWriters
	if len(facts) != wantFacts {
		t.Fatalf("concurrent Facts = %d, want %d", len(facts), wantFacts)
	}
	seen := make(map[string]bool, len(facts))
	for _, fact := range facts {
		if seen[fact.FactID] {
			t.Fatalf("duplicate Fact ID %q", fact.FactID)
		}
		seen[fact.FactID] = true
	}
	verification, err := workspace.Verify()
	if err != nil || verification.Integrity != mcr.IntegritySealedValid || verification.RecordCount != wantFacts+1 {
		t.Fatalf("Verify concurrent history = %+v, %v", verification, err)
	}
}

func TestLegacyStorageFreshnessLargeRecordAndNoReplace(t *testing.T) {
	unsealed, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	large := strings.Repeat("x", 1024*1024)
	largeLedger := mutateLegacyRecord(t, unsealed, 4, func(values map[string]any) {
		payload := values["payload"].(map[string]any)
		payload["large"] = large
	})
	root := writeLegacyWorkspace(t, largeLedger, []byte(`{"workspace_id":"workspace/unsealed","last_event_id":"extension+opaque"}`))
	workspace, err := mcr.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := workspace.Query(mcr.FactQuery{FactID: "extension+opaque"})
	if err != nil || len(facts) != 1 || len(facts[0].Payload) < len(large) {
		t.Fatalf("Query large legacy record = %#v, %v", facts, err)
	}
	before := snapshotFiles(t, root)
	invalid := mutateLegacyRecord(t, largeLedger, 2, func(values map[string]any) {
		values["event_hash"] = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	})
	if err := os.WriteFile(filepath.Join(root, ".mcr", "events.jsonl"), invalid, 0o644); err != nil {
		t.Fatal(err)
	}
	invalidBefore := snapshotFiles(t, root)
	verification, err := workspace.Verify()
	if err != nil || verification.Integrity != mcr.IntegrityPartialInvalid {
		t.Fatalf("fresh Verify = %#v, %v", verification, err)
	}
	if _, err := workspace.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrInvalidHistory) {
		t.Fatalf("Submit invalid legacy = %v", err)
	}
	if after := snapshotFiles(t, root); !reflect.DeepEqual(invalidBefore, after) {
		t.Fatal("invalid legacy Submit replaced storage")
	}
	if reflect.DeepEqual(before, invalidBefore) {
		t.Fatal("test did not replace ledger between operations")
	}
}

func TestLegacyStorageContainmentLocksAndNoReplace(t *testing.T) {
	sealed, err := os.ReadFile("testdata/legacy/sealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	unsealed, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	partial := mutateLegacyRecord(t, sealed, 2, func(values map[string]any) { delete(values, "event_hash") })
	tests := []struct {
		name      string
		ledger    []byte
		state     []byte
		integrity string
		accepted  bool
	}{
		{
			name:      "sealed-valid",
			ledger:    sealed,
			state:     []byte(`{"workspace_id":"workspace/opaque","last_event_id":"unknown+extension"}`),
			integrity: mcr.IntegritySealedValid,
			accepted:  true,
		},
		{
			name:      "unsealed",
			ledger:    unsealed,
			state:     []byte(`{"workspace_id":"workspace/unsealed","last_event_id":"extension+opaque"}`),
			integrity: mcr.IntegrityUnsealed,
			accepted:  true,
		},
		{
			name:      "partial-invalid",
			ledger:    partial,
			state:     []byte(`{"workspace_id":"workspace/opaque","last_event_id":"unknown+extension"}`),
			integrity: mcr.IntegrityPartialInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := writeLegacyWorkspace(t, test.ledger, test.state)
			alias := filepath.Join(t.TempDir(), "workspace-alias")
			if err := os.Symlink(root, alias); err != nil {
				t.Fatal(err)
			}
			workspace, err := mcr.Open(alias)
			if err != nil {
				t.Fatalf("Open through contained canonical alias: %v", err)
			}
			before := snapshotFiles(t, root)
			mcrDir := filepath.Join(root, ".mcr")
			shared := lockTestDirectory(t, mcrDir, syscall.LOCK_SH)
			verification, err := workspace.Verify()
			if err != nil || verification.Integrity != test.integrity {
				t.Fatalf("Verify under shared lock = %#v, %v", verification, err)
			}
			if _, err := workspace.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrBusy) {
				t.Fatalf("Submit under shared lock = %v, want ErrBusy", err)
			}
			unlockTestDirectory(t, shared)

			exclusive := lockTestDirectory(t, mcrDir, syscall.LOCK_EX)
			if _, err := workspace.Verify(); !errors.Is(err, mcr.ErrBusy) {
				t.Fatalf("Verify under exclusive lock = %v, want ErrBusy", err)
			}
			unlockTestDirectory(t, exclusive)

			if test.accepted {
				if _, err := workspace.Query(mcr.FactQuery{}); err != nil {
					t.Fatalf("accepted Query: %v", err)
				}
				if _, err := workspace.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrReadOnly) {
					t.Fatalf("accepted Submit = %v, want ErrReadOnly", err)
				}
			} else {
				if _, err := workspace.Query(mcr.FactQuery{}); !errors.Is(err, mcr.ErrInvalidHistory) {
					t.Fatalf("invalid Query = %v, want ErrInvalidHistory", err)
				}
				if _, err := workspace.Submit(mcr.Submission{}); !errors.Is(err, mcr.ErrInvalidHistory) {
					t.Fatalf("invalid Submit = %v, want ErrInvalidHistory", err)
				}
			}
			if after := snapshotFiles(t, root); !reflect.DeepEqual(before, after) {
				t.Fatalf("legacy storage changed\nbefore: %#v\nafter: %#v", before, after)
			}
		})
	}

	t.Run("legacy-ledger-symlink-and-non-regular", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "legacy-events.jsonl")
		if err := os.WriteFile(outside, sealed, 0o600); err != nil {
			t.Fatal(err)
		}
		linkedRoot := t.TempDir()
		linkedMCR := filepath.Join(linkedRoot, ".mcr")
		if err := os.Mkdir(linkedMCR, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(linkedMCR, "events.jsonl")); err != nil {
			t.Fatal(err)
		}
		if _, err := mcr.Open(linkedRoot); !errors.Is(err, mcr.ErrConflict) {
			t.Fatalf("Open linked legacy ledger = %v, want ErrConflict", err)
		}

		directoryRoot := t.TempDir()
		if err := os.MkdirAll(filepath.Join(directoryRoot, ".mcr", "events.jsonl"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := mcr.Open(directoryRoot); !errors.Is(err, mcr.ErrConflict) {
			t.Fatalf("Open non-regular legacy ledger = %v, want ErrConflict", err)
		}
	})
}

func TestWorkspaceConcurrentSubmitHelper(t *testing.T) {
	root := os.Getenv("MCR_TEST_SUBMIT_ROOT")
	if root == "" {
		return
	}
	handle, err := mcr.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := submitWithBusyRetry(handle, "test.process", os.Getenv("MCR_TEST_SUBMIT_INDEX")); err != nil {
		t.Fatal(err)
	}
}

func submitWithBusyRetry(workspace *mcr.Workspace, kind string, value any) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := workspace.Submit(submission("task-1", mcr.KindOpaqueRecorded, map[string]any{"kind": kind, "data": map[string]any{"value": value}}))
		if !errors.Is(err, mcr.ErrBusy) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWorkspaceStorageLockHelper(t *testing.T) {
	directory := os.Getenv("MCR_TEST_LOCK_DIR")
	if directory == "" {
		return
	}
	lockTestDirectory(t, directory, syscall.LOCK_EX)
	fmt.Fprintln(os.Stdout, "locked")
	select {}
}

func lockTestDirectory(t *testing.T, path string, operation int) *os.File {
	t.Helper()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(directory.Fd()), operation|syscall.LOCK_NB); err != nil {
		directory.Close()
		t.Fatal(err)
	}
	return directory
}

func unlockTestDirectory(t *testing.T, directory *os.File) {
	t.Helper()
	if err := syscall.Flock(int(directory.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode for %s = %04o, want %04o", path, got, want)
	}
}
