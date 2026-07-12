package mcr_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	mcr "github.com/Notyet1307/MCR-Core"
)

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validTaskSubmission(taskID string) mcr.Submission {
	payload, err := json.Marshal(map[string]any{
		"definition": map[string]string{
			"namespace": "example.test",
			"id":        "neutral-task",
			"version":   "v1",
			"locator":   "urn:example:neutral-task:v1",
			"sha256":    digest,
		},
	})
	if err != nil {
		panic(err)
	}
	return mcr.Submission{
		TaskID:  taskID,
		Actor:   mcr.Actor{Type: "integration", ID: "test-host"},
		Kind:    mcr.KindTaskCreated,
		Payload: payload,
	}
}

func TestNativeTaskWorkspaceRoundTrip(t *testing.T) {
	root := t.TempDir()
	workspace, err := mcr.Create(root, "workspace-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	fact, err := workspace.Submit(validTaskSubmission("task-1"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if fact.FactID == "" || fact.RecordedAt.IsZero() || fact.PrevHash == "" || fact.RecordHash == "" {
		t.Fatalf("Core-owned metadata missing: %+v", fact)
	}

	facts, err := workspace.Query(mcr.FactQuery{TaskID: "task-1", Kind: mcr.KindTaskCreated})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(facts) != 1 || facts[0].FactID != fact.FactID {
		t.Fatalf("Query = %+v, want submitted fact", facts)
	}

	projection, err := workspace.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(projection.Tasks) != 1 || projection.Tasks[0].TaskID != "task-1" || projection.Tasks[0].SourceFactID != fact.FactID {
		t.Fatalf("Replay = %+v", projection)
	}

	verification, err := workspace.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verification.StructuralValid || verification.Integrity != mcr.IntegritySealedValid || verification.RecordCount != 2 || verification.LastRecordID != fact.FactID {
		t.Fatalf("Verify = %+v", verification)
	}

	opened, err := mcr.Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	openedFacts, err := opened.Query(mcr.FactQuery{})
	if err != nil || len(openedFacts) != 1 || openedFacts[0].RecordHash != fact.RecordHash {
		t.Fatalf("opened Query = %+v, %v", openedFacts, err)
	}

	ledger, err := os.ReadFile(filepath.Join(root, ".mcr", "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(ledger), "\n") || len(strings.Split(strings.TrimSuffix(string(ledger), "\n"), "\n")) != 2 {
		t.Fatalf("ledger is not exact two-line JSONL: %q", ledger)
	}
}

func TestCreateAndOpenAreDistinct(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := mcr.Create(missing, "workspace-1"); !errors.Is(err, mcr.ErrNotFound) {
		t.Fatalf("Create missing error = %v", err)
	}
	if _, err := mcr.Open(missing); !errors.Is(err, mcr.ErrNotFound) {
		t.Fatalf("Open missing error = %v", err)
	}

	root := t.TempDir()
	if _, err := mcr.Create(root, "workspace-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := mcr.Create(root, "workspace-2"); !errors.Is(err, mcr.ErrConflict) {
		t.Fatalf("second Create error = %v", err)
	}
}

func TestInvalidSubmissionsLeaveLedgerUnchanged(t *testing.T) {
	tests := []struct {
		name       string
		submission mcr.Submission
	}{
		{"missing definition", mcr.Submission{TaskID: "task-1", Actor: mcr.Actor{Type: "integration", ID: "host"}, Kind: mcr.KindTaskCreated, Payload: json.RawMessage(`{}`)}},
		{"unknown payload field", mcr.Submission{TaskID: "task-1", Actor: mcr.Actor{Type: "integration", ID: "host"}, Kind: mcr.KindTaskCreated, Payload: json.RawMessage(`{"definition":{"namespace":"n","id":"i","version":"v","locator":"l","sha256":"` + digest + `"},"extra":true}`)}},
		{"wrong definition type", mcr.Submission{TaskID: "task-1", Actor: mcr.Actor{Type: "integration", ID: "host"}, Kind: mcr.KindTaskCreated, Payload: json.RawMessage(`{"definition":"wrong"}`)}},
		{"empty namespace", mcr.Submission{TaskID: "task-1", Actor: mcr.Actor{Type: "integration", ID: "host"}, Kind: mcr.KindTaskCreated, Payload: json.RawMessage(`{"definition":{"namespace":"","id":"i","version":"v","locator":"l","sha256":"` + digest + `"}}`)}},
		{"invalid digest", mcr.Submission{TaskID: "task-1", Actor: mcr.Actor{Type: "integration", ID: "host"}, Kind: mcr.KindTaskCreated, Payload: json.RawMessage(`{"definition":{"namespace":"n","id":"i","version":"v","locator":"l","sha256":"ABC"}}`)}},
		{"duplicate field", mcr.Submission{TaskID: "task-1", Actor: mcr.Actor{Type: "integration", ID: "host"}, Kind: mcr.KindTaskCreated, Payload: json.RawMessage(`{"definition":{"namespace":"n","namespace":"n2","id":"i","version":"v","locator":"l","sha256":"` + digest + `"}}`)}},
		{"non-task before creation", mcr.Submission{TaskID: "task-1", Actor: mcr.Actor{Type: "integration", ID: "host"}, Kind: "run.recorded", Payload: json.RawMessage(`{}`)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			workspace, err := mcr.Create(root, "workspace-1")
			if err != nil {
				t.Fatal(err)
			}
			ledgerPath := filepath.Join(root, ".mcr", "events.jsonl")
			before, err := os.ReadFile(ledgerPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := workspace.Submit(test.submission); !errors.Is(err, mcr.ErrInvalidSubmission) {
				t.Fatalf("Submit error = %v", err)
			}
			after, err := os.ReadFile(ledgerPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatal("rejected submission changed the ledger")
			}
		})
	}
}

func TestDuplicateTaskRejectsAndQueryFiltersWithAND(t *testing.T) {
	root := t.TempDir()
	workspace, err := mcr.Create(root, "workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	first, err := workspace.Submit(validTaskSubmission("task-1"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := workspace.Submit(validTaskSubmission("task-2"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Submit(validTaskSubmission("task-1")); !errors.Is(err, mcr.ErrInvalidSubmission) {
		t.Fatalf("duplicate task error = %v", err)
	}

	all, err := workspace.Query(mcr.FactQuery{})
	if err != nil || len(all) != 2 || all[0].FactID != first.FactID || all[1].FactID != second.FactID {
		t.Fatalf("unfiltered Query = %+v, %v", all, err)
	}
	filtered, err := workspace.Query(mcr.FactQuery{FactID: second.FactID, TaskID: "task-2", Kind: mcr.KindTaskCreated})
	if err != nil || len(filtered) != 1 || filtered[0].FactID != second.FactID {
		t.Fatalf("AND Query = %+v, %v", filtered, err)
	}
	none, err := workspace.Query(mcr.FactQuery{FactID: first.FactID, TaskID: "task-2"})
	if err != nil || len(none) != 0 {
		t.Fatalf("mismatched AND Query = %+v, %v", none, err)
	}
}

func TestVerifyDiagnosesTamperingWithoutRepair(t *testing.T) {
	root := t.TempDir()
	workspace, err := mcr.Create(root, "workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Submit(validTaskSubmission("task-1")); err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(root, ".mcr", "events.jsonl")
	tampered, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered = []byte(strings.Replace(string(tampered), "neutral-task", "altered-task", 1))
	if err := os.WriteFile(ledgerPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	opened, err := mcr.Open(root)
	if err != nil {
		t.Fatalf("Open malformed history: %v", err)
	}
	verification, err := opened.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if verification.Integrity == mcr.IntegritySealedValid || len(verification.Diagnostics) != 1 || verification.Diagnostics[0].Code != "record_hash_mismatch" {
		t.Fatalf("Verify = %+v", verification)
	}
	if _, err := opened.Query(mcr.FactQuery{}); !errors.Is(err, mcr.ErrInvalidHistory) {
		t.Fatalf("Query malformed history error = %v", err)
	}
	after, err := os.ReadFile(ledgerPath)
	if err != nil || string(after) != string(tampered) {
		t.Fatal("Verify repaired or rewrote the ledger")
	}
}

func TestNeutralSealedFixture(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "native-task.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	mcrDir := filepath.Join(root, ".mcr")
	if err := os.Mkdir(mcrDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mcrDir, "events.jsonl"), fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := mcr.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := workspace.Verify()
	if err != nil || verification.Integrity != mcr.IntegritySealedValid || verification.LastRecordID != "fact_fixture_01" {
		t.Fatalf("Verify fixture = %+v, %v", verification, err)
	}
	facts, err := workspace.Query(mcr.FactQuery{})
	if err != nil || len(facts) != 1 || facts[0].TaskID != "task-neutral" {
		t.Fatalf("Query fixture = %+v, %v", facts, err)
	}
	projection, err := workspace.Replay()
	if err != nil || len(projection.Tasks) != 1 || projection.Tasks[0].Definition.ID != "neutral-task" {
		t.Fatalf("Replay fixture = %+v, %v", projection, err)
	}
}

func TestCLIContracts(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "mcr")
	build := exec.Command("go", "build", "-o", bin, "./cmd/mcr")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}

	root := t.TempDir()
	if _, err := mcr.Create(root, "workspace-cli"); err != nil {
		t.Fatal(err)
	}
	payload := `{"task_id":"task-cli","actor":{"type":"integration","id":"cli-test"},"kind":"task.created","payload":{"definition":{"namespace":"example.test","id":"cli-task","version":"v1","locator":"urn:example:cli-task:v1","sha256":"` + digest + `"}}}`
	stdout, stderr, exit := runCLI(bin, payload, "submit", "--workspace", root)
	if exit != 0 || stderr != "" {
		t.Fatalf("submit exit=%d stderr=%q stdout=%q", exit, stderr, stdout)
	}
	var fact mcr.Fact
	if err := json.Unmarshal([]byte(stdout), &fact); err != nil || fact.TaskID != "task-cli" {
		t.Fatalf("submit stdout = %q, %v", stdout, err)
	}

	duplicate := `{"task_id":"task-shadow","task_id":"task-duplicate","actor":{"type":"integration","id":"cli-test"},"kind":"task.created","payload":{"definition":{"namespace":"example.test","id":"duplicate","version":"v1","locator":"urn:example:duplicate:v1","sha256":"` + digest + `"}}}`
	duplicateOut, duplicateErr, duplicateExit := runCLI(bin, duplicate, "submit", "--workspace", root)
	if duplicateExit == 0 || duplicateOut != "" || duplicateErr == "" {
		t.Fatalf("duplicate submission exit=%d stderr=%q stdout=%q", duplicateExit, duplicateErr, duplicateOut)
	}

	for _, command := range []string{"query", "replay", "verify"} {
		stdout, stderr, exit = runCLI(bin, "", command, "--workspace", root)
		if exit != 0 || stderr != "" || !json.Valid([]byte(stdout)) {
			t.Fatalf("%s exit=%d stderr=%q stdout=%q", command, exit, stderr, stdout)
		}
	}

	stdout, stderr, exit = runCLI(bin, "", "query")
	if exit == 0 || stdout != "" || stderr == "" || !json.Valid([]byte(stderr)) {
		t.Fatalf("missing workspace exit=%d stderr=%q stdout=%q", exit, stderr, stdout)
	}
}

func runCLI(bin, stdin string, args ...string) (string, string, int) {
	command := exec.Command(bin, args...)
	command.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err == nil {
		return stdout.String(), stderr.String(), 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return stdout.String(), stderr.String(), exitError.ExitCode()
	}
	return stdout.String(), stderr.String(), -1
}
