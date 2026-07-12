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
	"time"

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

func submission(taskID, kind string, payload any) mcr.Submission {
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return mcr.Submission{TaskID: taskID, Actor: mcr.Actor{Type: "integration", ID: "test-host"}, Kind: kind, Payload: raw}
}

func TestRunRoundTrip(t *testing.T) {
	workspace, err := mcr.Create(t.TempDir(), "workspace-runs")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := workspace.Submit(validTaskSubmission("task-1")); err != nil {
		t.Fatalf("Submit task: %v", err)
	}

	run, err := workspace.Submit(mcr.Submission{
		TaskID:  "task-1",
		Actor:   mcr.Actor{Type: "integration", ID: "test-host"},
		Kind:    mcr.KindRunRecorded,
		Payload: json.RawMessage(`{"started_at":"2026-07-12T08:00:00Z","ended_at":"2026-07-12T08:01:00Z","outcome":"completed"}`),
	})
	if err != nil {
		t.Fatalf("Submit run: %v", err)
	}
	facts, err := workspace.Query(mcr.FactQuery{TaskID: "task-1", Kind: mcr.KindRunRecorded})
	if err != nil || len(facts) != 1 || facts[0].FactID != run.FactID {
		t.Fatalf("Query runs = %+v, %v", facts, err)
	}
	projection, err := workspace.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	wantStart := time.Date(2026, 7, 12, 8, 0, 0, 0, time.UTC)
	if len(projection.Tasks) != 1 || len(projection.Tasks[0].Runs) != 1 {
		t.Fatalf("Replay = %+v", projection)
	}
	got := projection.Tasks[0].Runs[0]
	if got.SourceFactID != run.FactID || !got.StartedAt.Equal(wantStart) || got.Outcome != "completed" {
		t.Fatalf("projected Run = %+v", got)
	}
}

func TestRegisteredInputsAndArtifactsRoundTrip(t *testing.T) {
	workspace, err := mcr.Create(t.TempDir(), "workspace-content")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := workspace.Submit(validTaskSubmission("task-1")); err != nil {
		t.Fatalf("Submit task: %v", err)
	}
	run, err := workspace.Submit(submission("task-1", mcr.KindRunRecorded, map[string]any{
		"started_at": "2026-07-12T08:00:00Z", "ended_at": "2026-07-12T08:01:00Z", "outcome": "completed",
	}))
	if err != nil {
		t.Fatalf("Submit run: %v", err)
	}
	content := mcr.ContentRef{Locator: "urn:example:content", SHA256: digest}
	input1, err := workspace.Submit(submission("task-1", mcr.KindInputRegistered, map[string]any{"content": content}))
	if err != nil {
		t.Fatalf("Submit input: %v", err)
	}
	input2, err := workspace.Submit(submission("task-1", mcr.KindInputRegistered, map[string]any{"content": content}))
	if err != nil {
		t.Fatalf("Submit repeated input: %v", err)
	}
	withoutRun, err := workspace.Submit(submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content}))
	if err != nil {
		t.Fatalf("Submit artifact without Run: %v", err)
	}
	withRun, err := workspace.Submit(submission("task-1", mcr.KindArtifactRecorded, map[string]any{
		"content": content, "run": mcr.FactRef{FactID: run.FactID, RecordHash: run.RecordHash},
	}))
	if err != nil {
		t.Fatalf("Submit artifact with Run: %v", err)
	}
	if input1.FactID == input2.FactID {
		t.Fatal("repeated content reused Fact identity")
	}

	facts, err := workspace.Query(mcr.FactQuery{TaskID: "task-1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	wantIDs := []string{run.FactID, input1.FactID, input2.FactID, withoutRun.FactID, withRun.FactID}
	for i, want := range wantIDs {
		if facts[i+1].FactID != want {
			t.Fatalf("Query order = %+v", facts)
		}
	}
	projection, err := workspace.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	task := projection.Tasks[0]
	if len(task.RegisteredInputs) != 2 || task.RegisteredInputs[0].SourceFactID != input1.FactID || task.RegisteredInputs[0].Content != content {
		t.Fatalf("Registered Inputs = %+v", task.RegisteredInputs)
	}
	if len(task.Artifacts) != 2 || task.Artifacts[0].SourceFactID != withoutRun.FactID || task.Artifacts[0].Run != nil {
		t.Fatalf("Artifacts = %+v", task.Artifacts)
	}
	wantRun := mcr.FactRef{FactID: run.FactID, RecordHash: run.RecordHash}
	if task.Artifacts[1].SourceFactID != withRun.FactID || task.Artifacts[1].Content != content || task.Artifacts[1].Run == nil || *task.Artifacts[1].Run != wantRun {
		t.Fatalf("Artifact provenance = %+v", task.Artifacts[1])
	}
}

func TestRunInputArtifactRejectionsLeaveLedgerUnchanged(t *testing.T) {
	validRun := map[string]any{"started_at": "2026-07-12T08:00:00Z", "ended_at": "2026-07-12T08:01:00Z", "outcome": "completed"}
	content := mcr.ContentRef{Locator: "urn:example:content", SHA256: digest}
	otherDigest := "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	tests := []struct {
		name string
		make func(run, input, otherRun mcr.Fact) mcr.Submission
	}{
		{"missing Task", func(_, _, _ mcr.Fact) mcr.Submission { return submission("missing", mcr.KindRunRecorded, validRun) }},
		{"empty Run outcome", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindRunRecorded, map[string]any{"started_at": "2026-07-12T08:00:00Z", "ended_at": "2026-07-12T08:01:00Z", "outcome": ""})
		}},
		{"Run unknown field", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindRunRecorded, map[string]any{"started_at": "2026-07-12T08:00:00Z", "ended_at": "2026-07-12T08:01:00Z", "outcome": "ok", "model": "external"})
		}},
		{"Run wrong type", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindRunRecorded, map[string]any{"started_at": 1, "ended_at": "2026-07-12T08:01:00Z", "outcome": "ok"})
		}},
		{"Run non UTC", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindRunRecorded, map[string]any{"started_at": "2026-07-12T10:00:00+02:00", "ended_at": "2026-07-12T10:01:00+02:00", "outcome": "ok"})
		}},
		{"Run invalid timestamp", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindRunRecorded, map[string]any{"started_at": "not-time", "ended_at": "2026-07-12T08:01:00Z", "outcome": "ok"})
		}},
		{"Run end before start", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindRunRecorded, map[string]any{"started_at": "2026-07-12T08:01:00Z", "ended_at": "2026-07-12T08:00:00Z", "outcome": "ok"})
		}},
		{"Input empty locator", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindInputRegistered, map[string]any{"content": mcr.ContentRef{SHA256: digest}})
		}},
		{"Input invalid hash", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindInputRegistered, map[string]any{"content": mcr.ContentRef{Locator: "urn:x", SHA256: "0123"}})
		}},
		{"Input unknown field", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindInputRegistered, map[string]any{"content": content, "name": "external"})
		}},
		{"Input wrong type", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindInputRegistered, map[string]any{"content": "urn:x"})
		}},
		{"Artifact invalid content", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": mcr.ContentRef{Locator: "urn:x", SHA256: "bad"}})
		}},
		{"Artifact unknown field", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content, "format": "external"})
		}},
		{"Artifact null Run", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content, "run": nil})
		}},
		{"Artifact Run wrong type", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content, "run": "fact"})
		}},
		{"Artifact Run unknown field", func(run, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content, "run": map[string]any{"fact_id": run.FactID, "record_hash": run.RecordHash, "workspace": "other"}})
		}},
		{"Artifact missing or forward Run", func(_, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content, "run": mcr.FactRef{FactID: "fact_missing", RecordHash: otherDigest}})
		}},
		{"Artifact cross Task Run", func(_, _, otherRun mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content, "run": mcr.FactRef{FactID: otherRun.FactID, RecordHash: otherRun.RecordHash}})
		}},
		{"Artifact wrong Kind", func(_, input, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content, "run": mcr.FactRef{FactID: input.FactID, RecordHash: input.RecordHash}})
		}},
		{"Artifact hash mismatch", func(run, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content, "run": mcr.FactRef{FactID: run.FactID, RecordHash: otherDigest}})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			workspace, err := mcr.Create(root, "workspace-invalid")
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if _, err := workspace.Submit(validTaskSubmission("task-1")); err != nil {
				t.Fatalf("Submit task 1: %v", err)
			}
			run, err := workspace.Submit(submission("task-1", mcr.KindRunRecorded, validRun))
			if err != nil {
				t.Fatalf("Submit Run: %v", err)
			}
			input, err := workspace.Submit(submission("task-1", mcr.KindInputRegistered, map[string]any{"content": content}))
			if err != nil {
				t.Fatalf("Submit Input: %v", err)
			}
			if _, err := workspace.Submit(validTaskSubmission("task-2")); err != nil {
				t.Fatalf("Submit task 2: %v", err)
			}
			otherRun, err := workspace.Submit(submission("task-2", mcr.KindRunRecorded, validRun))
			if err != nil {
				t.Fatalf("Submit other Run: %v", err)
			}
			ledgerPath := filepath.Join(root, ".mcr", "events.jsonl")
			before, err := os.ReadFile(ledgerPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := workspace.Submit(test.make(run, input, otherRun)); !errors.Is(err, mcr.ErrInvalidSubmission) {
				t.Fatalf("Submit error = %v, want ErrInvalidSubmission", err)
			}
			after, err := os.ReadFile(ledgerPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("invalid submission changed ledger")
			}
		})
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
	if err != nil || verification.Integrity != mcr.IntegritySealedValid || verification.RecordCount != 5 || verification.LastRecordID != "fact_fixture_04" {
		t.Fatalf("Verify fixture = %+v, %v", verification, err)
	}
	facts, err := workspace.Query(mcr.FactQuery{})
	if err != nil || len(facts) != 4 || facts[0].TaskID != "task-neutral" || facts[3].Kind != mcr.KindArtifactRecorded {
		t.Fatalf("Query fixture = %+v, %v", facts, err)
	}
	projection, err := workspace.Replay()
	if err != nil || len(projection.Tasks) != 1 {
		t.Fatalf("Replay fixture = %+v, %v", projection, err)
	}
	task := projection.Tasks[0]
	if task.Definition.ID != "neutral-task" || len(task.Runs) != 1 || len(task.RegisteredInputs) != 1 || len(task.Artifacts) != 1 {
		t.Fatalf("Replay fixture Task = %+v", task)
	}
	if task.Artifacts[0].Run == nil || task.Artifacts[0].Run.FactID != task.Runs[0].SourceFactID {
		t.Fatalf("Replay fixture provenance = %+v", task.Artifacts[0])
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

	runPayload := `{"task_id":"task-cli","actor":{"type":"integration","id":"cli-test"},"kind":"run.recorded","payload":{"started_at":"2026-07-12T08:00:00Z","ended_at":"2026-07-12T08:01:00Z","outcome":"completed"}}`
	runOut, runErr, runExit := runCLI(bin, runPayload, "submit", "--workspace", root)
	if runExit != 0 || runErr != "" {
		t.Fatalf("Run submit exit=%d stderr=%q stdout=%q", runExit, runErr, runOut)
	}
	var run mcr.Fact
	if err := json.Unmarshal([]byte(runOut), &run); err != nil || run.Kind != mcr.KindRunRecorded || run.FactID == fact.FactID {
		t.Fatalf("Run submit stdout = %q, %v", runOut, err)
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
