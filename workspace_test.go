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

func TestClaimsSourcesAndEvidenceRoundTrip(t *testing.T) {
	workspace, err := mcr.Create(t.TempDir(), "workspace-evidence")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := workspace.Submit(validTaskSubmission("task-1")); err != nil {
		t.Fatalf("Submit task: %v", err)
	}
	content := mcr.ContentRef{Locator: "urn:example:artifact", SHA256: digest}
	artifact, err := workspace.Submit(submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content}))
	if err != nil {
		t.Fatalf("Submit Artifact: %v", err)
	}
	claimWithoutOrigin, err := workspace.Submit(submission("task-1", mcr.KindClaimRecorded, map[string]any{"statement": "The first exact statement."}))
	if err != nil {
		t.Fatalf("Submit Claim without origin: %v", err)
	}
	origin := mcr.FactRef{FactID: artifact.FactID, RecordHash: artifact.RecordHash}
	claimWithOrigin, err := workspace.Submit(submission("task-1", mcr.KindClaimRecorded, map[string]any{
		"statement": "The second exact statement.", "origin_artifact": origin,
	}))
	if err != nil {
		t.Fatalf("Submit Claim with origin: %v", err)
	}
	sourceContent := mcr.ContentRef{Locator: "urn:example:source", SHA256: digest}
	source, err := workspace.Submit(submission("task-1", mcr.KindSourceReferenceRecorded, map[string]any{
		"content": sourceContent, "anchor": "section-2",
	}))
	if err != nil {
		t.Fatalf("Submit Source Reference: %v", err)
	}
	evidence, err := workspace.Submit(submission("task-1", mcr.KindEvidenceLinked, map[string]any{
		"claim":  mcr.FactRef{FactID: claimWithOrigin.FactID, RecordHash: claimWithOrigin.RecordHash},
		"source": mcr.FactRef{FactID: source.FactID, RecordHash: source.RecordHash},
	}))
	if err != nil {
		t.Fatalf("Submit Evidence Link: %v", err)
	}

	facts, err := workspace.Query(mcr.FactQuery{TaskID: "task-1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	wantIDs := []string{artifact.FactID, claimWithoutOrigin.FactID, claimWithOrigin.FactID, source.FactID, evidence.FactID}
	for i, want := range wantIDs {
		if facts[i+1].FactID != want {
			t.Fatalf("Query order = %+v", facts)
		}
	}
	for _, filtered := range []struct {
		kind string
		ids  []string
	}{
		{mcr.KindClaimRecorded, []string{claimWithoutOrigin.FactID, claimWithOrigin.FactID}},
		{mcr.KindSourceReferenceRecorded, []string{source.FactID}},
		{mcr.KindEvidenceLinked, []string{evidence.FactID}},
	} {
		got, err := workspace.Query(mcr.FactQuery{TaskID: "task-1", Kind: filtered.kind})
		if err != nil || len(got) != len(filtered.ids) {
			t.Fatalf("Query %s = %+v, %v", filtered.kind, got, err)
		}
		for i, fact := range got {
			if fact.FactID != filtered.ids[i] {
				t.Fatalf("Query %s order = %+v", filtered.kind, got)
			}
		}
	}

	projection, err := workspace.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	task := projection.Tasks[0]
	if len(task.Claims) != 2 || task.Claims[0].SourceFactID != claimWithoutOrigin.FactID || task.Claims[0].Statement != "The first exact statement." || task.Claims[0].OriginArtifact != nil {
		t.Fatalf("Claims = %+v", task.Claims)
	}
	if task.Claims[1].SourceFactID != claimWithOrigin.FactID || task.Claims[1].OriginArtifact == nil || *task.Claims[1].OriginArtifact != origin {
		t.Fatalf("Claim origin = %+v", task.Claims[1])
	}
	if len(task.SourceReferences) != 1 || task.SourceReferences[0].SourceFactID != source.FactID || task.SourceReferences[0].Content != sourceContent || task.SourceReferences[0].Anchor != "section-2" {
		t.Fatalf("Source References = %+v", task.SourceReferences)
	}
	wantClaim := mcr.FactRef{FactID: claimWithOrigin.FactID, RecordHash: claimWithOrigin.RecordHash}
	wantSource := mcr.FactRef{FactID: source.FactID, RecordHash: source.RecordHash}
	if len(task.EvidenceLinks) != 1 || task.EvidenceLinks[0].SourceFactID != evidence.FactID || task.EvidenceLinks[0].Claim != wantClaim || task.EvidenceLinks[0].Source != wantSource {
		t.Fatalf("Evidence Links = %+v", task.EvidenceLinks)
	}
	replayedAgain, err := workspace.Replay()
	if err != nil {
		t.Fatalf("Replay again: %v", err)
	}
	firstJSON, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(replayedAgain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("Replay changed: %s != %s", firstJSON, secondJSON)
	}
}

func TestGovernanceDeliveryAndOpaqueRoundTrip(t *testing.T) {
	workspace, err := mcr.Create(t.TempDir(), "workspace-governance")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	taskFact, err := workspace.Submit(validTaskSubmission("task-1"))
	if err != nil {
		t.Fatalf("Submit Task: %v", err)
	}
	content := mcr.ContentRef{Locator: "urn:example:artifact", SHA256: digest}
	artifact1, err := workspace.Submit(submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content}))
	if err != nil {
		t.Fatalf("Submit Artifact 1: %v", err)
	}
	artifact2, err := workspace.Submit(submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content}))
	if err != nil {
		t.Fatalf("Submit Artifact 2: %v", err)
	}
	claim, err := workspace.Submit(submission("task-1", mcr.KindClaimRecorded, map[string]any{"statement": "Exact statement."}))
	if err != nil {
		t.Fatalf("Submit Claim: %v", err)
	}
	taskSubject := mcr.FactRef{FactID: taskFact.FactID, RecordHash: taskFact.RecordHash}
	review, err := workspace.Submit(submission("task-1", mcr.KindReviewRecorded, map[string]any{
		"subject": taskSubject, "outcome": "changes_requested", "findings": "Clarify the scope.",
	}))
	if err != nil {
		t.Fatalf("Submit Review: %v", err)
	}
	reviewSubject := mcr.FactRef{FactID: review.FactID, RecordHash: review.RecordHash}
	approval, err := workspace.Submit(submission("task-1", mcr.KindApprovalRecorded, map[string]any{
		"subject": reviewSubject, "scope": "release-candidate", "decision": "approved", "note": "Adapter decision.",
	}))
	if err != nil {
		t.Fatalf("Submit Approval: %v", err)
	}
	claimSubject := mcr.FactRef{FactID: claim.FactID, RecordHash: claim.RecordHash}
	policy, err := workspace.Submit(submission("task-1", mcr.KindPolicyDecisionRecorded, map[string]any{
		"subject": claimSubject, "action": "prepare", "policy": "external-policy-v1", "result": "allow",
	}))
	if err != nil {
		t.Fatalf("Submit Policy Decision: %v", err)
	}
	artifactRefs := []mcr.FactRef{
		{FactID: artifact1.FactID, RecordHash: artifact1.RecordHash},
		{FactID: artifact2.FactID, RecordHash: artifact2.RecordHash},
	}
	delivery, err := workspace.Submit(submission("task-1", mcr.KindDeliveryRecorded, map[string]any{
		"artifacts": artifactRefs, "format": "application/zip", "scope": "release-candidate", "target": "urn:example:delivery-target",
	}))
	if err != nil {
		t.Fatalf("Submit Delivery: %v", err)
	}
	opaqueData := json.RawMessage(`{"session":"external-1","details":{"attempt":2}}`)
	opaque, err := workspace.Submit(submission("task-1", mcr.KindOpaqueRecorded, map[string]any{
		"kind": "adapter.runtime_observation", "data": opaqueData,
	}))
	if err != nil {
		t.Fatalf("Submit Opaque Fact: %v", err)
	}

	facts, err := workspace.Query(mcr.FactQuery{TaskID: "task-1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	wantIDs := []string{taskFact.FactID, artifact1.FactID, artifact2.FactID, claim.FactID, review.FactID, approval.FactID, policy.FactID, delivery.FactID, opaque.FactID}
	if len(facts) != len(wantIDs) {
		t.Fatalf("Query count = %d, want %d", len(facts), len(wantIDs))
	}
	for i, want := range wantIDs {
		if facts[i].FactID != want {
			t.Fatalf("Query order = %+v", facts)
		}
	}
	for _, kind := range []string{mcr.KindReviewRecorded, mcr.KindApprovalRecorded, mcr.KindPolicyDecisionRecorded, mcr.KindDeliveryRecorded, mcr.KindOpaqueRecorded} {
		filtered, err := workspace.Query(mcr.FactQuery{Kind: kind})
		if err != nil || len(filtered) != 1 || filtered[0].Kind != kind {
			t.Fatalf("Query %s = %+v, %v", kind, filtered, err)
		}
	}

	projection, err := workspace.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	task := projection.Tasks[0]
	if len(task.Reviews) != 1 || task.Reviews[0].SourceFactID != review.FactID || task.Reviews[0].Subject != taskSubject || task.Reviews[0].Outcome != "changes_requested" || task.Reviews[0].Findings != "Clarify the scope." {
		t.Fatalf("Reviews = %+v", task.Reviews)
	}
	if len(task.Approvals) != 1 || task.Approvals[0].SourceFactID != approval.FactID || task.Approvals[0].Subject != reviewSubject || task.Approvals[0].Scope != "release-candidate" || task.Approvals[0].Decision != "approved" || task.Approvals[0].Note != "Adapter decision." {
		t.Fatalf("Approvals = %+v", task.Approvals)
	}
	if len(task.PolicyDecisions) != 1 || task.PolicyDecisions[0].SourceFactID != policy.FactID || task.PolicyDecisions[0].Subject != claimSubject || task.PolicyDecisions[0].Action != "prepare" || task.PolicyDecisions[0].Policy != "external-policy-v1" || task.PolicyDecisions[0].Result != "allow" {
		t.Fatalf("Policy Decisions = %+v", task.PolicyDecisions)
	}
	if len(task.Deliveries) != 1 || task.Deliveries[0].SourceFactID != delivery.FactID || len(task.Deliveries[0].Artifacts) != 2 || task.Deliveries[0].Artifacts[0] != artifactRefs[0] || task.Deliveries[0].Artifacts[1] != artifactRefs[1] {
		t.Fatalf("Deliveries = %+v", task.Deliveries)
	}
	if len(task.OpaqueFacts) != 1 || task.OpaqueFacts[0].SourceFactID != opaque.FactID || task.OpaqueFacts[0].Kind != "adapter.runtime_observation" || !bytes.Equal(task.OpaqueFacts[0].Data, opaqueData) {
		t.Fatalf("Opaque Facts = %+v", task.OpaqueFacts)
	}
	replayedAgain, err := workspace.Replay()
	if err != nil {
		t.Fatalf("Replay again: %v", err)
	}
	firstJSON, _ := json.Marshal(projection)
	secondJSON, _ := json.Marshal(replayedAgain)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("Replay changed: %s != %s", firstJSON, secondJSON)
	}
}

func TestGovernanceDeliveryAndOpaqueRejectionsLeaveLedgerUnchanged(t *testing.T) {
	otherDigest := "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	tests := []struct {
		name string
		make func(task, artifact, otherTask, otherArtifact mcr.Fact) mcr.Submission
	}{
		{"Review missing or forward subject", func(_, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindReviewRecorded, map[string]any{"subject": mcr.FactRef{FactID: "fact_missing", RecordHash: otherDigest}, "outcome": "accepted"})
		}},
		{"Review cross Task subject", func(_, _, otherTask, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindReviewRecorded, map[string]any{"subject": mcr.FactRef{FactID: otherTask.FactID, RecordHash: otherTask.RecordHash}, "outcome": "accepted"})
		}},
		{"Review subject hash mismatch", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindReviewRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: otherDigest}, "outcome": "accepted"})
		}},
		{"Review empty outcome", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindReviewRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "outcome": ""})
		}},
		{"Review empty findings", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindReviewRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "outcome": "accepted", "findings": ""})
		}},
		{"Review null findings", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindReviewRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "outcome": "accepted", "findings": nil})
		}},
		{"Review unknown field", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindReviewRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "outcome": "accepted", "extra": true})
		}},
		{"Approval missing or forward subject", func(_, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindApprovalRecorded, map[string]any{"subject": mcr.FactRef{FactID: "fact_missing", RecordHash: otherDigest}, "scope": "release", "decision": "approved"})
		}},
		{"Approval cross Task subject", func(_, _, otherTask, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindApprovalRecorded, map[string]any{"subject": mcr.FactRef{FactID: otherTask.FactID, RecordHash: otherTask.RecordHash}, "scope": "release", "decision": "approved"})
		}},
		{"Approval subject hash mismatch", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindApprovalRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: otherDigest}, "scope": "release", "decision": "approved"})
		}},
		{"Approval empty scope", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindApprovalRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "scope": "", "decision": "approved"})
		}},
		{"Approval empty decision", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindApprovalRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "scope": "release", "decision": ""})
		}},
		{"Approval empty note", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindApprovalRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "scope": "release", "decision": "approved", "note": ""})
		}},
		{"Approval unknown field", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindApprovalRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "scope": "release", "decision": "approved", "extra": true})
		}},
		{"Policy missing or forward subject", func(_, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindPolicyDecisionRecorded, map[string]any{"subject": mcr.FactRef{FactID: "fact_missing", RecordHash: otherDigest}, "action": "prepare", "policy": "p1", "result": "allow"})
		}},
		{"Policy cross Task subject", func(_, _, otherTask, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindPolicyDecisionRecorded, map[string]any{"subject": mcr.FactRef{FactID: otherTask.FactID, RecordHash: otherTask.RecordHash}, "action": "prepare", "policy": "p1", "result": "allow"})
		}},
		{"Policy subject hash mismatch", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindPolicyDecisionRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: otherDigest}, "action": "prepare", "policy": "p1", "result": "allow"})
		}},
		{"Policy empty action", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindPolicyDecisionRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "action": "", "policy": "p1", "result": "allow"})
		}},
		{"Policy empty policy", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindPolicyDecisionRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "action": "prepare", "policy": "", "result": "allow"})
		}},
		{"Policy empty result", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindPolicyDecisionRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "action": "prepare", "policy": "p1", "result": ""})
		}},
		{"Policy unknown field", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindPolicyDecisionRecorded, map[string]any{"subject": mcr.FactRef{FactID: task.FactID, RecordHash: task.RecordHash}, "action": "prepare", "policy": "p1", "result": "allow", "extra": true})
		}},
		{"Delivery empty Artifacts", func(_, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindDeliveryRecorded, map[string]any{"artifacts": []mcr.FactRef{}, "format": "zip", "scope": "release", "target": "urn:target"})
		}},
		{"Delivery duplicate Artifacts", func(_, artifact, _, _ mcr.Fact) mcr.Submission {
			ref := mcr.FactRef{FactID: artifact.FactID, RecordHash: artifact.RecordHash}
			return submission("task-1", mcr.KindDeliveryRecorded, map[string]any{"artifacts": []mcr.FactRef{ref, ref}, "format": "zip", "scope": "release", "target": "urn:target"})
		}},
		{"Delivery missing or forward Artifact", func(_, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindDeliveryRecorded, map[string]any{"artifacts": []mcr.FactRef{{FactID: "fact_missing", RecordHash: otherDigest}}, "format": "zip", "scope": "release", "target": "urn:target"})
		}},
		{"Delivery cross Task Artifact", func(_, _, _, otherArtifact mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindDeliveryRecorded, map[string]any{"artifacts": []mcr.FactRef{{FactID: otherArtifact.FactID, RecordHash: otherArtifact.RecordHash}}, "format": "zip", "scope": "release", "target": "urn:target"})
		}},
		{"Delivery wrong Kind", func(task, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindDeliveryRecorded, map[string]any{"artifacts": []mcr.FactRef{{FactID: task.FactID, RecordHash: task.RecordHash}}, "format": "zip", "scope": "release", "target": "urn:target"})
		}},
		{"Delivery hash mismatch", func(_, artifact, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindDeliveryRecorded, map[string]any{"artifacts": []mcr.FactRef{{FactID: artifact.FactID, RecordHash: otherDigest}}, "format": "zip", "scope": "release", "target": "urn:target"})
		}},
		{"Delivery empty format", func(_, artifact, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindDeliveryRecorded, map[string]any{"artifacts": []mcr.FactRef{{FactID: artifact.FactID, RecordHash: artifact.RecordHash}}, "format": "", "scope": "release", "target": "urn:target"})
		}},
		{"Delivery unknown field", func(_, artifact, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindDeliveryRecorded, map[string]any{"artifacts": []mcr.FactRef{{FactID: artifact.FactID, RecordHash: artifact.RecordHash}}, "format": "zip", "scope": "release", "target": "urn:target", "extra": true})
		}},
		{"Opaque empty external Kind", func(_, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindOpaqueRecorded, map[string]any{"kind": "", "data": map[string]any{}})
		}},
		{"Opaque non-object data", func(_, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindOpaqueRecorded, map[string]any{"kind": "adapter.event", "data": []string{"not", "object"}})
		}},
		{"Opaque unknown wrapper field", func(_, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindOpaqueRecorded, map[string]any{"kind": "adapter.event", "data": map[string]any{}, "extra": true})
		}},
		{"Unknown native submission Kind", func(_, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", "adapter.event", map[string]any{})
		}},
	}
	for _, nativeKind := range []string{mcr.KindTaskCreated, mcr.KindRunRecorded, mcr.KindInputRegistered, mcr.KindArtifactRecorded, mcr.KindClaimRecorded, mcr.KindSourceReferenceRecorded, mcr.KindEvidenceLinked, mcr.KindReviewRecorded, mcr.KindApprovalRecorded, mcr.KindPolicyDecisionRecorded, mcr.KindDeliveryRecorded, mcr.KindOpaqueRecorded} {
		kind := nativeKind
		tests = append(tests, struct {
			name string
			make func(task, artifact, otherTask, otherArtifact mcr.Fact) mcr.Submission
		}{"Opaque native Kind " + kind, func(_, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindOpaqueRecorded, map[string]any{"kind": kind, "data": map[string]any{}})
		}})
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			workspace, err := mcr.Create(root, "workspace-invalid-governance")
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			task, err := workspace.Submit(validTaskSubmission("task-1"))
			if err != nil {
				t.Fatalf("Submit Task 1: %v", err)
			}
			content := mcr.ContentRef{Locator: "urn:example:artifact", SHA256: digest}
			artifact, err := workspace.Submit(submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content}))
			if err != nil {
				t.Fatalf("Submit Artifact: %v", err)
			}
			otherTask, err := workspace.Submit(validTaskSubmission("task-2"))
			if err != nil {
				t.Fatalf("Submit Task 2: %v", err)
			}
			otherArtifact, err := workspace.Submit(submission("task-2", mcr.KindArtifactRecorded, map[string]any{"content": content}))
			if err != nil {
				t.Fatalf("Submit other Artifact: %v", err)
			}
			ledgerPath := filepath.Join(root, ".mcr", "events.jsonl")
			before, err := os.ReadFile(ledgerPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := workspace.Submit(test.make(task, artifact, otherTask, otherArtifact)); !errors.Is(err, mcr.ErrInvalidSubmission) {
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

func TestClaimSourceEvidenceRejectionsLeaveLedgerUnchanged(t *testing.T) {
	content := mcr.ContentRef{Locator: "urn:example:content", SHA256: digest}
	otherDigest := "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	tests := []struct {
		name string
		make func(artifact, claim, source, otherArtifact, otherClaim, otherSource mcr.Fact) mcr.Submission
	}{
		{"Claim empty statement", func(_, _, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindClaimRecorded, map[string]any{"statement": ""})
		}},
		{"Claim unknown field", func(_, _, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindClaimRecorded, map[string]any{"statement": "exact", "truth": true})
		}},
		{"Claim null origin", func(_, _, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindClaimRecorded, map[string]any{"statement": "exact", "origin_artifact": nil})
		}},
		{"Claim malformed origin", func(_, _, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindClaimRecorded, map[string]any{"statement": "exact", "origin_artifact": map[string]any{"fact_id": "fact", "record_hash": digest, "extra": true}})
		}},
		{"Claim missing or forward origin", func(_, _, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindClaimRecorded, map[string]any{"statement": "exact", "origin_artifact": mcr.FactRef{FactID: "fact_missing", RecordHash: otherDigest}})
		}},
		{"Claim cross Task origin", func(_, _, _, otherArtifact, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindClaimRecorded, map[string]any{"statement": "exact", "origin_artifact": mcr.FactRef{FactID: otherArtifact.FactID, RecordHash: otherArtifact.RecordHash}})
		}},
		{"Claim wrong Kind origin", func(_, _, source, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindClaimRecorded, map[string]any{"statement": "exact", "origin_artifact": mcr.FactRef{FactID: source.FactID, RecordHash: source.RecordHash}})
		}},
		{"Claim origin hash mismatch", func(artifact, _, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindClaimRecorded, map[string]any{"statement": "exact", "origin_artifact": mcr.FactRef{FactID: artifact.FactID, RecordHash: otherDigest}})
		}},
		{"Source invalid content", func(_, _, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindSourceReferenceRecorded, map[string]any{"content": mcr.ContentRef{Locator: "urn:x", SHA256: "bad"}, "anchor": "a"})
		}},
		{"Source empty anchor", func(_, _, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindSourceReferenceRecorded, map[string]any{"content": content, "anchor": ""})
		}},
		{"Source unknown field", func(_, _, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindSourceReferenceRecorded, map[string]any{"content": content, "anchor": "a", "authority": true})
		}},
		{"Source wrong type", func(_, _, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindSourceReferenceRecorded, map[string]any{"content": content, "anchor": 1})
		}},
		{"Evidence unknown field", func(_, claim, source, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindEvidenceLinked, map[string]any{"claim": mcr.FactRef{FactID: claim.FactID, RecordHash: claim.RecordHash}, "source": mcr.FactRef{FactID: source.FactID, RecordHash: source.RecordHash}, "proves": true})
		}},
		{"Evidence malformed Claim", func(_, _, source, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindEvidenceLinked, map[string]any{"claim": map[string]any{"fact_id": "fact"}, "source": mcr.FactRef{FactID: source.FactID, RecordHash: source.RecordHash}})
		}},
		{"Evidence malformed Source", func(_, claim, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindEvidenceLinked, map[string]any{"claim": mcr.FactRef{FactID: claim.FactID, RecordHash: claim.RecordHash}, "source": map[string]any{"fact_id": "fact"}})
		}},
		{"Evidence missing or forward Claim", func(_, _, source, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindEvidenceLinked, map[string]any{"claim": mcr.FactRef{FactID: "fact_missing", RecordHash: otherDigest}, "source": mcr.FactRef{FactID: source.FactID, RecordHash: source.RecordHash}})
		}},
		{"Evidence missing or forward Source", func(_, claim, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindEvidenceLinked, map[string]any{"claim": mcr.FactRef{FactID: claim.FactID, RecordHash: claim.RecordHash}, "source": mcr.FactRef{FactID: "fact_missing", RecordHash: otherDigest}})
		}},
		{"Evidence cross Task Claim", func(_, _, source, _, otherClaim, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindEvidenceLinked, map[string]any{"claim": mcr.FactRef{FactID: otherClaim.FactID, RecordHash: otherClaim.RecordHash}, "source": mcr.FactRef{FactID: source.FactID, RecordHash: source.RecordHash}})
		}},
		{"Evidence cross Task Source", func(_, claim, _, _, _, otherSource mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindEvidenceLinked, map[string]any{"claim": mcr.FactRef{FactID: claim.FactID, RecordHash: claim.RecordHash}, "source": mcr.FactRef{FactID: otherSource.FactID, RecordHash: otherSource.RecordHash}})
		}},
		{"Evidence swapped Kinds", func(_, claim, source, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindEvidenceLinked, map[string]any{"claim": mcr.FactRef{FactID: source.FactID, RecordHash: source.RecordHash}, "source": mcr.FactRef{FactID: claim.FactID, RecordHash: claim.RecordHash}})
		}},
		{"Evidence wrong Kind Source", func(artifact, claim, _, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindEvidenceLinked, map[string]any{"claim": mcr.FactRef{FactID: claim.FactID, RecordHash: claim.RecordHash}, "source": mcr.FactRef{FactID: artifact.FactID, RecordHash: artifact.RecordHash}})
		}},
		{"Evidence Claim hash mismatch", func(_, claim, source, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindEvidenceLinked, map[string]any{"claim": mcr.FactRef{FactID: claim.FactID, RecordHash: otherDigest}, "source": mcr.FactRef{FactID: source.FactID, RecordHash: source.RecordHash}})
		}},
		{"Evidence Source hash mismatch", func(_, claim, source, _, _, _ mcr.Fact) mcr.Submission {
			return submission("task-1", mcr.KindEvidenceLinked, map[string]any{"claim": mcr.FactRef{FactID: claim.FactID, RecordHash: claim.RecordHash}, "source": mcr.FactRef{FactID: source.FactID, RecordHash: otherDigest}})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			workspace, err := mcr.Create(root, "workspace-invalid-evidence")
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if _, err := workspace.Submit(validTaskSubmission("task-1")); err != nil {
				t.Fatalf("Submit Task 1: %v", err)
			}
			artifact, err := workspace.Submit(submission("task-1", mcr.KindArtifactRecorded, map[string]any{"content": content}))
			if err != nil {
				t.Fatalf("Submit Artifact: %v", err)
			}
			claim, err := workspace.Submit(submission("task-1", mcr.KindClaimRecorded, map[string]any{"statement": "exact"}))
			if err != nil {
				t.Fatalf("Submit Claim: %v", err)
			}
			source, err := workspace.Submit(submission("task-1", mcr.KindSourceReferenceRecorded, map[string]any{"content": content, "anchor": "a"}))
			if err != nil {
				t.Fatalf("Submit Source: %v", err)
			}
			if _, err := workspace.Submit(validTaskSubmission("task-2")); err != nil {
				t.Fatalf("Submit Task 2: %v", err)
			}
			otherArtifact, err := workspace.Submit(submission("task-2", mcr.KindArtifactRecorded, map[string]any{"content": content}))
			if err != nil {
				t.Fatalf("Submit other Artifact: %v", err)
			}
			otherClaim, err := workspace.Submit(submission("task-2", mcr.KindClaimRecorded, map[string]any{"statement": "other"}))
			if err != nil {
				t.Fatalf("Submit other Claim: %v", err)
			}
			otherSource, err := workspace.Submit(submission("task-2", mcr.KindSourceReferenceRecorded, map[string]any{"content": content, "anchor": "other"}))
			if err != nil {
				t.Fatalf("Submit other Source: %v", err)
			}
			ledgerPath := filepath.Join(root, ".mcr", "events.jsonl")
			before, err := os.ReadFile(ledgerPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := workspace.Submit(test.make(artifact, claim, source, otherArtifact, otherClaim, otherSource)); !errors.Is(err, mcr.ErrInvalidSubmission) {
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
	if err != nil || verification.Integrity != mcr.IntegritySealedValid || verification.RecordCount != 15 || verification.LastRecordID != "fact_fixture_14" {
		t.Fatalf("Verify fixture = %+v, %v", verification, err)
	}
	assertJSONGolden(t, "testdata/hashes/native-task.verify.json", verification)
	facts, err := workspace.Query(mcr.FactQuery{})
	if err != nil || len(facts) != 14 || facts[0].TaskID != "task-neutral" || facts[13].TaskID != "task-secondary" || facts[13].Kind != mcr.KindTaskCreated {
		t.Fatalf("Query fixture = %+v, %v", facts, err)
	}
	assertJSONGolden(t, "testdata/hashes/native-task.query.json", facts)
	projection, err := workspace.Replay()
	if err != nil || len(projection.Tasks) != 2 {
		t.Fatalf("Replay fixture = %+v, %v", projection, err)
	}
	assertJSONGolden(t, "testdata/hashes/native-task.replay.json", projection)
	task := projection.Tasks[0]
	if task.Definition.ID != "neutral-task" || len(task.Runs) != 1 || len(task.RegisteredInputs) != 1 || len(task.Artifacts) != 2 || len(task.Claims) != 1 || len(task.SourceReferences) != 1 || len(task.EvidenceLinks) != 1 || len(task.Reviews) != 1 || len(task.Approvals) != 1 || len(task.PolicyDecisions) != 1 || len(task.Deliveries) != 1 || len(task.OpaqueFacts) != 1 {
		t.Fatalf("Replay fixture Task = %+v", task)
	}
	if task.Artifacts[0].Run == nil || task.Artifacts[0].Run.FactID != task.Runs[0].SourceFactID {
		t.Fatalf("Replay fixture provenance = %+v", task.Artifacts[0])
	}
	if task.Claims[0].OriginArtifact == nil || task.Claims[0].OriginArtifact.FactID != task.Artifacts[0].SourceFactID || task.EvidenceLinks[0].Claim.FactID != task.Claims[0].SourceFactID || task.EvidenceLinks[0].Source.FactID != task.SourceReferences[0].SourceFactID {
		t.Fatalf("Replay fixture evidence = %+v", task)
	}
	if task.Reviews[0].Subject.FactID != task.EvidenceLinks[0].SourceFactID || task.Reviews[0].Findings != "Exact fixture finding." || task.Approvals[0].Subject.FactID != task.Reviews[0].SourceFactID || task.Approvals[0].Note != "" || task.PolicyDecisions[0].Subject.FactID != task.Approvals[0].SourceFactID {
		t.Fatalf("Replay fixture governance = %+v", task)
	}
	if len(task.Deliveries[0].Artifacts) != 2 || task.Deliveries[0].Artifacts[0].FactID != task.Artifacts[0].SourceFactID || task.Deliveries[0].Artifacts[1].FactID != task.Artifacts[1].SourceFactID || task.OpaqueFacts[0].Kind != "adapter.runtime_observation" {
		t.Fatalf("Replay fixture delivery and opaque Facts = %+v", task)
	}
	if projection.Tasks[1].TaskID != "task-secondary" || projection.Tasks[1].Definition.ID != "secondary-task" {
		t.Fatalf("Replay fixture second Task = %+v", projection.Tasks[1])
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

	claimPayload := `{"task_id":"task-cli","actor":{"type":"integration","id":"cli-test"},"kind":"claim.recorded","payload":{"statement":"Exact CLI statement."}}`
	claimOut, claimErr, claimExit := runCLI(bin, claimPayload, "submit", "--workspace", root)
	if claimExit != 0 || claimErr != "" {
		t.Fatalf("Claim submit exit=%d stderr=%q stdout=%q", claimExit, claimErr, claimOut)
	}
	var claim mcr.Fact
	if err := json.Unmarshal([]byte(claimOut), &claim); err != nil || claim.Kind != mcr.KindClaimRecorded || claim.FactID == run.FactID {
		t.Fatalf("Claim submit stdout = %q, %v", claimOut, err)
	}
	sourcePayload := `{"task_id":"task-cli","actor":{"type":"integration","id":"cli-test"},"kind":"source_reference.recorded","payload":{"content":{"locator":"urn:example:cli-source","sha256":"` + digest + `"},"anchor":"section-1"}}`
	sourceOut, sourceErr, sourceExit := runCLI(bin, sourcePayload, "submit", "--workspace", root)
	if sourceExit != 0 || sourceErr != "" {
		t.Fatalf("Source submit exit=%d stderr=%q stdout=%q", sourceExit, sourceErr, sourceOut)
	}
	var source mcr.Fact
	if err := json.Unmarshal([]byte(sourceOut), &source); err != nil || source.Kind != mcr.KindSourceReferenceRecorded {
		t.Fatalf("Source submit stdout = %q, %v", sourceOut, err)
	}

	evidencePayload := `{"task_id":"task-cli","actor":{"type":"integration","id":"cli-test"},"kind":"evidence.linked","payload":{"claim":{"fact_id":"` + claim.FactID + `","record_hash":"` + claim.RecordHash + `"},"source":{"fact_id":"` + source.FactID + `","record_hash":"` + source.RecordHash + `"}}}`
	evidenceOut, evidenceErr, evidenceExit := runCLI(bin, evidencePayload, "submit", "--workspace", root)
	if evidenceExit != 0 || evidenceErr != "" {
		t.Fatalf("Evidence submit exit=%d stderr=%q stdout=%q", evidenceExit, evidenceErr, evidenceOut)
	}
	var evidence mcr.Fact
	if err := json.Unmarshal([]byte(evidenceOut), &evidence); err != nil || evidence.Kind != mcr.KindEvidenceLinked {
		t.Fatalf("Evidence submit stdout = %q, %v", evidenceOut, err)
	}

	submitKind := func(payload, kind string) mcr.Fact {
		t.Helper()
		out, diagnostic, code := runCLI(bin, payload, "submit", "--workspace", root)
		if code != 0 || diagnostic != "" {
			t.Fatalf("%s submit exit=%d stderr=%q stdout=%q", kind, code, diagnostic, out)
		}
		var submitted mcr.Fact
		if err := json.Unmarshal([]byte(out), &submitted); err != nil || submitted.Kind != kind {
			t.Fatalf("%s submit stdout = %q, %v", kind, out, err)
		}
		return submitted
	}
	review := submitKind(`{"task_id":"task-cli","actor":{"type":"integration","id":"cli-test"},"kind":"review.recorded","payload":{"subject":{"fact_id":"`+evidence.FactID+`","record_hash":"`+evidence.RecordHash+`"},"outcome":"accepted"}}`, mcr.KindReviewRecorded)
	approval := submitKind(`{"task_id":"task-cli","actor":{"type":"integration","id":"cli-test"},"kind":"approval.recorded","payload":{"subject":{"fact_id":"`+review.FactID+`","record_hash":"`+review.RecordHash+`"},"scope":"release","decision":"approved"}}`, mcr.KindApprovalRecorded)
	_ = submitKind(`{"task_id":"task-cli","actor":{"type":"integration","id":"cli-test"},"kind":"policy_decision.recorded","payload":{"subject":{"fact_id":"`+approval.FactID+`","record_hash":"`+approval.RecordHash+`"},"action":"prepare","policy":"external-v1","result":"allow"}}`, mcr.KindPolicyDecisionRecorded)
	artifact := submitKind(`{"task_id":"task-cli","actor":{"type":"integration","id":"cli-test"},"kind":"artifact.recorded","payload":{"content":{"locator":"urn:example:cli-artifact","sha256":"`+digest+`"}}}`, mcr.KindArtifactRecorded)
	_ = submitKind(`{"task_id":"task-cli","actor":{"type":"integration","id":"cli-test"},"kind":"delivery.recorded","payload":{"artifacts":[{"fact_id":"`+artifact.FactID+`","record_hash":"`+artifact.RecordHash+`"}],"format":"application/zip","scope":"release","target":"urn:example:target"}}`, mcr.KindDeliveryRecorded)
	_ = submitKind(`{"task_id":"task-cli","actor":{"type":"integration","id":"cli-test"},"kind":"opaque.recorded","payload":{"kind":"adapter.runtime_observation","data":{"session":"external"}}}`, mcr.KindOpaqueRecorded)

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

func TestCLILegacyVerifyExitMatrix(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "mcr")
	build := exec.Command("go", "build", "-o", bin, "./cmd/mcr")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	sealed, err := os.ReadFile("testdata/legacy/sealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	unsealed, err := os.ReadFile("testdata/legacy/unsealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		ledger    []byte
		state     []byte
		exit      int
		integrity string
		stderr    bool
	}{
		{name: "sealed-valid-cache-warning", ledger: sealed, state: nil, exit: 0, integrity: mcr.IntegritySealedValid, stderr: true},
		{name: "unsealed", ledger: unsealed, state: []byte(`{"workspace_id":"workspace/unsealed","last_event_id":"extension+opaque"}`), exit: 1, integrity: mcr.IntegrityUnsealed},
		{name: "partial", ledger: mutateLegacyRecord(t, sealed, 2, func(values map[string]any) { delete(values, "event_hash") }), state: []byte(`{}`), exit: 1, integrity: mcr.IntegrityPartialInvalid, stderr: true},
		{name: "sealed-invalid", ledger: bytes.Replace(sealed, []byte(firstLegacyEventHash), []byte("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), 1), state: []byte(`{}`), exit: 1, integrity: mcr.IntegritySealedInvalid, stderr: true},
		{name: "structural-invalid", ledger: mutateLegacyRecord(t, sealed, 2, func(values map[string]any) { delete(values, "actor") }), state: []byte(`{}`), exit: 1, stderr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workspace := writeLegacyWorkspace(t, test.ledger, test.state)
			stdout, stderr, exit := runCLI(bin, "", "verify", "--workspace", workspace)
			if exit != test.exit || !json.Valid([]byte(stdout)) || (test.stderr != (stderr != "")) || (stderr != "" && !json.Valid([]byte(stderr))) {
				t.Fatalf("exit=%d stderr=%q stdout=%q", exit, stderr, stdout)
			}
			var verification mcr.Verification
			if err := json.Unmarshal([]byte(stdout), &verification); err != nil || verification.Integrity != test.integrity {
				t.Fatalf("verification=%#v, %v", verification, err)
			}
		})
	}
}

func TestCLISharedGoldensAndErrorMatrix(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "mcr")
	build := exec.Command("go", "build", "-o", bin, "./cmd/mcr")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	fixture, err := os.ReadFile("testdata/native-task.jsonl")
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

	queryOut, queryErr, queryExit := runCLI(bin, "", "query", "--workspace", root)
	if queryExit != 0 || queryErr != "" {
		t.Fatalf("query exit=%d stderr=%q stdout=%q", queryExit, queryErr, queryOut)
	}
	var facts []mcr.Fact
	if err := json.Unmarshal([]byte(queryOut), &facts); err != nil {
		t.Fatalf("query JSON: %v", err)
	}
	assertJSONGolden(t, "testdata/hashes/native-task.query.json", facts)

	replayOut, replayErr, replayExit := runCLI(bin, "", "replay", "--workspace", root)
	if replayExit != 0 || replayErr != "" {
		t.Fatalf("replay exit=%d stderr=%q stdout=%q", replayExit, replayErr, replayOut)
	}
	var projection mcr.Projection
	if err := json.Unmarshal([]byte(replayOut), &projection); err != nil {
		t.Fatalf("replay JSON: %v", err)
	}
	assertJSONGolden(t, "testdata/hashes/native-task.replay.json", projection)

	verifyOut, verifyErr, verifyExit := runCLI(bin, "", "verify", "--workspace", root)
	if verifyExit != 0 || verifyErr != "" {
		t.Fatalf("verify exit=%d stderr=%q stdout=%q", verifyExit, verifyErr, verifyOut)
	}
	var verification mcr.Verification
	if err := json.Unmarshal([]byte(verifyOut), &verification); err != nil {
		t.Fatalf("verify JSON: %v", err)
	}
	assertJSONGolden(t, "testdata/hashes/native-task.verify.json", verification)

	partial, err := os.ReadFile("testdata/legacy/sealed-valid.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	partial = mutateLegacyRecord(t, partial, 2, func(values map[string]any) { delete(values, "event_hash") })
	partialWorkspace := writeLegacyWorkspace(t, partial, []byte("{}\n"))
	tests := []struct {
		name  string
		stdin string
		args  []string
	}{
		{name: "unknown-command", args: []string{"unknown", "--workspace", root}},
		{name: "open-error", args: []string{"query", "--workspace", filepath.Join(t.TempDir(), "missing")}},
		{name: "read-operation-error", args: []string{"query", "--workspace", partialWorkspace}},
		{name: "submission-operation-error", stdin: "{}", args: []string{"submit", "--workspace", root}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout, stderr, exit := runCLI(bin, test.stdin, test.args...)
			if exit != 2 || stdout != "" || !json.Valid([]byte(stderr)) {
				t.Fatalf("exit=%d stderr=%q stdout=%q", exit, stderr, stdout)
			}
			var diagnostic map[string]string
			if err := json.Unmarshal([]byte(stderr), &diagnostic); err != nil || diagnostic["error"] == "" {
				t.Fatalf("stderr diagnostic = %#v, %v", diagnostic, err)
			}
		})
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
