package mcr

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Notyet1307/MCR-Core/internal/jsonstrict"
)

const zeroHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

var nativeHash = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type workspaceHeader struct {
	RecordType    string `json:"record_type"`
	FormatVersion string `json:"format_version"`
	WorkspaceID   string `json:"workspace_id"`
	RecordedAt    string `json:"recorded_at"`
	PrevHash      string `json:"prev_hash"`
	RecordHash    string `json:"record_hash"`
}

type factRecord struct {
	RecordType string          `json:"record_type"`
	FactID     string          `json:"fact_id"`
	TaskID     string          `json:"task_id"`
	Kind       string          `json:"kind"`
	Actor      Actor           `json:"actor"`
	RecordedAt string          `json:"recorded_at"`
	Payload    json.RawMessage `json:"payload"`
	PrevHash   string          `json:"prev_hash"`
	RecordHash string          `json:"record_hash"`
}

type history struct {
	header workspaceHeader
	facts  []Fact
}

type runPayload struct {
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Outcome   string    `json:"outcome"`
}

type artifactPayload struct {
	Content ContentRef
	Run     *FactRef
}

type claimPayload struct {
	Statement      string
	OriginArtifact *FactRef
}

type sourceReferencePayload struct {
	Content ContentRef `json:"content"`
	Anchor  string     `json:"anchor"`
}

type evidenceLinkPayload struct {
	Claim  FactRef `json:"claim"`
	Source FactRef `json:"source"`
}

type reviewPayload struct {
	Subject  FactRef
	Outcome  string
	Findings string
}

type approvalPayload struct {
	Subject  FactRef
	Scope    string
	Decision string
	Note     string
}

type policyDecisionPayload struct {
	Subject FactRef `json:"subject"`
	Action  string  `json:"action"`
	Policy  string  `json:"policy"`
	Result  string  `json:"result"`
}

type deliveryPayload struct {
	Artifacts []FactRef `json:"artifacts"`
	Format    string    `json:"format"`
	Scope     string    `json:"scope"`
	Target    string    `json:"target"`
}

type opaquePayload struct {
	Kind string
	Data json.RawMessage
}

type nativeState struct {
	tasks map[string]bool
	facts map[string]Fact
}

func newNativeState(facts []Fact) nativeState {
	state := nativeState{tasks: make(map[string]bool), facts: make(map[string]Fact, len(facts))}
	for _, fact := range facts {
		state.add(fact)
	}
	return state
}

func (s *nativeState) add(fact Fact) {
	s.facts[fact.FactID] = fact
	if fact.Kind == KindTaskCreated {
		s.tasks[fact.TaskID] = true
	}
}

func (s *nativeState) validate(taskID, kind string, payload json.RawMessage) (string, error) {
	if !isNativeKind(kind) {
		return "unknown_kind", errors.New("native fact kind is not supported")
	}
	taskExists := s.tasks[taskID]
	if kind != KindTaskCreated && !taskExists {
		return "invalid_payload", errors.New("task does not exist")
	}
	var err error
	switch kind {
	case KindTaskCreated:
		if taskExists {
			return "duplicate_task", errors.New("task already exists")
		}
		_, err = decodeTaskPayload(payload)
	case KindRunRecorded:
		_, err = decodeRunPayload(payload)
	case KindInputRegistered:
		_, err = decodeInputPayload(payload)
	case KindArtifactRecorded:
		var artifact artifactPayload
		artifact, err = decodeArtifactPayload(payload)
		if err == nil {
			err = validateFactReference(taskID, artifact.Run, s.facts, KindRunRecorded, "artifact run")
		}
	case KindClaimRecorded:
		var claim claimPayload
		claim, err = decodeClaimPayload(payload)
		if err == nil {
			err = validateFactReference(taskID, claim.OriginArtifact, s.facts, KindArtifactRecorded, "claim origin Artifact")
		}
	case KindSourceReferenceRecorded:
		_, err = decodeSourceReferencePayload(payload)
	case KindEvidenceLinked:
		var evidence evidenceLinkPayload
		evidence, err = decodeEvidenceLinkPayload(payload)
		if err == nil {
			err = validateFactReference(taskID, &evidence.Claim, s.facts, KindClaimRecorded, "evidence Claim")
		}
		if err == nil {
			err = validateFactReference(taskID, &evidence.Source, s.facts, KindSourceReferenceRecorded, "evidence Source Reference")
		}
	case KindReviewRecorded:
		var review reviewPayload
		review, err = decodeReviewPayload(payload)
		if err == nil {
			err = validateFactReference(taskID, &review.Subject, s.facts, "", "review subject")
		}
	case KindApprovalRecorded:
		var approval approvalPayload
		approval, err = decodeApprovalPayload(payload)
		if err == nil {
			err = validateFactReference(taskID, &approval.Subject, s.facts, "", "approval subject")
		}
	case KindPolicyDecisionRecorded:
		var decision policyDecisionPayload
		decision, err = decodePolicyDecisionPayload(payload)
		if err == nil {
			err = validateFactReference(taskID, &decision.Subject, s.facts, "", "policy decision subject")
		}
	case KindDeliveryRecorded:
		var delivery deliveryPayload
		delivery, err = decodeDeliveryPayload(payload)
		if err == nil {
			for i := range delivery.Artifacts {
				err = validateFactReference(taskID, &delivery.Artifacts[i], s.facts, KindArtifactRecorded, "delivery Artifact")
				if err != nil {
					break
				}
			}
		}
	case KindOpaqueRecorded:
		_, err = decodeOpaquePayload(payload)
	}
	return "invalid_payload", err
}

func Create(path, workspaceID string) (*Workspace, error) {
	if path == "" || workspaceID == "" {
		return nil, fmt.Errorf("%w: path and workspace ID are required", ErrConflict)
	}
	root, err := canonicalExistingDirectory(path)
	if err != nil {
		return nil, err
	}
	mcrDir := filepath.Join(root, ".mcr")
	if err := os.Mkdir(mcrDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s already exists", ErrConflict, mcrDir)
		}
		return nil, fmt.Errorf("create workspace: %w", err)
	}

	recordedAt := time.Now().UTC().Format(time.RFC3339Nano)
	header := workspaceHeader{
		RecordType: "workspace", FormatVersion: FormatNative, WorkspaceID: workspaceID,
		RecordedAt: recordedAt, PrevHash: zeroHash,
	}
	header.RecordHash, err = hashRecord(struct {
		RecordType    string `json:"record_type"`
		FormatVersion string `json:"format_version"`
		WorkspaceID   string `json:"workspace_id"`
		RecordedAt    string `json:"recorded_at"`
		PrevHash      string `json:"prev_hash"`
	}{header.RecordType, header.FormatVersion, header.WorkspaceID, header.RecordedAt, header.PrevHash})
	if err != nil {
		return nil, err
	}
	line, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	ledger, err := os.OpenFile(filepath.Join(mcrDir, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create ledger: %w", err)
	}
	if _, err = ledger.Write(append(line, '\n')); err == nil {
		err = ledger.Sync()
	}
	closeErr := ledger.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, fmt.Errorf("initialize ledger: %w", err)
	}
	return &Workspace{path: root}, nil
}

func Open(path string) (*Workspace, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: workspace path is required", ErrNotFound)
	}
	root, err := canonicalExistingDirectory(path)
	if err != nil {
		return nil, err
	}
	mcrDir := filepath.Join(root, ".mcr")
	if err := requireRealDirectory(mcrDir); err != nil {
		return nil, err
	}
	if err := requireRegular(filepath.Join(mcrDir, "events.jsonl")); err != nil {
		return nil, err
	}
	return &Workspace{path: root}, nil
}

func (w *Workspace) Submit(submission Submission) (Fact, error) {
	var zero Fact

	h, verification, err := w.readHistory()
	if err != nil {
		return zero, err
	}
	if !verification.StructuralValid || verification.Integrity != IntegritySealedValid {
		return zero, fmt.Errorf("%w: workspace ledger is not valid", ErrInvalidHistory)
	}
	if err := validateSubmission(submission, h); err != nil {
		return zero, err
	}

	factID, err := newFactID(h.facts)
	if err != nil {
		return zero, fmt.Errorf("generate fact identity: %w", err)
	}
	payload := compactJSON(submission.Payload)
	record := factRecord{
		RecordType: "fact", FactID: factID, TaskID: submission.TaskID, Kind: submission.Kind,
		Actor: submission.Actor, RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Payload: payload,
		PrevHash: h.header.RecordHash,
	}
	if len(h.facts) > 0 {
		record.PrevHash = h.facts[len(h.facts)-1].RecordHash
	}
	record.RecordHash, err = hashRecord(struct {
		RecordType string          `json:"record_type"`
		FactID     string          `json:"fact_id"`
		TaskID     string          `json:"task_id"`
		Kind       string          `json:"kind"`
		Actor      Actor           `json:"actor"`
		RecordedAt string          `json:"recorded_at"`
		Payload    json.RawMessage `json:"payload"`
		PrevHash   string          `json:"prev_hash"`
	}{record.RecordType, record.FactID, record.TaskID, record.Kind, record.Actor, record.RecordedAt, record.Payload, record.PrevHash})
	if err != nil {
		return zero, err
	}
	line, err := json.Marshal(record)
	if err != nil {
		return zero, err
	}
	if err := w.appendRecord(line); err != nil {
		return zero, err
	}
	return record.fact(), nil
}

func (w *Workspace) Query(query FactQuery) ([]Fact, error) {
	h, verification, err := w.readHistory()
	if err != nil {
		return nil, err
	}
	if !verification.StructuralValid || verification.Integrity != IntegritySealedValid {
		return nil, fmt.Errorf("%w: workspace ledger is not valid", ErrInvalidHistory)
	}
	facts := make([]Fact, 0, len(h.facts))
	for _, fact := range h.facts {
		if (query.FactID == "" || fact.FactID == query.FactID) &&
			(query.TaskID == "" || fact.TaskID == query.TaskID) &&
			(query.Kind == "" || fact.Kind == query.Kind) {
			facts = append(facts, fact)
		}
	}
	return facts, nil
}

func (w *Workspace) Replay() (Projection, error) {
	h, verification, err := w.readHistory()
	if err != nil {
		return Projection{}, err
	}
	if !verification.StructuralValid || verification.Integrity != IntegritySealedValid {
		return Projection{}, fmt.Errorf("%w: workspace ledger is not valid", ErrInvalidHistory)
	}
	projection := Projection{WorkspaceID: h.header.WorkspaceID, Format: "native", Integrity: IntegritySealedValid, Tasks: make([]TaskProjection, 0, len(h.facts))}
	taskIndexes := make(map[string]int)
	for _, fact := range h.facts {
		switch fact.Kind {
		case KindTaskCreated:
			definition, _ := decodeTaskPayload(fact.Payload)
			taskIndexes[fact.TaskID] = len(projection.Tasks)
			projection.Tasks = append(projection.Tasks, TaskProjection{
				TaskID: fact.TaskID, SourceFactID: fact.FactID, Definition: definition,
				Runs: []RunProjection{}, RegisteredInputs: []RegisteredInputProjection{}, Artifacts: []ArtifactProjection{},
				Claims: []ClaimProjection{}, SourceReferences: []SourceReferenceProjection{}, EvidenceLinks: []EvidenceLinkProjection{},
				Reviews: []ReviewProjection{}, Approvals: []ApprovalProjection{}, PolicyDecisions: []PolicyDecisionProjection{},
				Deliveries: []DeliveryProjection{}, OpaqueFacts: []OpaqueFactProjection{},
			})
		case KindRunRecorded:
			payload, _ := decodeRunPayload(fact.Payload)
			task := &projection.Tasks[taskIndexes[fact.TaskID]]
			task.Runs = append(task.Runs, RunProjection{
				SourceFactID: fact.FactID, StartedAt: payload.StartedAt, EndedAt: payload.EndedAt, Outcome: payload.Outcome,
			})
		case KindInputRegistered:
			content, _ := decodeInputPayload(fact.Payload)
			task := &projection.Tasks[taskIndexes[fact.TaskID]]
			task.RegisteredInputs = append(task.RegisteredInputs, RegisteredInputProjection{SourceFactID: fact.FactID, Content: content})
		case KindArtifactRecorded:
			payload, _ := decodeArtifactPayload(fact.Payload)
			task := &projection.Tasks[taskIndexes[fact.TaskID]]
			task.Artifacts = append(task.Artifacts, ArtifactProjection{SourceFactID: fact.FactID, Content: payload.Content, Run: payload.Run})
		case KindClaimRecorded:
			payload, _ := decodeClaimPayload(fact.Payload)
			task := &projection.Tasks[taskIndexes[fact.TaskID]]
			task.Claims = append(task.Claims, ClaimProjection{SourceFactID: fact.FactID, Statement: payload.Statement, OriginArtifact: payload.OriginArtifact})
		case KindSourceReferenceRecorded:
			payload, _ := decodeSourceReferencePayload(fact.Payload)
			task := &projection.Tasks[taskIndexes[fact.TaskID]]
			task.SourceReferences = append(task.SourceReferences, SourceReferenceProjection{SourceFactID: fact.FactID, Content: payload.Content, Anchor: payload.Anchor})
		case KindEvidenceLinked:
			payload, _ := decodeEvidenceLinkPayload(fact.Payload)
			task := &projection.Tasks[taskIndexes[fact.TaskID]]
			task.EvidenceLinks = append(task.EvidenceLinks, EvidenceLinkProjection{SourceFactID: fact.FactID, Claim: payload.Claim, Source: payload.Source})
		case KindReviewRecorded:
			payload, _ := decodeReviewPayload(fact.Payload)
			task := &projection.Tasks[taskIndexes[fact.TaskID]]
			task.Reviews = append(task.Reviews, ReviewProjection{SourceFactID: fact.FactID, Subject: payload.Subject, Outcome: payload.Outcome, Findings: payload.Findings})
		case KindApprovalRecorded:
			payload, _ := decodeApprovalPayload(fact.Payload)
			task := &projection.Tasks[taskIndexes[fact.TaskID]]
			task.Approvals = append(task.Approvals, ApprovalProjection{SourceFactID: fact.FactID, Subject: payload.Subject, Scope: payload.Scope, Decision: payload.Decision, Note: payload.Note})
		case KindPolicyDecisionRecorded:
			payload, _ := decodePolicyDecisionPayload(fact.Payload)
			task := &projection.Tasks[taskIndexes[fact.TaskID]]
			task.PolicyDecisions = append(task.PolicyDecisions, PolicyDecisionProjection{SourceFactID: fact.FactID, Subject: payload.Subject, Action: payload.Action, Policy: payload.Policy, Result: payload.Result})
		case KindDeliveryRecorded:
			payload, _ := decodeDeliveryPayload(fact.Payload)
			task := &projection.Tasks[taskIndexes[fact.TaskID]]
			task.Deliveries = append(task.Deliveries, DeliveryProjection{SourceFactID: fact.FactID, Artifacts: payload.Artifacts, Format: payload.Format, Scope: payload.Scope, Target: payload.Target})
		case KindOpaqueRecorded:
			payload, _ := decodeOpaquePayload(fact.Payload)
			task := &projection.Tasks[taskIndexes[fact.TaskID]]
			task.OpaqueFacts = append(task.OpaqueFacts, OpaqueFactProjection{SourceFactID: fact.FactID, Kind: payload.Kind, Data: payload.Data})
		}
	}
	return projection, nil
}

func (w *Workspace) Verify() (Verification, error) {
	_, verification, err := w.readHistory()
	return verification, err
}

func (w *Workspace) readHistory() (history, Verification, error) {
	ledgerPath := filepath.Join(w.path, ".mcr", "events.jsonl")
	data, err := os.ReadFile(ledgerPath)
	if err != nil {
		return history{}, Verification{}, fmt.Errorf("read workspace ledger: %w", err)
	}
	h, verification := parseNative(data)
	return h, verification, nil
}

func parseNative(data []byte) (history, Verification) {
	v := Verification{Format: "native", Diagnostics: []Diagnostic{}}
	if !utf8.Valid(data) || bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return history{}, invalidVerification("invalid_encoding", 0, "", "ledger must be UTF-8 without BOM")
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return history{}, invalidVerification("missing_newline", 0, "", "every record must end with a newline")
	}
	lines := bytes.Split(data[:len(data)-1], []byte{'\n'})
	v.RecordCount = len(lines)
	for i, line := range lines {
		if len(line) == 0 {
			return history{}, invalidVerificationWithCount("blank_line", i+1, "", "blank records are not allowed", len(lines))
		}
	}
	if len(lines) == 0 {
		return history{}, invalidVerification("missing_header", 1, "", "workspace header is required")
	}

	headerFields, err := decodeOrderedObject(lines[0])
	if err != nil || !fieldNamesEqual(headerFields, []string{"record_type", "format_version", "workspace_id", "recorded_at", "prev_hash", "record_hash"}) {
		return history{}, invalidVerificationWithCount("invalid_header", 1, "", "workspace header fields are invalid", len(lines))
	}
	var header workspaceHeader
	if err := strictDecode(lines[0], &header); err != nil || header.RecordType != "workspace" || header.FormatVersion != FormatNative || header.WorkspaceID == "" || header.PrevHash != zeroHash || !nativeHash.MatchString(header.RecordHash) || !validUTCTimestamp(header.RecordedAt) {
		return history{}, invalidVerificationWithCount("invalid_header", 1, header.WorkspaceID, "workspace header values are invalid", len(lines))
	}
	expectedHeaderHash, _ := hashRecord(struct {
		RecordType    string `json:"record_type"`
		FormatVersion string `json:"format_version"`
		WorkspaceID   string `json:"workspace_id"`
		RecordedAt    string `json:"recorded_at"`
		PrevHash      string `json:"prev_hash"`
	}{header.RecordType, header.FormatVersion, header.WorkspaceID, header.RecordedAt, header.PrevHash})
	if header.RecordHash != expectedHeaderHash {
		return history{}, invalidVerificationWithCount("record_hash_mismatch", 1, header.WorkspaceID, "workspace header hash does not match", len(lines))
	}

	h := history{header: header, facts: make([]Fact, 0, len(lines)-1)}
	state := newNativeState(nil)
	previousHash := header.RecordHash
	lastID := header.WorkspaceID
	for i := 1; i < len(lines); i++ {
		number := i + 1
		if err := jsonstrict.Validate(lines[i]); err != nil {
			return history{}, invalidVerificationWithCount("invalid_fact_envelope", number, "", err.Error(), len(lines))
		}
		fields, err := decodeOrderedObject(lines[i])
		if err != nil || !fieldNamesEqual(fields, []string{"record_type", "fact_id", "task_id", "kind", "actor", "recorded_at", "payload", "prev_hash", "record_hash"}) {
			return history{}, invalidVerificationWithCount("invalid_fact_envelope", number, "", "fact envelope fields are invalid", len(lines))
		}
		var record factRecord
		if err := strictDecode(lines[i], &record); err != nil || record.RecordType != "fact" || record.FactID == "" || record.TaskID == "" || record.Actor.Type == "" || record.Actor.ID == "" || !validUTCTimestamp(record.RecordedAt) || !nativeHash.MatchString(record.PrevHash) || !nativeHash.MatchString(record.RecordHash) {
			return history{}, invalidVerificationWithCount("invalid_fact_envelope", number, record.FactID, "fact envelope values are invalid", len(lines))
		}
		if record.PrevHash != previousHash {
			return history{}, invalidVerificationWithCount("previous_hash_mismatch", number, record.FactID, "previous hash does not match", len(lines))
		}
		expectedHash, _ := hashRecord(struct {
			RecordType string          `json:"record_type"`
			FactID     string          `json:"fact_id"`
			TaskID     string          `json:"task_id"`
			Kind       string          `json:"kind"`
			Actor      Actor           `json:"actor"`
			RecordedAt string          `json:"recorded_at"`
			Payload    json.RawMessage `json:"payload"`
			PrevHash   string          `json:"prev_hash"`
		}{record.RecordType, record.FactID, record.TaskID, record.Kind, record.Actor, record.RecordedAt, record.Payload, record.PrevHash})
		if record.RecordHash != expectedHash {
			return history{}, invalidVerificationWithCount("record_hash_mismatch", number, record.FactID, "fact hash does not match", len(lines))
		}
		code, err := state.validate(record.TaskID, record.Kind, record.Payload)
		if err != nil {
			return history{}, invalidVerificationWithCount(code, number, record.FactID, err.Error(), len(lines))
		}
		h.facts = append(h.facts, record.fact())
		state.add(h.facts[len(h.facts)-1])
		previousHash = record.RecordHash
		lastID = record.FactID
	}
	v.StructuralValid = true
	v.Integrity = IntegritySealedValid
	v.LastRecordID = lastID
	return h, v
}

func validateSubmission(submission Submission, h history) error {
	if submission.TaskID == "" || submission.Actor.Type == "" || submission.Actor.ID == "" || submission.Kind == "" {
		return fmt.Errorf("%w: task ID, actor, and kind are required", ErrInvalidSubmission)
	}
	state := newNativeState(h.facts)
	_, err := state.validate(submission.TaskID, submission.Kind, submission.Payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSubmission, err)
	}
	return nil
}

func decodeTaskPayload(raw json.RawMessage) (DefinitionRef, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return DefinitionRef{}, err
	}
	var payload struct {
		Definition DefinitionRef `json:"definition"`
	}
	if err := strictDecode(raw, &payload); err != nil {
		return DefinitionRef{}, fmt.Errorf("invalid task payload: %w", err)
	}
	d := payload.Definition
	if d.Namespace == "" || d.ID == "" || d.Version == "" || d.Locator == "" || !nativeHash.MatchString(d.SHA256) {
		return DefinitionRef{}, errors.New("definition requires namespace, id, version, locator, and native sha256")
	}
	return d, nil
}

func decodeRunPayload(raw json.RawMessage) (runPayload, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return runPayload{}, err
	}
	var encoded struct {
		StartedAt string `json:"started_at"`
		EndedAt   string `json:"ended_at"`
		Outcome   string `json:"outcome"`
	}
	if err := strictDecode(raw, &encoded); err != nil {
		return runPayload{}, fmt.Errorf("invalid run payload: %w", err)
	}
	if encoded.Outcome == "" || !validUTCTimestamp(encoded.StartedAt) || !validUTCTimestamp(encoded.EndedAt) {
		return runPayload{}, errors.New("run requires UTC start and end timestamps and a non-empty outcome")
	}
	startedAt, _ := time.Parse(time.RFC3339Nano, encoded.StartedAt)
	endedAt, _ := time.Parse(time.RFC3339Nano, encoded.EndedAt)
	if endedAt.Before(startedAt) {
		return runPayload{}, errors.New("run end cannot precede start")
	}
	return runPayload{StartedAt: startedAt, EndedAt: endedAt, Outcome: encoded.Outcome}, nil
}

func decodeInputPayload(raw json.RawMessage) (ContentRef, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return ContentRef{}, err
	}
	var payload struct {
		Content ContentRef `json:"content"`
	}
	if err := strictDecode(raw, &payload); err != nil {
		return ContentRef{}, fmt.Errorf("invalid input payload: %w", err)
	}
	if err := validateContentRef(payload.Content); err != nil {
		return ContentRef{}, err
	}
	return payload.Content, nil
}

func decodeArtifactPayload(raw json.RawMessage) (artifactPayload, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return artifactPayload{}, err
	}
	var encoded struct {
		Content ContentRef      `json:"content"`
		Run     json.RawMessage `json:"run"`
	}
	if err := strictDecode(raw, &encoded); err != nil {
		return artifactPayload{}, fmt.Errorf("invalid artifact payload: %w", err)
	}
	if err := validateContentRef(encoded.Content); err != nil {
		return artifactPayload{}, err
	}
	payload := artifactPayload{Content: encoded.Content}
	if len(encoded.Run) == 0 {
		return payload, nil
	}
	var ref FactRef
	if err := strictDecode(encoded.Run, &ref); err != nil || ref.FactID == "" || !nativeHash.MatchString(ref.RecordHash) {
		return artifactPayload{}, errors.New("artifact run must be an exact Fact Reference")
	}
	payload.Run = &ref
	return payload, nil
}

func decodeClaimPayload(raw json.RawMessage) (claimPayload, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return claimPayload{}, err
	}
	var encoded struct {
		Statement      string          `json:"statement"`
		OriginArtifact json.RawMessage `json:"origin_artifact"`
	}
	if err := strictDecode(raw, &encoded); err != nil {
		return claimPayload{}, fmt.Errorf("invalid claim payload: %w", err)
	}
	if encoded.Statement == "" {
		return claimPayload{}, errors.New("claim requires a non-empty statement")
	}
	payload := claimPayload{Statement: encoded.Statement}
	if len(encoded.OriginArtifact) == 0 {
		return payload, nil
	}
	var ref FactRef
	if err := strictDecode(encoded.OriginArtifact, &ref); err != nil || !validFactRef(ref) {
		return claimPayload{}, errors.New("claim origin Artifact must be an exact Fact Reference")
	}
	payload.OriginArtifact = &ref
	return payload, nil
}

func decodeSourceReferencePayload(raw json.RawMessage) (sourceReferencePayload, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return sourceReferencePayload{}, err
	}
	var payload struct {
		Content ContentRef `json:"content"`
		Anchor  string     `json:"anchor"`
	}
	if err := strictDecode(raw, &payload); err != nil {
		return sourceReferencePayload{}, fmt.Errorf("invalid source reference payload: %w", err)
	}
	if err := validateContentRef(payload.Content); err != nil {
		return sourceReferencePayload{}, err
	}
	if payload.Anchor == "" {
		return sourceReferencePayload{}, errors.New("source reference requires a non-empty anchor")
	}
	return sourceReferencePayload(payload), nil
}

func decodeEvidenceLinkPayload(raw json.RawMessage) (evidenceLinkPayload, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return evidenceLinkPayload{}, err
	}
	var payload evidenceLinkPayload
	if err := strictDecode(raw, &payload); err != nil {
		return evidenceLinkPayload{}, fmt.Errorf("invalid evidence link payload: %w", err)
	}
	if !validFactRef(payload.Claim) || !validFactRef(payload.Source) {
		return evidenceLinkPayload{}, errors.New("evidence link requires exact Claim and Source References")
	}
	return payload, nil
}

func decodeReviewPayload(raw json.RawMessage) (reviewPayload, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return reviewPayload{}, err
	}
	var encoded struct {
		Subject  FactRef         `json:"subject"`
		Outcome  string          `json:"outcome"`
		Findings json.RawMessage `json:"findings"`
	}
	if err := strictDecode(raw, &encoded); err != nil {
		return reviewPayload{}, fmt.Errorf("invalid review payload: %w", err)
	}
	if !validFactRef(encoded.Subject) || encoded.Outcome == "" {
		return reviewPayload{}, errors.New("review requires an exact subject and non-empty outcome")
	}
	findings, err := decodeOptionalNonEmptyString(encoded.Findings, "review findings")
	if err != nil {
		return reviewPayload{}, err
	}
	return reviewPayload{Subject: encoded.Subject, Outcome: encoded.Outcome, Findings: findings}, nil
}

func decodeApprovalPayload(raw json.RawMessage) (approvalPayload, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return approvalPayload{}, err
	}
	var encoded struct {
		Subject  FactRef         `json:"subject"`
		Scope    string          `json:"scope"`
		Decision string          `json:"decision"`
		Note     json.RawMessage `json:"note"`
	}
	if err := strictDecode(raw, &encoded); err != nil {
		return approvalPayload{}, fmt.Errorf("invalid approval payload: %w", err)
	}
	if !validFactRef(encoded.Subject) || encoded.Scope == "" || encoded.Decision == "" {
		return approvalPayload{}, errors.New("approval requires an exact subject and non-empty scope and decision")
	}
	note, err := decodeOptionalNonEmptyString(encoded.Note, "approval note")
	if err != nil {
		return approvalPayload{}, err
	}
	return approvalPayload{Subject: encoded.Subject, Scope: encoded.Scope, Decision: encoded.Decision, Note: note}, nil
}

func decodePolicyDecisionPayload(raw json.RawMessage) (policyDecisionPayload, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return policyDecisionPayload{}, err
	}
	var payload policyDecisionPayload
	if err := strictDecode(raw, &payload); err != nil {
		return policyDecisionPayload{}, fmt.Errorf("invalid policy decision payload: %w", err)
	}
	if !validFactRef(payload.Subject) || payload.Action == "" || payload.Policy == "" || payload.Result == "" {
		return policyDecisionPayload{}, errors.New("policy decision requires an exact subject and non-empty action, policy, and result")
	}
	return payload, nil
}

func decodeDeliveryPayload(raw json.RawMessage) (deliveryPayload, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return deliveryPayload{}, err
	}
	var payload deliveryPayload
	if err := strictDecode(raw, &payload); err != nil {
		return deliveryPayload{}, fmt.Errorf("invalid delivery payload: %w", err)
	}
	if len(payload.Artifacts) == 0 || payload.Format == "" || payload.Scope == "" || payload.Target == "" {
		return deliveryPayload{}, errors.New("delivery requires Artifacts and non-empty format, scope, and target")
	}
	seen := make(map[string]bool, len(payload.Artifacts))
	for _, artifact := range payload.Artifacts {
		if !validFactRef(artifact) {
			return deliveryPayload{}, errors.New("delivery Artifacts must be exact Fact References")
		}
		if seen[artifact.FactID] {
			return deliveryPayload{}, errors.New("delivery Artifacts must not contain duplicates")
		}
		seen[artifact.FactID] = true
	}
	return payload, nil
}

func decodeOpaquePayload(raw json.RawMessage) (opaquePayload, error) {
	if err := jsonstrict.Validate(raw); err != nil {
		return opaquePayload{}, err
	}
	var encoded struct {
		Kind string          `json:"kind"`
		Data json.RawMessage `json:"data"`
	}
	if err := strictDecode(raw, &encoded); err != nil {
		return opaquePayload{}, fmt.Errorf("invalid opaque payload: %w", err)
	}
	if encoded.Kind == "" || isNativeKind(encoded.Kind) {
		return opaquePayload{}, errors.New("opaque Fact requires a non-native external kind")
	}
	if _, err := decodeOrderedObject(encoded.Data); err != nil {
		return opaquePayload{}, errors.New("opaque Fact data must be a JSON object")
	}
	return opaquePayload{Kind: encoded.Kind, Data: append(json.RawMessage(nil), encoded.Data...)}, nil
}

func decodeOptionalNonEmptyString(raw json.RawMessage, name string) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", fmt.Errorf("%s must be a non-empty string when present", name)
	}
	var value string
	if err := strictDecode(trimmed, &value); err != nil || value == "" {
		return "", fmt.Errorf("%s must be a non-empty string when present", name)
	}
	return value, nil
}

func isNativeKind(kind string) bool {
	switch kind {
	case KindTaskCreated, KindRunRecorded, KindInputRegistered, KindArtifactRecorded, KindClaimRecorded, KindSourceReferenceRecorded, KindEvidenceLinked, KindReviewRecorded, KindApprovalRecorded, KindPolicyDecisionRecorded, KindDeliveryRecorded, KindOpaqueRecorded:
		return true
	default:
		return false
	}
}

func validFactRef(ref FactRef) bool {
	return ref.FactID != "" && nativeHash.MatchString(ref.RecordHash)
}

func validateFactReference(taskID string, ref *FactRef, prior map[string]Fact, kind, name string) error {
	if ref == nil {
		return nil
	}
	fact, found := prior[ref.FactID]
	if !found {
		return fmt.Errorf("%s does not reference an earlier Fact", name)
	}
	if fact.TaskID != taskID {
		return fmt.Errorf("%s must belong to the same Task", name)
	}
	if kind != "" && fact.Kind != kind {
		return fmt.Errorf("%s must reference %s", name, kind)
	}
	if fact.RecordHash != ref.RecordHash {
		return fmt.Errorf("%s record hash does not match", name)
	}
	return nil
}

func validateContentRef(content ContentRef) error {
	if content.Locator == "" || !nativeHash.MatchString(content.SHA256) {
		return errors.New("content requires a locator and native sha256")
	}
	return nil
}

func (w *Workspace) appendRecord(line []byte) error {
	ledger, err := os.OpenFile(filepath.Join(w.path, ".mcr", "events.jsonl"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("open workspace ledger: %w", err)
	}
	if _, err = ledger.Write(append(line, '\n')); err == nil {
		err = ledger.Sync()
	}
	closeErr := ledger.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("append workspace ledger: %w", err)
	}
	return nil
}

// ponytail: issue #15 owns inter-process locking and atomic replacement.

func canonicalExistingDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve workspace path: %w", err)
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return "", fmt.Errorf("resolve workspace path: %w", err)
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return "", fmt.Errorf("resolve workspace path: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: workspace path is not a directory", ErrConflict)
	}
	return canonical, nil
}

func requireRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: %s is not a real directory", ErrConflict, path)
	}
	return nil
}

func requireRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrConflict, path)
	}
	return nil
}

func newFactID(existing []Fact) (string, error) {
	known := make(map[string]struct{}, len(existing))
	for _, fact := range existing {
		known[fact.FactID] = struct{}{}
	}
	for {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		id := "fact_" + hex.EncodeToString(buf)
		if _, found := known[id]; !found {
			return id, nil
		}
	}
}

func hashRecord(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func compactJSON(raw []byte) []byte {
	var out bytes.Buffer
	_ = json.Compact(&out, raw)
	return out.Bytes()
}

func strictDecode(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

type objectField struct {
	name string
	raw  json.RawMessage
}

func decodeOrderedObject(raw []byte) ([]objectField, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	fields := make([]objectField, 0)
	seen := make(map[string]bool)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok || seen[key] {
			return nil, errors.New("duplicate or invalid object key")
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields = append(fields, objectField{name: key, raw: value})
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return nil, errors.New("trailing JSON value")
	}
	return fields, nil
}

func fieldNamesEqual(fields []objectField, expected []string) bool {
	if len(fields) != len(expected) {
		return false
	}
	for i := range fields {
		if fields[i].name != expected[i] {
			return false
		}
	}
	return true
}

func validUTCTimestamp(value string) bool {
	t, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && strings.HasSuffix(value, "Z") && t.Location() == time.UTC
}

func (record factRecord) fact() Fact {
	recordedAt, _ := time.Parse(time.RFC3339Nano, record.RecordedAt)
	return Fact{
		FactID: record.FactID, TaskID: record.TaskID, Kind: record.Kind, Actor: record.Actor,
		RecordedAt: recordedAt, Payload: append(json.RawMessage(nil), record.Payload...),
		PrevHash: record.PrevHash, RecordHash: record.RecordHash,
	}
}

func invalidVerification(code string, number int, id, message string) Verification {
	return invalidVerificationWithCount(code, number, id, message, 0)
}

func invalidVerificationWithCount(code string, number int, id, message string, count int) Verification {
	return Verification{
		Format: "native", StructuralValid: false, RecordCount: count,
		Diagnostics: []Diagnostic{{Code: code, RecordNumber: number, RecordID: id, Message: message}},
	}
}
