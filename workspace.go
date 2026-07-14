package mcr

import (
	"bufio"
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
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Notyet1307/MCR-Core/internal/jsonstrict"
)

const zeroHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

var nativeHash = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var beforeLedgerReplace = func() error { return nil }
var errNotRegular = errors.New("not regular")
var errCacheNotObject = errors.New("cache not object")
var errCacheInvalidJSON = errors.New("cache invalid JSON")

const maxLegacyCacheDepth = 10000

var afterWorkspaceLock = func() error { return nil }
var beforeWorkspaceIO = func() error { return nil }
var beforeRootRegularOpen = func(string) error { return nil }

type workspaceLock struct {
	root      *os.Root
	storage   *os.Root
	directory *os.File
}

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
	header         workspaceHeader
	format         string
	readOnly       bool
	state          nativeState
	lastRecordHash string
}

type factTarget struct {
	TaskID     string
	Kind       string
	RecordHash string
}

type factSink func(Fact, json.RawMessage)

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
	facts map[string]factTarget
}

func newNativeState(capacity int) nativeState {
	return nativeState{tasks: make(map[string]bool), facts: make(map[string]factTarget, capacity)}
}

func (s *nativeState) add(fact Fact) {
	s.facts[fact.FactID] = factTarget{TaskID: fact.TaskID, Kind: fact.Kind, RecordHash: fact.RecordHash}
	if fact.Kind == KindTaskCreated {
		s.tasks[fact.TaskID] = true
	}
}

func (s *nativeState) validate(taskID, kind string, payload json.RawMessage) (string, error) {
	if !isNativeKind(kind) {
		return "unknown_kind", errors.New("native fact kind is not supported")
	}
	if taskID == "" && kind != KindOpaqueRecorded {
		return "invalid_payload", errors.New("task ID is required")
	}
	taskExists := s.tasks[taskID]
	if kind != KindTaskCreated && !taskExists && !(kind == KindOpaqueRecorded && taskID == "") {
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
	rootLock, err := lockDirectory(root, true)
	if err != nil {
		return nil, err
	}
	defer unlockDirectory(rootLock)

	mcrDir := filepath.Join(root, ".mcr")
	if err := os.Mkdir(mcrDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s already exists", ErrConflict, mcrDir)
		}
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	storage, err := openDirectory(mcrDir)
	if err != nil {
		return nil, fmt.Errorf("open workspace storage: %w", err)
	}
	if err = storage.Chmod(0o700); err == nil {
		err = storage.Close()
	} else {
		_ = storage.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("set workspace storage permissions: %w", err)
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
	if err = ledger.Chmod(0o600); err == nil {
		_, err = ledger.Write(append(line, '\n'))
	}
	if err == nil {
		err = ledger.Sync()
	}
	closeErr := ledger.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = syncDirectory(mcrDir)
	}
	if err == nil {
		err = syncDirectory(root)
	}
	if err != nil {
		return nil, fmt.Errorf("initialize ledger: %w", err)
	}
	return captureWorkspace(root)
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
	return captureWorkspace(root)
}

func (w *Workspace) Submit(submission Submission) (Fact, error) {
	var zero Fact
	lock, err := w.lock(true)
	if err != nil {
		return zero, err
	}
	defer unlockWorkspace(lock)

	h, verification, err := w.readHistory(lock.storage, nil)
	if err != nil {
		return zero, err
	}
	if !acceptedHistory(verification) {
		return zero, fmt.Errorf("%w: workspace ledger is not valid", ErrInvalidHistory)
	}
	if h.readOnly {
		return zero, fmt.Errorf("%w: legacy workspace", ErrReadOnly)
	}
	if err := validateSubmission(submission, h.state); err != nil {
		return zero, err
	}

	factID, err := newFactID(h.state.facts)
	if err != nil {
		return zero, fmt.Errorf("generate fact identity: %w", err)
	}
	payload := compactJSON(submission.Payload)
	record := factRecord{
		RecordType: "fact", FactID: factID, TaskID: submission.TaskID, Kind: submission.Kind,
		Actor: submission.Actor, RecordedAt: time.Now().UTC().Format(time.RFC3339Nano), Payload: payload,
		PrevHash: h.lastRecordHash,
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
	if err := w.appendRecord(lock, line); err != nil {
		return zero, err
	}
	return record.fact(), nil
}

func (w *Workspace) Query(query FactQuery) ([]Fact, error) {
	lock, err := w.lock(false)
	if err != nil {
		return nil, err
	}
	defer unlockWorkspace(lock)

	facts := make([]Fact, 0)
	_, verification, err := w.readHistory(lock.storage, func(fact Fact, _ json.RawMessage) {
		if (query.FactID == "" || fact.FactID == query.FactID) &&
			(query.TaskID == "" || fact.TaskID == query.TaskID) &&
			(query.Kind == "" || fact.Kind == query.Kind) {
			facts = append(facts, fact)
		}
	})
	if err != nil {
		return nil, err
	}
	if !acceptedHistory(verification) {
		return nil, fmt.Errorf("%w: workspace ledger is not valid", ErrInvalidHistory)
	}
	return facts, nil
}

func (w *Workspace) Replay() (Projection, error) {
	lock, err := w.lock(false)
	if err != nil {
		return Projection{}, err
	}
	defer unlockWorkspace(lock)

	builder := newProjectionBuilder()
	h, verification, err := w.readHistory(lock.storage, builder.add)
	if err != nil {
		return Projection{}, err
	}
	if !acceptedHistory(verification) {
		return Projection{}, fmt.Errorf("%w: workspace ledger is not valid", ErrInvalidHistory)
	}
	return builder.result(h.header.WorkspaceID, verification.Format, verification.Integrity), nil
}

func acceptedHistory(verification Verification) bool {
	return verification.StructuralValid && (verification.Integrity == IntegritySealedValid || verification.Integrity == IntegrityUnsealed)
}

type projectionBuilder struct {
	projection  Projection
	taskIndexes map[string]int
}

func newProjectionBuilder() *projectionBuilder {
	return &projectionBuilder{
		projection:  Projection{Tasks: []TaskProjection{}, OpaqueFacts: []OpaqueFactProjection{}},
		taskIndexes: make(map[string]int),
	}
}

func (b *projectionBuilder) add(fact Fact, payload json.RawMessage) {
	switch fact.Kind {
	case KindTaskCreated:
		definition, _ := decodeTaskPayload(payload)
		b.taskIndexes[fact.TaskID] = len(b.projection.Tasks)
		b.projection.Tasks = append(b.projection.Tasks, TaskProjection{
			TaskID: fact.TaskID, SourceFactID: fact.FactID, Definition: definition,
			Runs: []RunProjection{}, RegisteredInputs: []RegisteredInputProjection{}, Artifacts: []ArtifactProjection{},
			Claims: []ClaimProjection{}, SourceReferences: []SourceReferenceProjection{}, EvidenceLinks: []EvidenceLinkProjection{},
			Reviews: []ReviewProjection{}, Approvals: []ApprovalProjection{}, PolicyDecisions: []PolicyDecisionProjection{},
			Deliveries: []DeliveryProjection{}, OpaqueFacts: []OpaqueFactProjection{},
		})
	case KindRunRecorded:
		decoded, _ := decodeRunPayload(payload)
		task := &b.projection.Tasks[b.taskIndexes[fact.TaskID]]
		task.Runs = append(task.Runs, RunProjection{SourceFactID: fact.FactID, StartedAt: decoded.StartedAt, EndedAt: decoded.EndedAt, Outcome: decoded.Outcome})
	case KindInputRegistered:
		content, _ := decodeInputPayload(payload)
		task := &b.projection.Tasks[b.taskIndexes[fact.TaskID]]
		task.RegisteredInputs = append(task.RegisteredInputs, RegisteredInputProjection{SourceFactID: fact.FactID, Content: content})
	case KindArtifactRecorded:
		decoded, _ := decodeArtifactPayload(payload)
		task := &b.projection.Tasks[b.taskIndexes[fact.TaskID]]
		task.Artifacts = append(task.Artifacts, ArtifactProjection{SourceFactID: fact.FactID, Content: decoded.Content, Run: decoded.Run})
	case KindClaimRecorded:
		decoded, _ := decodeClaimPayload(payload)
		task := &b.projection.Tasks[b.taskIndexes[fact.TaskID]]
		task.Claims = append(task.Claims, ClaimProjection{SourceFactID: fact.FactID, Statement: decoded.Statement, OriginArtifact: decoded.OriginArtifact})
	case KindSourceReferenceRecorded:
		decoded, _ := decodeSourceReferencePayload(payload)
		task := &b.projection.Tasks[b.taskIndexes[fact.TaskID]]
		task.SourceReferences = append(task.SourceReferences, SourceReferenceProjection{SourceFactID: fact.FactID, Content: decoded.Content, Anchor: decoded.Anchor})
	case KindEvidenceLinked:
		decoded, _ := decodeEvidenceLinkPayload(payload)
		task := &b.projection.Tasks[b.taskIndexes[fact.TaskID]]
		task.EvidenceLinks = append(task.EvidenceLinks, EvidenceLinkProjection{SourceFactID: fact.FactID, Claim: decoded.Claim, Source: decoded.Source})
	case KindReviewRecorded:
		decoded, _ := decodeReviewPayload(payload)
		task := &b.projection.Tasks[b.taskIndexes[fact.TaskID]]
		task.Reviews = append(task.Reviews, ReviewProjection{SourceFactID: fact.FactID, Subject: decoded.Subject, Outcome: decoded.Outcome, Findings: decoded.Findings})
	case KindApprovalRecorded:
		decoded, _ := decodeApprovalPayload(payload)
		task := &b.projection.Tasks[b.taskIndexes[fact.TaskID]]
		task.Approvals = append(task.Approvals, ApprovalProjection{SourceFactID: fact.FactID, Subject: decoded.Subject, Scope: decoded.Scope, Decision: decoded.Decision, Note: decoded.Note})
	case KindPolicyDecisionRecorded:
		decoded, _ := decodePolicyDecisionPayload(payload)
		task := &b.projection.Tasks[b.taskIndexes[fact.TaskID]]
		task.PolicyDecisions = append(task.PolicyDecisions, PolicyDecisionProjection{SourceFactID: fact.FactID, Subject: decoded.Subject, Action: decoded.Action, Policy: decoded.Policy, Result: decoded.Result})
	case KindDeliveryRecorded:
		decoded, _ := decodeDeliveryPayload(payload)
		task := &b.projection.Tasks[b.taskIndexes[fact.TaskID]]
		task.Deliveries = append(task.Deliveries, DeliveryProjection{SourceFactID: fact.FactID, Artifacts: decoded.Artifacts, Format: decoded.Format, Scope: decoded.Scope, Target: decoded.Target})
	case KindOpaqueRecorded:
		decoded, _ := decodeOpaquePayload(payload)
		opaque := OpaqueFactProjection{SourceFactID: fact.FactID, Kind: decoded.Kind, Data: decoded.Data}
		if taskIndex, found := b.taskIndexes[fact.TaskID]; found {
			b.projection.Tasks[taskIndex].OpaqueFacts = append(b.projection.Tasks[taskIndex].OpaqueFacts, opaque)
		} else {
			b.projection.OpaqueFacts = append(b.projection.OpaqueFacts, opaque)
		}
	}
}

func (b *projectionBuilder) result(workspaceID, format, integrity string) Projection {
	b.projection.WorkspaceID = workspaceID
	b.projection.Format = format
	b.projection.Integrity = integrity
	return b.projection
}

func (w *Workspace) Verify() (Verification, error) {
	lock, err := w.lock(false)
	if err != nil {
		return Verification{}, err
	}
	defer unlockWorkspace(lock)

	_, verification, err := w.readHistory(lock.storage, nil)
	return verification, err
}

func (w *Workspace) readHistory(storage *os.Root, sink factSink) (history, Verification, error) {
	if err := w.verifyOperationBoundary(); err != nil {
		return history{}, Verification{}, err
	}
	ledger, _, err := openRootRegular(storage, "events.jsonl")
	if err != nil {
		return history{}, Verification{}, err
	}
	if err := w.verifyCurrentStorage(); err != nil {
		ledger.Close()
		return history{}, Verification{}, err
	}
	defer ledger.Close()
	format, err := detectHistoryFormat(ledger)
	if err != nil {
		return history{}, Verification{}, fmt.Errorf("read workspace ledger: %w", err)
	}
	parse := func(sink factSink) (history, Verification, error) {
		if format == formatLegacy {
			return parseLegacy(ledger, sink)
		}
		return parseNative(ledger, sink)
	}
	parseSink := sink
	if sink != nil {
		parseSink = nil
	}
	h, verification, err := parse(parseSink)
	if err == nil && sink != nil && acceptedHistory(verification) {
		h, verification, err = parse(sink)
	}
	if err != nil {
		return history{}, Verification{}, fmt.Errorf("read workspace ledger: %w", err)
	}
	if format == formatLegacy {
		verification.Diagnostics = append(verification.Diagnostics, inspectLegacyCache(storage, h, verification)...)
	}
	return h, verification, nil
}

func inspectLegacyCache(storage *os.Root, h history, verification Verification) []Diagnostic {
	cache, _, err := openRootRegular(storage, "state.json")
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return []Diagnostic{{Code: "legacy_cache_missing", Message: "legacy state cache is missing"}}
		}
		if errors.Is(err, errNotRegular) {
			return []Diagnostic{{Code: "legacy_cache_not_regular", Message: "legacy state cache must be a regular file"}}
		}
		return []Diagnostic{{Code: "legacy_cache_unreadable", Message: "legacy state cache cannot be inspected"}}
	}
	fields, readErr := readLegacyCacheFields(cache, h.header.WorkspaceID, verification.LastRecordID)
	closeErr := cache.Close()
	if closeErr != nil {
		return []Diagnostic{{Code: "legacy_cache_unreadable", Message: "legacy state cache cannot be read"}}
	}
	if readErr != nil {
		if errors.Is(readErr, errCacheInvalidJSON) {
			return []Diagnostic{{Code: "legacy_cache_invalid_json", Message: "legacy state cache is not strict JSON"}}
		}
		if errors.Is(readErr, errCacheNotObject) {
			return []Diagnostic{{Code: "legacy_cache_not_object", Message: "legacy state cache must be a JSON object"}}
		}
		return []Diagnostic{{Code: "legacy_cache_unreadable", Message: "legacy state cache cannot be read"}}
	}
	diagnostics := make([]Diagnostic, 0, 2)
	if fields.invalidWorkspaceID {
		diagnostics = append(diagnostics, Diagnostic{Code: "legacy_cache_invalid_workspace", Message: "legacy state cache workspace_id must be a string"})
	} else if fields.workspaceIDPresent && !fields.workspaceIDMatches {
		diagnostics = append(diagnostics, Diagnostic{Code: "legacy_cache_workspace_mismatch", Message: "legacy state cache workspace_id does not match Events"})
	}
	if fields.invalidLastEventID {
		diagnostics = append(diagnostics, Diagnostic{Code: "legacy_cache_invalid_last_event", Message: "legacy state cache last_event_id must be a string"})
	} else if fields.lastEventIDPresent && !fields.lastEventIDMatches {
		diagnostics = append(diagnostics, Diagnostic{Code: "legacy_cache_last_event_stale", Message: "legacy state cache last_event_id does not match Events"})
	}
	return diagnostics
}

type legacyCacheFields struct {
	workspaceIDPresent bool
	workspaceIDMatches bool
	lastEventIDPresent bool
	lastEventIDMatches bool
	invalidWorkspaceID bool
	invalidLastEventID bool
}

func readLegacyCacheFields(cache io.ReadSeeker, workspaceID, lastEventID string) (legacyCacheFields, error) {
	if _, err := cache.Seek(0, io.SeekStart); err != nil {
		return legacyCacheFields{}, err
	}
	reader := bufio.NewReader(cache)
	first, err := readJSONNonSpace(reader)
	if err != nil {
		return legacyCacheFields{}, cacheParseError(err)
	}
	if first != '{' {
		if err := checkJSONDuplicates(reader, first, 0); err != nil {
			return legacyCacheFields{}, cacheParseError(err)
		}
		if _, err := readJSONNonSpace(reader); !errors.Is(err, io.EOF) {
			if err != nil {
				return legacyCacheFields{}, err
			}
			return legacyCacheFields{}, errCacheInvalidJSON
		}
		return legacyCacheFields{}, errCacheNotObject
	}
	fields, err := readLegacyCacheObject(reader, workspaceID, lastEventID)
	if err != nil {
		return legacyCacheFields{}, cacheParseError(err)
	}
	if _, err := readJSONNonSpace(reader); !errors.Is(err, io.EOF) {
		if err != nil {
			return legacyCacheFields{}, err
		}
		return legacyCacheFields{}, errCacheInvalidJSON
	}
	return fields, nil
}

func cacheParseError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, errCacheInvalidJSON) {
		return errCacheInvalidJSON
	}
	return err
}

func readLegacyCacheObject(reader *bufio.Reader, workspaceID, lastEventID string) (legacyCacheFields, error) {
	var fields legacyCacheFields
	seen := make(map[jsonKeyFingerprint]bool)
	next, err := readJSONNonSpace(reader)
	if err != nil {
		return fields, err
	}
	if next == '}' {
		return fields, nil
	}
	for {
		if next != '"' {
			return fields, errCacheInvalidJSON
		}
		fingerprint, key, err := readJSONKey(reader)
		if err != nil {
			return fields, err
		}
		if seen[fingerprint] {
			return fields, errCacheInvalidJSON
		}
		seen[fingerprint] = true
		next, err = readJSONNonSpace(reader)
		if err != nil {
			return fields, err
		}
		if next != ':' {
			return fields, errCacheInvalidJSON
		}
		next, err = readJSONNonSpace(reader)
		if err != nil {
			return fields, err
		}
		if key == "workspace_id" || key == "last_event_id" {
			expected := workspaceID
			if key == "last_event_id" {
				expected = lastEventID
			}
			invalidType := next != '"'
			nullValue := false
			matches := false
			if invalidType {
				nullValue, err = checkJSONNull(reader, next)
				if !nullValue && err == nil {
					err = checkJSONDuplicates(reader, next, 1)
				}
				matches = nullValue && expected == ""
			} else {
				matches, err = readJSONStringMatches(reader, expected)
			}
			if err != nil {
				return fields, err
			}
			if key == "workspace_id" {
				fields.workspaceIDPresent = true
				fields.workspaceIDMatches = matches
				fields.invalidWorkspaceID = invalidType && !nullValue
			} else {
				fields.lastEventIDPresent = true
				fields.lastEventIDMatches = matches
				fields.invalidLastEventID = invalidType && !nullValue
			}
		} else if err := checkJSONDuplicates(reader, next, 1); err != nil {
			return fields, err
		}
		next, err = readJSONNonSpace(reader)
		if err != nil {
			return fields, err
		}
		if next == '}' {
			return fields, nil
		}
		if next != ',' {
			return fields, errCacheInvalidJSON
		}
		next, err = readJSONNonSpace(reader)
		if err != nil {
			return fields, err
		}
	}
}

func checkJSONDuplicates(reader *bufio.Reader, first byte, depth int) error {
	if depth > maxLegacyCacheDepth {
		return errCacheInvalidJSON
	}
	switch first {
	case '{':
		seen := make(map[jsonKeyFingerprint]bool)
		next, err := readJSONNonSpace(reader)
		if err != nil {
			return err
		}
		if next == '}' {
			return nil
		}
		for {
			if next != '"' {
				return errCacheInvalidJSON
			}
			fingerprint, _, err := readJSONKey(reader)
			if err != nil {
				return err
			}
			if seen[fingerprint] {
				return errCacheInvalidJSON
			}
			seen[fingerprint] = true
			next, err = readJSONNonSpace(reader)
			if err != nil {
				return err
			}
			if next != ':' {
				return errCacheInvalidJSON
			}
			next, err = readJSONNonSpace(reader)
			if err != nil {
				return err
			}
			if err := checkJSONDuplicates(reader, next, depth+1); err != nil {
				return err
			}
			next, err = readJSONNonSpace(reader)
			if err != nil {
				return err
			}
			if next == '}' {
				return nil
			}
			if next != ',' {
				return errCacheInvalidJSON
			}
			next, err = readJSONNonSpace(reader)
			if err != nil {
				return err
			}
		}
	case '[':
		next, err := readJSONNonSpace(reader)
		if err != nil {
			return err
		}
		if next == ']' {
			return nil
		}
		for {
			if err := checkJSONDuplicates(reader, next, depth+1); err != nil {
				return err
			}
			next, err = readJSONNonSpace(reader)
			if err != nil {
				return err
			}
			if next == ']' {
				return nil
			}
			if next != ',' {
				return errCacheInvalidJSON
			}
			next, err = readJSONNonSpace(reader)
			if err != nil {
				return err
			}
		}
	case '"':
		_, err := readJSONStringBytes(reader, false)
		return err
	default:
		return checkJSONScalar(reader, first)
	}
}

type jsonKeyFingerprint struct {
	digest [sha256.Size]byte
	length uint64
}

func readJSONKey(reader *bufio.Reader) (jsonKeyFingerprint, string, error) {
	hasher := sha256.New()
	length := uint64(0)
	name := make([]byte, 0, len("last_event_id"))
	tooLong := false
	err := scanJSONString(reader, func(decoded []byte) {
		_, _ = hasher.Write(decoded)
		length += uint64(len(decoded))
		if !tooLong && len(name)+len(decoded) <= cap(name) {
			name = append(name, decoded...)
		} else {
			tooLong = true
			name = name[:0]
		}
	})
	if err != nil {
		return jsonKeyFingerprint{}, "", err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	text := string(name)
	if tooLong || text != "workspace_id" && text != "last_event_id" {
		text = ""
	}
	return jsonKeyFingerprint{digest: digest, length: length}, text, nil
}

func readJSONStringBytes(reader *bufio.Reader, capture bool) ([]byte, error) {
	var raw []byte
	if capture {
		raw = []byte{'"'}
	}
	for {
		value, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if capture {
			raw = append(raw, value)
		}
		switch {
		case value == '"':
			return raw, nil
		case value < 0x20:
			return nil, errCacheInvalidJSON
		case value == '\\':
			escape, err := reader.ReadByte()
			if err != nil {
				return nil, err
			}
			if capture {
				raw = append(raw, escape)
			}
			switch escape {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				for range 4 {
					digit, err := reader.ReadByte()
					if err != nil {
						return nil, err
					}
					if !isJSONHex(digit) {
						return nil, errCacheInvalidJSON
					}
					if capture {
						raw = append(raw, digit)
					}
				}
			default:
				return nil, errCacheInvalidJSON
			}
		case value >= utf8.RuneSelf:
			runeBytes := []byte{value}
			for !utf8.FullRune(runeBytes) {
				next, err := reader.ReadByte()
				if err != nil {
					return nil, err
				}
				runeBytes = append(runeBytes, next)
				if capture {
					raw = append(raw, next)
				}
			}
			if decoded, size := utf8.DecodeRune(runeBytes); decoded == utf8.RuneError && size == 1 {
				return nil, errCacheInvalidJSON
			}
		}
	}
}

func isJSONHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func readJSONStringMatches(reader *bufio.Reader, expected string) (bool, error) {
	position := 0
	matches := true
	emit := func(decoded []byte) {
		if position > len(expected) || position+len(decoded) > len(expected) || !bytes.Equal(decoded, []byte(expected[position:position+len(decoded)])) {
			matches = false
		}
		position += len(decoded)
	}
	if err := scanJSONString(reader, emit); err != nil {
		return false, err
	}
	return matches && position == len(expected), nil
}

func scanJSONString(reader *bufio.Reader, emit func([]byte)) error {
	for {
		value, err := reader.ReadByte()
		if err != nil {
			return err
		}
		switch {
		case value == '"':
			return nil
		case value < 0x20:
			return errCacheInvalidJSON
		case value == '\\':
			escape, err := reader.ReadByte()
			if err != nil {
				return err
			}
			switch escape {
			case '"', '\\', '/':
				emit([]byte{escape})
			case 'b':
				emit([]byte{'\b'})
			case 'f':
				emit([]byte{'\f'})
			case 'n':
				emit([]byte{'\n'})
			case 'r':
				emit([]byte{'\r'})
			case 't':
				emit([]byte{'\t'})
			case 'u':
				code, err := readJSONCodeUnit(reader)
				if err != nil {
					return err
				}
				if code >= 0xd800 && code <= 0xdbff {
					low, paired, err := peekJSONLowSurrogate(reader)
					if err != nil {
						return err
					}
					if paired {
						_, _ = reader.Discard(6)
						emit(utf8.AppendRune(nil, utf16.DecodeRune(rune(code), rune(low))))
						continue
					}
				}
				emitJSONCodeUnit(emit, code)
			default:
				return errCacheInvalidJSON
			}
		case value < utf8.RuneSelf:
			emit([]byte{value})
		default:
			runeBytes := []byte{value}
			for !utf8.FullRune(runeBytes) {
				next, err := reader.ReadByte()
				if err != nil {
					return err
				}
				runeBytes = append(runeBytes, next)
			}
			decoded, size := utf8.DecodeRune(runeBytes)
			if decoded == utf8.RuneError && size == 1 {
				return errCacheInvalidJSON
			}
			emit(runeBytes)
		}
	}
}

func peekJSONLowSurrogate(reader *bufio.Reader) (uint16, bool, error) {
	encoded, err := reader.Peek(6)
	if errors.Is(err, io.EOF) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !bytes.Equal(encoded[:2], []byte(`\u`)) {
		return 0, false, nil
	}
	var value uint16
	for _, digit := range encoded[2:] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, false, nil
		}
	}
	return value, value >= 0xdc00 && value <= 0xdfff, nil
}

func readJSONCodeUnit(reader *bufio.Reader) (uint16, error) {
	var value uint16
	for range 4 {
		digit, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value |= uint16(digit-'A') + 10
		default:
			return 0, errCacheInvalidJSON
		}
	}
	return value, nil
}

func emitJSONCodeUnit(emit func([]byte), code uint16) {
	if code >= 0xd800 && code <= 0xdfff {
		emit(utf8.AppendRune(nil, utf8.RuneError))
		return
	}
	emit(utf8.AppendRune(nil, rune(code)))
}

func checkJSONNull(reader *bufio.Reader, first byte) (bool, error) {
	if first != 'n' {
		return false, nil
	}
	if err := readJSONLiteral(reader, "ull"); err != nil {
		return false, err
	}
	return true, nil
}

func checkJSONScalar(reader *bufio.Reader, first byte) error {
	switch first {
	case 't':
		return readJSONLiteral(reader, "rue")
	case 'f':
		return readJSONLiteral(reader, "alse")
	case 'n':
		return readJSONLiteral(reader, "ull")
	case '-':
		next, err := readJSONByte(reader)
		if err != nil {
			return err
		}
		if next < '0' || next > '9' {
			return errCacheInvalidJSON
		}
		first = next
	}
	if first < '0' || first > '9' {
		return errCacheInvalidJSON
	}
	if first == '0' {
		next, ok, err := peekJSONByte(reader)
		if err != nil {
			return err
		}
		if ok && next >= '0' && next <= '9' {
			return errCacheInvalidJSON
		}
	} else if err := consumeJSONDigits(reader); err != nil {
		return err
	}
	next, ok, err := peekJSONByte(reader)
	if err != nil {
		return err
	}
	if ok && next == '.' {
		_, _ = reader.ReadByte()
		next, err := readJSONByte(reader)
		if err != nil {
			return err
		}
		if next < '0' || next > '9' {
			return errCacheInvalidJSON
		}
		if err := consumeJSONDigits(reader); err != nil {
			return err
		}
	}
	next, ok, err = peekJSONByte(reader)
	if err != nil {
		return err
	}
	if ok && (next == 'e' || next == 'E') {
		_, _ = reader.ReadByte()
		sign, signOK, err := peekJSONByte(reader)
		if err != nil {
			return err
		}
		if signOK && (sign == '+' || sign == '-') {
			_, _ = reader.ReadByte()
		}
		next, err := readJSONByte(reader)
		if err != nil {
			return err
		}
		if next < '0' || next > '9' {
			return errCacheInvalidJSON
		}
		if err := consumeJSONDigits(reader); err != nil {
			return err
		}
	}
	return requireJSONDelimiter(reader)
}

func consumeJSONDigits(reader *bufio.Reader) error {
	for {
		next, ok, err := peekJSONByte(reader)
		if err != nil {
			return err
		}
		if !ok || next < '0' || next > '9' {
			return nil
		}
		_, _ = reader.ReadByte()
	}
}

func readJSONLiteral(reader *bufio.Reader, rest string) error {
	for index := range len(rest) {
		value, err := reader.ReadByte()
		if err != nil {
			return err
		}
		if value != rest[index] {
			return errCacheInvalidJSON
		}
	}
	return requireJSONDelimiter(reader)
}

func requireJSONDelimiter(reader *bufio.Reader) error {
	value, ok, err := peekJSONByte(reader)
	if err != nil {
		return err
	}
	if !ok || value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == ',' || value == '}' || value == ']' {
		return nil
	}
	return errCacheInvalidJSON
}

func readJSONByte(reader *bufio.Reader) (byte, error) {
	value, err := reader.ReadByte()
	if err != nil {
		return 0, err
	}
	return value, nil
}

func peekJSONByte(reader *bufio.Reader) (byte, bool, error) {
	value, err := reader.Peek(1)
	if errors.Is(err, io.EOF) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return value[0], true, nil
}

func readJSONNonSpace(reader *bufio.Reader) (byte, error) {
	for {
		value, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		switch value {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return value, nil
		}
	}
}

func parseNative(ledger io.ReadSeeker, sink factSink) (history, Verification, error) {
	v := Verification{Format: "native", Diagnostics: []Diagnostic{}}
	recordCount, blankLine, invalidEncoding, missingNewline, err := inspectNativeRecords(ledger)
	if err != nil {
		return history{}, Verification{}, err
	}
	if invalidEncoding {
		return history{}, invalidVerificationWithCount("invalid_encoding", 0, "", "ledger must be UTF-8 without BOM", recordCount), nil
	}
	if missingNewline {
		return history{}, invalidVerificationWithCount("missing_newline", 0, "", "every record must end with a newline", recordCount), nil
	}
	v.RecordCount = recordCount
	if blankLine != 0 {
		return history{}, invalidVerificationWithCount("blank_line", blankLine, "", "blank records are not allowed", recordCount), nil
	}
	if _, err := ledger.Seek(0, io.SeekStart); err != nil {
		return history{}, Verification{}, err
	}
	reader := bufio.NewReader(ledger)
	headerLine, err := readNativeRecord(reader)
	if err != nil {
		return history{}, Verification{}, err
	}

	headerFields, err := decodeOrderedObject(headerLine)
	if err != nil || !fieldNamesEqual(headerFields, []string{"record_type", "format_version", "workspace_id", "recorded_at", "prev_hash", "record_hash"}) {
		return history{}, invalidVerificationWithCount("invalid_header", 1, "", "workspace header fields are invalid", recordCount), nil
	}
	var header workspaceHeader
	if err := strictDecode(headerLine, &header); err != nil || header.RecordType != "workspace" || header.FormatVersion != FormatNative || header.WorkspaceID == "" || header.PrevHash != zeroHash || !nativeHash.MatchString(header.RecordHash) || !validUTCTimestamp(header.RecordedAt) {
		return history{}, invalidVerificationWithCount("invalid_header", 1, header.WorkspaceID, "workspace header values are invalid", recordCount), nil
	}
	expectedHeaderHash, _ := hashRecord(struct {
		RecordType    string `json:"record_type"`
		FormatVersion string `json:"format_version"`
		WorkspaceID   string `json:"workspace_id"`
		RecordedAt    string `json:"recorded_at"`
		PrevHash      string `json:"prev_hash"`
	}{header.RecordType, header.FormatVersion, header.WorkspaceID, header.RecordedAt, header.PrevHash})
	if header.RecordHash != expectedHeaderHash {
		return history{}, invalidVerificationWithCount("record_hash_mismatch", 1, header.WorkspaceID, "workspace header hash does not match", recordCount), nil
	}

	h := history{header: header, lastRecordHash: header.RecordHash}
	state := newNativeState(recordCount - 1)
	previousHash := header.RecordHash
	lastID := header.WorkspaceID
	for number := 2; number <= recordCount; number++ {
		line, err := readNativeRecord(reader)
		if err != nil {
			return history{}, Verification{}, err
		}
		if err := jsonstrict.Validate(line); err != nil {
			return history{}, invalidVerificationWithCount("invalid_fact_envelope", number, "", err.Error(), recordCount), nil
		}
		fields, err := decodeOrderedObject(line)
		if err != nil || !fieldNamesEqual(fields, []string{"record_type", "fact_id", "task_id", "kind", "actor", "recorded_at", "payload", "prev_hash", "record_hash"}) {
			return history{}, invalidVerificationWithCount("invalid_fact_envelope", number, "", "fact envelope fields are invalid", recordCount), nil
		}
		var record factRecord
		if err := strictDecode(line, &record); err != nil || record.RecordType != "fact" || record.FactID == "" || record.TaskID == "" || record.Actor.Type == "" || record.Actor.ID == "" || !validUTCTimestamp(record.RecordedAt) || !nativeHash.MatchString(record.PrevHash) || !nativeHash.MatchString(record.RecordHash) {
			return history{}, invalidVerificationWithCount("invalid_fact_envelope", number, record.FactID, "fact envelope values are invalid", recordCount), nil
		}
		if _, found := state.facts[record.FactID]; found {
			return history{}, invalidVerificationWithCount("duplicate_fact_id", number, record.FactID, "Fact ID is not unique", recordCount), nil
		}
		if record.PrevHash != previousHash {
			return history{}, invalidVerificationWithCount("previous_hash_mismatch", number, record.FactID, "previous hash does not match", recordCount), nil
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
			return history{}, invalidVerificationWithCount("record_hash_mismatch", number, record.FactID, "fact hash does not match", recordCount), nil
		}
		code, err := state.validate(record.TaskID, record.Kind, record.Payload)
		if err != nil {
			return history{}, invalidVerificationWithCount(code, number, record.FactID, err.Error(), recordCount), nil
		}
		fact := record.fact()
		if sink != nil {
			sink(fact, fact.Payload)
		}
		state.add(fact)
		previousHash = record.RecordHash
		lastID = record.FactID
	}
	h.state = state
	h.lastRecordHash = previousHash
	v.StructuralValid = true
	v.Integrity = IntegritySealedValid
	v.LastRecordID = lastID
	return h, v, nil
}

func inspectNativeRecords(ledger io.ReadSeeker) (recordCount, blankLine int, invalidEncoding, missingNewline bool, err error) {
	if _, err = ledger.Seek(0, io.SeekStart); err != nil {
		return
	}
	reader := bufio.NewReader(ledger)
	first := true
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			recordCount++
			hasNewline := line[len(line)-1] == '\n'
			if hasNewline {
				line = line[:len(line)-1]
			} else {
				missingNewline = true
			}
			if first && bytes.HasPrefix(line, []byte{0xef, 0xbb, 0xbf}) {
				invalidEncoding = true
			}
			first = false
			if !utf8.Valid(line) {
				invalidEncoding = true
			}
			if hasNewline && len(line) == 0 && blankLine == 0 {
				blankLine = recordCount
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			err = readErr
			return
		}
	}
	if recordCount == 0 {
		missingNewline = true
	}
	return
}

func readNativeRecord(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	return line[:len(line)-1], nil
}

func validateSubmission(submission Submission, state nativeState) error {
	if submission.TaskID == "" || submission.Actor.Type == "" || submission.Actor.ID == "" || submission.Kind == "" {
		return fmt.Errorf("%w: task ID, actor, and kind are required", ErrInvalidSubmission)
	}
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

func validateFactReference(taskID string, ref *FactRef, prior map[string]factTarget, kind, name string) error {
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

func (w *Workspace) appendRecord(lock *workspaceLock, line []byte) error {
	if err := w.verifyOperationBoundary(); err != nil {
		return err
	}
	const ledgerName = "events.jsonl"
	ledger, info, err := openRootRegular(lock.storage, ledgerName)
	if err != nil {
		return err
	}
	if err := w.verifyCurrentStorage(); err != nil {
		ledger.Close()
		return err
	}
	prior, err := io.ReadAll(ledger)
	closeErr := ledger.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("read workspace ledger for commit: %w", err)
	}
	temp, tempName, err := createRootTemp(lock.storage)
	if err != nil {
		return fmt.Errorf("create workspace ledger temporary file: %w", err)
	}
	defer lock.storage.Remove(tempName)
	if err = temp.Chmod(info.Mode().Perm()); err == nil {
		_, err = temp.Write(prior)
	}
	if err == nil {
		_, err = temp.Write(line)
	}
	if err == nil {
		_, err = temp.Write([]byte{'\n'})
	}
	if err == nil {
		err = temp.Sync()
	}
	closeErr = temp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write workspace ledger replacement: %w", err)
	}
	if err := beforeLedgerReplace(); err != nil {
		return fmt.Errorf("replace workspace ledger: %w", err)
	}
	if err := w.verifyCurrentStorage(); err != nil {
		return err
	}
	if err := lock.storage.Rename(tempName, ledgerName); err != nil {
		return fmt.Errorf("replace workspace ledger: %w", err)
	}
	if err := lock.directory.Sync(); err != nil {
		return fmt.Errorf("sync workspace storage: %w", err)
	}
	if err := w.verifyCurrentStorage(); err != nil {
		return err
	}
	return nil
}

func (w *Workspace) lock(exclusive bool) (*workspaceLock, error) {
	root, storage, directory, err := w.openStorage()
	if err != nil {
		return nil, err
	}
	locked := &workspaceLock{root: root, storage: storage, directory: directory}
	operation := syscall.LOCK_SH | syscall.LOCK_NB
	if exclusive {
		operation = syscall.LOCK_EX | syscall.LOCK_NB
	}
	if err := syscall.Flock(int(directory.Fd()), operation); err != nil {
		unlockWorkspace(locked)
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w: lock workspace storage: %w", ErrBusy, err)
		}
		return nil, fmt.Errorf("lock workspace storage: %w", err)
	}
	if err := afterWorkspaceLock(); err != nil {
		unlockWorkspace(locked)
		return nil, err
	}
	if err := w.verifyCurrentStorage(); err != nil {
		unlockWorkspace(locked)
		return nil, err
	}
	return locked, nil
}

func unlockWorkspace(lock *workspaceLock) {
	_ = syscall.Flock(int(lock.directory.Fd()), syscall.LOCK_UN)
	_ = lock.directory.Close()
	_ = lock.storage.Close()
	_ = lock.root.Close()
}

func captureWorkspace(path string) (*Workspace, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, rootEntryError(path, err)
	}
	defer root.Close()
	rootIdentity, err := root.Stat(".")
	if err != nil {
		return nil, rootEntryError(path, err)
	}
	storage, directory, storageIdentity, err := openRootStorage(root, ".mcr")
	if err != nil {
		return nil, err
	}
	defer storage.Close()
	defer directory.Close()
	ledger, _, err := openRootRegular(storage, "events.jsonl")
	if err != nil {
		return nil, err
	}
	if err := ledger.Close(); err != nil {
		return nil, err
	}
	return &Workspace{path: path, rootIdentity: rootIdentity, storageIdentity: storageIdentity}, nil
}

func (w *Workspace) openStorage() (*os.Root, *os.Root, *os.File, error) {
	canonical, err := canonicalExistingDirectory(w.path)
	if err != nil {
		return nil, nil, nil, err
	}
	if canonical != w.path {
		return nil, nil, nil, fmt.Errorf("%w: workspace path no longer resolves to its canonical location", ErrConflict)
	}
	root, err := os.OpenRoot(w.path)
	if err != nil {
		return nil, nil, nil, rootEntryError(w.path, err)
	}
	rootIdentity, err := root.Stat(".")
	if err != nil || !os.SameFile(rootIdentity, w.rootIdentity) {
		root.Close()
		if err != nil {
			return nil, nil, nil, rootEntryError(w.path, err)
		}
		return nil, nil, nil, fmt.Errorf("%w: workspace root identity changed", ErrConflict)
	}
	storage, directory, storageIdentity, err := openRootStorage(root, ".mcr")
	if err != nil {
		root.Close()
		return nil, nil, nil, err
	}
	if !os.SameFile(storageIdentity, w.storageIdentity) {
		directory.Close()
		storage.Close()
		root.Close()
		return nil, nil, nil, fmt.Errorf("%w: workspace storage identity changed", ErrConflict)
	}
	return root, storage, directory, nil
}

func (w *Workspace) verifyOperationBoundary() error {
	if err := beforeWorkspaceIO(); err != nil {
		return err
	}
	return w.verifyCurrentStorage()
}

func (w *Workspace) verifyCurrentStorage() error {
	root, storage, directory, err := w.openStorage()
	if err != nil {
		return err
	}
	_ = directory.Close()
	_ = storage.Close()
	_ = root.Close()
	return nil
}

func openRootStorage(root *os.Root, name string) (*os.Root, *os.File, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, nil, rootEntryError(name, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, nil, nil, fmt.Errorf("%w: %s is not a real directory", ErrConflict, name)
	}
	storage, err := root.OpenRoot(name)
	if err != nil {
		if rootEntryChanged(root, name, before, true) {
			return nil, nil, nil, fmt.Errorf("%w: %s changed while opening: %w", ErrConflict, name, err)
		}
		return nil, nil, nil, rootEntryError(name, err)
	}
	current, err := root.Lstat(name)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(before, current) {
		storage.Close()
		if err != nil {
			return nil, nil, nil, rootEntryError(name, err)
		}
		return nil, nil, nil, fmt.Errorf("%w: %s changed while opening", ErrConflict, name)
	}
	identity, err := storage.Stat(".")
	if err != nil || !os.SameFile(before, identity) {
		storage.Close()
		if err != nil {
			return nil, nil, nil, rootEntryError(name, err)
		}
		return nil, nil, nil, fmt.Errorf("%w: %s changed while opening", ErrConflict, name)
	}
	directory, err := storage.Open(".")
	if err != nil {
		storage.Close()
		return nil, nil, nil, rootEntryError(name, err)
	}
	directoryIdentity, err := directory.Stat()
	if err != nil || !os.SameFile(identity, directoryIdentity) {
		directory.Close()
		storage.Close()
		if err != nil {
			return nil, nil, nil, rootEntryError(name, err)
		}
		return nil, nil, nil, fmt.Errorf("%w: %s changed while opening", ErrConflict, name)
	}
	return storage, directory, identity, nil
}

func openRootRegular(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, rootEntryError(name, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: %w: %s is not a regular file", ErrConflict, errNotRegular, name)
	}
	if err := beforeRootRegularOpen(name); err != nil {
		return nil, nil, err
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		if rootEntryChanged(root, name, before, false) {
			return nil, nil, fmt.Errorf("%w: %s changed while opening: %w", ErrConflict, name, err)
		}
		return nil, nil, rootEntryError(name, err)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		file.Close()
		if err != nil {
			return nil, nil, rootEntryError(name, err)
		}
		return nil, nil, fmt.Errorf("%w: %s changed while opening", ErrConflict, name)
	}
	current, err := root.Lstat(name)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(after, current) {
		file.Close()
		if err != nil {
			return nil, nil, rootEntryError(name, err)
		}
		return nil, nil, fmt.Errorf("%w: %s changed while opening", ErrConflict, name)
	}
	return file, after, nil
}

func rootEntryChanged(root *os.Root, name string, before os.FileInfo, directory bool) bool {
	current, err := root.Lstat(name)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, current) {
		return true
	}
	if directory {
		return !current.IsDir()
	}
	return !current.Mode().IsRegular()
}

func rootEntryError(name string, err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return fmt.Errorf("access %s: %w", name, err)
}

func createRootTemp(root *os.Root) (*os.File, string, error) {
	for {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := ".events-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return file, name, err
	}
}

func lockDirectory(path string, exclusive bool) (*os.File, error) {
	directory, err := openDirectory(path)
	if err != nil {
		return nil, fmt.Errorf("open workspace lock directory: %w", err)
	}
	operation := syscall.LOCK_SH | syscall.LOCK_NB
	if exclusive {
		operation = syscall.LOCK_EX | syscall.LOCK_NB
	}
	if err := syscall.Flock(int(directory.Fd()), operation); err != nil {
		directory.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w: lock workspace storage: %w", ErrBusy, err)
		}
		return nil, fmt.Errorf("lock workspace storage: %w", err)
	}
	return directory, nil
}

func unlockDirectory(directory *os.File) {
	_ = syscall.Flock(int(directory.Fd()), syscall.LOCK_UN)
	_ = directory.Close()
}

func syncDirectory(path string) error {
	directory, err := openDirectory(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func openDirectory(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
			return nil, fmt.Errorf("%w: %s is not a real directory: %w", ErrConflict, path, err)
		}
		if errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openRegular(path string) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, fmt.Errorf("%w: %s is not a regular file: %w", ErrConflict, path, err)
		}
		if errors.Is(err, syscall.ENOENT) {
			return nil, nil, fmt.Errorf("%w: %w", ErrNotFound, err)
		}
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, fmt.Errorf("%w: %s is not a regular file", ErrConflict, path)
	}
	return file, info, nil
}

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

func newFactID(existing map[string]factTarget) (string, error) {
	for {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		id := "fact_" + hex.EncodeToString(buf)
		if _, found := existing[id]; !found {
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
