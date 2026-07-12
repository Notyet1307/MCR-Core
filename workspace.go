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
	defs   []DefinitionRef
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
	for i, fact := range h.facts {
		if fact.Kind == KindTaskCreated {
			projection.Tasks = append(projection.Tasks, TaskProjection{TaskID: fact.TaskID, SourceFactID: fact.FactID, Definition: h.defs[i]})
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

	h := history{header: header, facts: make([]Fact, 0, len(lines)-1), defs: make([]DefinitionRef, 0, len(lines)-1)}
	knownTasks := make(map[string]bool)
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
		if record.Kind != KindTaskCreated {
			return history{}, invalidVerificationWithCount("unknown_kind", number, record.FactID, "native fact kind is not supported", len(lines))
		}
		if knownTasks[record.TaskID] {
			return history{}, invalidVerificationWithCount("duplicate_task", number, record.FactID, "task already exists", len(lines))
		}
		definition, err := decodeTaskPayload(record.Payload)
		if err != nil {
			return history{}, invalidVerificationWithCount("invalid_payload", number, record.FactID, err.Error(), len(lines))
		}
		knownTasks[record.TaskID] = true
		h.facts = append(h.facts, record.fact())
		h.defs = append(h.defs, definition)
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
	for _, fact := range h.facts {
		if fact.TaskID == submission.TaskID {
			if submission.Kind == KindTaskCreated {
				return fmt.Errorf("%w: task %q already exists", ErrInvalidSubmission, submission.TaskID)
			}
			return fmt.Errorf("%w: kind %q is not supported in this slice", ErrInvalidSubmission, submission.Kind)
		}
	}
	if submission.Kind != KindTaskCreated {
		return fmt.Errorf("%w: task %q must begin with %s", ErrInvalidSubmission, submission.TaskID, KindTaskCreated)
	}
	if _, err := decodeTaskPayload(submission.Payload); err != nil {
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
