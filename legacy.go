package mcr

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/Notyet1307/MCR-Core/internal/jsonstrict"
)

const formatLegacy = "legacy"

type legacyEvent struct {
	EventID      string          `json:"event_id"`
	EventType    string          `json:"event_type"`
	Timestamp    string          `json:"timestamp"`
	Actor        Actor           `json:"actor"`
	PrevHash     string          `json:"prev_hash"`
	EventHash    string          `json:"event_hash"`
	Payload      json.RawMessage `json:"payload"`
	prevPresent  bool
	eventPresent bool
}

func detectHistoryFormat(ledger io.ReadSeeker) (string, error) {
	if _, err := ledger.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(ledger).ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "native", nil
		}
		return "", err
	}
	line = line[:len(line)-1]
	var fields map[string]json.RawMessage
	if json.Unmarshal(line, &fields) == nil {
		var eventType string
		if raw, ok := fields["event_type"]; ok && json.Unmarshal(raw, &eventType) == nil && eventType == "McrInitialized" {
			return formatLegacy, nil
		}
		if _, native := fields["record_type"]; native {
			return "native", nil
		}
	}
	return "native", nil
}

func parseLegacy(ledger io.ReadSeeker, sink factSink) (history, Verification, error) {
	verification := Verification{Format: formatLegacy, Diagnostics: []Diagnostic{}}
	recordCount, blankLine, invalidEncoding, missingNewline, err := inspectNativeRecords(ledger)
	if err != nil {
		return history{}, Verification{}, err
	}
	verification.RecordCount = recordCount
	if invalidEncoding {
		return history{}, invalidLegacyVerification("invalid_encoding", 0, "", "ledger must be UTF-8 without BOM", recordCount), nil
	}
	if missingNewline {
		return history{}, invalidLegacyVerification("missing_newline", 0, "", "every record must end with a newline", recordCount), nil
	}
	if blankLine != 0 {
		return history{}, invalidLegacyVerification("blank_line", blankLine, "", "blank records are not allowed", recordCount), nil
	}
	if _, err := ledger.Seek(0, io.SeekStart); err != nil {
		return history{}, Verification{}, err
	}

	parsedHistory := history{format: formatLegacy, readOnly: true}
	reader := bufio.NewReader(ledger)
	seen := make(map[string]bool, recordCount)
	state := newNativeState(recordCount - 1)
	integrity := newLegacyIntegrityState()
	lastID := ""
	for number := 1; number <= recordCount; number++ {
		line, err := readNativeRecord(reader)
		if err != nil {
			return history{}, Verification{}, err
		}
		event, diagnostic := decodeLegacyEvent(line, number, recordCount)
		if diagnostic != nil {
			return history{}, *diagnostic, nil
		}
		if seen[event.EventID] {
			return history{}, invalidLegacyVerification("duplicate_event_id", number, event.EventID, "legacy event ID is not unique", recordCount), nil
		}
		seen[event.EventID] = true
		if number == 1 {
			workspaceID, ok := legacyString(event.Payload, "workspace_id")
			if event.EventType != "McrInitialized" || !ok || workspaceID == "" {
				return history{}, invalidLegacyVerification("invalid_header", number, event.EventID, "first legacy event must initialize a non-empty workspace ID", recordCount), nil
			}
			parsedHistory.header = workspaceHeader{WorkspaceID: workspaceID, RecordedAt: event.Timestamp, PrevHash: event.PrevHash, RecordHash: event.EventHash}
		} else {
			if event.EventType == "McrInitialized" {
				return history{}, invalidLegacyVerification("invalid_event_envelope", number, event.EventID, "legacy initialization event must be unique and first", recordCount), nil
			}
			fact, semanticTaskID, semanticPayload := normalizeLegacyEvent(event, state)
			code, validateErr := state.validate(semanticTaskID, fact.Kind, semanticPayload)
			if validateErr != nil {
				return history{}, invalidLegacyVerification(code, number, event.EventID, validateErr.Error(), recordCount), nil
			}
			if sink != nil {
				sink(fact, semanticPayload)
			}
			state.add(fact)
		}
		integrity.add(event, number)
		lastID = event.EventID
		parsedHistory.lastRecordHash = event.EventHash
	}
	parsedHistory.state = state
	verification.StructuralValid = true
	verification.LastRecordID = lastID
	verification.Integrity, verification.Diagnostics = integrity.result()
	return parsedHistory, verification, nil
}

func decodeLegacyEvent(line []byte, number, count int) (legacyEvent, *Verification) {
	invalid := func(message string, id string) (legacyEvent, *Verification) {
		v := invalidLegacyVerification("invalid_event_envelope", number, id, message, count)
		return legacyEvent{}, &v
	}
	if err := jsonstrict.Validate(line); err != nil {
		return invalid(err.Error(), "")
	}
	fields, err := decodeOrderedObject(line)
	if err != nil {
		return invalid("legacy event must be a JSON object", "")
	}
	fieldSet := make(map[string]bool, len(fields))
	for _, field := range fields {
		fieldSet[field.name] = true
	}
	for _, required := range []string{"event_id", "event_type", "timestamp", "actor", "payload"} {
		if !fieldSet[required] {
			return invalid("legacy event is missing required envelope fields", "")
		}
	}
	var event legacyEvent
	if err := json.Unmarshal(line, &event); err != nil {
		return invalid(err.Error(), "")
	}
	event.prevPresent = fieldSet["prev_hash"]
	event.eventPresent = fieldSet["event_hash"]
	if event.EventID == "" || event.EventType == "" || event.Actor.Type == "" || event.Actor.ID == "" || !validUTCTimestamp(event.Timestamp) {
		return invalid("legacy event envelope values are invalid", event.EventID)
	}
	if _, err := decodeOrderedObject(event.Payload); err != nil {
		return invalid("legacy event payload must be a JSON object", event.EventID)
	}
	return event, nil
}

type legacyIntegrityState struct {
	allAbsent          bool
	allPresent         bool
	previousHash       string
	partialDiagnostics []Diagnostic
	sealedDiagnostics  []Diagnostic
}

func newLegacyIntegrityState() legacyIntegrityState {
	return legacyIntegrityState{allAbsent: true, allPresent: true, previousHash: zeroHash}
}

func (s *legacyIntegrityState) add(event legacyEvent, number int) {
	s.allAbsent = s.allAbsent && !event.prevPresent && !event.eventPresent
	s.allPresent = s.allPresent && event.prevPresent && event.eventPresent
	if !event.prevPresent {
		s.partialDiagnostics = append(s.partialDiagnostics, legacyIntegrityDiagnostic("missing_previous_hash", number, event.EventID, "legacy event is missing prev_hash"))
	}
	if !event.eventPresent {
		s.partialDiagnostics = append(s.partialDiagnostics, legacyIntegrityDiagnostic("missing_event_hash", number, event.EventID, "legacy event is missing event_hash"))
	}
	if event.prevPresent && event.eventPresent {
		previousValid := nativeHash.MatchString(event.PrevHash)
		eventValid := nativeHash.MatchString(event.EventHash)
		if !previousValid {
			s.sealedDiagnostics = append(s.sealedDiagnostics, legacyIntegrityDiagnostic("invalid_previous_hash", number, event.EventID, "legacy previous hash spelling is invalid"))
		}
		if !eventValid {
			s.sealedDiagnostics = append(s.sealedDiagnostics, legacyIntegrityDiagnostic("invalid_event_hash", number, event.EventID, "legacy event hash spelling is invalid"))
		}
		if previousValid && event.PrevHash != s.previousHash {
			s.sealedDiagnostics = append(s.sealedDiagnostics, legacyIntegrityDiagnostic("previous_hash_mismatch", number, event.EventID, "previous hash does not match"))
		}
		if previousValid {
			expected, err := hashLegacyEvent(event)
			if err == nil && eventValid && event.EventHash != expected {
				s.sealedDiagnostics = append(s.sealedDiagnostics, legacyIntegrityDiagnostic("event_hash_mismatch", number, event.EventID, "legacy event hash does not match"))
			}
		}
	}
	s.previousHash = event.EventHash
}

func (s legacyIntegrityState) result() (string, []Diagnostic) {
	if s.allAbsent {
		return IntegrityUnsealed, []Diagnostic{}
	}
	if !s.allPresent {
		return IntegrityPartialInvalid, s.partialDiagnostics
	}
	if len(s.sealedDiagnostics) != 0 {
		return IntegritySealedInvalid, s.sealedDiagnostics
	}
	return IntegritySealedValid, []Diagnostic{}
}

func legacyIntegrityDiagnostic(code string, number int, id, message string) Diagnostic {
	return Diagnostic{Code: code, RecordNumber: number, RecordID: id, Message: message}
}

func hashLegacyEvent(event legacyEvent) (string, error) {
	core, err := json.Marshal(struct {
		EventID   string          `json:"event_id"`
		EventType string          `json:"event_type"`
		Timestamp string          `json:"timestamp"`
		Actor     Actor           `json:"actor"`
		Payload   json.RawMessage `json:"payload"`
	}{event.EventID, event.EventType, event.Timestamp, event.Actor, event.Payload})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append(append(core, '\n'), []byte(event.PrevHash)...))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func normalizeLegacyEvent(event legacyEvent, state nativeState) (Fact, string, json.RawMessage) {
	taskID, _ := legacyString(event.Payload, "task_id")
	kind := ""
	var semantic json.RawMessage
	values := legacyObject(event.Payload)
	sourceComplete := false
	switch event.EventType {
	case "TaskCreated":
		sourceComplete = legacyKeysPresent(values, "task_id", "definition") && legacyObjectSourceComplete(values["definition"], "namespace", "id", "version", "locator", "sha256")
		if sourceComplete {
			definition := marshalSelected(legacyObject(values["definition"]), "namespace", "id", "version", "locator", "sha256")
			kind = KindTaskCreated
			semantic = marshalLegacySemantic(struct {
				Definition json.RawMessage `json:"definition"`
			}{definition})
		}
	case "RunCompleted":
		sourceComplete = legacyKeysPresent(values, "task_id", "started_at", "ended_at", "outcome")
		if sourceComplete {
			kind = KindRunRecorded
			semantic = marshalLegacySemantic(struct {
				StartedAt json.RawMessage `json:"started_at"`
				EndedAt   json.RawMessage `json:"ended_at"`
				Outcome   json.RawMessage `json:"outcome"`
			}{values["started_at"], values["ended_at"], values["outcome"]})
		}
	case "InputRegistered":
		if content, ok := legacyContent(values, "content", "stored_path", "sha256"); ok {
			kind = KindInputRegistered
			semantic = marshalLegacySemantic(struct {
				Content json.RawMessage `json:"content"`
			}{content})
		}
	case "ArtifactAdded":
		content, hasContent := legacyContent(values, "content", firstPresent(values, "locator", "path", "stored_path"), firstPresent(values, "sha256", "content_hash"))
		run := exactLegacyRef(values, "run")
		_, claimsRunID := values["run_id"]
		_, claimsRun := values["run"]
		_, claimsRunFactID := values["run_fact_id"]
		_, claimsRunRecordHash := values["run_record_hash"]
		hasRunSource := claimsRunID || claimsRun || claimsRunFactID || claimsRunRecordHash
		if hasContent && (!hasRunSource || (legacyRefSourceComplete(values, "run") && len(run) != 0)) {
			kind = KindArtifactRecorded
			semantic = marshalLegacySemantic(struct {
				Content json.RawMessage `json:"content"`
				Run     json.RawMessage `json:"run,omitempty"`
			}{content, run})
		}
	case "NarrativeDraftReviewed", "ReviewSubmitted":
		semantic = marshalSelectedWithRef(values, "subject", "outcome", "findings")
		sourceComplete = legacyKeysPresent(values, "task_id", "outcome") && legacyRefSourceComplete(values, "subject")
		if sourceComplete {
			kind = KindReviewRecorded
		}
	case "ApprovalGranted":
		semantic = marshalSelectedWithRef(values, "subject", "scope", "decision", "note")
		sourceComplete = legacyKeysPresent(values, "task_id", "scope", "decision") && legacyRefSourceComplete(values, "subject")
		if sourceComplete {
			kind = KindApprovalRecorded
		}
	case "PolicyDecisionRecorded":
		semantic = marshalSelectedWithRef(values, "subject", "action", "policy", "result")
		sourceComplete = legacyKeysPresent(values, "task_id", "action", "policy", "result") && legacyRefSourceComplete(values, "subject")
		if sourceComplete {
			kind = KindPolicyDecisionRecorded
		}
	case "DeliveryRecorded":
		semantic = marshalSelected(values, "artifacts", "format", "scope", "target")
		sourceComplete = legacyKeysPresent(values, "task_id", "artifacts", "format", "scope", "target") && legacyArtifactsSourceComplete(values["artifacts"])
		if sourceComplete {
			kind = KindDeliveryRecorded
		}
	}
	if kind == "" || (taskID == "" && !sourceComplete) {
		reason := "legacy_extension"
		if isLegacyUnderbound(event.EventType) {
			reason = "legacy_underbound"
		}
		return opaqueLegacyFact(event, state, reason)
	}
	fact := legacyFact(event, taskID, kind, false, "")
	return fact, taskID, semantic
}

func legacyContent(values map[string]json.RawMessage, nestedName, locatorName, digestName string) (json.RawMessage, bool) {
	if nested := values[nestedName]; len(nested) != 0 {
		var object map[string]json.RawMessage
		if json.Unmarshal(nested, &object) != nil || object == nil {
			return nested, true
		}
		locator, locatorOK := rawString(object["locator"])
		digest, digestOK := rawString(object["sha256"])
		if !locatorOK || !digestOK {
			return nil, false
		}
		return marshalLegacySemantic(ContentRef{Locator: locator, SHA256: normalizeLegacyDigest(digest)}), true
	}
	locator, locatorOK := rawString(values[locatorName])
	digest, digestOK := rawString(values[digestName])
	if !locatorOK || !digestOK {
		return nil, false
	}
	return marshalLegacySemantic(ContentRef{Locator: locator, SHA256: normalizeLegacyDigest(digest)}), true
}

func firstPresent(values map[string]json.RawMessage, names ...string) string {
	for _, name := range names {
		if _, ok := values[name]; ok {
			return name
		}
	}
	return names[0]
}

func rawString(raw json.RawMessage) (string, bool) {
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func normalizeLegacyDigest(value string) string {
	if len(value) != 64 || value != strings.ToLower(value) {
		return value
	}
	if _, err := hex.DecodeString(value); err != nil {
		return value
	}
	return "sha256:" + value
}
func opaqueLegacyFact(event legacyEvent, state nativeState, reason string) (Fact, string, json.RawMessage) {
	taskID, _ := legacyString(event.Payload, "task_id")
	semanticTaskID := ""
	if state.tasks[taskID] {
		semanticTaskID = taskID
	}
	semantic := marshalLegacySemantic(struct {
		Kind string          `json:"kind"`
		Data json.RawMessage `json:"data"`
	}{event.EventType, event.Payload})
	return legacyFact(event, taskID, KindOpaqueRecorded, true, reason), semanticTaskID, semantic
}

func legacyFact(event legacyEvent, taskID, kind string, opaque bool, reason string) Fact {
	recordedAt, _ := time.Parse(time.RFC3339Nano, event.Timestamp)
	return Fact{FactID: event.EventID, TaskID: taskID, Kind: kind, Actor: event.Actor, RecordedAt: recordedAt, Payload: append(json.RawMessage(nil), event.Payload...), PrevHash: event.PrevHash, RecordHash: event.EventHash, Opaque: opaque, OpaqueReason: reason}
}

func isLegacyUnderbound(kind string) bool {
	switch kind {
	case "TaskCreated", "RunCompleted", "InputRegistered", "ArtifactAdded", "NarrativeDraftReviewed", "ReviewSubmitted", "ApprovalGranted", "PolicyDecisionRecorded", "DeliveryRecorded", "EvidenceLinked":
		return true
	default:
		return false
	}
}

func legacyObject(raw json.RawMessage) map[string]json.RawMessage {
	var values map[string]json.RawMessage
	_ = json.Unmarshal(raw, &values)
	return values
}

func legacyString(raw json.RawMessage, name string) (string, bool) {
	value, ok := legacyObject(raw)[name]
	if !ok {
		return "", false
	}
	var text string
	if json.Unmarshal(value, &text) != nil {
		return "", false
	}
	return text, true
}

func firstLegacyString(raw json.RawMessage, names ...string) string {
	for _, name := range names {
		if value, ok := legacyString(raw, name); ok && value != "" {
			return value
		}
	}
	return ""
}

func legacyKeysPresent(values map[string]json.RawMessage, names ...string) bool {
	for _, name := range names {
		if _, ok := values[name]; !ok {
			return false
		}
	}
	return true
}

func legacyObjectSourceComplete(raw json.RawMessage, names ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return true
	}
	return legacyKeysPresent(object, names...)
}

func legacyRefSourceComplete(values map[string]json.RawMessage, name string) bool {
	if nested, ok := values[name]; ok {
		var object map[string]json.RawMessage
		if json.Unmarshal(nested, &object) != nil || object == nil {
			return true
		}
		return legacyKeysPresent(object, "fact_id", "record_hash")
	}
	return legacyKeysPresent(values, name+"_fact_id", name+"_record_hash")
}

func legacyArtifactsSourceComplete(raw json.RawMessage) bool {
	var artifacts []json.RawMessage
	if json.Unmarshal(raw, &artifacts) != nil {
		return true
	}
	for _, artifact := range artifacts {
		var object map[string]json.RawMessage
		if json.Unmarshal(artifact, &object) == nil && object != nil && !legacyKeysPresent(object, "fact_id", "record_hash") {
			return false
		}
	}
	return true
}

func exactLegacyRef(values map[string]json.RawMessage, name string) json.RawMessage {
	if nested, ok := values[name]; ok {
		return nested
	}
	factID, hasFactID := values[name+"_fact_id"]
	recordHash, hasRecordHash := values[name+"_record_hash"]
	if !hasFactID || !hasRecordHash {
		return nil
	}
	return marshalSelected(map[string]json.RawMessage{
		"fact_id":     factID,
		"record_hash": recordHash,
	}, "fact_id", "record_hash")
}

func marshalSelectedWithRef(values map[string]json.RawMessage, refName string, names ...string) json.RawMessage {
	selected := make(map[string]json.RawMessage, len(names)+1)
	for _, name := range names {
		if value := values[name]; len(value) != 0 {
			selected[name] = value
		}
	}
	if ref := exactLegacyRef(values, refName); len(ref) != 0 {
		selected[refName] = ref
	}
	ordered := append([]string{refName}, names...)
	return marshalSelected(selected, ordered...)
}

func marshalLegacySemantic(value any) json.RawMessage {
	encoded, _ := json.Marshal(value)
	return encoded
}

func marshalSelected(values map[string]json.RawMessage, names ...string) json.RawMessage {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	wrote := false
	for _, name := range names {
		value, ok := values[name]
		if !ok {
			continue
		}
		if wrote {
			buffer.WriteByte(',')
		}
		nameJSON, _ := json.Marshal(name)
		buffer.Write(nameJSON)
		buffer.WriteByte(':')
		buffer.Write(value)
		wrote = true
	}
	buffer.WriteByte('}')
	return buffer.Bytes()
}

func invalidLegacyVerification(code string, number int, id, message string, count int) Verification {
	return Verification{Format: formatLegacy, RecordCount: count, Diagnostics: []Diagnostic{{Code: code, RecordNumber: number, RecordID: id, Message: message}}}
}
