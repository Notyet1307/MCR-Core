package mcr

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/Notyet1307/MCR-Core/internal/jsonstrict"
)

const formatLegacy = "legacy"

type legacyEvent struct {
	EventID   string          `json:"event_id"`
	EventType string          `json:"event_type"`
	Timestamp string          `json:"timestamp"`
	Actor     Actor           `json:"actor"`
	PrevHash  string          `json:"prev_hash"`
	EventHash string          `json:"event_hash"`
	Payload   json.RawMessage `json:"payload"`
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
		if _, native := fields["record_type"]; native {
			return "native", nil
		}
		var eventType string
		if raw, ok := fields["event_type"]; ok && json.Unmarshal(raw, &eventType) == nil && eventType == "McrInitialized" && hasLegacyEnvelope(fields) {
			return formatLegacy, nil
		}
	}
	return "native", nil
}

func hasLegacyEnvelope(fields map[string]json.RawMessage) bool {
	for _, name := range []string{"event_id", "event_type", "timestamp", "actor", "prev_hash", "event_hash", "payload"} {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

func parseLegacy(ledger io.ReadSeeker) (history, Verification, error) {
	v := Verification{Format: formatLegacy, Diagnostics: []Diagnostic{}}
	recordCount, blankLine, invalidEncoding, missingNewline, err := inspectNativeRecords(ledger)
	if err != nil {
		return history{}, Verification{}, err
	}
	v.RecordCount = recordCount
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

	h := history{format: formatLegacy, readOnly: true, facts: make([]Fact, 0, recordCount-1), semanticPayloads: make([]json.RawMessage, 0, recordCount-1), semanticTaskIDs: make([]string, 0, recordCount-1), rawLines: make([][]byte, 0, recordCount)}
	reader := bufio.NewReader(ledger)
	seen := make(map[string]bool, recordCount)
	state := newNativeState(nil)
	previousHash := zeroHash
	lastID := ""
	for number := 1; number <= recordCount; number++ {
		line, err := readNativeRecord(reader)
		if err != nil {
			return history{}, Verification{}, err
		}
		h.rawLines = append(h.rawLines, append([]byte(nil), line...))
		event, diagnostic := decodeLegacyEvent(line, number, recordCount)
		if diagnostic != nil {
			return history{}, *diagnostic, nil
		}
		if seen[event.EventID] {
			return history{}, invalidLegacyVerification("duplicate_event_id", number, event.EventID, "legacy event ID is not unique", recordCount), nil
		}
		seen[event.EventID] = true
		if event.PrevHash != previousHash {
			return history{}, invalidLegacyVerification("previous_hash_mismatch", number, event.EventID, "previous hash does not match", recordCount), nil
		}
		expected, err := hashLegacyEvent(event)
		if err != nil {
			return history{}, Verification{}, err
		}
		if event.EventHash != expected {
			return history{}, invalidLegacyVerification("event_hash_mismatch", number, event.EventID, "legacy event hash does not match", recordCount), nil
		}
		if number == 1 {
			workspaceID, ok := legacyString(event.Payload, "workspace_id")
			if event.EventType != "McrInitialized" || !ok || workspaceID == "" {
				return history{}, invalidLegacyVerification("invalid_header", number, event.EventID, "first legacy event must initialize a non-empty workspace ID", recordCount), nil
			}
			h.header = workspaceHeader{WorkspaceID: workspaceID, RecordedAt: event.Timestamp, PrevHash: event.PrevHash, RecordHash: event.EventHash}
		} else {
			if event.EventType == "McrInitialized" {
				return history{}, invalidLegacyVerification("invalid_event_envelope", number, event.EventID, "legacy initialization event must be unique and first", recordCount), nil
			}
			fact, semanticTaskID, semanticPayload := normalizeLegacyEvent(event, state)
			code, validateErr := state.validate(semanticTaskID, fact.Kind, semanticPayload)
			if validateErr != nil && fact.Kind != KindOpaqueRecorded {
				fact, semanticTaskID, semanticPayload = opaqueLegacyFact(event, state, "legacy_underbound")
				code, validateErr = state.validate(semanticTaskID, fact.Kind, semanticPayload)
			}
			if validateErr != nil {
				return history{}, invalidLegacyVerification(code, number, event.EventID, validateErr.Error(), recordCount), nil
			}
			h.facts = append(h.facts, fact)
			h.semanticTaskIDs = append(h.semanticTaskIDs, semanticTaskID)
			h.semanticPayloads = append(h.semanticPayloads, semanticPayload)
			state.add(fact)
		}
		previousHash = event.EventHash
		lastID = event.EventID
	}
	v.StructuralValid = true
	v.Integrity = IntegritySealedValid
	v.LastRecordID = lastID
	return h, v, nil
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
	for _, required := range []string{"event_id", "event_type", "timestamp", "actor", "prev_hash", "event_hash", "payload"} {
		if !fieldSet[required] {
			return invalid("legacy event is missing required envelope fields", "")
		}
	}
	var event legacyEvent
	if err := json.Unmarshal(line, &event); err != nil {
		return invalid(err.Error(), "")
	}
	if event.EventID == "" || event.EventType == "" || event.Actor.Type == "" || event.Actor.ID == "" || !validUTCTimestamp(event.Timestamp) || !nativeHash.MatchString(event.PrevHash) || !nativeHash.MatchString(event.EventHash) {
		return invalid("legacy event envelope values are invalid", event.EventID)
	}
	if _, err := decodeOrderedObject(event.Payload); err != nil {
		return invalid("legacy event payload must be a JSON object", event.EventID)
	}
	return event, nil
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
	switch event.EventType {
	case "TaskCreated":
		kind = KindTaskCreated
		semantic = marshalLegacySemantic(struct {
			Definition json.RawMessage `json:"definition"`
		}{values["definition"]})
	case "RunCompleted":
		kind = KindRunRecorded
		semantic = marshalLegacySemantic(struct {
			StartedAt json.RawMessage `json:"started_at"`
			EndedAt   json.RawMessage `json:"ended_at"`
			Outcome   json.RawMessage `json:"outcome"`
		}{values["started_at"], values["ended_at"], values["outcome"]})
	case "InputRegistered":
		if content := values["content"]; len(content) != 0 {
			kind = KindInputRegistered
			semantic = marshalLegacySemantic(struct {
				Content json.RawMessage `json:"content"`
			}{content})
		} else {
			locator, _ := legacyString(event.Payload, "stored_path")
			sha, _ := legacyString(event.Payload, "sha256")
			if locator != "" && nativeHash.MatchString(sha) {
				kind = KindInputRegistered
				semantic = marshalLegacySemantic(struct {
					Content ContentRef `json:"content"`
				}{ContentRef{Locator: locator, SHA256: sha}})
			}
		}
	case "ArtifactAdded":
		content := values["content"]
		if len(content) == 0 {
			locator := firstLegacyString(event.Payload, "locator", "path", "stored_path")
			sha := firstLegacyString(event.Payload, "sha256", "content_hash")
			if locator != "" && nativeHash.MatchString(sha) {
				content = marshalLegacySemantic(ContentRef{Locator: locator, SHA256: sha})
			}
		}
		run := exactLegacyRef(values, "run")
		_, claimsRun := values["run_id"]
		if len(content) != 0 && (!claimsRun || len(run) != 0) {
			kind = KindArtifactRecorded
			semantic = marshalLegacySemantic(struct {
				Content json.RawMessage `json:"content"`
				Run     json.RawMessage `json:"run,omitempty"`
			}{content, run})
		}
	case "NarrativeDraftReviewed", "ReviewSubmitted":
		kind = KindReviewRecorded
		semantic = marshalSelectedWithRef(values, "subject", "outcome", "findings")
	case "ApprovalGranted":
		kind = KindApprovalRecorded
		semantic = marshalSelectedWithRef(values, "subject", "scope", "decision", "note")
	case "PolicyDecisionRecorded":
		kind = KindPolicyDecisionRecorded
		semantic = marshalSelectedWithRef(values, "subject", "action", "policy", "result")
	case "DeliveryRecorded":
		kind = KindDeliveryRecorded
		semantic = marshalSelected(values, "artifacts", "format", "scope", "target")
	}
	if kind == "" || taskID == "" {
		reason := "legacy_extension"
		if isLegacyUnderbound(event.EventType) {
			reason = "legacy_underbound"
		}
		return opaqueLegacyFact(event, state, reason)
	}
	fact := legacyFact(event, taskID, kind, false, "")
	return fact, taskID, semantic
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

func exactLegacyRef(values map[string]json.RawMessage, name string) json.RawMessage {
	if nested := values[name]; len(nested) != 0 {
		return nested
	}
	var factID, recordHash string
	_ = json.Unmarshal(values[name+"_fact_id"], &factID)
	_ = json.Unmarshal(values[name+"_record_hash"], &recordHash)
	if factID == "" || recordHash == "" {
		return nil
	}
	return marshalLegacySemantic(FactRef{FactID: factID, RecordHash: recordHash})
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
