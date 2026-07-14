package mcr

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

const (
	KindTaskCreated             = "task.created"
	KindRunRecorded             = "run.recorded"
	KindInputRegistered         = "input.registered"
	KindArtifactRecorded        = "artifact.recorded"
	KindClaimRecorded           = "claim.recorded"
	KindSourceReferenceRecorded = "source_reference.recorded"
	KindEvidenceLinked          = "evidence.linked"
	KindReviewRecorded          = "review.recorded"
	KindApprovalRecorded        = "approval.recorded"
	KindPolicyDecisionRecorded  = "policy_decision.recorded"
	KindDeliveryRecorded        = "delivery.recorded"
	KindOpaqueRecorded          = "opaque.recorded"
	IntegritySealedValid        = "sealed_valid"
	IntegrityUnsealed           = "unsealed"
	IntegrityPartialInvalid     = "partial_invalid"
	IntegritySealedInvalid      = "sealed_invalid"
	FormatNative                = "mcr-core/v1"
)

var (
	ErrNotFound          = errors.New("not found")
	ErrConflict          = errors.New("conflict")
	ErrBusy              = errors.New("busy")
	ErrInvalidSubmission = errors.New("invalid submission")
	ErrInvalidHistory    = errors.New("invalid history")
	ErrReadOnly          = errors.New("read only")
)

type Workspace struct {
	path            string
	rootIdentity    os.FileInfo
	storageIdentity os.FileInfo
}

type Actor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type DefinitionRef struct {
	Namespace string `json:"namespace"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	Locator   string `json:"locator"`
	SHA256    string `json:"sha256"`
}

type ContentRef struct {
	Locator string `json:"locator"`
	SHA256  string `json:"sha256"`
}

type FactRef struct {
	FactID     string `json:"fact_id"`
	RecordHash string `json:"record_hash"`
}

type Submission struct {
	TaskID  string          `json:"task_id"`
	Actor   Actor           `json:"actor"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

type Fact struct {
	FactID       string          `json:"fact_id"`
	TaskID       string          `json:"task_id"`
	Kind         string          `json:"kind"`
	Actor        Actor           `json:"actor"`
	RecordedAt   time.Time       `json:"recorded_at"`
	Payload      json.RawMessage `json:"payload"`
	PrevHash     string          `json:"prev_hash"`
	RecordHash   string          `json:"record_hash"`
	Opaque       bool            `json:"opaque"`
	OpaqueReason string          `json:"opaque_reason,omitempty"`
}

type FactQuery struct {
	FactID string `json:"fact_id,omitempty"`
	TaskID string `json:"task_id,omitempty"`
	Kind   string `json:"kind,omitempty"`
}

type Projection struct {
	WorkspaceID string                 `json:"workspace_id"`
	Format      string                 `json:"format"`
	Integrity   string                 `json:"integrity"`
	Tasks       []TaskProjection       `json:"tasks"`
	OpaqueFacts []OpaqueFactProjection `json:"opaque_facts"`
}

type TaskProjection struct {
	TaskID           string                      `json:"task_id"`
	SourceFactID     string                      `json:"source_fact_id"`
	Definition       DefinitionRef               `json:"definition"`
	Runs             []RunProjection             `json:"runs"`
	RegisteredInputs []RegisteredInputProjection `json:"registered_inputs"`
	Artifacts        []ArtifactProjection        `json:"artifacts"`
	Claims           []ClaimProjection           `json:"claims"`
	SourceReferences []SourceReferenceProjection `json:"source_references"`
	EvidenceLinks    []EvidenceLinkProjection    `json:"evidence_links"`
	Reviews          []ReviewProjection          `json:"reviews"`
	Approvals        []ApprovalProjection        `json:"approvals"`
	PolicyDecisions  []PolicyDecisionProjection  `json:"policy_decisions"`
	Deliveries       []DeliveryProjection        `json:"deliveries"`
	OpaqueFacts      []OpaqueFactProjection      `json:"opaque_facts"`
}

type RunProjection struct {
	SourceFactID string    `json:"source_fact_id"`
	StartedAt    time.Time `json:"started_at"`
	EndedAt      time.Time `json:"ended_at"`
	Outcome      string    `json:"outcome"`
}

type RegisteredInputProjection struct {
	SourceFactID string     `json:"source_fact_id"`
	Content      ContentRef `json:"content"`
}

type ArtifactProjection struct {
	SourceFactID string     `json:"source_fact_id"`
	Content      ContentRef `json:"content"`
	Run          *FactRef   `json:"run,omitempty"`
}

type ClaimProjection struct {
	SourceFactID   string   `json:"source_fact_id"`
	Statement      string   `json:"statement"`
	OriginArtifact *FactRef `json:"origin_artifact,omitempty"`
}

type SourceReferenceProjection struct {
	SourceFactID string     `json:"source_fact_id"`
	Content      ContentRef `json:"content"`
	Anchor       string     `json:"anchor"`
}

type EvidenceLinkProjection struct {
	SourceFactID string  `json:"source_fact_id"`
	Claim        FactRef `json:"claim"`
	Source       FactRef `json:"source"`
}

type ReviewProjection struct {
	SourceFactID string  `json:"source_fact_id"`
	Subject      FactRef `json:"subject"`
	Outcome      string  `json:"outcome"`
	Findings     string  `json:"findings,omitempty"`
}

type ApprovalProjection struct {
	SourceFactID string  `json:"source_fact_id"`
	Subject      FactRef `json:"subject"`
	Scope        string  `json:"scope"`
	Decision     string  `json:"decision"`
	Note         string  `json:"note,omitempty"`
}

type PolicyDecisionProjection struct {
	SourceFactID string  `json:"source_fact_id"`
	Subject      FactRef `json:"subject"`
	Action       string  `json:"action"`
	Policy       string  `json:"policy"`
	Result       string  `json:"result"`
}

type DeliveryProjection struct {
	SourceFactID string    `json:"source_fact_id"`
	Artifacts    []FactRef `json:"artifacts"`
	Format       string    `json:"format"`
	Scope        string    `json:"scope"`
	Target       string    `json:"target"`
}

type OpaqueFactProjection struct {
	SourceFactID string          `json:"source_fact_id"`
	Kind         string          `json:"kind"`
	Data         json.RawMessage `json:"data"`
}

type Diagnostic struct {
	Code         string `json:"code"`
	RecordNumber int    `json:"record_number,omitempty"`
	RecordID     string `json:"record_id,omitempty"`
	Message      string `json:"message"`
}

type Verification struct {
	Format          string       `json:"format,omitempty"`
	StructuralValid bool         `json:"structural_valid"`
	Integrity       string       `json:"integrity,omitempty"`
	RecordCount     int          `json:"record_count"`
	LastRecordID    string       `json:"last_record_id,omitempty"`
	Diagnostics     []Diagnostic `json:"diagnostics"`
}
