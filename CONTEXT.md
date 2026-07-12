# MCR Core

MCR Core is the scenario-independent domain for governing facts about a task. It exists to make those facts recordable, relatable, reviewable, and verifiable without owning agent execution or business-scenario interpretation.

## Language

**MCR Core**:
The scenario-independent task-fact governance domain. It does not execute agents, interpret Pack content, or act as a general workflow engine.
_Avoid_: agent runtime, Pack runtime, workflow engine, audit-log library

**Workspace**:
The ledger boundary containing one ordered MCR history and zero or more Tasks. Each Task belongs to exactly one Workspace; a Workspace does not represent a customer, tenant, project, or business case.
_Avoid_: tenant, customer, project, case, directory

**Task**:
The immutable governance subject identified within one Workspace and introduced with its initial contract. Later changes are additional Task Facts; MCR Core defines no universal lifecycle or status enum, and any current status is an adapter projection.
_Avoid_: mutable task row, workflow job, agent process

**Definition Reference**:
The immutable binding from a Task to exactly one external Pack or scenario definition. It records the definition's namespace, stable external identity, version label, locator, and SHA-256 digest; a different definition requires a different Task. MCR Core governs the recorded binding but does not resolve the locator, re-hash external content, or interpret the definition.
_Avoid_: Pack content, mutable Pack pointer, scenario configuration, Core-owned manifest

**Actor**:
The opaque attribution on a Task Fact identifying the human or integration that submitted it. An Actor is not proof of identity, authentication, authorization, or role membership; those remain adapter responsibilities.
_Avoid_: user account, authenticated principal, RBAC role

**Task Fact**:
An immutable assertion about a task that an actor or integration explicitly submits for MCR Core to govern. Mutable AI-runtime state is not a Task Fact until it is recorded.
_Avoid_: live runtime state, mutable status row, raw log line

**Run**:
A Task Fact that records a bounded execution observation submitted by an adapter. MCR Core does not start or control execution; prompts, model details, Herdr sessions, panes, and logs remain external or opaque.
_Avoid_: agent execution, job scheduler, live run state, Herdr session

**Registered Input**:
An immutable, task-scoped reference to content supplied to a Task, bound to a content hash and submission metadata. It is distinct from an Artifact, which records produced content; input kinds and content semantics remain external.
_Avoid_: Artifact, unaudited upload, mutable source file

**Artifact**:
An immutable, task-scoped reference to produced content, bound to a stable identity, content hash, and locator and optionally associated with a Run. MCR Core may preserve and verify its bytes but does not interpret their meaning; changed content is a new Artifact.
_Avoid_: mutable output file, editable document, business conclusion

**Claim**:
A stable, task-scoped statement that can be reviewed and may originate in an Artifact. Recording a Claim does not establish that it is true.
_Avoid_: proven fact, Artifact, final conclusion

**Source Reference**:
An immutable reference to source content bound to a locator, anchor, and content hash. A Source Reference identifies what can support a Claim without asserting that the source is authoritative or true.
_Avoid_: evidence attachment, trusted source, business truth

**Evidence Link**:
A Task Fact relating one Claim to one Source Reference. MCR Core validates the relationship, scope, and referenced content hash but does not judge the Claim's truth or interpret the source's business meaning.
_Avoid_: attachment, proof by existence, source interpretation

**Review**:
A Task Fact recording an attributed evaluation of an exact subject or version. A Review may carry an outcome and findings but does not authorize use of the reviewed subject.
_Avoid_: Approval, task completion, mutable review state

**Approval**:
A Task Fact recording an attributed authorization decision for an exact subject or version within an explicit scope. An Approval does not mean that the Task is complete and does not replace a Review.
_Avoid_: blanket success, task completion, Review

**Policy Decision**:
A Task Fact recording the result of an external policy evaluation and the exact action or subject evaluated. MCR Core records the result but does not execute the policy or treat the result as an Approval.
_Avoid_: Approval, permission grant, Core policy execution

**Delivery**:
A Task Fact recording that exact Artifact versions were prepared for an explicit format, scope, and target reference. Packaging, transmission, publication, and interpretation remain adapter responsibilities.
_Avoid_: network transfer, Customer Report, task completion

**Opaque Fact**:
A recorded fact whose envelope and integrity are governed while its payload semantics remain outside MCR Core. It can be preserved and replayed without contributing scenario meaning to Core projections.
_Avoid_: ignored event, interpreted extension, plugin contract

**Deterministic Projection**:
A read-only view derived solely from one ordered MCR history, so the same valid history produces the same view. It is not authoritative mutable state and does not rerun external execution or interpret scenario content.
_Avoid_: mutable status store, workflow state machine, re-execution

**Core Invariant**:
A scenario-independent validity rule enforced by MCR Core: facts are immutable, internal fact references stay within one Workspace and Task, referenced internal facts exist, hash bindings on those references exactly match the recorded facts, and decisions bind an exact subject and scope. External content references may cross that boundary only through stable identifiers and hashes; Core governs those recorded bindings but does not infer that an external locator still resolves to the same bytes. Lifecycle gates, role separation, and scenario prerequisites are external policies rather than Core Invariants.
_Avoid_: workflow rule, Pack rule, approval policy

**Replay Compatibility**:
The ability to load and verify an accepted legacy MCR history without rewriting it. Scenario-specific facts may remain opaque when MCR Core does not govern their meaning.
_Avoid_: history migration, scenario-behavior compatibility, legacy-history rewrite
