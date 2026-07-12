# MCR Core

MCR Core is the scenario-independent domain for governing facts about a task. It exists to make those facts recordable, relatable, reviewable, and verifiable without owning agent execution or business-scenario interpretation.

## Language

**MCR Core**:
The scenario-independent task-fact governance domain. It does not execute agents, interpret Pack content, or act as a general workflow engine.
_Avoid_: agent runtime, Pack runtime, workflow engine, audit-log library

**Task Fact**:
An immutable assertion about a task that an actor or integration explicitly submits for MCR Core to govern. Mutable AI-runtime state is not a Task Fact until it is recorded.
_Avoid_: live runtime state, mutable status row, raw log line

**Replay Compatibility**:
The ability to load and verify an accepted legacy MCR history without rewriting it. Scenario-specific facts may remain opaque when MCR Core does not govern their meaning.
_Avoid_: history migration, scenario-behavior compatibility, legacy-history rewrite
