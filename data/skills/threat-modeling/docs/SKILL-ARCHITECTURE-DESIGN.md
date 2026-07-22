<!-- Threat Modeling Skill | Version 3.1.0 (20260313a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# STRIDE Threat Modeling System Architecture Analysis

> **Version**: 3.1.0
> **Date**: 2026-02-04 (updated 2026-03-13)
> **Purpose**: Comprehensive system architecture analysis with diagrams, module relationships, and formal workflow specification

> **Note (v3.0.2)**: Architecture refactored for clarity and determinism:
> - SKILL.md: "WHAT & WHY" (静态契约) - ~4K tokens target
> - WORKFLOW.md: "HOW & WHEN" (动态协议) - ~4K tokens target
> - FSM formalization for 8-phase workflow
> - 4-Gate Protocol per phase (ENTRY → THINKING → PLANNING → EXECUTING → REFLECTING → EXIT)

---

## 0. File Responsibility Matrix (v3.0.2)

### SKILL.md - "WHAT & WHY" (Static Contract)

**Responsibilities**:
- Version management and compatibility
- Core concept definitions (STRIDE, Dual Knowledge System)
- Global constraints and invariants
- Data model specifications (YAML Schema type definitions)
- Output conventions and format standards
- Quick Start guide
- First principles declaration

**Should NOT contain**:
- Specific execution steps
- Phase-to-phase data flow details
- Validation gate logic
- Error recovery procedures

**Token Budget**: ~4,000 (reduced from ~7,000)

### WORKFLOW.md - "HOW & WHEN" (Dynamic Protocol)

**Responsibilities**:
- Session lifecycle management
- Phase execution protocol (FSM definition)
- Phase-to-phase data contracts (I/O Schema)
- Validation gate rules and phase-end protocol
- STRIDE matrix mapping
- Error recovery and rollback strategies
- Final report output specifications

**Should NOT contain**:
- Version information (reference SKILL.md)
- Repeated global concept definitions
- Data model type definitions (reference only)

**Token Budget**: ~4,000 (reduced from ~5,000)

### Cross-Reference Convention

```yaml
# In WORKFLOW.md (referencing SKILL.md):
"See SKILL.md §1.2 for directory structure"
"Data model defined in SKILL.md §3"

# In SKILL.md (referencing WORKFLOW.md):
"Execution protocol details in WORKFLOW.md §2"
"Validation gates specified in WORKFLOW.md §4"
```

---

## 0.1 Workflow State Machine (FSM) Specification

### 8-Phase Workflow as Finite State Machine

```
┌─────────────────────────────────────────────────────────────────┐
│                    STRIDE Threat Modeling FSM                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  States: {INIT, P1, P2, P3, P4, P5, P6, P7, P8, P8R, DONE, ERROR} │
│                                                                  │
│  Alphabet (Transitions):                                         │
│    σ = {start, p1_complete, p2_complete, ..., p8_complete,      │
│         p8r_complete, validation_fail, recovery_success, abort}  │
│                                                                  │
│  Transition Function δ:                                          │
│    δ(INIT, start) → P1                                          │
│    δ(Pn, pn_complete) → P(n+1)  where n ∈ {1..7}                │
│    δ(P8, p8_complete ∧ ¬detailed) → DONE                        │
│    δ(P8, p8_complete ∧ detailed) → P8R                           │
│    δ(P8R, p8r_complete) → DONE                                   │
│    δ(Pn, validation_fail) → ERROR                               │
│    δ(ERROR, recovery_success) → Pn  (rollback to last valid)    │
│    δ(ERROR, abort) → DONE (with partial results)                │
│                                                                  │
│  Accepting States: {DONE}                                        │
│                                                                  │
│  Data Dependencies (Non-blocking):                               │
│    P5 → P2 (STRIDE analysis on DFD elements)                    │
│    P3/P4 data enhances but does not block P5                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

> **Note**: While the FSM enforces sequential phase completion, data dependencies
> allow flexibility. P5 (STRIDE Analysis) directly consumes P2 (DFD Elements)
> for threat enumeration. P3 (Trust Boundaries) and P4 (Security Design) provide
> enhancement data but are not blocking prerequisites for P5.

### State Transition Diagram

```
         start
    ┌──────┴──────┐
    │    INIT     │
    └──────┬──────┘
           │ start
           ▼
    ┌──────────────┐    p1_complete    ┌─────────────────┐
    │      P1      │ ─────────────────►│       P2        │
    │  Project     │                   │   DFD Analysis  │
    │ Understanding│                   │                 │
    └──────┬───────┘                   └────────┬────────┘
           │                                    │ p2_complete
           │ validation_fail                    ▼
           │                            ┌─────────────────┐
           │         ┌──────────────────│       P3        │
           │         │                  │  Trust Boundary │
           ▼         ▼                  └────────┬────────┘
    ┌──────────────┐                            │
    │    ERROR     │◄───────────────────────────┤ validation_fail
    └──────┬───────┘                            │
           │                                    ▼
           │ recovery_success           ... P4 → P5 → P6 → P7 → P8 ...
           │                                    │
           └──────────► (rollback)              │ p8_complete
                                               ▼
                                        ┌─────────────────┐
                                        │      DONE       │
                                        │  (Final Report) │
                                        └─────────────────┘
```

### Phase Internal 4-Gate Sub-FSM

Each Phase Pn internally follows this sub-state machine:

```
┌───────────────────────────────────────────────────────┐
│                 Phase Pn SubFSM                       │
├───────────────────────────────────────────────────────┤
│                                                       │
│  SubStates: {ENTRY, THINKING, PLANNING, EXECUTING,   │
│              REFLECTING, EXIT}                        │
│                                                       │
│  ┌───────┐  entry_check   ┌──────────┐              │
│  │ ENTRY │ ─────────────► │ THINKING │              │
│  └───────┘   [YES]        └────┬─────┘              │
│      │                         │ think_complete      │
│      │ [NO]                    ▼                     │
│      │                   ┌──────────┐               │
│      │                   │ PLANNING │               │
│      │                   └────┬─────┘               │
│      │                        │ plan_approved        │
│      │                        ▼                      │
│      │                   ┌───────────┐              │
│      │                   │ EXECUTING │◄─────┐       │
│      │                   └─────┬─────┘      │       │
│      │                         │            │ loop  │
│      │                         │ iter_done  │       │
│      │                         ▼            │       │
│      │                   ┌────────────┐     │       │
│      │                   │ REFLECTING │─────┘       │
│      │                   └─────┬──────┘             │
│      │                         │ all_complete       │
│      │                         ▼                    │
│      │                   ┌──────┐                   │
│      └─────────────────► │ EXIT │ (emit pn_complete)│
│         (abort)          └──────┘                   │
│                                                     │
└───────────────────────────────────────────────────────┘
```

---

## 0.2 Formal Verification Properties

### Safety Properties (□ = always)

```
Property S1: Phase Order Invariant
  □ (current_phase = Pn ∧ next_phase = Pm) → m = n+1 ∨ m = ERROR

Property S2: Data Contract Completeness
  □ (phase_complete(Pn)) → exists(output_yaml(Pn))

Property S3: Count Conservation (P5→P6)
  □ count(P5.threats) = count(P6.verified) + count(P6.theoretical)
                       + count(P6.pending) + count(P6.excluded)

Property S4: No Deadlock
  □ (current_state ≠ DONE ∧ current_state ≠ ERROR) → ◇ (next_transition)
```

### Liveness Properties (◇ = eventually)

```
Property L1: Eventual Completion
  ◇ (current_state = DONE ∨ current_state = ERROR)

Property L2: Error Recoverability
  □ (current_state = ERROR) → ◇ (recovery_attempted)
```

### Temporal Logic Notation

| Symbol | Meaning |
|--------|---------|
| □ | Always (in all future states) |
| ◇ | Eventually (in some future state) |
| → | Implies |
| ∧ | And |
| ∨ | Or |

---

## 1. System Architecture Overview

### 1.1 High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                           Code-First Deep Risk Analysis System v3.1.0                          │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              PRESENTATION LAYER (Layer 4)                               │ │
│  ├───────────────────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────────────────┐    │ │
│  │  │                         Claude Skill Interface                                │    │ │
│  │  │  SKILL.md ──► YAML Front Matter (name, description, triggers)                 │    │ │
│  │  │     │         ├── 8-Phase Workflow Definition                                │    │ │
│  │  │     │         ├── Report Output Convention                                   │    │ │
│  │  │     │         ├── Language Adaptation Rules                                  │    │ │
│  │  │     │         └── Core Data Model (Entity Definitions)                       │    │ │
│  │  │     │                                                                         │    │ │
│  │  │     └──► Templates (9 files)                                                  │    │ │
│  │  │           ├── RISK-ASSESSMENT-REPORT.template.md (Main Report)               │    │ │
│  │  │           ├── RISK-INVENTORY.template.md                                     │    │ │
│  │  │           ├── MITIGATION-MEASURES.template.md                                │    │ │
│  │  │           ├── PENETRATION-TEST-PLAN.template.md                              │    │ │
│  │  │           └── 5 additional templates                                         │    │ │
│  │  └──────────────────────────────────────────────────────────────────────────────┘    │ │
│  └───────────────────────────────────────────────────────────────────────────────────────┘ │
│                                              │                                              │
│                                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              WORKFLOW LAYER (Layer 3)                                  │ │
│  ├───────────────────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                                        │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐                      │ │
│  │  │ WORKFLOW.md│  │VALIDATION.md│ │  REPORT.md │  │  GUIDE.md  │                      │ │
│  │  │ (839 lines)│  │ (946 lines)│  │ (852 lines)│  │ (580 lines)│                      │ │
│  │  │            │  │            │  │            │  │            │                      │ │
│  │  │ Phase 1-5  │  │  Phase 6   │  │ Phase 7-8  │  │ User Guide │                      │ │
│  │  │ Steps      │  │  Validation│  │ Mitigation │  │            │                      │ │
│  │  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └────────────┘                      │ │
│  │        │               │               │                                              │ │
│  │        └───────────────┴───────────────┘                                              │ │
│  │                        │                                                              │ │
│  │                        ▼                                                              │ │
│  │  ┌──────────────────────────────────────────────────────────────────────────────┐    │ │
│  │  │                         8-Phase Execution Pipeline                            │    │ │
│  │  │  P1 → P2 → P3 → P4 → P5 → P6 → P7 → P8                                       │    │ │
│  │  │  Project  DFD   Trust Security STRIDE Risk   Mitigation Report               │    │ │
│  │  │                      Design  Analysis Validate                                │    │ │
│  │  └──────────────────────────────────────────────────────────────────────────────┘    │ │
│  └───────────────────────────────────────────────────────────────────────────────────────┘ │
│                                              │                                              │
│                                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              SCRIPT LAYER (Layer 2)                                    │ │
│  ├───────────────────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                                        │ │
│  │  scripts/                                                                             │ │
│  │  ├── unified_kb_query.py (102KB)     ◄── Main KB Query Interface                     │ │
│  │  │   ├── STRIDE queries (--stride)                                                    │ │
│  │  │   ├── CWE/CAPEC chains (--cwe, --capec, --full-chain)                             │ │
│  │  │   ├── CVE lookups (--cve, --cve-for-cwe)                                          │ │
│  │  │   ├── Semantic search (--search)                                                   │ │
│  │  │   ├── ASVS/WSTG verification (--asvs-level, --wstg)                               │ │
│  │  │   └── Compliance queries (--stride-compliance)                                     │ │
│  │  │                                                                                    │ │
│  │  ├── module_discovery.py (11KB)            ◄── Phase 1: Project Structure                  │ │
│  │  │   └── File categorization, type detection                                         │ │
│  │  │                                                                                    │ │
│  │  ├── stride_matrix.py (7.6KB)        ◄── Phase 5: STRIDE per Interaction             │ │
│  │  │   └── Threat category calculation                                                 │ │
│  │  │                                                                                    │ │
│  │  ├── phase_data.py                    ◄── Cross-Phase Data & Validation (v3.1.0)    │ │
│  │  │   └── YAML extraction, CP1/CP2/CP3 validation                                    │ │
│  │  │                                                                                    │ │
│  │  │  [Development Only - Not in Release]                                              │ │
│  │  │  ├── collect_code_stats.py        ◄── LOC/File Statistics                        │ │
│  │  │  ├── build_knowledge_base.py      ◄── KB Build (Offline)                          │ │
│  │  │  ├── build_cve_index.py           ◄── CVE Index Build                             │ │
│  │  │  ├── prebuild_semantic_index.py   ◄── Embedding Generation                        │ │
│  │  │  └── kb_incremental_update.py     ◄── KB Updates                                  │ │
│  │                                                                                        │ │
│  └───────────────────────────────────────────────────────────────────────────────────────┘ │
│                                              │                                              │
│                                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐ │
│  │                              KNOWLEDGE LAYER (Layer 1)                                 │ │
│  ├───────────────────────────────────────────────────────────────────────────────────────┤ │
│  │                                                                                        │ │
│  │  ┌─────────────────────────────┐  ┌─────────────────────────────────────────────────┐│ │
│  │  │    SQLite Databases         │  │           YAML Knowledge Files                   ││ │
│  │  │                             │  │                                                   ││ │
│  │  │  security_kb.sqlite (14MB)  │  │  security-design.yaml (17KB)                     ││ │
│  │  │  ├── CWE (974)              │  │  ├── 16 Security Domains                         ││ │
│  │  │  ├── CAPEC (615)            │  │  └── Domain → STRIDE mapping                     ││ │
│  │  │  ├── ATT&CK (835)           │  │                                                   ││ │
│  │  │  ├── WSTG (121)             │  │  stride-library.yaml (5KB)                       ││ │
│  │  │  ├── MASTG (206)            │  │  ├── STRIDE categories                           ││ │
│  │  │  ├── ASVS (345)             │  │  └── Element→threat mapping                      ││ │
│  │  │  ├── Compliance (115)       │  │                                                   ││ │
│  │  │  └── Embeddings (3,278)     │  │  capec-mappings.yaml (300KB)                     ││ │
│  │  │                             │  │  ├── Attack patterns                              ││ │
│  │  │  security_kb_extension.sqlite │  │  └── ATT&CK mapping                             ││ │
│  │  │  (304MB)                    │  │                                                   ││ │
│  │  │  ├── CVE (323,830)          │  │  llm-threats.yaml (31KB)                         ││ │
│  │  │  └── CVE→CWE (108,409)      │  │  └── OWASP LLM Top 10                            ││ │
│  │  └─────────────────────────────┘  └─────────────────────────────────────────────────┘│ │
│  │                                                                                        │ │
│  │  ┌─────────────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                         Security Controls (L3+L4)                                │ │ │
│  │  │  security-controls/                                                              │ │ │
│  │  │  ├── control-set-{01-10}-*.md    ◄── 10 Core Domain Controls                    │ │ │
│  │  │  ├── control-set-ext-*.md        ◄── 8 Extended Domain Controls                 │ │ │
│  │  │  └── references/ (73 files)       ◄── OWASP Scenario Practices                  │ │ │
│  │  └─────────────────────────────────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Summary

| Layer | Component | Files | Purpose |
|-------|-----------|-------|---------|
| **Layer 4** | Presentation | 1 SKILL + 9 templates + 4 schemas | User interface and report generation |
| **Layer 3** | Workflow | WORKFLOW + VALIDATION + REPORT + GUIDE | Phase execution logic |
| **Layer 2** | Scripts | 11 Python scripts | Automation and data processing |
| **Layer 1** | Knowledge | 2 SQLite DBs + 12 YAML files + 90 MD controls | Security knowledge store |

---

## 2. Data Flow Diagram

### 2.1 Complete System Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              STRIDE System Data Flow Diagram                                 │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              INPUT SOURCES                                            │  │
│  ├──────────────────────────────────────────────────────────────────────────────────────┤  │
│  │                                                                                       │  │
│  │  [EI-01]              [EI-02]              [EI-03]              [EI-04]               │  │
│  │  User/Claude  ───►    Target      ───►    Knowledge    ───►    Previous              │  │
│  │  Request              Project              Base                 Session              │  │
│  │  (NL command)         (Codebase)           (SQLite+YAML)        (_session_meta)      │  │
│  │                                                                                       │  │
│  └────────┬─────────────────┬─────────────────┬─────────────────────┬───────────────────┘  │
│           │                 │                 │                     │                       │
│           ▼                 ▼                 ▼                     ▼                       │
│  ┌──────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              8-PHASE PROCESSING PIPELINE                              │  │
│  ├──────────────────────────────────────────────────────────────────────────────────────┤  │
│  │                                                                                       │  │
│  │  ╔═══════════════╗      DF-01: project_context                                       │  │
│  │  ║   Phase 1     ║ ────────────────────────────────────────────────────────────►     │  │
│  │  ║   Project     ║      - file_structure, tech_stack, entry_points                   │  │
│  │  ║ Understanding ║      - security_modules, scale_metrics                            │  │
│  │  ╚═══════════════╝                                                                   │  │
│  │         │                                                                             │  │
│  │         │ DF-01                                                                       │  │
│  │         ▼                                                                             │  │
│  │  ╔═══════════════╗      DF-02: dfd_elements                                          │  │
│  │  ║   Phase 2     ║ ────────────────────────────────────────────────────────────►     │  │
│  │  ║   DFD/Call    ║      - processes[], data_stores[], data_flows[]                   │  │
│  │  ║   Flow        ║      - external_interactors[], element_map                        │  │
│  │  ╚═══════════════╝                                                                   │  │
│  │         │                                                                             │  │
│  │         │ DF-01 + DF-02                                                               │  │
│  │         ▼                                                                             │  │
│  │  ╔═══════════════╗      DF-03: boundary_context                                      │  │
│  │  ║   Phase 3     ║ ────────────────────────────────────────────────────────────►     │  │
│  │  ║   Trust       ║      - trust_boundaries[], boundary_crossings[]                   │  │
│  │  ║   Boundaries  ║      - security_zones, element_zone_mapping                       │  │
│  │  ╚═══════════════╝                                                                   │  │
│  │         │                                                                             │  │
│  │         │ DF-01 + DF-02 + DF-03                                                       │  │
│  │         ▼                                                                             │  │
│  │  ╔═══════════════╗      DF-04: security_gaps                                         │  │
│  │  ║   Phase 4     ║ ────────────────────────────────────────────────────────────►     │  │
│  │  ║   Security    ║      - domain_assessments[16], gaps[], recommendations[]          │  │
│  │  ║   Design      ║      - security_coverage_matrix                                   │  │
│  │  ╚═══════════════╝                                                                   │  │
│  │         │              ┌──────────────────────────────────────────────────────┐      │  │
│  │         │              │            KB QUERY: STRIDE → CWE → CAPEC            │      │  │
│  │         │              │  python unified_kb_query.py --stride {category}      │      │  │
│  │         ▼              └──────────────────────────────────────────────────────┘      │  │
│  │  ╔═══════════════╗      DF-05: threat_inventory                                      │  │
│  │  ║   Phase 5     ║ ────────────────────────────────────────────────────────────►     │  │
│  │  ║   STRIDE      ║      - threats[] (T-{S}-{E}-{Seq})                                │  │
│  │  ║   Analysis    ║      - element_threat_map, stride_distribution                    │  │
│  │  ╚═══════════════╝      - cwe_refs[], capec_refs[], total: 50-200                    │  │
│  │         │              ┌──────────────────────────────────────────────────────┐      │  │
│  │         │              │         KB QUERY: CAPEC → ATT&CK → CVE/KEV          │      │  │
│  │         │              │  python unified_kb_query.py --capec {id} --attack   │      │  │
│  │         ▼              └──────────────────────────────────────────────────────┘      │  │
│  │  ╔═══════════════╗      DF-06: validated_risks                                       │  │
│  │  ║   Phase 6     ║ ────────────────────────────────────────────────────────────►     │  │
│  │  ║   Risk        ║      - validated_risks[] (VR-{Seq})                               │  │
│  │  ║   Validation  ║      - poc_details[], attack_paths[], attack_chains[]             │  │
│  │  ╚═══════════════╝      - threat_disposition (count conservation)                    │  │
│  │         │              ┌──────────────────────────────────────────────────────┐      │  │
│  │         │              │      KB QUERY: CWE Mitigations + ASVS + Controls     │      │  │
│  │         │              │  python unified_kb_query.py --cwe {id} --mitigations │      │  │
│  │         ▼              └──────────────────────────────────────────────────────┘      │  │
│  │  ╔═══════════════╗      DF-07: mitigation_plan                                       │  │
│  │  ║   Phase 7     ║ ────────────────────────────────────────────────────────────►     │  │
│  │  ║   Mitigation  ║      - mitigations[] (M-{Seq})                                    │  │
│  │  ║   Planning    ║      - fix_locations, asvs_compliance, implementation_steps       │  │
│  │  ╚═══════════════╝                                                                   │  │
│  │         │                                                                             │  │
│  │         │ ALL DataFlows (DF-01 to DF-07)                                             │  │
│  │         ▼                                                                             │  │
│  │  ╔═══════════════╗      DF-08: final_reports                                         │  │
│  │  ║   Phase 8     ║ ────────────────────────────────────────────────────────────►     │  │
│  │  ║   Report      ║      - 4 Required Reports + 6 Phase Documents                     │  │
│  │  ║   Generation  ║      - Risk_Assessment_Report/{PROJECT}-*.md                      │  │
│  │  ╚═══════════════╝                                                                   │  │
│  │                                                                                       │  │
│  └──────────────────────────────────────────────────────────────────────────────────────┘  │
│                                              │                                              │
│                                              ▼                                              │
│  ┌──────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              OUTPUT ARTIFACTS                                         │  │
│  ├──────────────────────────────────────────────────────────────────────────────────────┤  │
│  │                                                                                       │  │
│  │  Risk_Assessment_Report/                                                              │  │
│  │  │                                                                                    │  │
│  │  ├── {PROJECT}-RISK-ASSESSMENT-REPORT.md    ◄── Main Report (all phases aggregated)  │  │
│  │  ├── {PROJECT}-RISK-INVENTORY.md            ◄── Complete VR list with threat_refs    │  │
│  │  ├── {PROJECT}-MITIGATION-MEASURES.md       ◄── M-{Seq} with fix_locations          │  │
│  │  ├── {PROJECT}-PENETRATION-TEST-PLAN.md     ◄── POC-based test plan                 │  │
│  │  │                                                                                    │  │
│  │  ├── P1-PROJECT-UNDERSTANDING.md            ◄── Phase 1 working document             │  │
│  │  ├── P2-DFD-ANALYSIS.md                     ◄── DFD elements and flows               │  │
│  │  ├── P3-TRUST-BOUNDARY.md                   ◄── Boundary definitions                 │  │
│  │  ├── P4-SECURITY-DESIGN-REVIEW.md           ◄── 16 domain assessments               │  │
│  │  ├── P5-STRIDE-THREATS.md                   ◄── Complete threat inventory           │  │
│  │  └── P6-RISK-VALIDATION.md                  ◄── POCs and attack paths               │  │
│  │                                                                                       │  │
│  │  .phase_working/                                                                      │  │
│  │  └── _session_meta.yaml                     ◄── Session state for recovery           │  │
│  │                                                                                       │  │
│  └──────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow Summary Table

| Flow ID | Source | Target | Data Structure | Volume |
|---------|--------|--------|----------------|--------|
| DF-01 | P1 | P2,P3,P4 | project_context | 1 object |
| DF-02 | P2 | P3,P4,P5 | dfd_elements | 10-50 elements |
| DF-03 | P3 | P4,P5 | boundary_context | 3-10 boundaries |
| DF-04 | P4 | P5,P6 | security_gaps | 16 domain assessments |
| DF-05 | P5 | P6 | threat_inventory | 50-200 threats |
| DF-06 | P6 | P7,P8 | validated_risks | 5-30 VRs |
| DF-07 | P7 | P8 | mitigation_plan | 5-20 mitigations |
| DF-08 | P8 | Output | final_reports | 10 files |

---

## 3. Module Relationships

### 3.1 File Dependency Graph

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              Module Dependency Graph                                         │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                              SKILL.md (Entry Point)                                  │   │
│  │                              ════════════════════════                                │   │
│  │                                                                                      │   │
│  │  Defines:                                                                            │   │
│  │  ├── Workflow activation triggers                                                    │   │
│  │  ├── 8-Phase structure                                                               │   │
│  │  ├── Core Data Model (Finding → Threat → VR → Mitigation)                           │   │
│  │  ├── ID conventions (F-P{N}-{Seq}, T-{S}-{E}-{Seq}, VR-{Seq}, M-{Seq})              │   │
│  │  ├── Count conservation rules                                                        │   │
│  │  └── Knowledge architecture overview                                                 │   │
│  │                                                                                      │   │
│  └──────┬────────────────────────────────────────────────────────────────────┬─────────┘   │
│         │                                                                     │             │
│         │ references                                                          │ references  │
│         ▼                                                                     ▼             │
│  ┌───────────────────────┐  ┌────────────────────┐  ┌─────────────────────────────────┐   │
│  │     WORKFLOW.md       │  │    VALIDATION.md   │  │          REPORT.md              │   │
│  │  ═══════════════════  │  │  ═════════════════ │  │  ═══════════════════════════    │   │
│  │                       │  │                    │  │                                 │   │
│  │  Phase 1-5 Details:   │  │  Phase 6 Details:  │  │  Phase 7-8 Details:             │   │
│  │  ├── Step definitions │  │  ├── Consolidation │  │  ├── KB query patterns          │   │
│  │  ├── Output templates │  │  │   algorithm     │  │  ├── Mitigation templates       │   │
│  │  ├── Checkpoints      │  │  ├── Dedup rules   │  │  ├── ASVS integration          │   │
│  │  └── KB query points  │  │  ├── POC design    │  │  ├── Fix location tracking      │   │
│  │                       │  │  └── Attack paths  │  │  └── Report aggregation         │   │
│  └───────────┬───────────┘  └─────────┬──────────┘  └───────────────┬─────────────────┘   │
│              │                         │                             │                      │
│              │                         │                             │                      │
│              └─────────────────────────┼─────────────────────────────┘                      │
│                                        │                                                    │
│                                        │ use                                                │
│                                        ▼                                                    │
│  ┌──────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              assets/contracts/ (1 file)                                      │  │
│  │                              ══════════════════════                                  │  │
│  │                                                                                       │  │
│  │  data-model.yaml              ◄── Entity schemas, data contracts, type definitions   │  │
│  │                                                                                       │  │
│  │  Note: assets/templates/ and assets/schemas/ are reserved (empty).                   │  │
│  │  Report templates are defined inline in phase instruction files (P8, P8R).            │  │
│  │                                                                                       │  │
│  └──────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Module Purpose Matrix

| Module | Type | Purpose | Dependencies |
|--------|------|---------|--------------|
| SKILL.md | Definition | Entry point, data model, global constraints | - |
| WORKFLOW.md | Execution | Phase orchestration, FSM, data contracts | SKILL.md |
| phases/P1-P8-*.md | Execution | Per-phase instructions (9 files including P8R) | SKILL.md, WORKFLOW.md |
| scripts/*.py | Automation | Session management, KB queries, validation | SKILL.md |
| assets/contracts/data-model.yaml | Schema | Entity schemas and data contracts | SKILL.md |

---

## 4. Workflow Decomposition

### 4.1 8-Phase Workflow Detail

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              8-Phase Workflow Decomposition                                  │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                              │
│  ╔═══════════════════════════════════════════════════════════════════════════════════════╗ │
│  ║  PHASE 1: Project Understanding                                                        ║ │
│  ╠═══════════════════════════════════════════════════════════════════════════════════════╣ │
│  ║                                                                                        ║ │
│  ║  Steps:                                          Scripts:                              ║ │
│  ║  1. Get file structure ────────────────────────► module_discovery.py                 ║ │
│  ║  2. Identify project type                                                              ║ │
│  ║  3. Collect scale metrics ─────────────────────► module_discovery.py --stats         ║ │
│  ║  4. Read key files                                                                     ║ │
│  ║  5. Document architecture                                                              ║ │
│  ║                                                                                        ║ │
│  ║  Output: P1-PROJECT-UNDERSTANDING.md                                                   ║ │
│  ║  Data: project_context {file_structure, tech_stack, scale_metrics, modules}           ║ │
│  ╚═══════════════════════════════════════════════════════════════════════════════════════╝ │
│                                              │                                              │
│                                              ▼                                              │
│  ╔═══════════════════════════════════════════════════════════════════════════════════════╗ │
│  ║  PHASE 2: Call Flow & DFD Analysis                                                     ║ │
│  ╠═══════════════════════════════════════════════════════════════════════════════════════╣ │
│  ║                                                                                        ║ │
│  ║  Steps:                                          LLM Tasks:                            ║ │
│  ║  1. Identify External Interactors                - Trace user flows                   ║ │
│  ║  2. Map Processes                                - Identify data transformations      ║ │
│  ║  3. Identify Data Stores                         - Map sensitive data                  ║ │
│  ║  4. Define Data Flows                            - Assign element IDs                  ║ │
│  ║  5. Construct DFD                                                                      ║ │
│  ║                                                                                        ║ │
│  ║  Output: P2-DFD-ANALYSIS.md                                                            ║ │
│  ║  Data: dfd_elements {processes[], data_stores[], data_flows[], external_interactors[]}║ │
│  ╚═══════════════════════════════════════════════════════════════════════════════════════╝ │
│                                              │                                              │
│                                              ▼                                              │
│  ╔═══════════════════════════════════════════════════════════════════════════════════════╗ │
│  ║  PHASE 3: Trust Boundary Evaluation                                                    ║ │
│  ╠═══════════════════════════════════════════════════════════════════════════════════════╣ │
│  ║                                                                                        ║ │
│  ║  Steps:                                          LLM Tasks:                            ║ │
│  ║  1. Identify trust zones                         - Analyze network boundaries          ║ │
│  ║  2. Map elements to zones                        - Identify privilege transitions      ║ │
│  ║  3. Identify boundary crossings                  - Map data sensitivity                ║ │
│  ║  4. Document crossing risks                                                            ║ │
│  ║                                                                                        ║ │
│  ║  Output: P3-TRUST-BOUNDARY.md                                                          ║ │
│  ║  Data: boundary_context {trust_boundaries[], security_zones, boundary_crossings[]}    ║ │
│  ╚═══════════════════════════════════════════════════════════════════════════════════════╝ │
│                                              │                                              │
│                                              ▼                                              │
│  ╔═══════════════════════════════════════════════════════════════════════════════════════╗ │
│  ║  PHASE 4: Security Design Review                                                       ║ │
│  ╠═══════════════════════════════════════════════════════════════════════════════════════╣ │
│  ║                                                                                        ║ │
│  ║  Steps:                                          Knowledge Files:                      ║ │
│  ║  1. Assess 16 security domains                   - security-design.yaml               ║ │
│  ║     (AUTHN, AUTHZ, INPUT, OUTPUT,               - control-set-{01-16}.md             ║ │
│  ║      CLIENT, CRYPTO, LOG, ERROR,                - reference-set-*.md                  ║ │
│  ║      API, DATA, INFRA, SUPPLY, AI,                                                    ║ │
│  ║      MOBILE, CLOUD)                                                                    ║ │
│  ║  2. Identify security gaps                                                             ║ │
│  ║  3. Rate coverage (✅/⚠️/❌)                                                          ║ │
│  ║                                                                                        ║ │
│  ║  Output: P4-SECURITY-DESIGN-REVIEW.md                                                  ║ │
│  ║  Data: security_gaps {domain_assessments[16], gaps[], coverage_matrix}                ║ │
│  ╚═══════════════════════════════════════════════════════════════════════════════════════╝ │
│                                              │                                              │
│                                              ▼                                              │
│  ╔═══════════════════════════════════════════════════════════════════════════════════════╗ │
│  ║  PHASE 5: STRIDE Threat Analysis                                                       ║ │
│  ╠═══════════════════════════════════════════════════════════════════════════════════════╣ │
│  ║                                                                                        ║ │
│  ║  Steps:                                          Scripts:                              ║ │
│  ║  1. For each DFD element: ──────────────────────► stride_matrix.py --element {type}  ║ │
│  ║     - Get applicable STRIDE categories                                                 ║ │
│  ║  2. For each STRIDE category: ──────────────────► unified_kb_query.py --stride {cat} ║ │
│  ║     - Query CWE/CAPEC mappings                                                         ║ │
│  ║  3. Generate threat ID: T-{S}-{E}-{Seq}                                                ║ │
│  ║  4. Build threat inventory                                                             ║ │
│  ║                                                                                        ║ │
│  ║  Output: P5-STRIDE-THREATS.md                                                          ║ │
│  ║  Data: threat_inventory {threats[50-200], element_threat_map, stride_distribution}    ║ │
│  ╚═══════════════════════════════════════════════════════════════════════════════════════╝ │
│                                              │                                              │
│                                              ▼                                              │
│  ╔═══════════════════════════════════════════════════════════════════════════════════════╗ │
│  ║  PHASE 6: Risk Validation (VALIDATION.md)                                              ║ │
│  ╠═══════════════════════════════════════════════════════════════════════════════════════╣ │
│  ║                                                                                        ║ │
│  ║  Steps:                                          Scripts:                              ║ │
│  ║  1. Collect all findings (P1-P5) ◄───────────── Read .phase_working/P{1-5}*.md       ║ │
│  ║  2. Normalize to unified format                                                        ║ │
│  ║  3. Deduplicate (CWE + location match)                                                 ║ │
│  ║  4. Create VR-{Seq} with threat_refs[]                                                 ║ │
│  ║  5. Query attack patterns: ─────────────────────► unified_kb_query.py --capec --attack║ │
│  ║  6. Design POCs                                                                        ║ │
│  ║  7. Map attack paths                                                                   ║ │
│  ║  8. Track threat_disposition (count conservation)                                      ║ │
│  ║                                                                                        ║ │
│  ║  Output: P6-RISK-VALIDATION.md                                                         ║ │
│  ║  Data: validated_risks {vrs[], poc_details[], attack_paths[], threat_disposition}     ║ │
│  ╚═══════════════════════════════════════════════════════════════════════════════════════╝ │
│                                              │                                              │
│                                              ▼                                              │
│  ╔═══════════════════════════════════════════════════════════════════════════════════════╗ │
│  ║  PHASE 7: Mitigation Planning (REPORT.md)                                              ║ │
│  ╠═══════════════════════════════════════════════════════════════════════════════════════╣ │
│  ║                                                                                        ║ │
│  ║  Steps:                                          Scripts:                              ║ │
│  ║  For each VR (parallel sub-agents):                                                    ║ │
│  ║  1. Query CWE mitigations: ─────────────────────► unified_kb_query.py --cwe --mitigs ║ │
│  ║  2. Query CVE context: ─────────────────────────► unified_kb_query.py --cve-for-cwe  ║ │
│  ║  3. Get STRIDE controls: ───────────────────────► unified_kb_query.py --stride       ║ │
│  ║  4. Query ASVS requirements: ───────────────────► unified_kb_query.py --asvs-level   ║ │
│  ║  5. Design stack-specific mitigation                                                   ║ │
│  ║  6. Collect fix_location (module, function, file, line)                               ║ │
│  ║  7. Define verification criteria                                                       ║ │
│  ║                                                                                        ║ │
│  ║  Output: .phase_working/P7-MITIGATION-PLANNING.md (optional)                           ║ │
│  ║  Data: mitigation_plan {mitigations[], fix_locations[], asvs_compliance[]}           ║ │
│  ╚═══════════════════════════════════════════════════════════════════════════════════════╝ │
│                                              │                                              │
│                                              ▼                                              │
│  ╔═══════════════════════════════════════════════════════════════════════════════════════╗ │
│  ║  PHASE 8: Report Generation (REPORT.md)                                                ║ │
│  ╠═══════════════════════════════════════════════════════════════════════════════════════╣ │
│  ║                                                                                        ║ │
│  ║  Steps:                                          Templates:                            ║ │
│  ║  1. Read ALL phase documents                     - RISK-ASSESSMENT-REPORT.template.md ║ │
│  ║  2. Aggregate content (NO summarization)        - RISK-INVENTORY.template.md          ║ │
│  ║  3. Generate 4 required reports                  - MITIGATION-MEASURES.template.md    ║ │
│  ║  4. Copy phase docs to output                    - PENETRATION-TEST-PLAN.template.md  ║ │
│  ║  5. Validate count conservation ────────────────► phase_data.py --validate-all-cp    ║ │
│  ║                                                                                        ║ │
│  ║  Output: Risk_Assessment_Report/                                                       ║ │
│  ║  ├── {PROJECT}-RISK-ASSESSMENT-REPORT.md                                              ║ │
│  ║  ├── {PROJECT}-RISK-INVENTORY.md                                                      ║ │
│  ║  ├── {PROJECT}-MITIGATION-MEASURES.md                                                 ║ │
│  ║  ├── {PROJECT}-PENETRATION-TEST-PLAN.md                                               ║ │
│  ║  └── P{1-6}-*.md (phase documents)                                                    ║ │
│  ╚═══════════════════════════════════════════════════════════════════════════════════════╝ │
│                                                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Script-Workflow Interactions

### 5.1 Script Usage by Phase

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              Script-Workflow Interaction Matrix                              │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                              │
│  Script                         │ P1 │ P2 │ P3 │ P4 │ P5 │ P6 │ P7 │ P8 │                  │
│  ═══════════════════════════════╪════╪════╪════╪════╪════╪════╪════╪════╪                  │
│                                 │    │    │    │    │    │    │    │    │                  │
│  module_discovery.py            │ ●● │ ●  │    │    │    │    │    │    │                  │
│  └─ Project analysis & modules  │    │    │    │    │    │    │    │    │                  │
│                                 │    │    │    │    │    │    │    │    │                  │
│  stride_matrix.py               │    │    │    │    │ ●● │    │    │    │                  │
│  └─ STRIDE per Interaction      │    │    │    │    │    │    │    │    │                  │
│                                 │    │    │    │    │    │    │    │    │                  │
│  unified_kb_query.py            │    │    │    │    │ ●● │ ●● │ ●● │    │                  │
│  ├─ --stride {category}         │    │    │    │    │ ●  │    │ ●  │    │                  │
│  ├─ --cwe {id}                  │    │    │    │    │ ●  │ ●  │    │    │                  │
│  ├─ --cwe --full-chain          │    │    │    │    │ ●  │ ●  │    │    │                  │
│  ├─ --cwe --mitigations         │    │    │    │    │    │    │ ●● │    │                  │
│  ├─ --capec {id}                │    │    │    │    │ ●  │ ●  │    │    │                  │
│  ├─ --capec --attack-chain      │    │    │    │    │    │ ●● │    │    │                  │
│  ├─ --cve-for-cwe               │    │    │    │    │    │ ●  │ ●  │    │                  │
│  ├─ --check-kev                 │    │    │    │    │    │ ●  │    │    │                  │
│  ├─ --asvs-level                │    │    │    │    │    │    │ ●● │    │                  │
│  ├─ --asvs-chapter              │    │    │    │    │    │    │ ●  │    │                  │
│  ├─ --wstg                      │    │    │    │    │    │ ●  │    │    │                  │
│  ├─ --stride-compliance         │    │    │    │    │    │    │    │ ●  │                  │
│  └─ --search (semantic)         │    │    │ ○  │ ○  │ ○  │ ○  │ ○  │    │                  │
│                                 │    │    │    │    │    │    │    │    │                  │
│  phase_data.py (v3.1.0)         │ ●  │ ●  │    │    │ ●  │ ●  │ ●  │ ●● │                  │
│  └─ Cross-phase data & CP valid │    │    │    │    │    │    │    │    │                  │
│                                                                                              │
│  Legend: ●● Primary usage  ● Secondary usage  ○ Optional usage                             │
│                                                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Script Command Examples by Phase

| Phase | Command | Purpose |
|-------|---------|---------|
| P1 | `python module_discovery.py <path> --analyze` | Get project structure and modules |
| P5 | `python stride_matrix.py --element process` | Get applicable STRIDE categories |
| P5 | `python unified_kb_query.py --stride spoofing` | Query STRIDE→CWE mapping |
| P5 | `python unified_kb_query.py --cwe CWE-89 --full-chain` | Get complete CWE chain |
| P6 | `python unified_kb_query.py --capec CAPEC-66 --attack-chain` | Get attack techniques |
| P6 | `python unified_kb_query.py --check-kev CVE-2021-44228` | Check if CVE is actively exploited |
| P7 | `python unified_kb_query.py --cwe CWE-287 --mitigations` | Get mitigation recommendations |
| P7 | `python unified_kb_query.py --asvs-level L2` | Get ASVS L2 requirements |
| P8 | `python phase_data.py --validate-all-cp --root .` | Validate count conservation |

---

## 6. Knowledge Base Architecture

### 6.1 5-Layer Knowledge Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              5-Layer Security Knowledge Architecture                         │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                              │
│  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│  ┃  LAYER 5: Live Vulnerability Data (Optional)                                           ┃ │
│  ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫ │
│  ┃                                                                                        ┃ │
│  ┃  NVD API ◄──────── Real-time CVE lookup when extension DB unavailable                  ┃ │
│  ┃  └─ NVDClient class in unified_kb_query.py                                             ┃ │
│  ┃                                                                                        ┃ │
│  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
│                                              │                                              │
│                                              ▼                                              │
│  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│  ┃  LAYER 4: Compliance Framework Knowledge                                               ┃ │
│  ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫ │
│  ┃                                                                                        ┃ │
│  ┃  SQLite: compliance_framework (14) + compliance_control (115)                          ┃ │
│  ┃  ├── NIST 800-53 Rev 5                                                                 ┃ │
│  ┃  ├── CIS Controls v8                                                                   ┃ │
│  ┃  ├── CSA CCM v4                                                                        ┃ │
│  ┃  ├── ISO 27001/27017/42001                                                             ┃ │
│  ┃  └── stride_compliance (51) → STRIDE category mapping                                  ┃ │
│  ┃                                                                                        ┃ │
│  ┃  Query: --stride-compliance S|T|R|I|D|E                                                ┃ │
│  ┃                                                                                        ┃ │
│  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
│                                              │                                              │
│                                              ▼                                              │
│  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│  ┃  LAYER 3: Security Verification Knowledge                                              ┃ │
│  ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫ │
│  ┃                                                                                        ┃ │
│  ┃  SQLite Tables:                                                                        ┃ │
│  ┃  ├── wstg_test (121)         OWASP Web Security Testing Guide 4.2                     ┃ │
│  ┃  ├── mastg_test (206)        OWASP Mobile App Security Testing Guide 2.0              ┃ │
│  ┃  ├── asvs_requirement (345)  Application Security Verification Standard 5.0           ┃ │
│  ┃  ├── stride_verification (162)  STRIDE → test mapping                                 ┃ │
│  ┃  └── cwe_verification (12,035)   CWE → test mapping                                   ┃ │
│  ┃                                                                                        ┃ │
│  ┃  Queries: --asvs-level L2, --asvs-chapter V4, --wstg ATHN                              ┃ │
│  ┃                                                                                        ┃ │
│  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
│                                              │                                              │
│                                              ▼                                              │
│  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│  ┃  LAYER 2: Security Controls & Implementation Patterns                                  ┃ │
│  ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫ │
│  ┃                                                                                        ┃ │
│  ┃  YAML: security-design.yaml (16 domains)                                               ┃ │
│  ┃  │                                                                                     ┃ │
│  ┃  │  Core Domains (01-10):                                                              ┃ │
│  ┃  │  ├── 01 AUTHN: Authentication & Session                                             ┃ │
│  ┃  │  ├── 02 AUTHZ: Authorization & Access Control                                       ┃ │
│  ┃  │  ├── 03 INPUT: Input Validation                                                     ┃ │
│  ┃  │  ├── 04 OUTPUT: Output Encoding                                                     ┃ │
│  ┃  │  ├── 05 CLIENT: Client-Side Security                                                ┃ │
│  ┃  │  ├── 06 CRYPTO: Cryptography & Transport                                            ┃ │
│  ┃  │  ├── 07 LOG: Logging & Monitoring                                                   ┃ │
│  ┃  │  ├── 08 ERROR: Error Handling                                                       ┃ │
│  ┃  │  ├── 09 API: API & Service Security                                                 ┃ │
│  ┃  │  └── 10 DATA: Data Protection                                                       ┃ │
│  ┃  │                                                                                     ┃ │
│  ┃  │  Extended Domains (ext-11 to ext-16):                                               ┃ │
│  ┃  │  ├── ext-11 INFRA: Infrastructure Security                                          ┃ │
│  ┃  │  ├── ext-12 SUPPLY: Supply Chain Security                                           ┃ │
│  ┃  │  ├── ext-13 AI: AI/LLM Security                                                     ┃ │
│  ┃  │  ├── ext-14 MOBILE: Mobile Security                                                 ┃ │
│  ┃  │  ├── ext-15 CLOUD: Cloud Security                                                   ┃ │
│  ┃  │  └── ext-16 AGENT: Agentic Security (OWASP ASI)                                     ┃ │
│  ┃  │                                                                                     ┃ │
│  ┃  └── security-controls/ (18 control sets + 74 references)                              ┃ │
│  ┃                                                                                        ┃ │
│  ┃  SQLite: security_control (16) + stride_security_control (37)                          ┃ │
│  ┃                                                                                        ┃ │
│  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
│                                              │                                              │
│                                              ▼                                              │
│  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│  ┃  LAYER 1: Core Threat Intelligence                                                     ┃ │
│  ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫ │
│  ┃                                                                                        ┃ │
│  ┃  Threat Intelligence Chain:                                                            ┃ │
│  ┃                                                                                        ┃ │
│  ┃  STRIDE ──► OWASP ──► CWE ──► CAPEC ──► ATT&CK ──► CVE/KEV                            ┃ │
│  ┃    (6)       (10)     (974)    (615)     (835)     (323K)                              ┃ │
│  ┃                                                                                        ┃ │
│  ┃  SQLite Tables:                                                                        ┃ │
│  ┃  ├── stride_category (6)      S, T, R, I, D, E definitions                            ┃ │
│  ┃  ├── stride_cwe (403)         STRIDE → CWE mappings                                   ┃ │
│  ┃  ├── owasp_top10 (10)         OWASP Top 10 2025                                       ┃ │
│  ┃  ├── owasp_cwe (248)          OWASP → CWE mappings                                    ┃ │
│  ┃  ├── cwe (974)                Complete CWE definitions                                ┃ │
│  ┃  ├── capec (615)              CAPEC attack patterns                                   ┃ │
│  ┃  ├── attack_technique (835)   MITRE ATT&CK techniques                                 ┃ │
│  ┃  └── attack_mitigation (43)   ATT&CK mitigations                                      ┃ │
│  ┃                                                                                        ┃ │
│  ┃  Extension DB (security_kb_extension.sqlite):                                          ┃ │
│  ┃  ├── cve (323,830)            NVD CVE index                                           ┃ │
│  ┃  └── cve_cwe (108,409)        CVE → CWE mappings                                      ┃ │
│  ┃                                                                                        ┃ │
│  ┃  YAML Files:                                                                           ┃ │
│  ┃  ├── stride-library.yaml      STRIDE category details                                 ┃ │
│  ┃  ├── capec-mappings.yaml      Extended CAPEC patterns                                 ┃ │
│  ┃  ├── cwe-mappings.yaml        CWE Top 25 details                                      ┃ │
│  ┃  └── llm-threats.yaml         OWASP LLM Top 10                                        ┃ │
│  ┃                                                                                        ┃ │
│  ┃  Semantic Search:                                                                      ┃ │
│  ┃  └── kb_embeddings (3,278)    384-dim vectors (all-MiniLM-L6-v2)                       ┃ │
│  ┃                                                                                        ┃ │
│  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
│                                                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Knowledge Base Statistics

| Category | Table/File | Records | Size |
|----------|------------|---------|------|
| **Layer 1** | CWE | 974 | - |
| | CAPEC | 615 | - |
| | ATT&CK | 835 | - |
| | CVE (extension) | 323,830 | 304MB |
| | Embeddings | 3,278 | 4.8MB |
| **Layer 2** | Security Controls | 18 files | - |
| | OWASP References | 73 files | - |
| **Layer 3** | WSTG | 121 | - |
| | MASTG | 206 | - |
| | ASVS | 345 | - |
| **Layer 4** | Compliance | 115 controls | - |
| **Total Core DB** | security_kb.sqlite | - | 14MB |
| **Total Extension** | security_kb_extension.sqlite | - | 304MB |

---

## 7. Entity Data Model

### 7.1 Core Entity Relationships

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              Core Entity Data Model                                          │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                              PHASE ENTITIES                                          │   │
│  └─────────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                              │
│  Phase 1-4                    Phase 5                    Phase 6                            │
│  ┌───────────────┐            ┌───────────────┐          ┌───────────────┐                 │
│  │   Finding     │            │    Threat     │          │ ValidatedRisk │                 │
│  │ ═════════════ │            │ ═════════════ │          │ ═════════════ │                 │
│  │               │            │               │          │               │                 │
│  │ id:           │            │ id:           │          │ id:           │                 │
│  │  F-P{N}-{Seq} │            │  T-{S}-{E}-   │          │  VR-{Seq}     │                 │
│  │  F-P1-001     │            │    {Seq}      │          │  VR-001       │                 │
│  │               │    N:1     │  T-T-P013-002 │   N:1    │               │                 │
│  │ source_phase: │ ─────────► │               │ ───────► │ threat_refs:  │                 │
│  │  P1|P2|P3|P4  │            │ element_id:   │          │ [T-T-P013-001,│                 │
│  │               │            │ P001|DS002|DF3│          │  T-T-P013-002,│                 │
│  │ description   │            │               │          │  T-E-P013-001]│                 │
│  │ location      │            │ stride_cat:   │          │               │                 │
│  │ severity      │            │  S|T|R|I|D|E  │          │ severity:     │                 │
│  │               │            │               │          │  critical|high│                 │
│  │ Count: 10-30  │            │ cwe_refs[]    │          │  medium|low   │                 │
│  │               │            │ capec_refs[]  │          │               │                 │
│  └───────────────┘            │               │          │ poc_id:       │                 │
│                               │ Count: 50-200 │          │  POC-001      │                 │
│                               │               │          │               │                 │
│                               └───────────────┘          │ Count: 5-30   │                 │
│                                                          │               │                 │
│                                                          └───────┬───────┘                 │
│                                                                  │                          │
│                                                                  │ N:1                      │
│                                                                  ▼                          │
│                              Phase 7                    ┌───────────────┐                  │
│                              ┌───────────────┐          │  Mitigation   │                  │
│                              │    POC        │          │ ═════════════ │                  │
│                              │ ═════════════ │          │               │                  │
│                              │               │          │ id:           │                  │
│                              │ id:           │          │  M-{Seq}      │                  │
│                              │  POC-{Seq}    │          │  M-001        │                  │
│                              │  POC-001      │          │               │                  │
│                              │               │          │ risk_refs:    │                  │
│                              │ threat_id:    │          │  [VR-001,     │                  │
│                              │  T-xxx        │          │   VR-002]     │                  │
│                              │               │          │               │                  │
│                              │ steps[]       │          │ priority:     │                  │
│                              │ code          │          │  P0|P1|P2|P3  │                  │
│                              │ expected      │          │               │                  │
│                              │               │          │ fix_location: │                  │
│                              └───────────────┘          │  module       │                  │
│                                                          │  function     │                  │
│  ┌─────────────────────────────────────────────────────┐ │  file         │                  │
│  │  Attack Entities (Phase 6)                          │ │  line_range   │                  │
│  └─────────────────────────────────────────────────────┘ │               │                  │
│                                                          │ asvs_reqs[]   │                  │
│  ┌───────────────┐          ┌───────────────┐          │               │                  │
│  │  AttackPath   │          │  AttackChain  │          │ Count: 5-20   │                  │
│  │ ═════════════ │          │ ═════════════ │          │               │                  │
│  │               │          │               │          └───────────────┘                  │
│  │ id: AP-{Seq}  │          │ id: AC-{Seq}  │                                              │
│  │ entry_point   │          │ steps[]       │                                              │
│  │ target        │          │ threat_ids[]  │                                              │
│  │ feasibility   │          │ defense_cuts[]│                                              │
│  │               │          │               │                                              │
│  └───────────────┘          └───────────────┘                                              │
│                                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────────────────┐   │
│  │                              COUNT CONSERVATION RULE                                  │   │
│  │                                                                                      │   │
│  │  P5.threat_inventory.total = SUM(consolidated_into_vr) + SUM(excluded_with_reason)  │   │
│  │                                                                                      │   │
│  │  ∀ threat ∈ P5:                                                                      │   │
│  │    threat ∈ VR.threat_refs[]  OR  threat.status = 'excluded' with documented reason │   │
│  │                                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 ID Format Reference

| Entity | Format | Example | Phase |
|--------|--------|---------|-------|
| Finding | `F-P{N}-{Seq:03d}` | F-P1-001, F-P4-003 | P1-P4 |
| Threat | `T-{STRIDE}-{Element}-{Seq}` | T-T-P013-002, T-S-DS001-001 | P5 |
| ValidatedRisk | `VR-{Seq:03d}` | VR-001, VR-025 | P6 |
| POC | `POC-{Seq:03d}` | POC-001 | P6 |
| AttackPath | `AP-{Seq:03d}` | AP-001 | P6 |
| AttackChain | `AC-{Seq:03d}` | AC-001 | P6 |
| Mitigation | `M-{Seq:03d}` | M-001, M-015 | P7 |

---

## 8. Summary

### 8.1 System Statistics

| Metric | Value |
|--------|-------|
| **Total Files** | ~140 |
| **Workflow Files** | 4 (SKILL, WORKFLOW, VALIDATION, REPORT) |
| **Templates** | 9 |
| **Schemas** | 4 |
| **Python Scripts** | 11 |
| **Knowledge YAML** | 12 |
| **Security Controls** | 92 (18 + 74 references) |
| **SQLite Tables** | 25+ |
| **Threat Intelligence Records** | 326,000+ |
| **Version** | 2.1.0 |

### 8.2 Key Design Principles

1. **8-Phase Sequential Workflow**: Strict P1→P2→P3→P4→P5→P6→P7→P8 execution (FSM-enforced)
2. **Core Data Model**: Finding → Threat → ValidatedRisk → Mitigation with mandatory traceability
3. **Count Conservation**: All P5 threats must be accounted for in P6 (consolidated or excluded with reason)
4. **Script as Black Box**: Python scripts handle deterministic operations, LLM handles semantic analysis
5. **5-Layer Knowledge**: Threat Intelligence → Controls → Verification → Compliance → Live Data
6. **Template-Based Reports**: Single English template + LLM translation for localization
7. **File Responsibility Separation**: SKILL.md (WHAT/WHY) vs WORKFLOW.md (HOW/WHEN)
8. **4-Gate Protocol**: Every phase follows ENTRY→THINKING→PLANNING→EXECUTING→REFLECTING→EXIT
9. **Formal Verification**: Safety properties (S1-S4) and Liveness properties (L1-L2) enforceable

---

## 9. Core Objectives Alignment (v3.0.2)

| Objective | Pre-Optimization | Post-Optimization |
|-----------|------------------|-------------------|
| Code-First Threat Modeling | ✅ Maintained | ✅ Maintained (FSM doesn't change analysis method) |
| 8-Phase Sequential Workflow | ⚠️ Implicit | ✅ **Strengthened** (FSM guarantees execution order) |
| Deterministic Verification | ⚠️ Partial | ✅ **Enhanced** (formal properties verifiable) |
| Progressive Context Loading | ⚠️ ~7K+5K tokens | ✅ **Improved** (~4K+4K tokens, 33% reduction) |

---

**Document Version**: 3.1.0
**Last Updated**: 2026-03-12
