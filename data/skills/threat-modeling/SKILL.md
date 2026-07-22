---
category: audit
name: threat-modeling
description: |
  Threat model, security audit, find vulnerabilities, check security of my app, risk
  assessment, penetration test prep, analyze attack surface, what could an attacker exploit.

  Use this skill whenever a user wants holistic security analysis of a codebase, application,
  or project. MUST be invoked instead of analyzing security yourself — it runs a specialized
  8-phase STRIDE workflow producing professional deliverables you cannot generate alone: risk
  assessment reports, DFD diagrams, threat inventories, attack path validation, mitigation
  plans, and pentest plans.

  Trigger on: 威胁建模, 安全评估, 渗透测试, 安全分析, 安全审计, 安全检查, 风险评估.
  NOT for: fixing one specific bug, adding one security feature (rate limiting, CORS),
  writing tests, CI/CD setup, or debugging errors.
---

<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

> **Note**: All relative paths in this skill are relative to `SKILL_PATH` / `CLAUDE_SKILL_DIR` (the directory containing this SKILL.md file). Use `${SKILL_PATH:-$CLAUDE_SKILL_DIR}` in Bash commands for cross-runtime compatibility.

# Threat Modeling Skill v3.2.0 (20260512a)

AI-native automated software risk analysis skill. LLM-driven, Code-First approach for comprehensive security risk assessment, threat modeling, security testing, penetration testing, and compliance checking.

## Version Banner

```
━━━ 🛡️ Threat Modeling Skill v3.2.0 (20260512a) ━━━
```

## Command Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--debug` | Publish internal YAML data files, KB queries, coverage validation, and evaluation report | OFF |
| `--lang=xx` | Set output language (en, zh, ja, ko, es, fr, de, pt, ru) | Auto-detect |
| `--detailed` | Auto-trigger P8R (detailed per-VR analysis reports) after P8 completes | OFF |

**Usage Examples**:
```bash
# Default mode - 11 deliverable files only
/threat-model @my-project

# Debug mode - all internal files published
/threat-model @my-project --debug

# Chinese output with debug
/threat-model @my-project --lang=zh --debug

# Generate detailed per-VR analysis reports after P8
/threat-model @my-project --detailed

# Full options
/threat-model @my-project --detailed --debug --lang=zh
```

---

## ⚠️ CRITICAL: Data vs Report Separation

> **PRINCIPLE**: Markdown is for reports (human-readable), YAML is for data (machine-readable). They MUST be separated!

```
┌─────────────────────────────────────────────────────────────────────┐
│  DUAL OUTPUT MODEL - Each phase produces TWO files:                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. DATA FILE (.yaml) - PRIMARY                                     │
│     • Written FIRST                                                  │
│     • Structured, machine-readable                                   │
│     • Used by NEXT phase as input                                    │
│     • Path: .phase_working/{SESSION_ID}/data/P{N}_*.yaml            │
│                                                                      │
│  2. REPORT FILE (.md) - SECONDARY                                   │
│     • Written AFTER data file                                        │
│     • Human-readable, formatted                                      │
│     • For review and documentation                                   │
│     • Path: .phase_working/{SESSION_ID}/reports/P{N}-*.md           │
│                                                                      │
│  ❌ FORBIDDEN: Reading .md files for data extraction                │
│  ❌ FORBIDDEN: Embedding data as yaml blocks inside .md AS SOURCE   │
│  ✅ ALLOWED: YAML blocks in .md for schema documentation/examples   │
│  ✅ REQUIRED: Data flows via .yaml files only                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## §1 Execution Model

**Mode**: Full Assessment Only - All 8 phases executed sequentially.

```
Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► Phase 6 ──► Phase 7 ──► Phase 8
   │            │            │            │            │            │            │
   ▼            ▼            ▼            ▼            ▼            ▼            ▼
P1.yaml ──► P2.yaml ──► P3.yaml ──► P4.yaml ──► P5.yaml ──► P6.yaml ──► P7.yaml ──► P8.yaml
```

**Rules**:
1. Phases execute strictly in order (1→8)
2. Each phase reads previous phase's YAML, writes its own YAML
3. Each phase also writes a human-readable .md report
4. Validation runs on YAML files, not .md files
5. Phase 6 = Risk Validation (NOT mitigation)
6. Phase 7 = Mitigation Planning (AFTER validation)

**Phase Gate Protocol**:
```
FOR each phase N in [1..8]:
    1. Read: @phases/P{N}-*.md (instructions)
    2. Read: .phase_working/{SESSION_ID}/data/P{N-1}_*.yaml (input, except P1)
    3. Execute analysis per phase instructions
    4. Write: .phase_working/{SESSION_ID}/data/P{N}_*.yaml (PRIMARY output)
    5. Write: .phase_working/{SESSION_ID}/reports/P{N}-*.md (SECONDARY output)
    6. Validate: python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --phase-end --phase N --root .
    7. IF exit != 0: Fix YAML and rewrite, re-run --phase-end
    8. IF exit == 0: Update session meta, continue to N+1
```

---

## §2 Output Convention

### Output Modes

```
┌─────────────────────────────────────────────────────────────────────┐
│  OUTPUT MODES - Control what files are generated                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DEFAULT MODE (Production)                                          │
│  ─────────────────────────────────────────────────────────────────  │
│  Only user-deliverable files are published:                         │
│  ✅ 4 Required Reports (RISK-ASSESSMENT, INVENTORY, MITIGATION,    │
│                         PENETRATION-TEST-PLAN)                      │
│  ✅ 7 Phase Reports (P1-P7-*.md) for audit trail                    │
│  ❌ .phase_working/ - NOT published (kept internally)               │
│  ❌ YAML data files - NOT published                                 │
│  ❌ EVALUATION-REPORT.md - NOT published                            │
│                                                                      │
│  DEBUG MODE (--debug flag)                                          │
│  ─────────────────────────────────────────────────────────────────  │
│  All files are published including internal data:                   │
│  ✅ All default mode outputs                                        │
│  ✅ .phase_working/{SESSION_ID}/data/*.yaml - Published             │
│  ✅ P5_knowledge_base_queries.yaml - Published                      │
│  ✅ P8_coverage_validation.yaml - Published                         │
│  ✅ EVALUATION-REPORT.md - Published                                │
│                                                                      │
│  Usage: /threat-model @project --debug                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Directory Structure

**Default Mode** (11 files published):
```
{PROJECT_ROOT}/
└── Risk_Assessment_Report/
    ├── {PROJECT}-RISK-ASSESSMENT-REPORT.md    ← Required (P8)
    ├── {PROJECT}-RISK-INVENTORY.md            ← Required (P6)
    ├── {PROJECT}-MITIGATION-MEASURES.md       ← Required (P7)
    ├── {PROJECT}-PENETRATION-TEST-PLAN.md     ← Required (P6)
    ├── P1-PROJECT-UNDERSTANDING.md            ← Phase reports
    ├── P2-DFD-ANALYSIS.md
    ├── P3-TRUST-BOUNDARY.md
    ├── P4-SECURITY-DESIGN-REVIEW.md
    ├── P5-STRIDE-THREATS.md
    ├── P6-RISK-VALIDATION.md
    ├── P7-MITIGATION-PLAN.md
    ├── detailed/                              ← P8R only (--detailed flag)
    │   ├── VR-001-{title-slug}.md
    │   └── ...
    └── html/                                  ← HTML output (report_generator.py)
        ├── index.html
        ├── {PROJECT}-RISK-ASSESSMENT-REPORT.html
        ├── ...
        └── detailed/
            └── VR-001-{slug}.html
```

**Debug Mode** (--debug, full structure):
```
{PROJECT_ROOT}/
└── Risk_Assessment_Report/
    ├── {PROJECT}-RISK-ASSESSMENT-REPORT.md    ← Main report (from P8)
    ├── {PROJECT}-RISK-INVENTORY.md            ← From P6 YAML
    ├── {PROJECT}-MITIGATION-MEASURES.md       ← From P7 YAML
    ├── {PROJECT}-PENETRATION-TEST-PLAN.md     ← From P6 YAML
    ├── {PROJECT}-ARCHITECTURE-ANALYSIS.md     ← From P1-P3 YAML
    ├── {PROJECT}-DFD-DIAGRAM.md               ← From P2 YAML
    ├── {PROJECT}-COMPLIANCE-REPORT.md         ← From P4+P7 YAML
    ├── {PROJECT}-ATTACK-PATH-VALIDATION.md    ← From P6 YAML
    ├── P1-PROJECT-UNDERSTANDING.md            ← Published phase reports
    ├── P2-DFD-ANALYSIS.md
    ├── P3-TRUST-BOUNDARY.md
    ├── P4-SECURITY-DESIGN-REVIEW.md
    ├── P5-STRIDE-THREATS.md
    ├── P6-RISK-VALIDATION.md
    ├── EVALUATION-REPORT.md                   ← DEBUG ONLY
    └── .phase_working/                        ← DEBUG ONLY
        ├── _sessions_index.yaml               ← Multi-session index (optional)
        └── {SESSION_ID}/                      ← Session isolated directory
            ├── _session_meta.yaml             ← Session state
            ├── data/                          ← STRUCTURED DATA
            │   ├── P1_project_context.yaml
            │   ├── P2_dfd_elements.yaml
            │   ├── P3_boundary_context.yaml
            │   ├── P4_security_gaps.yaml
            │   ├── P5_threat_inventory.yaml
            │   ├── P5_knowledge_base_queries.yaml  ← KB transparency
            │   ├── P6_validated_risks.yaml
            │   ├── P7_mitigation_plan.yaml
            │   ├── P8_report_manifest.yaml
            │   └── P8_coverage_validation.yaml     ← Coverage metrics
            ├── reports/                       ← WORKING REPORTS
            │   └── (phase reports during execution)
            └── data/P8R_manifest.yaml         ← P8R manifest (--detailed only)
```

### Naming Convention

- **PROJECT**: Uppercase, max 30 chars, format: `^[A-Z][A-Z0-9-]{0,29}$`
- **Example**: `OPEN-WEBUI`, `MY-PROJECT`, `STRIDE-DEMO`

### Session ID Format

- **SESSION_ID**: `{PROJECT_NAME}_{YYYYMMDD_HHMMSS}`
- **Example**: `OPEN-WEBUI_20260130_143022`

### Session Metadata

```yaml
# .phase_working/{SESSION_ID}/_session_meta.yaml
schema_version: "3.2.0 (20260512a)"
session_id: "OPEN-WEBUI_20260130_143022"  # {PROJECT}_{YYYYMMDD_HHMMSS}
project_name: "OPEN-WEBUI"
project_path: "/path/to/project"
started_at: "ISO8601 timestamp"
language: "en"
skill_version: "3.2.0 (20260512a)"

phases:
  P1:
    status: "completed"
    started_at: "2026-01-30T10:00:00Z"
    completed_at: "2026-01-30T10:30:00Z"
    data_file: "data/P1_project_context.yaml"
    report_file: "reports/P1-PROJECT-UNDERSTANDING.md"
  P2:
    status: "in_progress"
    # ...
```

---

## §3 Core Data Model

> See @assets/contracts/data-model.yaml for complete schema definitions.

### Entity Types

| Entity | ID Format | Phase | Description |
|--------|-----------|-------|-------------|
| Module | M-{Seq:03d} | P1 | Code modules/components |
| Finding | F-P{N}-{Seq:03d} | P1-P3 | Security observations (factual) |
| Gap | GAP-{Seq:03d} | P4 | Security control deficiencies |
| Threat | T-{STRIDE}-{Element}-{Seq} | P5 | STRIDE threats |
| ValidatedRisk | VR-{Seq:03d} | P6 | Verified risks |
| Mitigation | MIT-{Seq:03d} | P7 | Remediation measures |
| POC | POC-{Seq:03d} | P6 | Proof of concept |
| AttackPath | AP-{Seq:03d} | P6 | Attack vectors (single path) |
| AttackChain | AC-{Seq:03d} | P6 | Multi-step attack sequences |
| TestCase | TC-{Seq:03d} | P8 | Penetration test cases |
| DetailedRiskRpt | (uses VR-{Seq:03d}) | P8R | Per-VR analysis report |

### Finding vs Gap Semantic Boundary

- **Finding (F-P{N}-xxx)**: A factual **observation** from phases 1-3 that MAY have security implications. Findings are objective facts about architecture, data flows, or boundaries. Example: "API endpoint uses HTTP instead of HTTPS"

- **Gap (GAP-xxx)**: A **security control deficiency** identified in P4 after analyzing findings against security domains. Gaps represent missing or inadequate controls. Example: "Missing TLS enforcement (NETWORK domain)"

**Transition Rule**: Findings from P1-P3 feed into P4 analysis. P4 evaluates findings against 16 security domains and produces Gaps where controls are deficient.

### DFD Element IDs

| Element Type | Prefix | Format | Example |
|--------------|--------|--------|---------|
| External Interactor | EI | EI-{NNN} | EI-001 |
| Process | P | P-{NNN} | P-001 |
| Data Store | DS | DS-{NNN} | DS-001 |
| Data Flow | DF | DF-{NNN} | DF-001 |
| Trust Boundary | TB | TB-{NNN} | TB-001 |

### Count Conservation (P5→P6 Threat Accounting)

```
P5.threat_count = P6.verified + P6.theoretical + P6.pending + P6.excluded
```

All threats from P5 must be accounted for in P6 (no threat loss).

**Semantic Distinction**:
- **Count Conservation**: P5→P6 threat accounting (threats flow from P5 to P6 dispositions)
- **Element Coverage Verification**: P2→P5 element coverage (every DFD element has STRIDE analysis)

---

## §4 Security Knowledge Architecture

> See @knowledge/ for complete reference materials (~11 MB, 113 files).

### Three Knowledge Sets

1. **Security Control Set** (What to do)
   - 16 Security Domains (AUTHN, AUTHZ, INPUT, etc.)
   - Control Sets (18 files, 107 controls)
   - OWASP References (74 items)
   - Compliance Frameworks (14 frameworks)

2. **Threat Pattern Set** (What to know)
   - CWE Weaknesses (974)
   - CAPEC Attack Patterns (615)
   - ATT&CK Techniques (835)
   - CVE/KEV Vulnerabilities (323K+)

3. **Verification Set** (How to test)
   - WSTG Tests (121)
   - MASTG Tests (206)
   - ASVS Requirements (345)

### Security Principles (11)

| Code | Principle | Definition |
|------|-----------|------------|
| DID | Defense in Depth | Multiple independent security controls |
| LP | Least Privilege | Minimum permissions required |
| ZT | Zero Trust | Never trust, always verify |
| FS | Fail Secure | Default to secure state on error |
| SOD | Separation of Duties | Critical ops require multiple parties |
| SBD | Secure by Default | Default config is secure |
| CM | Complete Mediation | Every access verified |
| EOM | Economy of Mechanism | Simple, auditable mechanisms |
| OD | Open Design | Security not dependent on secrecy |
| IV | Input Validation | All input validated |
| LA | Least Agency | Limit AI agent autonomy |

### STRIDE Categories

| STRIDE | Name | CWEs | CAPEC |
|--------|------|------|-------|
| S | Spoofing | CWE-287, 290, 307 | CAPEC-151, 194, 600 |
| T | Tampering | CWE-20, 77, 78, 89 | CAPEC-66, 88, 248 |
| R | Repudiation | CWE-117, 223, 778 | CAPEC-93 |
| I | Information Disclosure | CWE-200, 209, 311 | CAPEC-116, 157 |
| D | Denial of Service | CWE-400, 770, 918 | CAPEC-125, 227 |
| E | Elevation of Privilege | CWE-269, 284, 862 | CAPEC-122, 233 |

---

## §5 Knowledge Base Queries

### kb Wrapper Usage

```bash
# Resolve skill path (works in Claude Code, Codex CLI, and manual testing)
SKILL_PATH=${SKILL_PATH:-${CLAUDE_SKILL_DIR:-$(bash skill_path.sh)}}

# STRIDE queries
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --stride spoofing
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --stride-controls S

# CWE queries
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --cwe CWE-89
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --full-chain CWE-89

# Attack patterns
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --capec CAPEC-89
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --attack-technique T1078

# Verification tests
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --stride-tests S
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --wstg-category ATHN

# LLM/AI extensions
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --all-llm
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --ai-component
```

---

## §6 Language Adaptation

Output language follows context language unless `--lang=xx` specified.

| Context | File Names | Content |
|---------|------------|---------|
| Chinese | P1-项目理解.md | 中文 |
| English | P1-PROJECT-UNDERSTANDING.md | English |

Supported: en, zh, ja, ko, es, fr, de, pt, ru

---

## §7 Progressive Context Loading

This skill uses progressive disclosure:

1. **Always Loaded**: This file (SKILL.md) - ~5.5K tokens
2. **Session Start**: @WORKFLOW.md - ~4.8K tokens
3. **Per Phase**: @phases/P{N}-*.md - ~4K-10K tokens each (varies by phase)

Total per-phase context: ~12K-18K tokens per phase (vs 30K monolithic)

**Loading Pattern**:
```
Session Start:
  1. Load SKILL.md (global rules)
  2. Load WORKFLOW.md (orchestration)
  3. Create 8 phase todos

Per Phase:
  1. Read @phases/P{N}-*.md
  2. Execute phase instructions
  3. Write to .phase_working/{SESSION_ID}/reports/P{N}-*.md
  4. Run: python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --phase-end --phase N --root .

Post-P8 (Optional):
  1. If --detailed flag OR user confirms: Load @phases/P8R-DETAILED-REPORT.md
  2. Generate per-VR detailed analysis reports
  3. Write to Risk_Assessment_Report/detailed/VR-{NNN}-{slug}.md
```

---

## §8 Reference Files

| Path | Purpose |
|------|---------|
| @WORKFLOW.md | Orchestration contracts, phase gates |
| @phases/P{1-8}-*.md | Phase-specific instructions |
| @assets/contracts/data-model.yaml | Entity schemas |
| @knowledge/security-design.yaml | 16 security domains |
| @knowledge/security-principles.yaml | 11 security principles |
| @knowledge/sast-rules.yaml | SAST tool configs and STRIDE mappings |
| @scripts/module_discovery.py | P1 three-layer module discovery |
| @scripts/phase_data.py | Phase validation and extraction |
| @scripts/unified_kb_query.py | Knowledge base queries |
| @scripts/report_generator.py | MD→HTML batch converter |
| @phases/P8R-DETAILED-REPORT.md | Optional per-VR detailed reports |
| @docs/REPORT-DESIGN.md | v3.0.3+ report enhancement design |
| @skill_path.sh | SKILL_PATH resolution helper |

---

## §9 Quick Start

```bash
# 1. Start new session (default mode - 11 deliverable files)
/threat-model @my-project

# 2. With debug mode (all internal files published)
/threat-model @my-project --debug

# 3. Session execution:
#    - Claude loads SKILL.md + WORKFLOW.md automatically
#    - For each phase N (1-8): Read → Execute → Write → Validate
#    - Generate final reports in Risk_Assessment_Report/
```

### Output Summary

| Mode | Files Published | Use Case |
|------|-----------------|----------|
| Default | 11 (4 required + 7 phase reports) | Production delivery |
| `--detailed` | 11 + per-VR detailed reports | Comprehensive assessment |
| `--debug` | 11 + YAML data + evaluation | Development, audit |

---

## §10 Core Execution Constraints (Invariants)

> **PRINCIPLE**: The quality of threat modeling depends on execution rigor. The following constraints are INVIOLABLE.

### Three Absolute Prohibitions

| Constraint | Description | Violation Consequence |
|------------|-------------|----------------------|
| ❌ NO MOCK DATA | All analysis must be based on real code evidence | Analysis results invalid |
| ❌ NO SIMPLIFIED IMPLEMENTATIONS | Each phase must be fully executed | Coverage requirements not met |
| ❌ NO BYPASSING PROBLEMS | Must diagnose root cause when blocked | Data chain broken |

### Phase Execution Invariant

```
∀ Phase N ∈ [1..8]:
  - Input: P{N-1}_*.yaml (except P1)
  - Output: P{N}_*.yaml (PRIMARY) + P{N}-*.md (SECONDARY)
  - Gate: phase_data.py --phase-end must return exit 0
  - Transition: Only proceed to N+1 after gate passes
```

> **Execution Protocol Details**: See WORKFLOW.md §2 Phase Execution Protocol

---

## §11 Phase Isolation Constraints

> **INVARIANT**: Each Phase is an independent execution unit. FSM state transitions MUST follow strict sequential order.

### Forbidden State Transitions

| Illegal Transition | Reason |
|-------------------|--------|
| Pn → Pn+2 (skip) | Violates FSM order invariant (S1) |
| Pn → Pn+1 (unvalidated) | Violates data contract completeness (S2) |
| Parallel Phase execution | Data dependencies cannot be satisfied |

> **Complete FSM Specification**: See WORKFLOW.md §1
> **Formal Properties**: See docs/SKILL-ARCHITECTURE-DESIGN.md §0.2

---

**End of SKILL.md** (~540 lines, ~5.5K tokens)
