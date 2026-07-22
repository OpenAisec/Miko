<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Phase 5: STRIDE Threat Analysis

**Type**: Enumerative
**Executor**: LLM
**Knowledge**: CWE → CAPEC (Threat Pattern Set)

---

## ⚠️ 4-Phase Gating Protocol — THINKING → PLANNING → EXECUTION → REFLECTION (output each stage)

> **⚠️ CHECKPOINT**: P5 — Request user confirmation after threat enumeration.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🧠 THINKING - Phase 5 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Purpose**: Systematically apply STRIDE method to all DFD elements, ensuring no element is missed.

**⚠️ You MUST output THINKING results in the following format:**

```
🧠 THINKING - P5 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 CORE PROBLEM
Apply STRIDE analysis to every DFD element, generate complete threat inventory

📊 UPSTREAM DATA (Read from P2/P3/P4 YAML)
| Metric | Value | Source |
|--------|-------|--------|
| P2 Process Count | {actual_value} | P2_dfd_elements.yaml → dfd_elements.processes length |
| P2 Data Store Count | {actual_value} | P2_dfd_elements.yaml → dfd_elements.data_stores length |
| P2 Data Flow Count | {actual_value} | P2_dfd_elements.yaml → dfd_elements.data_flows length |
| P2 External Interactor Count | {actual_value} | P2_dfd_elements.yaml → dfd_elements.external_interactors length |
| P3 Boundary Count | {actual_value} | P3_boundary_context.yaml → boundary_context.boundaries length |
| P4 Gap Count | {actual_value} | P4_security_gaps.yaml → security_gaps.summary.total_gaps |

❓ UNKNOWNS
- Specific threat scenarios for each element
- Precise CWE/CAPEC mapping
- Severity amplification for cross-boundary threats

⚠️ RISKS
- Element coverage < 100%
- STRIDE completeness < 80% (some elements missing required STRIDE categories)
- KB enrichment coverage too low
- P0/P1 threats missing CWE mapping

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⛔ STOP CHECK
- P2 YAML read? [YES/NO]
- P3 YAML read? [YES/NO]
- P4 YAML read? [YES/NO]
- Upstream data complete (DFD element count/boundary count/Gap count all have values)? [YES/NO]
- Ready to continue PLANNING? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ **STOP CONDITION**: If any STOP CHECK = NO → Read upstream data first before continuing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 📋 PLANNING - Sub-task Decomposition
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Step 1: Read Upstream Data** (BLOCKING - MUST execute)
```bash
# Read P2/P3/P4 YAML data
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 2 --type dfd --root .
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 3 --summary --root .
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 4 --type gaps --root .

# Or read directly
cat .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
cat .phase_working/{SESSION_ID}/data/P3_boundary_context.yaml
cat .phase_working/{SESSION_ID}/data/P4_security_gaps.yaml
```
⛔ If any upstream YAML does not exist or is invalid → STOP and return to complete upstream Phase

**Step 2: Output Sub-task Table** (MANDATORY)

**⚠️ You MUST output PLANNING results in the following format:**

```
📋 PLANNING - P5 Sub-tasks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| # | Sub-task | Expected Output |
|---|----------|-----------------|
| T1 | Read P2/P3/P4 data, extract DFD elements and Gap inventory | Data structures |
| T2 | Apply STRIDE to all Processes (S,T,R,I,D,E) | Process threats |
| T3 | Apply STRIDE to all DataStores (T,R,I,D) | Store threats |
| T4 | Apply STRIDE to all DataFlows (T,I,D) | Flow threats |
| T5 | Apply STRIDE to all ExternalInteractors (S,R) | Interactor threats |
| T6 | KB enrichment - CWE/CAPEC/ATT&CK mapping | Threat enrichment |
| T7 | Write final output | P5_threat_inventory.yaml + MD |

⛔ PLANNING CHECK
- Sub-tasks decomposed? [YES/NO]
- Ready to TaskCreate? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Step 3**: ⚠️ `TaskCreate` ALL sub-tasks before implementation (MANDATORY).

**Step 4: Multi-Perspective Parallel Analysis** (RECOMMENDED)

Launch 4 `‖` sub-agents via `Task` tool (`subagent_type: "general-purpose"`, `model: "opus"`). Each applies STRIDE to ALL DFD elements from its unique angle. Each receives P2-P4 data + its perspective prompt:

**‖ Architecture Perspective**: "Apply STRIDE to all DFD elements from an architecture viewpoint. Focus: threats from architectural design decisions, component interaction patterns, trust boundary violations, defense-in-depth gaps, systemic/structural weaknesses."

**‖ Code Implementation Perspective**: "Apply STRIDE to all DFD elements from a code implementation viewpoint. Focus: threats from coding practices, implementation flaws, injection points, buffer handling, CWE mapping, insecure API usage, hardcoded credentials."

**‖ Security Testing Perspective**: "Apply STRIDE to all DFD elements from a security testing viewpoint. Focus: threats detectable via SAST/DAST/IAST, OWASP Testing Guide (WSTG) coverage, test case design per element, false-positive-resistant threat identification."

**‖ Penetration Testing Perspective**: "Apply STRIDE to all DFD elements from an offensive security viewpoint. Focus: threats exploitable by real attackers, CAPEC/ATT&CK mapping, attack chain construction, exploitation feasibility, real-world impact assessment."

**Merge**: Union of all T-{STRIDE}-{Element}-{Seq} → deduplicate by element+category → keep highest severity → union of unique CWE/CAPEC/ATT&CK mappings.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### ⚡ EXECUTION — TaskUpdate(in_progress) → Execute → Verify → TaskUpdate(completed) | Fail → Retry 3x → CHECKPOINT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Output Sequence** (CRITICAL):
1. **Write YAML first**: `.phase_working/{SESSION_ID}/data/P5_threat_inventory.yaml`
2. **Write MD after**: `.phase_working/{SESSION_ID}/reports/P5-STRIDE-THREATS.md`

**Key KB Queries**:
```bash
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --stride spoofing           # STRIDE category details
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --full-chain CWE-89         # Full chain: STRIDE→CWE→CAPEC→ATT&CK
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --cwe CWE-287               # Specific CWE details
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🔍 REFLECTION - Completion Verification
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**⚠️ After completing EXECUTION, you MUST output REFLECTION results in the following format:**

```
🔍 REFLECTION - P5 Completion Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| Check Item | Status |
|------------|--------|
| P2/P3/P4 YAML data read and understood? | [✅/❌] |
| P5_threat_inventory.yaml exists and valid? | [✅/❌] |
| element_coverage_verification exists? | [✅/❌] |
| processes.coverage_percentage == 100%? | [✅/❌] |
| data_stores.coverage_percentage == 100%? | [✅/❌] |
| data_flows.coverage_percentage == 100%? | [✅/❌] |
| external_interactors.coverage_percentage == 100%? | [✅/❌] |
| stride_completeness >= 0.80? | [✅/❌] |
| kb_enrichment_log exists? | [✅/❌] |
| All P0/P1 threats have CWE mapping? | [✅/❌] |
| summary.total matches threats[] length? | [✅/❌] |
| `--phase-end` validation passed (exit 0)? | [✅/❌] |

⛔ COMPLETION GATE
- All checks passed? [YES/NO]
- Ready to proceed to P6? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ Any check fails → Fix and re-verify until all pass

---

### ⚠️ Dual Output (YAML first → MD second)

1. **YAML** (PRIMARY): `.phase_working/{SESSION_ID}/data/P5_threat_inventory.yaml`
2. **MD** (SECONDARY): `.phase_working/{SESSION_ID}/reports/P5-STRIDE-THREATS.md`
- **Input**: Read `P2_dfd_elements.yaml` + `P4_security_gaps.yaml` (❌ NOT .md reports)
- ❌ Writing only .md without .yaml | ✅ .yaml is the authoritative data source

### Required Data Sections in YAML

| Section | Validation |
|---------|------------|
| `threat_inventory.threats[]` | BLOCKING - all threats with T-xxx-xxx IDs |
| `threat_inventory.summary` | BLOCKING - by_stride, by_priority counts |

### Validation Gate

Phase 5 CANNOT complete until:
1. `.phase_working/{SESSION_ID}/data/P5_threat_inventory.yaml` exists and is valid YAML
2. Every DFD element has associated threats (per STRIDE matrix)
3. Summary totals match threat list count
4. `.phase_working/{SESSION_ID}/reports/P5-STRIDE-THREATS.md` exists
5. Element coverage verification shows 100% coverage

### Element Coverage Verification (CRITICAL)

**P5 MUST verify complete STRIDE coverage of ALL P2 DFD elements**:

```yaml
# In P5_threat_inventory.yaml - REQUIRED section
element_coverage_verification:
  # P2 Input Reference
  p2_input_ref: "P2_dfd_elements.yaml"

  # Process Coverage (STRIDE: S,T,R,I,D,E)
  processes:
    total_from_p2: 12              # Count from P2.dfd_elements.processes
    elements_with_threats: 12     # Processes that have at least one threat
    coverage_percentage: 100      # MUST be 100%
    uncovered_elements: []        # MUST be empty
    stride_coverage:              # Each process should have S,T,R,I,D,E
      P-001: {S: 2, T: 3, R: 1, I: 2, D: 1, E: 2}  # Count per category
      P-002: {S: 1, T: 2, R: 1, I: 1, D: 1, E: 1}
      # ... all processes

  # Data Store Coverage (STRIDE: T,R,I,D)
  data_stores:
    total_from_p2: 5
    elements_with_threats: 5
    coverage_percentage: 100
    uncovered_elements: []
    stride_coverage:              # Each store should have T,R,I,D
      DS-001: {T: 2, R: 1, I: 3, D: 1}
      # ... all data stores

  # Data Flow Coverage (STRIDE: T,I,D)
  data_flows:
    total_from_p2: 25
    elements_with_threats: 25
    coverage_percentage: 100
    uncovered_elements: []
    stride_coverage:              # Each flow should have T,I,D
      DF-001: {T: 1, I: 2, D: 1}
      # ... all data flows

  # External Interactor Coverage (STRIDE: S,R)
  external_interactors:
    total_from_p2: 3
    elements_with_threats: 3
    coverage_percentage: 100
    uncovered_elements: []
    stride_coverage:              # Each interactor should have S,R
      EI-001: {S: 2, R: 1}
      # ... all external interactors

  # Overall Coverage Summary
  overall:
    total_dfd_elements: 45        # Sum of all element types
    elements_covered: 45          # Elements with at least one threat
    coverage_percentage: 100      # MUST be 100%
    stride_completeness: 0.95     # % of applicable STRIDE categories covered

  # ============================================================
  # GAP-6 FIX: STRIDE Completeness Per-Element Verification
  # Ensures EVERY element has threats for ALL applicable STRIDE categories
  # ============================================================
  stride_completeness_detail:
    # Expected STRIDE categories per element type (from STRIDE per Element matrix)
    expected_categories:
      Process: [S, T, R, I, D, E]       # 6 categories
      DataStore: [T, R, I, D]           # 4 categories
      DataFlow: [T, I, D]               # 3 categories
      ExternalInteractor: [S, R]        # 2 categories

    # Per-element STRIDE completeness validation
    element_stride_completeness:
      # Process completeness (must have all 6: S,T,R,I,D,E)
      processes:
        P-001:
          expected: [S, T, R, I, D, E]
          actual: [S, T, R, I, D, E]
          complete: true
          missing: []
        P-002:
          expected: [S, T, R, I, D, E]
          actual: [S, T, R, I, D]      # Missing E
          complete: false
          missing: [E]
          missing_reason: "Elevation of Privilege considered N/A due to sandboxed process"
        # ... all processes

      # Data store completeness (must have all 4: T,R,I,D)
      data_stores:
        DS-001:
          expected: [T, R, I, D]
          actual: [T, R, I, D]
          complete: true
          missing: []
        # ... all data stores

      # Data flow completeness (must have all 3: T,I,D)
      data_flows:
        DF-001:
          expected: [T, I, D]
          actual: [T, I, D]
          complete: true
          missing: []
        # ... all data flows

      # External interactor completeness (must have all 2: S,R)
      external_interactors:
        EI-001:
          expected: [S, R]
          actual: [S, R]
          complete: true
          missing: []
        # ... all external interactors

    # Summary statistics
    completeness_summary:
      processes:
        total: 12
        fully_complete: 11          # All 6 STRIDE categories present
        partially_complete: 1       # Some categories missing with reason
        stride_completeness: 0.97   # (11×6 + 5) / (12×6) = 0.97
      data_stores:
        total: 5
        fully_complete: 5
        partially_complete: 0
        stride_completeness: 1.0
      data_flows:
        total: 25
        fully_complete: 24
        partially_complete: 1
        stride_completeness: 0.99
      external_interactors:
        total: 3
        fully_complete: 3
        partially_complete: 0
        stride_completeness: 1.0

    # Overall STRIDE completeness (weighted)
    overall_stride_completeness:
      total_expected_categories: 182    # (12×6) + (5×4) + (25×3) + (3×2)
      total_actual_categories: 180      # Actual count
      completeness_percentage: 98.9     # 180/182
      missing_categories_count: 2
      missing_categories_documented: true  # All missing have reasons

    # Missing category documentation (REQUIRED for any missing STRIDE)
    missing_stride_documentation:
      - element_id: P-002
        element_type: Process
        missing_category: E
        reason: "Process runs in isolated sandbox with no privilege escalation path"
        verified_by: "Code review confirmed no setuid, no sudo, no capability changes"
      - element_id: DF-015
        element_type: DataFlow
        missing_category: D
        reason: "Internal async queue with rate limiting - DoS not applicable"
        verified_by: "Rate limiter configured at 1000 req/s with backpressure"
```

**Validation Rules** (GAP-6 Enhanced):
- **Element Coverage**: Every element from P2 MUST have at least one threat (coverage_percentage == 100%)
- **STRIDE Completeness**: Every element SHOULD have threats for ALL applicable STRIDE categories
- **Missing Category Documentation**: Any missing STRIDE category MUST have documented reason and verification

**BLOCKING**:
- `coverage_percentage < 100%` for any element type
- `missing_categories_documented == false` (missing STRIDE without explanation)

**WARNING** (threshold = 0.80, recommended = 0.95):
- `stride_completeness < 0.80` - Below minimum acceptable STRIDE coverage
- `stride_completeness < 0.95` - Below recommended full STRIDE coverage
- `missing_categories_count > 5` - Too many missing categories may indicate incomplete analysis

---

## Error Handling

| Error | Cause | Recovery Action |
|-------|-------|-----------------|
| P2 YAML not found | P2 not completed | Return to P2, complete DFD analysis |
| P4 YAML not found | P4 not completed | Return to P4, complete security design review |
| DFD element missing threats | Incomplete analysis | Apply STRIDE matrix, generate minimum threats |
| CWE/CAPEC lookup failure | KB not available | Document without mapping, note limitation |
| Summary count mismatch | Calculation error | Recount threats[], update summary |

**Fallback Strategy**: If KB lookup fails, generate threats with manual CWE assignment based on STRIDE category. Mark `kb_lookup: failed` in threat metadata.

---

## Input Context

← P2: `dfd_elements` from `.phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml`
← P3: `boundary_context` from `.phase_working/{SESSION_ID}/data/P3_boundary_context.yaml`
← P4: `security_gaps` from `.phase_working/{SESSION_ID}/data/P4_security_gaps.yaml`

### ⚠️ MANDATORY: Query P2/P3/P4 Data Before Analysis

**Before starting P5 STRIDE analysis**, LLM MUST execute these queries to obtain upstream data:

```bash
# Step 1: Get P2 DFD elements (PRIMARY - REQUIRED for STRIDE)
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 2 --type dfd --root .

# Step 2: Get P3 boundaries for severity amplification
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 3 --summary --root .

# Step 3: Get P4 security gaps as threat triggers
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 4 --type gaps --root .
```

**Or read YAML directly**:
```bash
# PRIMARY sources - ALL REQUIRED
cat .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
cat .phase_working/{SESSION_ID}/data/P3_boundary_context.yaml
cat .phase_working/{SESSION_ID}/data/P4_security_gaps.yaml
```

**CRITICAL**: STRIDE analysis MUST cover ALL P2 DFD elements. Do NOT skip elements or generate threats from memory!

**P3 Boundary Integration**:
- Consider trust boundary crossings when assessing threat severity
- Cross-boundary threats inherit higher initial_priority
- Use `boundaries[]` to identify attack surface exposure

## Output Context

→ P6: `threat_inventory` {threats[], summary{}}

---

## Core Analysis Goal

Apply STRIDE method systematically to ALL DFD elements, generating a complete threat inventory. Each element must be analyzed for applicable STRIDE categories.

---

## Knowledge Reference

**Query Commands**:
```bash
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --stride spoofing           # STRIDE category details
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --stride tampering
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --full-chain CWE-89         # Complete chain: STRIDE→CWE→CAPEC→ATT&CK
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --all-llm                   # LLM-specific threats
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --cwe CWE-287               # Specific CWE details
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --full-chain CWE-287        # Full chain: STRIDE→CWE→CAPEC→ATT&CK
```

### KB Enrichment Log (MANDATORY per GAP-4 Contract)

> **CRITICAL**: P5 MUST query KB for CWE/CAPEC/ATT&CK mapping per KBQueryContract in assets/contracts/data-model.yaml

**Required Queries**:
1. `--cwe CWE-{NNN}` - For each threat's CWE classification
2. `--full-chain CWE-{NNN}` - For full chain: STRIDE→CWE→CAPEC→ATT&CK mapping
3. `--stride-controls {S|T|R|I|D|E}` - For category-wide enrichment

```yaml
# In P5_threat_inventory.yaml - MANDATORY section (GAP-4 Contract)
kb_enrichment_log:
  # Query record for auditability
  queries_made:
    - query: "--stride-controls S"
      timestamp: "2026-01-31T10:15:30Z"
      result_count: 25
      usage: "Informed spoofing threats T-S-*"
      cache_hit: false
    - query: "--cwe CWE-287"
      timestamp: "2026-01-31T10:15:45Z"
      result_count: 1
      usage: "Enriched T-S-P-001-001"
      cache_hit: true
    - query: "--full-chain CWE-287"
      timestamp: "2026-01-31T10:16:00Z"
      result_count: 3
      usage: "Mapped CAPEC-114, CAPEC-151, CAPEC-194"
      cache_hit: false

  # Enrichment tracking
  cwes_queried: [CWE-287, CWE-89, CWE-79, CWE-798, CWE-312]  # All unique CWEs
  capecs_mapped: [CAPEC-114, CAPEC-151, CAPEC-66, CAPEC-7]   # All CAPEC mappings
  attack_techniques: [T1078, T1190, T1059]                    # ATT&CK mappings

  # Coverage metrics (MANDATORY)
  enrichment_coverage:
    total_threats: 85
    threats_with_cwe: 78
    threats_with_capec: 65
    threats_with_attack: 45
    p0_p1_threats_total: 15
    p0_p1_with_cwe: 15          # MUST be 100% - ERROR if not
    coverage_percentage: 91.8    # threats_with_cwe / total_threats

  # Error tracking
  errors:
    - query: "--cwe CWE-9999"
      error_type: "not_found"
      action_taken: "Manual classification based on STRIDE category"
      affected_threats: [T-T-P-003-002]

  # KB availability status
  kb_available: true
  kb_version: "v4.19"           # CWE database version
```

**Validation Rules** (GAP-4 Contract):
- **ERROR**: Any P0/P1 threat without CWE mapping (`p0_p1_with_cwe < p0_p1_threats_total`)
- **WARNING**: `enrichment_coverage.coverage_percentage < 80%`
- **INFO**: All errors must be documented with `action_taken`

**Fallback Strategy**: If KB unavailable, set `kb_available: false` and use LLM knowledge for threat classification. Document limitation in errors[].

---

## ⚠️ STRIDE per Interaction (PRIMARY METHOD)

> **CRITICAL**: Use STRIDE per Interaction for systematic threat generation on data flows. This follows Microsoft TMT methodology where threats are generated based on **Source → Target** relationships.

### Interaction-Based Threat Generation

STRIDE per Interaction analyzes threats based on **who/what is interacting with whom/what**:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    STRIDE per Interaction Model                           │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│   [Source Element] ──── Data Flow ───► [Target Element]                  │
│         ↓                    ↓                ↓                          │
│   Applicable:           Applicable:     Applicable:                       │
│   S (if external)        T, I, D        Full STRIDE                      │
│   R (if external)                       (based on type)                   │
│                                                                           │
│   Example:                                                                │
│   [User Browser] ─── DF-001 (HTTPS) ───► [API Gateway (P-001)]           │
│        EI-001                                  ↓                          │
│         ↓                            Target gets S,T,R,I,D,E              │
│   Source adds S,R                    Flow adds T,I,D                      │
│                                                                           │
└──────────────────────────────────────────────────────────────────────────┘
```

### Source → Target Threat Matrix

| Source Type | Target Type | Applicable STRIDE | Rationale |
|------------|-------------|-------------------|-----------|
| **ExternalInteractor** | Process | **S**, T, **R**, I, D, E | External actors may spoof identity, repudiate actions |
| ExternalInteractor | DataStore | T, R, I, D | Direct store access rarely allowed |
| **Process** | Process | T, R, I, D, E | Inter-process tampering, privilege escalation |
| Process | DataStore | **T**, R, **I**, **D** | Store integrity, confidentiality, availability |
| **DataStore** | Process | T, I | Data poisoning, information leakage |

### Data Flow Threat Inheritance

When analyzing a data flow, threats are inherited from:

```yaml
# Threat generation rule for DF-xxx
data_flow_threat_analysis:
  flow_id: DF-001
  source: EI-001  # External Interactor (User)
  target: P-001   # Process (API Gateway)
  trust_boundary_crossed: true  # Critical factor

  # Threats on the TARGET (P-001)
  target_threats:
    - S: "Spoofing - Source (EI-001) may spoof identity to Target"
    - T: "Tampering - Data from Source may be modified before reaching Target"
    - R: "Repudiation - Source (EI-001) may deny sending data"
    - I: "Information Disclosure - Target may leak sensitive data to unauthorized parties"
    - D: "Denial of Service - Target may be overwhelmed by Source requests"
    - E: "Elevation of Privilege - Attacker may gain higher privileges in Target"

  # Threats on the DATA FLOW itself (DF-001)
  flow_threats:
    - T: "Tampering - Data in transit may be modified"
    - I: "Information Disclosure - Data in transit may be intercepted"
    - D: "Denial of Service - Communication channel may be disrupted"

  # Threats from SOURCE perspective (EI-001)
  source_threats:
    - S: "Spoofing - External actor identity cannot be verified"
    - R: "Repudiation - External actor may deny actions"
```

### Trust Boundary Amplification

Threats crossing trust boundaries have elevated severity:

| Boundary Type | Severity Multiplier | Example |
|--------------|---------------------|---------|
| Internet ↔ DMZ | ×2.0 | Public API endpoint |
| DMZ ↔ Internal | ×1.5 | Internal service boundary |
| Internal ↔ Database | ×1.8 | Data tier access |
| Same Trust Zone | ×1.0 | No boundary crossing |

```yaml
# Example: Cross-boundary threat
threat_with_boundary:
  id: T-S-P-001-001
  element_id: P-001
  interaction:
    source: EI-001
    target: P-001
    flow: DF-001
    boundary_crossed: TB-001  # Internet → DMZ
  base_priority: P1
  boundary_multiplier: 2.0
  effective_priority: P0  # Elevated due to boundary
```

### Interaction Coverage Verification (REQUIRED)

**P5 MUST verify all interactions have STRIDE analysis**:

```yaml
# In P5_threat_inventory.yaml - REQUIRED section
interaction_coverage:
  # P2 Flow Input Reference
  p2_flow_ref: "P2_dfd_elements.yaml"

  # Total interactions analyzed
  total_interactions: 45           # Count of Source→Target pairs
  interactions_with_threats: 45    # All should have threats
  coverage_percentage: 100         # MUST be 100%

  # By boundary crossing
  cross_boundary_interactions:
    total: 12
    analyzed: 12
    coverage_percentage: 100       # BLOCKING if < 100%

  # Interaction detail
  interactions:
    - flow_id: DF-001
      source: EI-001
      target: P-001
      boundary_crossed: TB-001
      threats_generated: [T-S-P-001-001, T-T-DF-001-001, T-R-EI-001-001]
      stride_coverage: {S: 1, T: 1, R: 1, I: 0, D: 0, E: 0}
    - flow_id: DF-002
      source: P-001
      target: DS-001
      boundary_crossed: null
      threats_generated: [T-T-DS-001-001, T-I-DS-001-001]
      stride_coverage: {T: 1, I: 1, D: 0}
```

**Validation Rules**:
- **BLOCKING**: `coverage_percentage < 100%` (all interactions must be analyzed)
- **BLOCKING**: `cross_boundary_interactions.coverage_percentage < 100%` (boundary crossings are critical)
- **WARNING**: Any interaction with incomplete STRIDE coverage for its type

---

## STRIDE per Element Matrix (SECONDARY)

| Element Type | S | T | R | I | D | E |
|--------------|---|---|---|---|---|---|
| Process      | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Data Store   |   | ✓ | ✓ | ✓ | ✓ |   |
| Data Flow    |   | ✓ |   | ✓ | ✓ |   |
| External Interactor (as source) | ✓ |   | ✓ |   |   |   |

### AI/LLM STRIDE Extensions

> When P4 triggers ext-13 (AI) or ext-16 (AGENT), apply these additional threat patterns.

| AI Element Type | S | T | R | I | D | E | Special Threats |
|-----------------|---|---|---|---|---|---|-----------------|
| LLM Gateway     | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Prompt injection, jailbreak |
| Model Endpoint  | ✓ | ✓ |   | ✓ | ✓ | ✓ | Model poisoning, adversarial input |
| RAG Pipeline    |   | ✓ |   | ✓ | ✓ |   | Context injection, data leakage |
| Agent Tool      | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Tool abuse, goal hijacking |

**AI-Specific CWE/CAPEC**:
- CWE-1039: Automatic Eval of Untrusted Data → CAPEC-676 (LLM Prompt Injection)
- CWE-1336: Object Injection → CAPEC-175 (Context Injection)
- CWE-20: Input Validation → CAPEC-242 (Adversarial Input)

---

## STRIDE Categories

### S - Spoofing

**Definition**: Impersonating something or someone

**CWE Mapping**: CWE-287, CWE-290, CWE-307
**CAPEC Mapping**: CAPEC-151, CAPEC-194, CAPEC-600

**Questions**:
- Can an attacker impersonate another user?
- Can an attacker impersonate a system component?
- Is authentication properly implemented?

### T - Tampering

**Definition**: Modifying data or code

**CWE Mapping**: CWE-20, CWE-77, CWE-78, CWE-89
**CAPEC Mapping**: CAPEC-66, CAPEC-88, CAPEC-248

**Questions**:
- Can input data be modified?
- Can stored data be modified?
- Can data in transit be modified?

### R - Repudiation

**Definition**: Denying having performed an action

**CWE Mapping**: CWE-117, CWE-223, CWE-778
**CAPEC Mapping**: CAPEC-93

**Questions**:
- Are actions logged?
- Can logs be modified or deleted?
- Is there sufficient audit trail?

### I - Information Disclosure

**Definition**: Exposing information to unauthorized parties

**CWE Mapping**: CWE-200, CWE-209, CWE-311
**CAPEC Mapping**: CAPEC-116, CAPEC-157

**Questions**:
- Can sensitive data be accessed?
- Are error messages revealing?
- Is data encrypted properly?

### D - Denial of Service

**Definition**: Making a resource unavailable

**CWE Mapping**: CWE-400, CWE-770, CWE-918
**CAPEC Mapping**: CAPEC-125, CAPEC-227

**Questions**:
- Can the service be overwhelmed?
- Are there resource limits?
- Can an attacker exhaust resources?

### E - Elevation of Privilege

**Definition**: Gaining unauthorized capabilities

**CWE Mapping**: CWE-269, CWE-284, CWE-862
**CAPEC Mapping**: CAPEC-122, CAPEC-233

**Questions**:
- Can a user gain admin privileges?
- Are authorization checks complete?
- Can an attacker escape sandbox?

---

## Threat ID Format

```
T-{STRIDE}-{ElementID}-{Seq}
```

- **STRIDE**: Single letter (S/T/R/I/D/E)
- **ElementID**: From P2 (e.g., P-001, DS-001, DF-001)
- **Seq**: Three-digit sequence (001-999)

**Examples**:
- `T-S-P-001-001` - First Spoofing threat for Process 001
- `T-T-DF-003-002` - Second Tampering threat for Data Flow 003
- `T-I-DS-001-001` - First Info Disclosure threat for Data Store 001

---

## Analysis Process

For each DFD element:

1. **Identify applicable STRIDE categories** (per matrix above)
2. **For each applicable category**:
   - Describe the threat scenario
   - Identify related CWE
   - Map to CAPEC if available
   - Assess initial priority

3. **Document in threat inventory**

---

## Threat Inventory Structure

```yaml:threat_inventory
threats:
  - id: T-S-P-001-001
    element_id: P-001
    element_name: "API Gateway"
    stride_type: S
    stride_name: Spoofing
    title: "Authentication Bypass via Token Manipulation"
    description: |
      An attacker could forge or manipulate JWT tokens to impersonate
      legitimate users or bypass authentication entirely.
    attack_scenario: |
      1. Attacker obtains a valid JWT token
      2. Modifies token payload (user_id, role)
      3. Server accepts modified token due to weak verification
    affected_flows: [DF-001, DF-002]
    affected_stores: []
    cwe: CWE-287
    capec: CAPEC-194
    initial_priority: P1
    likelihood: HIGH
    impact: HIGH

  - id: T-T-DS-001-001
    element_id: DS-001
    element_name: "User Database"
    stride_type: T
    stride_name: Tampering
    title: "SQL Injection in User Lookup"
    description: |
      User input in login query may allow SQL injection, enabling
      attackers to modify database contents.
    attack_scenario: |
      1. Attacker enters malicious input in username field
      2. Input concatenated into SQL query
      3. Attacker modifies or extracts database data
    affected_flows: [DF-003]
    affected_stores: [DS-001]
    cwe: CWE-89
    capec: CAPEC-66
    initial_priority: P0
    likelihood: MEDIUM
    impact: CRITICAL

summary:
  total: 85
  by_stride:
    S: 12
    T: 18
    R: 8
    I: 22
    D: 10
    E: 15
  by_element_type:
    process: 45
    datastore: 20
    dataflow: 15
    external: 5
  by_priority:
    P0: 5
    P1: 15
    P2: 35
    P3: 30
```

---

## Priority Classification

| CVSS Score | Priority | Action |
|------------|----------|--------|
| 9.0 - 10.0 | P0 | Immediate fix |
| 7.0 - 8.9 | P1 | Fix within 24h |
| 4.0 - 6.9 | P2 | Fix within 7d |
| 0.1 - 3.9 | P3 | Plan within 30d |

---

## Report Template

```markdown
# P5: STRIDE Threat Analysis

## Threat Summary

| Metric | Count |
|--------|-------|
| Total Threats | N |
| Critical (P0) | N |
| High (P1) | N |
| Medium (P2) | N |
| Low (P3) | N |

## STRIDE Distribution

| Category | Count | Percentage |
|----------|-------|------------|
| Spoofing | N | N% |
| Tampering | N | N% |
| Repudiation | N | N% |
| Information Disclosure | N | N% |
| Denial of Service | N | N% |
| Elevation of Privilege | N | N% |

## Element Coverage

| Element | Type | Threats |
|---------|------|---------|
| P-001 | Process | T-S-P-001-001, T-T-P-001-001, ... |
| DS-001 | Data Store | T-T-DS-001-001, T-I-DS-001-001, ... |
| DF-001 | Data Flow | T-T-DF-001-001, T-I-DF-001-001, ... |

## Threat Details

### T-S-P-001-001: Authentication Bypass via Token Manipulation

- **Element**: P-001 (API Gateway)
- **STRIDE**: Spoofing
- **CWE**: CWE-287
- **CAPEC**: CAPEC-194
- **Priority**: P1
- **Description**: ...
- **Attack Scenario**: ...

### T-T-DS-001-001: SQL Injection in User Lookup

...

## Threat Inventory

[yaml:threat_inventory block]
```

---

## Validation Gates

| Check | Severity |
|-------|----------|
| yaml:threat_inventory block present | BLOCKING |
| element_coverage_verification present | BLOCKING |
| Process coverage_percentage == 100% | BLOCKING |
| Data store coverage_percentage == 100% | BLOCKING |
| Data flow coverage_percentage == 100% | BLOCKING |
| External interactor coverage_percentage == 100% | BLOCKING |
| stride_completeness >= 0.80 | WARNING |
| Threat count per element >= 2 | WARNING |
| CWE mapping provided for each threat | WARNING |
| Summary totals match threat list | BLOCKING |

---

## Tool-Assisted Threat Evidence (Optional)

For C/C++ targets or complex data flows, supplement manual STRIDE analysis with automated tools. Load `@references/binary-analysis.md` for binary targets.

**Automated CWE detection** (C/C++ via Joern):
```bash
joern-parse --language c <target>
python -m luoshu.joern_queries.runner --cpg .luoshu/joern-work/cpg.bin --all
```
15 CWE checks: buffer overflow, use-after-free, command/SQL injection, format string, integer overflow, etc. Each CWE finding maps to STRIDE: buffer overflow → T/EoP, injection → T/ID, UAF → T/DoS.

**Source-to-sink verification**:
- `luoshu_query_chain(symbol="<entry>", edge_kind="CALLS", direction="outbound", max_depth=5)` — verify data flows from P2 reach the sinks claimed in threats

**Integration**: Tool findings provide evidence for threat likelihood ratings. Mark threats with `kb_lookup: automated` and include tool + CWE ID in threat metadata.

---

## Completion Checklist

Before marking Phase 5 complete:

**Element Coverage Verification**:
- [ ] `element_coverage_verification` section present in YAML
- [ ] Process coverage_percentage == 100%
- [ ] Data store coverage_percentage == 100%
- [ ] Data flow coverage_percentage == 100%
- [ ] External interactor coverage_percentage == 100%
- [ ] stride_completeness >= 0.80

**STRIDE Analysis**:
- [ ] All Processes analyzed for S,T,R,I,D,E
- [ ] All Data Stores analyzed for T,R,I,D
- [ ] All Data Flows analyzed for T,I,D
- [ ] All External Interactors analyzed for S,R
- [ ] yaml:threat_inventory block present
- [ ] Summary totals correct
- [ ] CWE/CAPEC mappings provided
- [ ] Validation passed

---

**End of Phase 5 Instructions** (~960 lines, ~8K tokens)
