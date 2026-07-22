<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Phase 8: Report Generation

**Type**: Comprehensive
**Executor**: LLM
**Knowledge**: Compliance Frameworks, ASVS

---

## ⚠️ 4-Phase Gating Protocol — THINKING → PLANNING → EXECUTION → REFLECTION (output each stage)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🧠 THINKING - Phase 8 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Purpose**: Aggregate all P1-P7 data, generate complete reports without truncation or summarization.

**⚠️ You MUST output THINKING results in the following format:**

```
🧠 THINKING - P8 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 CORE PROBLEM
Synthesize 10-section main report + 7 auxiliary reports, must include complete P6 POC and P7 mitigation code

📊 UPSTREAM DATA (Read from P1-P7 YAML)
| Metric | Value | Source |
|--------|-------|--------|
| P1 Module/Entry Point Count | {actual_value} | P1_project_context.yaml |
| P2 DFD Element Count | {actual_value} | P2_dfd_elements.yaml |
| P3 Boundary Count | {actual_value} | P3_boundary_context.yaml |
| P4 Gap Count | {actual_value} | P4_security_gaps.yaml |
| P5 Threat Count | {actual_value} | P5_threat_inventory.yaml |
| P6 VR Count | {actual_value} | P6_validated_risks.yaml |
| P6 POC Count | {actual_value} | P6_validated_risks.yaml → poc_details length |
| P6 AC Count | {actual_value} | P6_validated_risks.yaml → attack_chains length |
| P7 MIT Count | {actual_value} | P7_mitigation_plan.yaml → mitigations length |

❓ UNKNOWNS
- Compliance framework mapping details

⚠️ RISKS
- Not all 8 reports generated
- P6 POC truncated or summarized
- P7 mitigation code omitted
- Attack chain diagrams missing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⛔ STOP CHECK
- All P1-P7 YAML read? [YES/NO]
- All data counts recorded? [YES/NO]
- Upstream data complete? [YES/NO]
- Ready to continue PLANNING? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ **STOP CONDITION**: If any STOP CHECK = NO → Read all Phase data first before continuing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 📋 PLANNING - Sub-task Decomposition
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Step 1: Read ALL P1-P7 Data** (BLOCKING - MUST execute)
```bash
# Read all Phase YAML
cat .phase_working/{SESSION_ID}/data/P1_project_context.yaml
cat .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
cat .phase_working/{SESSION_ID}/data/P3_boundary_context.yaml
cat .phase_working/{SESSION_ID}/data/P4_security_gaps.yaml
cat .phase_working/{SESSION_ID}/data/P5_threat_inventory.yaml
cat .phase_working/{SESSION_ID}/data/P6_validated_risks.yaml
cat .phase_working/{SESSION_ID}/data/P7_mitigation_plan.yaml
```
⛔ If any upstream YAML does not exist or is invalid → STOP and return to complete upstream Phase

**Step 2: Output Sub-task Table** (MANDATORY)

**⚠️ You MUST output PLANNING results in the following format:**

```
📋 PLANNING - P8 Sub-tasks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| # | Sub-task | Expected Output |
|---|----------|-----------------|
| T1 | Read all P1-P7 YAML data | Data aggregation |
| T2 | Generate main report {PROJECT}-RISK-ASSESSMENT-REPORT.md | Main report (10 sections) |
| T3 | Generate RISK-INVENTORY.md | P6 complete content |
| T4 | Generate MITIGATION-MEASURES.md | P7 complete code |
| T5 | Generate PENETRATION-TEST-PLAN.md | POC→TC mapping |
| T6 | Generate other 4 reports | ARCHITECTURE, DFD, COMPLIANCE, ATTACK-PATH |
| T7 | Copy Phase reports, write manifest | P8_report_manifest.yaml |

⛔ PLANNING CHECK
- Sub-tasks decomposed? [YES/NO]
- Ready to TaskCreate? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Step 3**: ⚠️ `TaskCreate` ALL sub-tasks before implementation (MANDATORY).

**Step 4: Parallel Report Generation** (RECOMMENDED)

Launch 4 `‖` sub-agent groups via `Task` tool (`subagent_type: "general-purpose"`, `model: "opus"`). Each generates 2 reports from P1-P7 data:

| ‖ Group | Report A | Report B |
|---------|----------|----------|
| **‖ G1** | {PROJECT}-RISK-ASSESSMENT-REPORT.md (main, 10 sections) | {PROJECT}-RISK-INVENTORY.md |
| **‖ G2** | {PROJECT}-MITIGATION-MEASURES.md | {PROJECT}-PENETRATION-TEST-PLAN.md |
| **‖ G3** | {PROJECT}-ARCHITECTURE-ANALYSIS.md | {PROJECT}-DFD-DIAGRAM.md |
| **‖ G4** | {PROJECT}-COMPLIANCE-REPORT.md | {PROJECT}-ATTACK-PATH-VALIDATION.md |

**Constraint**: Each report MUST include complete P6 POC code and P7 mitigation code — NO summarization or truncation.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### ⚡ EXECUTION — TaskUpdate(in_progress) → Execute → Verify → TaskUpdate(completed) | Fail → Retry 3x → CHECKPOINT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Output Sequence** (CRITICAL):
1. **Write YAML first**: `.phase_working/{SESSION_ID}/data/P8_report_manifest.yaml`
2. **Then write 8 reports**: `Risk_Assessment_Report/{PROJECT}-*.md`
3. **Copy Phase reports**: `.phase_working/{SESSION_ID}/reports/P*-*.md → Risk_Assessment_Report/`

**Prohibited Actions**:
- ❌ "See P6 for details"
- ❌ "Top 3 risks shown, others omitted"
- ❌ Summarizing POC code
- ❌ Truncating attack chains

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🔍 REFLECTION - Completion Verification
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**⚠️ After completing EXECUTION, you MUST output REFLECTION results in the following format:**

```
🔍 REFLECTION - P8 Completion Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| Check Item | Status |
|------------|--------|
| ALL P1-P7 YAML data read? | [✅/❌] |
| P8_report_manifest.yaml exists and valid? | [✅/❌] |
| {PROJECT}-RISK-ASSESSMENT-REPORT.md (main report 10 sections)? | [✅/❌] |
| {PROJECT}-RISK-INVENTORY.md generated? | [✅/❌] |
| {PROJECT}-MITIGATION-MEASURES.md generated? | [✅/❌] |
| {PROJECT}-PENETRATION-TEST-PLAN.md generated? | [✅/❌] |
| {PROJECT}-ARCHITECTURE-ANALYSIS.md generated? | [✅/❌] |
| {PROJECT}-DFD-DIAGRAM.md generated? | [✅/❌] |
| {PROJECT}-COMPLIANCE-REPORT.md generated? | [✅/❌] |
| {PROJECT}-ATTACK-PATH-VALIDATION.md generated? | [✅/❌] |
| Main report §0 contains Top-10 risk cards + STRIDE heatmap? | [✅/❌] |
| Main report §1 contains 10 key findings? | [✅/❌] |
| Main report §2 contains dependency graph + entry point stats? | [✅/❌] |
| Main report §3 contains security scorecard + gap categorization? | [✅/❌] |
| Main report §5 contains complete P6 POC code? | [✅/❌] |
| Main report §6 contains complete attack chain diagrams? | [✅/❌] |
| Main report §8 contains complete P7 mitigation code? | [✅/❌] |
| Phase reports copied to report directory? | [✅/❌] |
| `--phase-end` validation passed (exit 0)? | [✅/❌] |

⛔ COMPLETION GATE
- All checks passed? [YES/NO]
- Threat modeling analysis complete? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ Any check fails → Fix and re-verify until all pass

---

## ⚠️ MANDATORY OUTPUT RULES

> **CRITICAL**: Phase 8 requires 8 mandatory reports output to Risk_Assessment_Report/ directory.

### Output Validation

Phase 8 CANNOT complete until:
1. All 8 mandatory reports exist in `Risk_Assessment_Report/`
2. Main report contains all 10 sections with complete content
3. P6 POCs and attack chains included verbatim (not summarized)
4. P7 mitigations included with full code examples
5. All phase outputs published to report directory

---

## Error Handling

| Error | Cause | Recovery Action |
|-------|-------|-----------------|
| Phase YAML not found | Previous phase incomplete | Identify missing phase, return to complete it |
| P6 content incomplete | POC/attack chain missing | Re-read P6 YAML, extract all structured data |
| P7 content incomplete | Mitigation code missing | Re-read P7 YAML, extract all implementation steps |
| Report generation fails | File write error | Check permissions, retry with explicit path |
| Content aggregation mismatch | Count discrepancy | Verify phase YAML counts match report counts |

**Fallback Strategy**: If a specific phase YAML cannot be parsed, use the corresponding phase MD report as secondary source. Mark affected sections with `[Source: MD Report - verify against YAML]`.

---

## Input Context

← P1-P7: ALL preceding phase outputs

**CRITICAL**: Phase 8 MUST read all phase files and aggregate content completely - do NOT summarize from memory!

**Required Input Files**:
```
.phase_working/{SESSION_ID}/data/P1_project_context.yaml
.phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
.phase_working/{SESSION_ID}/data/P3_boundary_context.yaml
.phase_working/{SESSION_ID}/data/P4_security_gaps.yaml
.phase_working/{SESSION_ID}/data/P5_threat_inventory.yaml
.phase_working/{SESSION_ID}/data/P6_validated_risks.yaml
.phase_working/{SESSION_ID}/data/P7_mitigation_plan.yaml
```

## Output Context

→ Final Reports: 8 mandatory reports + phase outputs

### Primary Output: P8_report_manifest.yaml

```yaml
# P8_report_manifest.yaml Schema Definition
session_id: "{SESSION_ID}"
timestamp: "ISO8601"
version: "3.2.0 (20260512a)"

generation_summary:
  total_reports: 8
  generated_reports:
    - name: "{PROJECT}-RISK-ASSESSMENT-REPORT.md"
      type: main_synthesis
      status: generated | failed
      sections_count: 10
    - name: "{PROJECT}-RISK-INVENTORY.md"
      type: risk_inventory
      source: P6
      status: generated
    - name: "{PROJECT}-MITIGATION-MEASURES.md"
      type: mitigations
      source: P7
      status: generated
    - name: "{PROJECT}-PENETRATION-TEST-PLAN.md"
      type: pentest_plan
      source: P6
      status: generated
    - name: "{PROJECT}-ARCHITECTURE-ANALYSIS.md"
      type: architecture
      source: P1-P3
      status: generated
    - name: "{PROJECT}-DFD-DIAGRAM.md"
      type: dfd
      source: P2
      status: generated
    - name: "{PROJECT}-COMPLIANCE-REPORT.md"
      type: compliance
      source: P4
      status: generated
    - name: "{PROJECT}-ATTACK-PATH-VALIDATION.md"
      type: attack_paths
      source: P6
      status: generated

content_verification:
  p6_pocs_included: true
  p6_pocs_count: 0
  p6_attack_chains_included: true
  p6_attack_chains_count: 0
  p7_mitigations_included: true
  p7_mitigations_count: 0

test_case_mapping:
  total_test_cases: 0
  poc_to_tc_mapping:
    - poc_id: "POC-xxx"
      tc_id: "TC-xxx"
  coverage:
    attack_paths_covered: 0
    attack_paths_total: 0
    coverage_percentage: 0.0

phase_outputs_published:
  - source: ".phase_working/{SESSION_ID}/reports/P1-*.md"
    target: "Risk_Assessment_Report/"
    status: copied
  # ... P2-P7

validation_result:
  all_reports_generated: true
  content_complete: true
  errors: []
  warnings: []
```

---

## Core Analysis Goal

Synthesize all phase outputs into complete threat model documentation. Every finding, threat, risk, and mitigation from previous phases must be included - no omission.

---

## Knowledge Reference

**Query Commands**:
```bash
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --compliance nist-csf
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --compliance iso27001
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --asvs-level L2 --asvs-chapter V1
```

---

## Report Generation Process

### Step 1: Read All Phase Data Files

```bash
# Read each phase YAML data file (PRIMARY source)
.phase_working/{SESSION_ID}/data/P1_project_context.yaml
.phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
.phase_working/{SESSION_ID}/data/P3_boundary_context.yaml
.phase_working/{SESSION_ID}/data/P4_security_gaps.yaml
.phase_working/{SESSION_ID}/data/P5_threat_inventory.yaml
.phase_working/{SESSION_ID}/data/P6_validated_risks.yaml
.phase_working/{SESSION_ID}/data/P7_mitigation_plan.yaml
```

### Step 2: Extract Structured Data

Use phase_data.py or manually extract:
- yaml:module_inventory from P1
- yaml:dfd_elements from P2
- yaml:threat_inventory from P5
- yaml:validated_risks from P6
- yaml:mitigation_plan from P7

### Step 3: Generate Reports

Create all 8 mandatory reports in `Risk_Assessment_Report/`

---

## Required Reports (8)

| # | Report | Content Source |
|---|--------|----------------|
| 1 | RISK-ASSESSMENT-REPORT.md | All phases synthesis |
| 2 | RISK-INVENTORY.md | P6 validated_risks |
| 3 | MITIGATION-MEASURES.md | P7 mitigation_plan |
| 4 | PENETRATION-TEST-PLAN.md | P6 POCs + test cases |
| 5 | ARCHITECTURE-ANALYSIS.md | P1-P3 synthesis |
| 6 | DFD-DIAGRAM.md | P2 DFD content |
| 7 | COMPLIANCE-REPORT.md | P4 + frameworks |
| 8 | ATTACK-PATH-VALIDATION.md | P6 attack chains |

---

## Report 1: Main Risk Assessment Report

**File**: `{PROJECT}-RISK-ASSESSMENT-REPORT.md`

### Structure (10 Sections)

```markdown
# {PROJECT} Risk Assessment Report

**Generated**: {timestamp}
**Skill Version**: 3.2.0
**Assessment Scope**: {project_path}

---

## 0. Risk Posture Overview

### Top-10 Risk Cards

| # | VR-ID | Title | CVSS | STRIDE | Priority | Affected Modules |
|---|-------|-------|------|--------|----------|-----------------|
| 1 | VR-001 | {title} | 9.8 | S, E | P0 | M-001, M-003 |
| 2 | VR-002 | {title} | 9.5 | T | P0 | M-002 |
| ... | ... | ... | ... | ... | ... | ... |
| 10 | VR-010 | {title} | 7.2 | I | P1 | M-005 |

### STRIDE × Severity Heatmap

|          | CRITICAL | HIGH | MEDIUM | LOW |
|----------|----------|------|--------|-----|
| **S** Spoofing | N | N | N | N |
| **T** Tampering | N | N | N | N |
| **R** Repudiation | N | N | N | N |
| **I** Info Disclosure | N | N | N | N |
| **D** Denial of Service | N | N | N | N |
| **E** Elevation | N | N | N | N |

### Key Metrics Dashboard

| Metric | Value |
|--------|-------|
| Total Risks | N |
| Critical (P0) | N |
| High (P1) | N |
| Medium (P2) | N |
| Low (P3) | N |
| Average CVSS | X.X |
| Attack Surface (Entry Points × Boundaries) | N × N |
| Mitigation Coverage | N/N (XX%) |

---

## 1. Executive Summary

### 10 Key Findings
1. {finding_1}
2. {finding_2}
...
10. {finding_10}

### Immediate Action Items (P0)
| # | Risk | Action | Responsible | Deadline |
|---|------|--------|-------------|----------|
| 1 | VR-001 | {action} | {team} | Immediate |
| 2 | VR-002 | {action} | {team} | 24h |
| 3 | VR-003 | {action} | {team} | 48h |

### Assessment Scope
| Attribute | Value |
|-----------|-------|
| Project Path | {project_path} |
| Tech Stack | {framework, language, db, ...} |
| Module Count | N modules, N entry points |
| Analysis Duration | P1-P8 timestamps |

---

## 2. System Architecture Overview

{From P1: Project structure, modules, entry points}
{From P2: DFD summary}
{From P3: Trust boundary summary}

### Module Dependency Graph

```
[ASCII dependency diagram showing module relationships]
[Mark security-critical modules with ⚠️]
```

### Tech Stack Security Context

| Component | Version | Known CVEs | Status |
|-----------|---------|------------|--------|
| {framework} | {version} | {cve_count} | {ok/warning/critical} |

### Entry Point Summary

| Type | Count | Auth Required | No Auth |
|------|-------|--------------|---------|
| API  | N | N | N |
| UI   | N | N | N |
| CLI  | N | N | N |
| WebSocket | N | N | N |
| gRPC | N | N | N |

### Key Components

| Component | Type | Security Relevance | Criticality |
|-----------|------|-------------------|-------------|
| {name} | {type} | {relevance} | ⚠️ Critical / Normal |

### Trust Boundary Mechanisms

| Boundary | Type | Controls | Crossing Flows |
|----------|------|----------|----------------|
| TB-001 | {type} | {controls} | N flows |

### Security Observations (P1-P3)

| Finding | Severity | Location | Description |
|---------|----------|----------|-------------|
| F-P1-001 | {sev} | {file:line} | {description} |
| F-P2-003 | {sev} | {flow_id} | {description} |

---

## 3. Security Design Assessment

{From P4: Complete security_gaps content}

### Security Scorecard

| Domain | Score | Checks | Passed | Gaps | Status |
|--------|-------|--------|--------|------|--------|
| AUTHN | XX/100 | N | N | N | ✅/⚠️/❌ |
| AUTHZ | XX/100 | N | N | N | ✅/⚠️/❌ |
| INPUT | XX/100 | N | N | N | ✅/⚠️/❌ |
| OUTPUT | XX/100 | N | N | N | ✅/⚠️/❌ |
| CLIENT | XX/100 | N | N | N | ✅/⚠️/❌ |
| CRYPTO | XX/100 | N | N | N | ✅/⚠️/❌ |
| LOG | XX/100 | N | N | N | ✅/⚠️/❌ |
| ERROR | XX/100 | N | N | N | ✅/⚠️/❌ |
| API | XX/100 | N | N | N | ✅/⚠️/❌ |
| DATA | XX/100 | N | N | N | ✅/⚠️/❌ |
| INFRA | XX/100 | N | N | N | ✅/⚠️/❌ |
| SUPPLY | XX/100 | N | N | N | ✅/⚠️/❌ |
| AI | XX/100 | N | N | N | ✅/⚠️/❌ |
| MOBILE | XX/100 | N | N | N | ✅/⚠️/❌ |
| CLOUD | XX/100 | N | N | N | ✅/⚠️/❌ |
| AGENT | XX/100 | N | N | N | ✅/⚠️/❌ |

### Threat-Gap Traceability Matrix

| GAP ID | Severity | Related Threats | Validated Risks | Category |
|--------|----------|----------------|-----------------|----------|
| GAP-001 | CRITICAL | T-S-P-001-001 | VR-001 | G-IMPL |
| GAP-002 | HIGH | T-T-DS-001-001 | VR-003 | G-ARCH |

### Gap Categorization

| Category | Code | Count | Description |
|----------|------|-------|-------------|
| Architecture | G-ARCH | N | Requires architecture redesign |
| Implementation | G-IMPL | N | Code/configuration fix |
| Process | G-PROC | N | Policy/process change |

### Gap Priority Matrix

|          | LOW Effort | MEDIUM Effort | HIGH Effort |
|----------|-----------|---------------|-------------|
| CRITICAL | {GAP-xxx} | {GAP-xxx} | {GAP-xxx} |
| HIGH | {GAP-xxx} | {GAP-xxx} | {GAP-xxx} |
| MEDIUM | {GAP-xxx} | {GAP-xxx} | {GAP-xxx} |

---

## 4. STRIDE Threat Analysis

{From P5: Complete threat_inventory content}

### Threat Distribution
| STRIDE | Count | Critical | High | Medium | Low |
|--------|-------|----------|------|--------|-----|
| S | N | N | N | N | N |
| T | N | N | N | N | N |
| R | N | N | N | N | N |
| I | N | N | N | N | N |
| D | N | N | N | N | N |
| E | N | N | N | N | N |

### Threat Coverage
{Element-by-element threat mapping}

---

## 5. Risk Validation & POC Design ← CRITICAL SECTION

{From P6: Complete poc_details content - DO NOT SUMMARIZE}

### Validated Risks

{Full VR-xxx details with POC code}

For each VR:
- **Status Badge**: ✅ Verified | ⚠️ Theoretical | ❓ Pending | ❌ Excluded
- **Complete POC code** in fenced code blocks
- **Execution environment**: Required tools and setup

### POC Summary
| POC ID | Risk | Status | Difficulty | Tools |
|--------|------|--------|------------|-------|
| POC-001 | VR-001 | ✅ Verified | Medium | {tools} |

---

## 6. Attack Path Analysis ← CRITICAL SECTION

{From P6: Complete attack_chains content - DO NOT SUMMARIZE}

### Attack Chain: {name}

**ASCII Diagram**:
```
[Attack flow ASCII art]
```

**Mermaid Source** (for HTML rendering):
```mermaid
graph LR
    A[Entry Point] --> B[Exploit Step 1]
    B --> C[Exploit Step 2]
    C --> D[Target Asset]
```

### Feasibility Matrix
| Path ID | Entry | Target | Score | Priority |
|---------|-------|--------|-------|----------|
| AP-001 | API | Admin | 9.2 | Yes |

---

## 7. Threat Priority Matrix

### By Severity
| Priority | Count | Examples |
|----------|-------|----------|
| P0 | N | VR-001, VR-002 |
| P1 | N | VR-003, VR-004 |

### By STRIDE Category
{Distribution chart}

---

## 8. Mitigation Recommendations ← CRITICAL SECTION

{From P7: Complete mitigation_plan content - DO NOT SUMMARIZE}

### Immediate Actions (P0)
{Full MIT-xxx details with code}

For each MIT:
- **Difficulty**: LOW / MEDIUM / HIGH
- **Effort**: Estimated hours/days
- **Before/After code** in side-by-side format
- **Prerequisites**: MIT-xxx dependencies if any

### Implementation Roadmap
| Timeline | Actions | Owner | Difficulty | Effort |
|----------|---------|-------|------------|--------|
| Immediate | MIT-001, MIT-002 | Security | HIGH | 2d |
| 7 days | MIT-003, MIT-004 | Backend | MEDIUM | 3d |

---

## 9. Compliance Mapping

### Framework Coverage
| Framework | Coverage | Gaps |
|-----------|----------|------|
| OWASP Top 10 | 80% | A03, A07 |
| ASVS L2 | 65% | V3, V4 |
| ISO 27001 | 70% | A.12, A.14 |

### Gap Analysis
{Per-framework gap details}

---

## Appendices

### A. Complete Risk Inventory
See: {PROJECT}-RISK-INVENTORY.md

### B. Detailed Mitigations
See: {PROJECT}-MITIGATION-MEASURES.md

### C. DFD Diagrams
See: {PROJECT}-DFD-DIAGRAM.md

### D. Phase Working Documents
- P1-PROJECT-UNDERSTANDING.md
- P2-DFD-ANALYSIS.md
- P3-TRUST-BOUNDARY.md
- P4-SECURITY-DESIGN-REVIEW.md
- P5-STRIDE-THREATS.md
- P6-RISK-VALIDATION.md
- P7-MITIGATION-PLAN.md

### E. Detailed Risk Analysis (if --detailed)
See: Risk_Assessment_Report/detailed/VR-xxx-*.md
```

---

## Report 2: Risk Inventory

**File**: `{PROJECT}-RISK-INVENTORY.md`

```markdown
# {PROJECT} Risk Inventory

## Summary Statistics
| Metric | Value |
|--------|-------|
| Total Risks | N |
| Critical | N |
| High | N |
| Medium | N |
| Low | N |

## Risk Listing

### VR-001: {title}
- **Priority**: P0
- **CVSS**: 9.8
- **STRIDE**: S, E
- **CWE**: CWE-287
- **Location**: src/api/auth.py:45
- **Description**: {description}
- **Threat Refs**: T-S-P-001-001, T-E-P-001-002
- **Mitigation**: MIT-001

### VR-002: {title}
...
```

---

## Report 3: Mitigation Measures

**File**: `{PROJECT}-MITIGATION-MEASURES.md`

Complete P7 content with implementation details.

---

## Report 4: Penetration Test Plan

**File**: `{PROJECT}-PENETRATION-TEST-PLAN.md`

### Attack Path Coverage Requirement (CRITICAL)

**Every P6 attack path and attack chain MUST have corresponding test coverage**:

```yaml
# Required section in PENETRATION-TEST-PLAN.md or P8_report_manifest.yaml
attack_path_coverage:
  # P6 Input Reference
  p6_input_ref: "P6_validated_risks.yaml"

  # Attack Path Coverage
  attack_paths:
    total_from_p6: 5              # Count of AP-xxx from P6
    paths_with_test_cases: 5      # AP-xxx that have TC-xxx
    coverage_percentage: 100      # SHOULD be 100%
    path_test_mapping:
      AP-001: [TC-001, TC-002]    # Test cases for this path
      AP-002: [TC-003]
      AP-003: [TC-004, TC-005]
      AP-004: [TC-006]            # Or "DEFERRED" with reason
      AP-005: [TC-007]
    uncovered_paths: []           # Paths without test cases
    deferred_paths:               # Paths intentionally not tested
      - path_id: AP-004
        reason: "Requires production environment access"
        planned_date: "2026-Q2"

  # Attack Chain Coverage
  attack_chains:
    total_from_p6: 3              # Count of AC-xxx from P6
    chains_with_scenarios: 3      # AC-xxx that have test scenarios
    coverage_percentage: 100
    chain_scenario_mapping:
      AC-001: "Full privilege escalation scenario"
      AC-002: "Data exfiltration scenario"
      AC-003: "Lateral movement scenario"
    uncovered_chains: []

  # Validated Risk Coverage
  validated_risks:
    total_from_p6: 15             # Count of VR-xxx from P6
    risks_with_tests: 15          # VR-xxx that have TC-xxx
    coverage_percentage: 100
    risk_test_mapping:
      VR-001: [TC-001, TC-002]
      VR-002: [TC-003]
      # ... all VRs

  # Overall Coverage Summary
  overall:
    total_attack_artifacts: 23    # AP + AC + VR
    artifacts_covered: 23
    coverage_percentage: 100
```

**Validation Rules**:
- Every AP-xxx from P6 should have at least one TC-xxx or documented deferral reason
- Every AC-xxx from P6 should have a test scenario description
- Every VR-xxx (Critical/High) from P6 must have test coverage

**WARNING**: `attack_paths.coverage_percentage < 100%` (allows deferred paths)
**WARNING**: `validated_risks.coverage_percentage < 100%` for non-Critical/High

### Report Template

```markdown
# {PROJECT} Penetration Test Plan

## Scope
{From P1: entry points, modules}

## Attack Path Coverage Summary
| P6 Artifact | Count | Covered | Coverage |
|-------------|-------|---------|----------|
| Attack Paths (AP-xxx) | N | N | 100% |
| Attack Chains (AC-xxx) | N | N | 100% |
| Validated Risks (VR-xxx) | N | N | 100% |

## Test Cases

### TC-001: JWT Token Forgery
- **Attack Path**: AP-001
- **Risk**: VR-001
- **POC**: POC-001
- **Prerequisites**: {list}
- **Steps**: {exploitation steps}
- **Expected Result**: {expected outcome}
- **Verification**: {how to verify}

### TC-002: SQL Injection
...

## Attack Chain Scenarios

### Scenario 1: Privilege Escalation (AC-001)
- **Chain**: AP-001 → AP-002
- **Test Cases**: TC-001, TC-002, TC-003
- **End-to-End Steps**: {full attack chain steps}

## Deferred Tests
| Path/Chain | Reason | Planned Date |
|------------|--------|--------------|
| AP-004 | Requires production access | 2026-Q2 |

## Tools Required
- Burp Suite
- sqlmap
- jwt_tool

## Test Environment
{Environment requirements}
```

---

## Report 5: Architecture Analysis

**File**: `{PROJECT}-ARCHITECTURE-ANALYSIS.md`

Synthesis of P1-P3 content.

---

## Report 6: DFD Diagram

**File**: `{PROJECT}-DFD-DIAGRAM.md`

P2 DFD content with **ASCII + Mermaid side-by-side**:

```markdown
### Data Flow Diagram

**ASCII Representation**:
```
[ASCII DFD diagram]
```

**Mermaid Source** (rendered in HTML version):
```mermaid
graph TD
    EI-001[User Browser] -->|DF-001: HTTP Request| P-001[Web Server]
    P-001 -->|DF-002: Query| DS-001[(Database)]
    ...
```
```

---

## Report 7: Compliance Report

**File**: `{PROJECT}-COMPLIANCE-REPORT.md`

P4 gaps mapped to compliance frameworks.

---

## Report 8: Attack Path Validation

**File**: `{PROJECT}-ATTACK-PATH-VALIDATION.md`

Complete P6 attack chains with diagrams.

---

## Phase Output Publication

Copy from `.phase_working/{SESSION_ID}/reports/` to `Risk_Assessment_Report/`:

```bash
cp .phase_working/{SESSION_ID}/reports/P1-PROJECT-UNDERSTANDING.md Risk_Assessment_Report/
cp .phase_working/{SESSION_ID}/reports/P2-DFD-ANALYSIS.md Risk_Assessment_Report/
cp .phase_working/{SESSION_ID}/reports/P3-TRUST-BOUNDARY.md Risk_Assessment_Report/
cp .phase_working/{SESSION_ID}/reports/P4-SECURITY-REVIEW.md Risk_Assessment_Report/
cp .phase_working/{SESSION_ID}/reports/P5-STRIDE-THREATS.md Risk_Assessment_Report/
cp .phase_working/{SESSION_ID}/reports/P6-RISK-VALIDATION.md Risk_Assessment_Report/
cp .phase_working/{SESSION_ID}/reports/P7-MITIGATION-PLAN.md Risk_Assessment_Report/
```

---

## Content Aggregation Rules

**CRITICAL**: These sections MUST include COMPLETE content from referenced phases:

| Report Section | Source | Rule |
|----------------|--------|------|
| §5 Risk Validation | P6 poc_details | Copy ALL POCs verbatim |
| §6 Attack Paths | P6 attack_chains | Copy ALL chains with diagrams |
| §8 Mitigations | P7 mitigation_plan | Copy ALL mitigations with code |

**Prohibited Actions**:
- ❌ "See P6 for details"
- ❌ "Top 3 risks shown, others omitted"
- ❌ Summarizing POC code
- ❌ Truncating attack chains

---

## Validation Gates

| Check | Severity |
|-------|----------|
| All 8 reports generated | BLOCKING |
| Main report has all 10 sections | BLOCKING |
| §0 Risk Posture Overview with Top-10 cards | BLOCKING |
| §1 Executive Summary with 10 key findings | BLOCKING |
| §2 Architecture with entry point stats | WARNING |
| §3 Security Assessment with scorecard | WARNING |
| P6 content included completely | BLOCKING |
| P7 content included completely | BLOCKING |
| attack_path_coverage section in pentest plan | WARNING |
| AP-xxx coverage_percentage documented | WARNING |
| AC-xxx coverage_percentage documented | WARNING |
| VR-xxx (Critical/High) have test cases | WARNING |
| Phase outputs copied to report dir | WARNING |

---

## P8R: Detailed Risk Reports (Optional)

After P8 completes, prompt the user:

```
Report generation complete. Generate detailed per-risk analysis reports? [Y/N]
(This creates individual VR-xxx analysis reports in Risk_Assessment_Report/detailed/)
```

If user confirms (or `--detailed` flag was set):
- Read `@phases/P8R-DETAILED-REPORT.md` for instructions
- Generate per-VR detailed reports in `Risk_Assessment_Report/detailed/`

---

## Tool-Assisted Report Enhancement (Optional)

**Architecture diagrams**: Use `luoshu_export(format="mermaid")` to generate Mermaid diagrams for inclusion in ARCHITECTURE-ANALYSIS report and DFD-DIAGRAM report.

**Binary call graphs**: For reports on binary targets, use `gen_callgraph(binary_name="<bin>", function_name="<entry>")` to generate MermaidJS attack path diagrams for ATTACK-PATH-VALIDATION report.

---

## Completion Checklist

Before marking Phase 8 complete:

**Report Generation**:
- [ ] All 8 reports created in Risk_Assessment_Report/
- [ ] Main report §0 has Top-10 risk cards and STRIDE heatmap
- [ ] Main report §1 has 10 key findings
- [ ] Main report §2 has dependency graph and entry point stats
- [ ] Main report §3 has security scorecard and gap categorization
- [ ] Main report includes complete P6 POCs
- [ ] Main report includes complete P7 mitigations
- [ ] Attack chain diagrams included (ASCII + Mermaid for DFD)

**Penetration Test Plan Coverage**:
- [ ] attack_path_coverage section present in pentest plan
- [ ] Every AP-xxx has test cases or documented deferral
- [ ] Every AC-xxx has test scenario description
- [ ] Every VR-xxx (Critical/High) has test coverage

**Finalization**:
- [ ] Phase outputs published
- [ ] _session_meta.yaml updated
- [ ] Validation passed

---

**End of Phase 8 Instructions** (~985 lines, ~8K tokens)
