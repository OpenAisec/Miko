<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Phase 4: Security Design Review

**Type**: Evaluative
**Executor**: LLM
**Knowledge**: Control Sets, OWASP References

---

## ⚠️ 4-Phase Gating Protocol — THINKING → PLANNING → EXECUTION → REFLECTION (output each stage)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🧠 THINKING - Phase 4 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Purpose**: Understand deeply before acting. Prevent hasty actions based on incomplete understanding.

**⚠️ You MUST output THINKING results in the following format:**

```
🧠 THINKING - P4 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 CORE PROBLEM
Evaluate project's design maturity across 16 security domains, identify security control gaps

📊 UPSTREAM DATA (Read from P1-P3 YAML)
| Metric | Value | Source |
|--------|-------|--------|
| P1 Total Modules | {actual_value} | P1_project_context.yaml → module_inventory.summary.total_modules |
| P2 Total Data Flows | {actual_value} | P2_dfd_elements.yaml → data_flow_traces.summary.total_flows |
| P2 Data Store Count | {actual_value} | P2_dfd_elements.yaml → data_store_inventory.summary.total_data_stores |
| P3 Boundary Count | {actual_value} | P3_boundary_context.yaml → boundary_context.boundaries length |
| Tech stack | {actual_value} | P1_project_context.yaml → project_context.tech_stack |

❓ UNKNOWNS
- Security controls to be confirmed through code review
- Best practices to be confirmed through KB queries

⚠️ RISKS
- Incomplete domain assessment (not all 16 domains covered)
- Missing traceability chain between Gap and Module/Flow
- Extended domain trigger detection missed

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⛔ STOP CHECK
- P1 YAML read? [YES/NO]
- P2 YAML read? [YES/NO]
- P3 YAML read? [YES/NO]
- Upstream data complete? [YES/NO]
- Ready to continue PLANNING? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ **STOP CONDITION**: If any STOP CHECK = NO → Read upstream data first before continuing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 📋 PLANNING - Sub-task Decomposition
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Step 1: Read Upstream Data** (BLOCKING - MUST execute)
```bash
# Read P1-P3 YAML data (choose one method)
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --aggregate --phases 1,2,3 --format summary --root .

# Or read directly
cat .phase_working/{SESSION_ID}/data/P1_project_context.yaml
cat .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
cat .phase_working/{SESSION_ID}/data/P3_boundary_context.yaml
```
⛔ If any file does not exist or is invalid → STOP and return to complete upstream Phase

**Step 2: Output Sub-task Table** (MANDATORY)

**⚠️ You MUST output PLANNING results in the following format:**

```
📋 PLANNING - P4 Sub-tasks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| # | Sub-task | Expected Output |
|---|----------|-----------------|
| T1 | Read P1-P3 data, extract module/flow/boundary inventory | Data structures |
| T2 | Assess 10 core security domains (AUTHN→DATA) | Domain assessment matrix |
| T3 | Detect extended domain trigger conditions (ext-11→ext-16) | Trigger detection results |
| T4 | Assess triggered extended domains | Extended domain assessment |
| T5 | Generate Gap inventory (GAP-xxx) | Gap inventory |
| T6 | Write P4_security_gaps.yaml | PRIMARY output |
| T7 | Write P4-SECURITY-REVIEW.md | SECONDARY output |

⛔ PLANNING CHECK
- Sub-tasks decomposed? [YES/NO]
- Ready to TaskCreate? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Step 3**: ⚠️ `TaskCreate` ALL sub-tasks before implementation (MANDATORY).

**Step 4: Multi-Perspective Parallel Analysis** (RECOMMENDED)

Launch 7 `‖` sub-agents via `Task` tool (`subagent_type: "general-purpose"`, `model: "opus"`). Each receives P1-P3 data + its perspective prompt:

**Domain Experts** (assess specific security control domains):

**‖ Infrastructure Expert**: "Assess NETWORK, CLOUD, CONFIG, ext-11 (Infrastructure) domains. Evaluate infrastructure controls, network segmentation, cloud configuration hardening, deployment security, infrastructure-as-code practices."

**‖ AppSec Expert**: "Assess AUTHN, AUTHZ, SESSION, ACCESS domains. Evaluate identity management, authentication mechanisms, permission models, session handling, access control enforcement, OAuth/OIDC implementation."

**‖ Data Expert**: "Assess INPUT, OUTPUT, CRYPTO, DATA domains. Evaluate input validation, output encoding, cryptographic implementations (algorithms/key management), data protection at rest and in transit."

**‖ Advanced Threat Expert**: "Assess AUDIT, ERROR, API, AI/LLM (ext-13), Agentic (ext-16), Supply Chain (ext-12) domains. Evaluate logging/monitoring, error handling, API security, prompt injection defenses, agent tool-use controls, dependency integrity."

**Cross-cutting Perspectives** (complementary angles on ALL domains):

**‖ Architect**: "As security architect, review ALL 16+ domains for defense-in-depth coherence. Focus: architectural blind spots, missing security layers, design pattern weaknesses, cross-domain interaction risks."

**‖ Code Auditor**: "As code auditor, review ALL domains for implementation-level vulnerabilities. Focus: CWE mapping, insecure coding patterns, missing sanitization in specific code paths, hardcoded secrets, unsafe deserialization."

**‖ Penetration Tester**: "As penetration tester, review ALL domains for real-world exploitability. Focus: attack chain feasibility, exploitation prerequisites, attacker-perspective severity ranking, quick wins vs. complex attack paths."

**Merge**: Union of all GAP-xxx → deduplicate by domain+control → cross-reference perspectives for severity calibration.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### ⚡ EXECUTION — TaskUpdate(in_progress) → Execute → Verify → TaskUpdate(completed) | Fail → Retry 3x → CHECKPOINT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Output Sequence** (CRITICAL):
1. **Write YAML FIRST**: `.phase_working/{SESSION_ID}/data/P4_security_gaps.yaml`
2. **Write MD SECOND**: `.phase_working/{SESSION_ID}/reports/P4-SECURITY-REVIEW.md`

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🔍 REFLECTION - Completion Verification
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**⚠️ After completing EXECUTION, you MUST output REFLECTION results in the following format:**

```
🔍 REFLECTION - P4 Completion Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| Check Item | Status |
|------------|--------|
| All sub-tasks completed? (TaskList check) | [✅/❌] |
| P4_security_gaps.yaml exists and valid? | [✅/❌] |
| design_matrix contains all 16 domains? | [✅/❌] |
| Every Gap has unique ID (GAP-xxx)? | [✅/❌] |
| coverage_verification shows 100% coverage? | [✅/❌] |
| input_ref field points to P3_boundary_context.yaml? | [✅/❌] |
| `--phase-end` validation passed (exit 0)? | [✅/❌] |

⛔ COMPLETION GATE
- All checks passed? [YES/NO]
- Ready to proceed to P5? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ If ANY check fails → Fix and re-verify until ALL pass

---

### ⚠️ Dual Output (YAML first → MD second)

1. **YAML** (PRIMARY): `.phase_working/{SESSION_ID}/data/P4_security_gaps.yaml`
2. **MD** (SECONDARY): `.phase_working/{SESSION_ID}/reports/P4-SECURITY-REVIEW.md`
- ❌ Writing only .md without .yaml | ✅ .yaml is the authoritative data source

### Required Data Sections in YAML

| Section | Validation |
|---------|------------|
| `security_gaps.gaps[]` | BLOCKING - all identified gaps with GAP-xxx IDs |
| `security_gaps.design_matrix` | BLOCKING - all 16 domains assessed |
| `security_gaps.summary` | BLOCKING - counts and statistics |
| `extended_domains_triggered[]` | CONDITIONAL - list triggered ext domains |

### Validation Gate

Phase 4 CANNOT complete until:
1. `.phase_working/{SESSION_ID}/data/P4_security_gaps.yaml` exists and is valid YAML
2. `design_matrix` contains all 16 domains (10 core + 6 extended)
3. Every gap has unique ID (GAP-xxx format) and risk_level assigned
4. Every domain has `assessed: true` or `assessed: false` (N/A)
5. `.phase_working/{SESSION_ID}/reports/P4-SECURITY-REVIEW.md` exists

### Coverage Verification (CRITICAL)

**P4 MUST verify complete coverage of P1/P2 inputs**:

```yaml
# In P4_security_gaps.yaml - REQUIRED section
coverage_verification:
  # P1 Module Coverage
  p1_modules:
    total_modules: 15          # From P1.module_inventory.summary.total_modules
    modules_assessed: 15       # Modules referenced in gaps or confirmed secure
    coverage_percentage: 100   # MUST be 100%
    unassessed_modules: []     # MUST be empty

  # P2 Data Flow Coverage
  p2_flows:
    total_data_flows: 45       # From P2.dfd_elements.data_flows count
    flows_assessed: 45         # Flows analyzed for security controls
    coverage_percentage: 100   # MUST be 100%
    unassessed_flows: []       # MUST be empty

  # P2 Data Store Coverage
  p2_stores:
    total_data_stores: 8       # From P2.dfd_elements.data_stores count
    stores_assessed: 8         # Stores with DATA domain assessment
    coverage_percentage: 100   # MUST be 100%
    unassessed_stores: []      # MUST be empty
```

**Validation Rules**:
- P1 Module Coverage: Every M-xxx from P1 must be referenced in at least one gap's `affected_elements` OR confirmed as secure
- P2 Flow Coverage: Every DF-xxx from P2 must be assessed for INPUT/OUTPUT/CRYPTO controls
- P2 Store Coverage: Every DS-xxx from P2 must be assessed for DATA domain compliance

**BLOCKING**: `coverage_percentage < 100%` for any category

---

### Domain Coverage Verification (GAP-5 FIX)

> **CRITICAL**: P4 MUST verify all 16 security domains are assessed with proper completeness criteria.

#### Domain Assessment Completeness Matrix

```yaml
# In P4_security_gaps.yaml - MANDATORY section (GAP-5)
domain_coverage_verification:
  # ============================================================
  # Core Domains (01-10) - MANDATORY Assessment
  # ============================================================
  core_domains:
    assessment_requirement: MANDATORY
    domains_total: 10
    domains_assessed: 10       # MUST equal domains_total
    coverage_percentage: 100   # MUST be 100%

    # Per-domain assessment status
    domain_status:
      AUTHN:
        assessed: true
        assessment_result: Partial    # Yes | Partial | No | N/A
        checks_performed: 6           # From checklist
        checks_passed: 4
        gaps_identified: [GAP-001, GAP-002]
        coverage_detail:
          module_refs: [M-001, M-003]   # Modules assessed for this domain
          flow_refs: [DF-001, DF-005]   # Flows relevant to this domain
        kb_ref: "control-set-01"
      AUTHZ:
        assessed: true
        assessment_result: Yes
        checks_performed: 4
        checks_passed: 4
        gaps_identified: []             # No gaps = fully compliant
        coverage_detail:
          module_refs: [M-001, M-002, M-004]
          flow_refs: [DF-002, DF-003]
        kb_ref: "control-set-02"
      INPUT:
        assessed: true
        assessment_result: Partial
        checks_performed: 5
        checks_passed: 3
        gaps_identified: [GAP-003]
        coverage_detail:
          module_refs: [M-005, M-006]
          flow_refs: [DF-010, DF-011, DF-015]
        kb_ref: "control-set-03"
      OUTPUT:
        assessed: true
        assessment_result: No
        checks_performed: 4
        checks_passed: 1
        gaps_identified: [GAP-004, GAP-005]
        coverage_detail:
          module_refs: [M-007]
          flow_refs: [DF-020, DF-021]
        kb_ref: "control-set-04"
      # ... (CLIENT, CRYPTO, LOG, ERROR, API, DATA)

  # ============================================================
  # Extended Domains (ext-11 to ext-16) - CONDITIONAL Assessment
  # ============================================================
  # AUTHORITY: P1 is the AUTHORITATIVE source for extended domain detection.
  # P4 READS P1.project_context.tech_stack and APPLIES trigger patterns.
  # P4 does NOT redefine detection - it uses P1's detection results.
  # The trigger_patterns below are REFERENCE patterns used to validate
  # P1's detection, not independent detection logic.
  # ============================================================
  extended_domains:
    assessment_requirement: CONDITIONAL
    trigger_detection_source: "P1.project_context.tech_stack"

    # Complete trigger pattern library for all extended domains
    domain_triggers:
      INFRA:  # ext-11: Infrastructure as Code
        trigger_patterns:
          - "Dockerfile"
          - "docker-compose.yml"
          - "docker-compose.yaml"
          - "kubernetes/*.yaml"
          - "k8s/*.yaml"
          - "helm/"
          - ".github/workflows/*.yml"
          - "Vagrantfile"
          - "ansible/"
          - "chef/"
          - "puppet/"
        triggered: true                # Detected in P1
        assessed: true
        assessment_result: Partial
        gaps_identified: [GAP-010]
        trigger_evidence:
          files_found: ["Dockerfile", "kubernetes/deployment.yaml"]
          detection_method: "File pattern match"
      SUPPLY:  # ext-12: Supply Chain
        trigger_patterns:
          - "package.json"
          - "package-lock.json"
          - "yarn.lock"
          - "pnpm-lock.yaml"
          - "requirements.txt"
          - "Pipfile"
          - "Pipfile.lock"
          - "poetry.lock"
          - "go.mod"
          - "go.sum"
          - "Cargo.toml"
          - "Cargo.lock"
          - "pom.xml"
          - "build.gradle"
          - "Gemfile"
          - "composer.json"
        triggered: true
        assessed: true
        assessment_result: No
        gaps_identified: [GAP-011, GAP-012]
        trigger_evidence:
          files_found: ["package.json", "requirements.txt"]
          detection_method: "Dependency manifest detection"
      AI:  # ext-13: AI/LLM Applications
        trigger_patterns:
          - "**/llm/**"
          - "**/model/**"
          - "**/ai/**"
          - "**/ml/**"
          - "langchain"
          - "openai"
          - "anthropic"
          - "huggingface"
          - "transformers"
          - "ollama"
          - "llama"
          - "gpt"
          - "claude"
          - "embedding"
          - "vector"
          - "rag"
        triggered: false               # Not detected
        assessed: false
        assessment_result: N/A
        gaps_identified: []
        trigger_evidence:
          files_found: []
          detection_method: "No LLM/AI patterns detected"
      MOBILE:  # ext-14: Mobile Applications
        trigger_patterns:
          - "*.apk"
          - "*.ipa"
          - "*.aab"
          - "AndroidManifest.xml"
          - "Info.plist"
          - "build.gradle"
          - "Podfile"
          - "*.xcodeproj"
          - "*.xcworkspace"
          - "react-native"
          - "flutter"
          - "ionic"
          - "cordova"
        triggered: false
        assessed: false
        assessment_result: N/A
        gaps_identified: []
        trigger_evidence:
          files_found: []
          detection_method: "No mobile artifacts detected"
      CLOUD:  # ext-15: Cloud Native
        trigger_patterns:
          - "terraform/"
          - "*.tf"
          - "*.tfvars"
          - "pulumi/"
          - "cloudformation/"
          - "*.cdk.ts"
          - "serverless.yml"
          - "sam.yaml"
          - "aws-cdk/"
          - "bicep/"
          - "*.bicep"
          - "gcp/"
          - "azure/"
        triggered: true
        assessed: true
        assessment_result: Partial
        gaps_identified: [GAP-015]
        trigger_evidence:
          files_found: ["terraform/main.tf", "terraform/aws.tf"]
          detection_method: "IaC pattern detection"
      AGENT:  # ext-16: Agentic AI
        trigger_patterns:
          - "**/agent/**"
          - "**/agents/**"
          - "**/tool_use/**"
          - "**/tools/**"
          - "langchain.agents"
          - "crewai"
          - "autogen"
          - "swarm"
          - "autogpt"
          - "babyagi"
          - "function_calling"
          - "tool_calls"
        triggered: false
        assessed: false
        assessment_result: N/A
        gaps_identified: []
        trigger_evidence:
          files_found: []
          detection_method: "No agentic patterns detected"

    # Extended domain summary
    summary:
      domains_triggered: 3           # Domains with detected triggers
      domains_assessed: 3            # MUST equal domains_triggered
      domains_skipped: 3             # N/A domains (not triggered)
      assessment_coverage: 100       # domains_assessed / domains_triggered * 100

  # ============================================================
  # Overall Domain Assessment Summary
  # ============================================================
  overall:
    total_domains: 16
    core_assessed: 10
    extended_triggered: 3
    extended_skipped: 3
    total_assessed: 13               # core + extended_triggered
    total_gaps_by_domain:
      AUTHN: 2
      AUTHZ: 0
      INPUT: 1
      OUTPUT: 2
      # ... etc
    assessment_completeness: 100     # All applicable domains assessed
```

#### Domain Assessment Validation Rules

| Rule | Level | Description |
|------|-------|-------------|
| Core domain coverage | **BLOCKING** | All 10 core domains MUST be assessed |
| Extended trigger validation | **BLOCKING** | Triggered extended domains MUST be assessed |
| N/A justification | **WARNING** | Core domains marked N/A need documented reason |
| Check coverage | **WARNING** | `checks_passed / checks_performed < 0.5` triggers review |
| Gap-to-domain traceability | **BLOCKING** | Every GAP-xxx MUST reference exactly one domain |

#### Completeness Criteria Per Assessment Result

| Result | Criteria |
|--------|----------|
| **Yes** | All checklist items pass, no gaps identified |
| **Partial** | Some items pass, gaps identified but not critical |
| **No** | Critical controls missing, high-severity gaps |
| **N/A** | Domain not applicable (requires documented reason) |

**BLOCKING Conditions**:
- `core_domains.coverage_percentage < 100%`
- `extended_domains.assessment_coverage < 100%` (for triggered domains)
- Any gap without domain assignment
- Triggered extended domain with `assessed: false`

---

## Error Handling

| Error | Cause | Recovery Action |
|-------|-------|-----------------|
| P3 YAML not found | P3 not completed | Return to P3, complete boundary analysis |
| Domain assessment incomplete | Complex code | Document known state, mark domain as Partial |
| Extended domain trigger failure | Missing P1 data | Check P1 project_context, re-run detection |
| Gap count mismatch | YAML validation error | Verify gaps[] count matches summary.total_gaps |

**Fallback Strategy**: If domain assessment cannot be completed due to insufficient data, mark domain with `assessed: partial` and document the limitation.

---

## Input Context

← P1/P2/P3: All cumulative findings (from `{SESSION_ID}/data/` directory)

**Required Input Files**:
- `P1_project_context.yaml` - For tech stack detection (extended domain triggers)
- `P2_dfd_elements.yaml` - For security control mapping
- `P3_boundary_context.yaml` - For boundary-aware gap analysis

### ⚠️ MANDATORY: Query P1-P3 Data Before Analysis

**Before starting P4 analysis**, LLM MUST execute these queries to obtain upstream data:

```bash
# Step 1: Get aggregate summary from P1-P3
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --aggregate --phases 1,2,3 --format summary --root .

# Step 2: Get P1 modules for coverage tracking
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 1 --type modules --root .

# Step 3: Get P2 DFD elements for security mapping
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 2 --type dfd --root .

# Step 4: Get P3 boundaries for gap context
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 3 --summary --root .
```

**Or read YAML directly**:
```bash
# PRIMARY sources - ALL REQUIRED
cat .phase_working/{SESSION_ID}/data/P1_project_context.yaml
cat .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
cat .phase_working/{SESSION_ID}/data/P3_boundary_context.yaml
```

**CRITICAL**: Do NOT assess security domains from memory. MUST read P1-P3 data first!

**P3 Boundary Integration**:
- Use P3's `boundaries[]` to identify security control points
- Map gaps to `cross_boundary_flows[]` for risk context
- Reference `data_nodes[]` sensitivity when assessing DATA domain
- Consider Model/Agent boundary types for ext-13/ext-16 assessment

## Output Context

→ P5: `security_gaps` {gaps[], design_matrix{}}

---

## Core Analysis Goal

Evaluate project's design maturity across all 16 security domains, identify gaps between current implementation and security best practices.

---

## Knowledge Reference (Progressive Loading)

1. **Always load**: `security-design.yaml` (16 domains overview)
2. **Per domain**: `control-set-*.md` when assessing that domain
3. **For details**: `reference-set-*.md` for specific implementation guidance

**Query Commands**:
```bash
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --control authentication       # Domain-specific controls
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --stride-controls S            # STRIDE category controls
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --control api                  # Full control details
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --control {ext_domain}         # Extended domain (may have limited support)
```

### KB Usage Log (MANDATORY per GAP-4 Contract)

> **CRITICAL**: P4 MUST query KB for each assessed security domain per KBQueryContract in assets/contracts/data-model.yaml

**Required Queries**:
1. `--control {domain_code}` - For each core domain (AUTHN, AUTHZ, INPUT, etc.)
2. `--stride-controls {S|T|R|I|D|E}` - For STRIDE-to-domain mapping validation

```yaml
# In P4_security_gaps.yaml - MANDATORY section (GAP-4 Contract)
kb_usage_log:
  # Query record for auditability
  queries_made:
    - query: "--control authentication"
      timestamp: "2026-01-31T09:15:00Z"
      result_count: 15
      domain_assessed: AUTHN
      findings_informed: [GAP-001, GAP-002]
      cache_hit: false
    - query: "--control authorization"
      timestamp: "2026-01-31T09:15:30Z"
      result_count: 12
      domain_assessed: AUTHZ
      findings_informed: []  # No gaps found - KB confirmed implementation
      cache_hit: false
    - query: "--stride-controls S"
      timestamp: "2026-01-31T09:16:00Z"
      result_count: 8
      domains_assessed: [AUTHN, CLIENT]
      findings_informed: [GAP-003]
      cache_hit: true

  # Domain coverage tracking (MANDATORY)
  coverage:
    core_domains_total: 10          # AUTHN through DATA
    core_domains_queried: 10        # MUST equal core_domains_total
    extended_domains_total: 6       # INFRA through AGENT
    extended_domains_queried: 3     # Best effort - may have limited KB support
    kb_coverage_percentage: 81.25   # (10+3)/(10+6) * 100

  # Error handling
  errors:
    - query: "--control AGENT"
      error_type: "limited_support"
      action_taken: "Used LLM knowledge for ext-16 assessment"
      domain_affected: AGENT

  kb_available: true
  note: "Extended domains (ext-11 to ext-16) may not have full KB support"
```

**Validation Rules** (GAP-4 Contract):
- **WARNING**: `kb_coverage_percentage < 50%` for core domains (01-10)
- **INFO**: Extended domains (ext-11 to ext-16) queries are optional
- **BLOCKING**: None - KB queries are best-effort but strongly recommended

---

## Security Domains (16)

| Seq | Code | Name | STRIDE Relevance |
|-----|------|------|------------------|
| 01 | AUTHN | Authentication & Session | S |
| 02 | AUTHZ | Authorization & Access Control | E |
| 03 | INPUT | Input Validation | T |
| 04 | OUTPUT | Output Encoding | T, I |
| 05 | CLIENT | Client-Side Security | S, T, I |
| 06 | CRYPTO | Cryptography & Transport | I |
| 07 | LOG | Logging & Monitoring | R |
| 08 | ERROR | Error Handling | I |
| 09 | API | API & Service Security | S, T, I, D, E |
| 10 | DATA | Data Protection | I |
| ext-11 | INFRA | Infrastructure Security | - |
| ext-12 | SUPPLY | Supply Chain Security | - |
| ext-13 | AI | AI/LLM Security | - |
| ext-14 | MOBILE | Mobile Security | - |
| ext-15 | CLOUD | Cloud Security | - |
| ext-16 | AGENT | Agentic Security | S, T, R, I, D, E |

---

## Assessment Process

For each domain:

1. **Identify Implementation**: What security controls exist in the code?
2. **Compare to Standards**: How does it compare to OWASP/industry standards?
3. **Assess Maturity**: Rate as Yes/No/Partial
4. **Document Gaps**: What's missing or inadequate?
5. **Assign Risk Level**: High/Medium/Low based on impact

---

## Assessment Matrix Template

| Domain | Code | Current Implementation | Assessment | Gap Description | Risk Level | KB Ref |
|--------|------|----------------------|------------|-----------------|------------|--------|
| Authentication | AUTHN | OAuth2 + local auth | Partial | MFA not implemented | High | control-set-01 |
| Authorization | AUTHZ | Role-based access | Yes | - | Low | control-set-02 |
| Input Validation | INPUT | Basic sanitization | Partial | Missing schema validation | Medium | control-set-03 |
| ... | ... | ... | ... | ... | ... | ... |

**Assessment Values**:
- **Yes**: Fully implemented per standards
- **Partial**: Partially implemented, gaps exist
- **No**: Not implemented
- **N/A**: Not applicable to this project

---

## Domain-Specific Checks

### AUTHN - Authentication & Session

- [ ] Multi-factor authentication available?
- [ ] Secure password storage (bcrypt/argon2)?
- [ ] Session timeout implemented?
- [ ] Session fixation protection?
- [ ] Account lockout policy?
- [ ] Secure credential recovery?

### AUTHZ - Authorization

- [ ] Role-based or attribute-based access control?
- [ ] Principle of least privilege applied?
- [ ] Authorization checks on all endpoints?
- [ ] Sensitive operations require re-authentication?

### INPUT - Input Validation

- [ ] All input validated server-side?
- [ ] Allowlist validation preferred?
- [ ] File upload restrictions?
- [ ] SQL injection prevention?
- [ ] Command injection prevention?

### OUTPUT - Output Encoding

- [ ] Context-aware output encoding?
- [ ] XSS prevention measures?
- [ ] Content-Type headers set correctly?
- [ ] Content Security Policy implemented?

### CRYPTO - Cryptography

- [ ] TLS 1.2+ for all connections?
- [ ] Strong cipher suites only?
- [ ] Sensitive data encrypted at rest?
- [ ] Proper key management?
- [ ] No hardcoded secrets?

### LOG - Logging & Monitoring

- [ ] Security events logged?
- [ ] Log injection prevention?
- [ ] Sensitive data masked in logs?
- [ ] Log integrity protection?
- [ ] Alerting configured?

### API - API Security

- [ ] API authentication required?
- [ ] Rate limiting implemented?
- [ ] Input validation on all endpoints?
- [ ] CORS properly configured?
- [ ] API versioning strategy?

### CLIENT - Client-Side Security (05)

- [ ] XSS prevention (CSP, output encoding)?
- [ ] DOM-based XSS mitigation?
- [ ] CSRF protection (tokens, SameSite)?
- [ ] Clickjacking prevention (X-Frame-Options)?
- [ ] Third-party script isolation?
- [ ] Prototype pollution prevention?
- [ ] Content Security Policy implemented?
- [ ] Subresource Integrity (SRI) for CDN resources?

### ERROR - Error Handling (08)

- [ ] Generic error messages to users?
- [ ] Detailed logging internally?
- [ ] Stack traces hidden in production?
- [ ] Fail-secure mode implemented?
- [ ] Error codes don't leak system info?
- [ ] Graceful degradation on failures?

### DATA - Data Protection (10)

- [ ] PII identified and protected?
- [ ] Data classification implemented?
- [ ] Data retention policy?
- [ ] Secure data deletion?
- [ ] Secrets management (no hardcoded)?
- [ ] Database credentials secured?

---

## Extended Domain Checks (Conditional - Based on Tech Stack)

> Load these checks only when corresponding trigger conditions are detected in P1.

### ext-11: INFRA - Infrastructure Security

**Trigger**: Dockerfile, docker-compose.yml, kubernetes/*.yaml, helm charts

- [ ] Container images from trusted registries?
- [ ] Base images regularly updated?
- [ ] Container runs as non-root?
- [ ] Resource limits (CPU/memory) configured?
- [ ] Network policies/segmentation?
- [ ] Secrets not baked into images?
- [ ] Pod security policies/standards?
- [ ] Container vulnerability scanning?

### ext-12: SUPPLY - Supply Chain Security

**Trigger**: package.json, requirements.txt, pom.xml, go.mod

- [ ] Dependencies vulnerability scanned?
- [ ] Lock files (package-lock.json, poetry.lock) committed?
- [ ] Private registry security?
- [ ] SBOM generated?
- [ ] Dependency update policy?
- [ ] No known vulnerable dependencies?
- [ ] CI/CD pipeline security?
- [ ] Artifact signing/verification?

### ext-13: AI - AI/LLM Security

**Trigger**: openai/anthropic API, langchain, LLM model loading

- [ ] Prompt injection prevention?
- [ ] System prompt protection?
- [ ] Output filtering/validation?
- [ ] Model access control?
- [ ] Training data protection?
- [ ] PII not sent to external LLMs?
- [ ] Rate limiting on LLM calls?
- [ ] Jailbreak detection?

### ext-14: MOBILE - Mobile Security

**Trigger**: iOS/Android project, React Native, Flutter

- [ ] Secure local storage (Keychain/Keystore)?
- [ ] Certificate pinning implemented?
- [ ] Code obfuscation enabled?
- [ ] Jailbreak/root detection?
- [ ] Biometric authentication?
- [ ] Secure IPC (Intent/URL scheme)?
- [ ] Binary protections (ASLR, PIE)?
- [ ] Debug disabled in release?

### ext-15: CLOUD - Cloud Security

**Trigger**: terraform/*.tf, AWS/Azure/GCP SDK, serverless.yml

- [ ] IAM least privilege?
- [ ] No wildcards in IAM policies?
- [ ] Resources not publicly accessible?
- [ ] Security groups properly configured?
- [ ] Encryption enabled (at-rest, in-transit)?
- [ ] CloudTrail/logging enabled?
- [ ] VPC properly configured?
- [ ] Secrets in secrets manager (not env vars)?

### ext-16: AGENT - Agentic Security

**Trigger**: langchain/langgraph, crewai/autogen, MCP config, Agent workflows

- [ ] Agent goal/intent protection?
- [ ] Tool/skill governance (whitelist)?
- [ ] Autonomy boundaries defined?
- [ ] Human-in-the-loop for critical actions?
- [ ] Agent authentication/identity?
- [ ] Multi-agent trust boundaries?
- [ ] Tool call rate limiting?
- [ ] Agent behavior logging/auditing?
- [ ] Goal hijack prevention?
- [ ] Indirect prompt injection defense?

---

## Gap Documentation Format

> **File Path**: `.phase_working/{SESSION_ID}/data/P4_security_gaps.yaml`

```yaml
# P4_security_gaps.yaml - Phase 4 Data Output
schema_version: "3.2.0 (20260512a)"
phase: 4
generated_at: "ISO8601 timestamp"

security_gaps:
  # Summary statistics (REQUIRED)
  summary:
    total_domains: 16
    domains_assessed: 16
    fully_compliant: 8
    partially_compliant: 5
    non_compliant: 2
    not_applicable: 1
    total_gaps: 12
    critical_gaps: 2
    high_gaps: 4
    medium_gaps: 4
    low_gaps: 2

  # Identified security gaps (REQUIRED)
  gaps:
    - id: GAP-001
      domain: AUTHN
      domain_seq: "01"
      description: "Multi-factor authentication not implemented"
      current_state: "Single-factor (password only)"
      expected_state: "TOTP or WebAuthn MFA available"
      impact: "Credential compromise leads to full account takeover"
      risk_level: HIGH  # CRITICAL|HIGH|MEDIUM|LOW
      affected_elements: [P-002, EP-API-001]
      kb_reference: "control-set-01-authentication.md"
      owasp_refs: ["A07:2021-Identification and Authentication Failures"]

    - id: GAP-002
      domain: INPUT
      domain_seq: "03"
      description: "Missing request schema validation"
      current_state: "Basic type checking only"
      expected_state: "JSON Schema validation on all API inputs"
      impact: "Malformed input may bypass security controls"
      risk_level: MEDIUM
      affected_elements: [P-001, DF-001]
      kb_reference: "control-set-03-input-validation.md"
      owasp_refs: ["A03:2021-Injection"]

  # Design matrix - ALL 16 domains (REQUIRED)
  design_matrix:
    # Core Domains (01-10)
    AUTHN:
      seq: "01"
      assessed: true
      rating: Partial  # Yes|Partial|No|N/A
      gaps_count: 2
      risk_level: HIGH
    AUTHZ:
      seq: "02"
      assessed: true
      rating: Yes
      gaps_count: 0
      risk_level: LOW
    INPUT:
      seq: "03"
      assessed: true
      rating: Partial
      gaps_count: 1
      risk_level: MEDIUM
    OUTPUT:
      seq: "04"
      assessed: true
      rating: Yes
      gaps_count: 0
      risk_level: LOW
    CLIENT:
      seq: "05"
      assessed: true
      rating: Partial
      gaps_count: 2
      risk_level: MEDIUM
    CRYPTO:
      seq: "06"
      assessed: true
      rating: Yes
      gaps_count: 0
      risk_level: LOW
    LOG:
      seq: "07"
      assessed: true
      rating: Partial
      gaps_count: 1
      risk_level: MEDIUM
    ERROR:
      seq: "08"
      assessed: true
      rating: Yes
      gaps_count: 0
      risk_level: LOW
    API:
      seq: "09"
      assessed: true
      rating: Partial
      gaps_count: 2
      risk_level: HIGH
    DATA:
      seq: "10"
      assessed: true
      rating: Partial
      gaps_count: 1
      risk_level: MEDIUM

    # Extended Domains (ext-11 to ext-16)
    INFRA:
      seq: "ext-11"
      assessed: true  # or false if not triggered
      triggered: true
      rating: Partial
      gaps_count: 2
      risk_level: MEDIUM
    SUPPLY:
      seq: "ext-12"
      assessed: true
      triggered: true
      rating: Partial
      gaps_count: 1
      risk_level: MEDIUM
    AI:
      seq: "ext-13"
      assessed: true
      triggered: true
      rating: No
      gaps_count: 3
      risk_level: CRITICAL
    MOBILE:
      seq: "ext-14"
      assessed: false
      triggered: false
      rating: N/A
      gaps_count: 0
      risk_level: N/A
    CLOUD:
      seq: "ext-15"
      assessed: true
      triggered: true
      rating: Partial
      gaps_count: 2
      risk_level: HIGH
    AGENT:
      seq: "ext-16"
      assessed: true
      triggered: true
      rating: No
      gaps_count: 4
      risk_level: CRITICAL

  # Extended domains triggered based on P1 tech stack detection
  extended_domains_triggered:
    - { domain: INFRA, trigger: "Dockerfile detected" }
    - { domain: SUPPLY, trigger: "package.json detected" }
    - { domain: AI, trigger: "openai API usage" }
    - { domain: CLOUD, trigger: "terraform/*.tf detected" }
    - { domain: AGENT, trigger: "langchain import" }
```

---

## Report Template

```markdown
# P4: Security Design Review

## Executive Summary

- **Domains Assessed**: 16
- **Fully Compliant**: N
- **Partially Compliant**: N
- **Non-Compliant**: N
- **Critical Gaps**: N

## Security Design Assessment Matrix

| Domain | Code | Implementation | Rating | Gaps | Risk | Reference |
|--------|------|----------------|--------|------|------|-----------|
| Authentication | AUTHN | OAuth2, local | Partial | 2 | High | control-set-01 |
| Authorization | AUTHZ | RBAC | Yes | 0 | Low | control-set-02 |
| ... | ... | ... | ... | ... | ... | ... |

## Gap Analysis

### GAP-001: Missing Multi-Factor Authentication

- **Domain**: AUTHN
- **Current State**: Password-only authentication
- **Expected State**: TOTP or WebAuthn MFA
- **Impact**: High - Full account takeover on credential compromise
- **Affected Elements**: P-002, EP-API-001, EP-API-002
- **Recommendation**: Implement TOTP with recovery codes

### GAP-002: ...

## Domain Details

### AUTHN - Authentication & Session

**Implementation Found**:
- OAuth2 with Google/GitHub providers
- Local authentication with bcrypt password hashing
- JWT session tokens

**Gaps Identified**:
1. No MFA support
2. Session timeout not configurable

**Recommendations**:
1. Add TOTP MFA option
2. Implement configurable session timeout

### AUTHZ - Authorization

...

## Summary

[yaml:security_gaps block]
```

---

## Tool-Assisted Security Analysis (Optional)

For automated vulnerability scanning, supplement manual domain review with static analysis tools. Load `@references/tool-integration-guide.md` for full catalog.

**CodeQL security scan**:
- `luoshu_auto_codeql(languages=["python"], repo="<target>")` — one-shot security analysis imported into Luoshu
- Or: `codeql_database_analyze(database="<db>", suite="python-security-extended")` → SARIF findings

**Code quality hotspots** (focus review effort):
- `find_most_complex_functions(top_n=20)` — highest cyclomatic complexity
- `find_dead_code(repo_path="<target>")` — unreachable code (potential maintenance risk)

**Integration**: SARIF findings map to security gaps (GAP-NNN). Each SARIF rule ↔ CWE ↔ existing threat-modeling KB chain. Tool findings supplement (not replace) manual 16-domain review.

---

## Completion Checklist

Before marking Phase 4 complete:

**Data File Requirements**:
- [ ] `.phase_working/{SESSION_ID}/data/P4_security_gaps.yaml` exists
- [ ] YAML is valid with `schema_version: "3.2.0 (20260512a)"`
- [ ] `security_gaps.summary` contains all required statistics
- [ ] `security_gaps.design_matrix` has all 16 domains
- [ ] Each domain has `assessed`, `rating`, `gaps_count`, `risk_level`
- [ ] Extended domains have `triggered` field

**Gap Documentation**:
- [ ] All gaps have unique GAP-xxx IDs
- [ ] Each gap has `domain`, `domain_seq`, `description`
- [ ] Each gap has `current_state`, `expected_state`, `impact`
- [ ] Risk levels assigned (CRITICAL/HIGH/MEDIUM/LOW)
- [ ] KB references provided for each gap
- [ ] OWASP refs mapped where applicable

**Report File Requirements**:
- [ ] `.phase_working/{SESSION_ID}/reports/P4-SECURITY-REVIEW.md` exists
- [ ] Executive summary with statistics
- [ ] Complete assessment matrix (16 domains)
- [ ] Gap analysis with recommendations
- [ ] Domain details section

**Validation**:
- [ ] `--phase-end` validation passed (exit 0)
- [ ] Count conservation: summary.total_gaps == len(gaps[])

---

**End of Phase 4 Instructions** (~1120 lines, ~9K tokens)
