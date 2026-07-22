<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Phase 7: Mitigation Planning

**Type**: Prescriptive
**Executor**: LLM
**Knowledge**: Control Sets, CWE Mitigations, ASVS

---

## ⚠️ 4-Phase Gating Protocol — THINKING → PLANNING → EXECUTION → REFLECTION (output each stage)

> **⚠️ CHECKPOINT**: P7 — Request user confirmation after mitigation planning.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🧠 THINKING - Phase 7 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Purpose**: Design specific, actionable mitigation measures based on P6 validated risks.

**⚠️ You MUST output THINKING results in the following format:**

```
🧠 THINKING - P7 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 CORE PROBLEM
Design specific mitigation measures MIT-xxx for each VR-xxx, including executable code examples

📊 UPSTREAM DATA (Read from P6 YAML)
| Metric | Value | Source |
|--------|-------|--------|
| P6 Verified Risk Count | {actual_value} | P6_validated_risks.yaml → risk_summary.total_verified |
| P6 Theoretical Risk Count | {actual_value} | P6_validated_risks.yaml → risk_summary.total_theoretical |
| P6 Critical Risk Count | {actual_value} | P6_validated_risks.yaml → risk_summary.risk_by_severity.critical |
| P6 High Risk Count | {actual_value} | P6_validated_risks.yaml → risk_summary.risk_by_severity.high |
| Tech stack | {actual_value} | P1_project_context.yaml → project_context.tech_stack |

❓ UNKNOWNS
- Specific code fix locations
- Best practice implementation details
- ASVS compliance requirements

⚠️ RISKS
- VR-xxx missing corresponding MIT-xxx
- Mitigation measures too generic (no specific code)
- Missing verification steps
- KB mitigation coverage too low

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⛔ STOP CHECK
- P6 YAML read? [YES/NO]
- P6 risk count recorded? [YES/NO]
- Upstream data complete? [YES/NO]
- Ready to continue PLANNING? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ **STOP CONDITION**: If any STOP CHECK = NO → Read P6 data first before continuing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 📋 PLANNING - Sub-task Decomposition
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Step 1: Read Upstream Data** (BLOCKING - MUST execute)
```bash
# Read P6 validated risks
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 6 --summary --root .
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 6 --type risks --root .

# Or read directly
cat .phase_working/{SESSION_ID}/data/P6_validated_risks.yaml
```
⛔ If P6 YAML does not exist or is invalid → STOP and return to complete P6

**Step 2: Output Sub-task Table** (MANDATORY)

**⚠️ You MUST output PLANNING results in the following format:**

```
📋 PLANNING - P7 Sub-tasks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| # | Sub-task | Expected Output |
|---|----------|-----------------|
| T1 | Read P6 data, extract VR-xxx inventory | VR inventory |
| T2 | Design immediate mitigations for P0 (Critical) risks | MIT-xxx (Critical) |
| T3 | Design urgent mitigations for P1 (High) risks | MIT-xxx (High) |
| T4 | Design planned mitigations for P2/P3 risks | MIT-xxx (Medium/Low) |
| T5 | KB query - CWE mitigations and ASVS mapping | KB references |
| T6 | Create implementation roadmap | roadmap |
| T7 | Write final output | P7_mitigation_plan.yaml + MD |

⛔ PLANNING CHECK
- Sub-tasks decomposed? [YES/NO]
- Ready to TaskCreate? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Step 3**: ⚠️ `TaskCreate` ALL sub-tasks before implementation (MANDATORY).

**Step 4: Multi-Perspective Parallel Analysis** (RECOMMENDED)

Launch 5 `‖` sub-agents via `Task` tool (`subagent_type: "general-purpose"`, `model: "opus"`). Each receives P6 validated risks + its perspective prompt, independently designs mitigations for all VR-xxx:

**‖ Architect**: "Design mitigations from an architecture perspective. Focus: structural remediation (component isolation, defense-in-depth reinforcement, trust boundary hardening), architectural refactoring recommendations, dependency decoupling to reduce blast radius."

**‖ Code Auditor**: "Design mitigations from a code audit perspective. Focus: secure coding fixes (input validation, output encoding, parameterized queries), CWE-specific remediation patterns, code-level patches with before/after examples."

**‖ Security Researcher**: "Design mitigations from a security research perspective. Focus: control selection based on industry best practices (NIST, OWASP ASVS, CIS), emerging defense techniques, compensating controls for risks that cannot be fully remediated."

**‖ Penetration Tester**: "Design mitigations from a penetration testing perspective. Focus: verify mitigation effectiveness against known attack paths (from P6 AP/AC), bypass resistance evaluation, regression test scenarios to confirm fix completeness."

**‖ Tester**: "Design mitigation validation plans from a QA perspective. Focus: test case design for each MIT-xxx (unit/integration/E2E), acceptance criteria, regression test coverage, automated test feasibility, CI/CD integration points."

**Merge**: For each VR-xxx → synthesize MIT-xxx combining: architectural fix (Architect) + code patch (Code Auditor) + control selection (Security Researcher) + bypass resistance (Penetration Tester) + validation plan (Tester).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### ⚡ EXECUTION — TaskUpdate(in_progress) → Execute → Verify → TaskUpdate(completed) | Fail → Retry 3x → CHECKPOINT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Output Sequence** (CRITICAL):
1. **Write YAML first**: `.phase_working/{SESSION_ID}/data/P7_mitigation_plan.yaml`
2. **Write MD after**: `.phase_working/{SESSION_ID}/reports/P7-MITIGATION-PLAN.md`

**Key KB Queries**:
```bash
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --cwe CWE-89 --mitigations      # CWE-specific mitigations
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --control authentication         # Security control details
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --asvs-level L2                  # ASVS requirements
```

**Mitigation Coverage Verification**:
```
∀ VR-xxx ∈ P6.validated_risks → ∃ MIT-xxx ∈ P7.mitigation_plan
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🔍 REFLECTION - Completion Verification
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**⚠️ After completing EXECUTION, you MUST output REFLECTION results in the following format:**

```
🔍 REFLECTION - P7 Completion Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| Check Item | Status |
|------------|--------|
| P6 YAML data read and understood? | [✅/❌] |
| P7_mitigation_plan.yaml exists and valid? | [✅/❌] |
| Every VR-xxx has corresponding MIT-xxx? | [✅/❌] |
| kb_mitigation_sources exists? | [✅/❌] |
| P0/P1 risk MIT-xxx have KB references? | [✅/❌] |
| implementation_steps contain specific code? | [✅/❌] |
| roadmap (immediate/short/medium/long) defined? | [✅/❌] |
| ASVS/WSTG references provided? | [✅/❌] |
| `--phase-end` validation passed (exit 0)? | [✅/❌] |

⛔ COMPLETION GATE
- All checks passed? [YES/NO]
- Ready to proceed to P8? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ Any check fails → Fix and re-verify until all pass

---

### ⚠️ Dual Output (YAML first → MD second)

1. **YAML** (PRIMARY): `.phase_working/{SESSION_ID}/data/P7_mitigation_plan.yaml`
2. **MD** (SECONDARY): `.phase_working/{SESSION_ID}/reports/P7-MITIGATION-PLAN.md`
- **Input**: Read `P6_validated_risks.yaml` (❌ NOT .md reports)
- ❌ Writing only .md without .yaml | ✅ .yaml is the authoritative data source

### Required Data Sections in YAML

| Section | Validation |
|---------|------------|
| `mitigation_plan.mitigations[]` | BLOCKING - all mitigations with MIT-xxx IDs |
| `mitigation_plan.roadmap` | BLOCKING - timeline with priorities |

### Validation Gate

Phase 7 CANNOT complete until:
1. `.phase_working/{SESSION_ID}/data/P7_mitigation_plan.yaml` exists and is valid YAML
2. Every validated risk (VR-xxx) has corresponding mitigation (MIT-xxx)
3. Implementation steps are specific (not generic)
4. `.phase_working/{SESSION_ID}/reports/P7-MITIGATION-PLAN.md` exists

---

## Error Handling

| Error | Cause | Recovery Action |
|-------|-------|-----------------|
| P6 YAML not found | P6 not completed | Return to P6, complete risk validation |
| Missing risk_refs | Orphan mitigation | Link MIT-xxx to VR-xxx, verify coverage |
| Generic mitigation | Insufficient detail | Add specific code/config with file:line references |
| KB lookup failure | Knowledge base error | Provide manual ASVS/WSTG reference |

**Fallback Strategy**: If specific implementation cannot be determined due to missing code context, mark mitigation with `implementation_level: guidance` and provide general security principles.

---

## Input Context

← P6: `validated_risks` from `.phase_working/{SESSION_ID}/data/P6_validated_risks.yaml`

### ⚠️ MANDATORY: Query P6 Data Before Planning

**Before starting P7 mitigation planning**, LLM MUST execute these queries to obtain P6 validated risks:

```bash
# Step 1: Get P6 risk summary for overview
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 6 --summary --root .

# Step 2: Get detailed validated risks (PRIMARY input)
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 6 --type risks --root .

# Step 3: Verify P6 coverage for completeness
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --verify-p6-coverage --root .
```

**Or read YAML directly**:
```bash
# PRIMARY source - REQUIRED
cat .phase_working/{SESSION_ID}/data/P6_validated_risks.yaml
```

**CRITICAL**: Every VR-xxx in P6 MUST have a corresponding MIT-xxx mitigation!
```
∀ VR-xxx ∈ P6.validated_risks → ∃ MIT-xxx ∈ P7.mitigation_plan
```

Do NOT plan mitigations from memory. MUST read P6 validated risks first!

## Output Context

→ P8: `mitigation_plan` {mitigations[], roadmap{}}

---

## Core Analysis Goal

Design specific mitigation measures and implementation plans for each validated risk. Focus on actionable, tech-stack-specific remediation that developers can implement.

---

## Knowledge Reference

**Query Commands**:
```bash
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --cwe CWE-89 --mitigations      # CWE-specific mitigations
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --control authentication         # Security control details
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --asvs-level L2                  # ASVS requirements
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --asvs-chapter V4                # ASVS by chapter
${SKILL_PATH:-$CLAUDE_SKILL_DIR}/kb --wstg-category ATHN              # OWASP WSTG tests
```

### KB Mitigation Sources (MANDATORY per GAP-4 Contract)

> **CRITICAL**: P7 MUST query KB for mitigation guidance per KBQueryContract in assets/contracts/data-model.yaml

**Required Queries per Risk**:
1. `--cwe CWE-{NNN} --mitigations` - For each risk's related_cwe
2. `--asvs-level {L1|L2|L3}` - For verification requirements
3. `--control {domain}` - For implementation guidance

```yaml
# In P7_mitigation_plan.yaml - MANDATORY section (GAP-4 Contract)
kb_mitigation_sources:
  # Query record
  queries_made:
    - query: "--cwe CWE-287 --mitigations"
      timestamp: "2026-01-31T14:30:00Z"
      result_count: 8
      usage: "Informed MIT-001 implementation steps"
      mitigations_informed: [MIT-001, MIT-002]
    - query: "--asvs-level L2"
      timestamp: "2026-01-31T14:30:15Z"
      result_count: 286
      usage: "Populated verification.asvs_requirement fields"
      mitigations_informed: [MIT-001, MIT-002, MIT-003]
    - query: "--control authentication"
      timestamp: "2026-01-31T14:30:30Z"
      result_count: 15
      usage: "Detailed implementation guidance for auth controls"
      mitigations_informed: [MIT-001]

  # Source tracking per mitigation
  mitigation_kb_refs:
    - mitigation_id: MIT-001
      cwe_ref: CWE-287
      cwe_mitigations_applied: ["Use multi-factor authentication", "Implement secure session management"]
      asvs_requirement: "V2.1.1"
      control_guidance: "control-set-01"
    - mitigation_id: MIT-002
      cwe_ref: CWE-89
      cwe_mitigations_applied: ["Use parameterized queries", "Apply input validation"]
      asvs_requirement: "V5.3.4"
      control_guidance: "control-set-03"

  # Coverage metrics (MANDATORY)
  coverage:
    total_mitigations: 25
    cwes_with_mitigations: 22       # Mitigations with CWE --mitigations query
    asvs_requirements_mapped: 20    # Mitigations with ASVS refs
    control_guidance_applied: 18    # Mitigations with control refs
    p0_p1_mitigations_total: 8
    p0_p1_with_kb_ref: 8            # MUST be 100% - ERROR if not
    mitigation_kb_coverage: 88.0    # cwes_with_mitigations / total_mitigations

  # Error handling
  errors:
    - query: "--cwe CWE-9999 --mitigations"
      error_type: "not_found"
      action_taken: "Used general CWE category mitigations"
      affected_mitigations: [MIT-015]

  kb_available: true
```

**Validation Rules** (GAP-4 Contract):
- **ERROR**: P0/P1 mitigation without any KB reference (`p0_p1_with_kb_ref < p0_p1_mitigations_total`)
- **WARNING**: `mitigation_kb_coverage < 70%`
- **INFO**: Generic mitigations should reference control guidance even if CWE-specific unavailable

---

## Mitigation Priority Framework

| Risk Priority | Timeline | Action |
|---------------|----------|--------|
| P0 (Critical) | Immediate | Emergency fix, hotfix deployment |
| P1 (High) | 24-48 hours | Urgent patch, next release |
| P2 (Medium) | 7 days | Planned fix, sprint priority |
| P3 (Low) | 30 days | Backlog, technical debt |

---

## Mitigation Structure

```yaml
mitigation_plan:
  mitigations:
    - id: MIT-001
      title: "Enable JWT Signature Verification"
      risk_refs: [VR-001]                  # MANDATORY: Link to risks
      threat_refs: [T-S-P-001-001, T-E-P-001-002]
      priority: P0
      effort: LOW                          # LOW/MEDIUM/HIGH
      implementation_time: "2 hours"

      # Current State
      current_implementation: |
        jwt.decode(token, options={"verify_signature": False})

      # Recommended Fix
      recommended_fix: |
        # Use proper secret key from environment
        secret_key = os.environ.get('JWT_SECRET_KEY')
        jwt.decode(token, secret_key, algorithms=['HS256'])

      # Detailed Implementation
      implementation_steps:
        - step: 1
          action: "Generate secure JWT secret"
          code: |
            # Generate 256-bit random key
            openssl rand -base64 32 > jwt_secret.txt

        - step: 2
          action: "Store secret in environment"
          code: |
            # .env file
            JWT_SECRET_KEY=<generated-key>

        - step: 3
          action: "Update token verification"
          file: "src/api/auth.py"
          line: 45
          before: |
            def verify_token(token):
                return jwt.decode(token, options={"verify_signature": False})
          after: |
            def verify_token(token):
                secret_key = os.environ.get('JWT_SECRET_KEY')
                if not secret_key:
                    raise ValueError("JWT_SECRET_KEY not configured")
                return jwt.decode(token, secret_key, algorithms=['HS256'])

        - step: 4
          action: "Add unit test"
          code: |
            def test_token_verification_rejects_invalid_signature():
                invalid_token = jwt.encode(
                    {"user_id": "admin"},
                    "wrong_key",
                    algorithm="HS256"
                )
                with pytest.raises(jwt.InvalidSignatureError):
                    verify_token(invalid_token)

      # Verification
      verification:
        test_cases:
          - "Verify valid token is accepted"
          - "Verify invalid signature is rejected"
          - "Verify tampered payload is rejected"
        asvs_requirement: "V3.5.3"
        wstg_test: "WSTG-ATHN-04"

      # Security Controls Applied
      security_controls:
        - control: "Cryptographic verification"
          domain: CRYPTO
        - control: "Authentication token validation"
          domain: AUTHN

      # Additional Recommendations
      additional_recommendations:
        - "Consider using asymmetric keys (RS256) for better key management"
        - "Implement token refresh mechanism"
        - "Add token revocation support"
```

---

## Mitigation Categories

### Code Fixes

Direct code modifications to remediate vulnerabilities:

```yaml
code_fix:
  file: "src/api/auth.py"
  function: "verify_token"
  line_range: "45-50"
  fix_type: security_patch
  before: |
    # Vulnerable code
  after: |
    # Fixed code
  test: |
    # Verification test
```

### Configuration Changes

Security configuration updates:

```yaml
config_change:
  file: ".env.example"
  setting: "JWT_SECRET_KEY"
  current: "not set"
  recommended: "256-bit random key"
  impact: "All JWT operations"
```

### Infrastructure Changes

Infrastructure-level mitigations:

```yaml
infra_change:
  component: "API Gateway"
  change: "Enable WAF rate limiting"
  config: |
    # nginx rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
```

### Process Changes

Operational/process improvements:

```yaml
process_change:
  type: "Security policy"
  description: "Implement code review for auth changes"
  implementation: "Require security team review for auth/* files"
```

---

## Roadmap Structure

```yaml
roadmap:
  immediate:                    # P0 - Do now
    - MIT-001: "Enable JWT verification"
    - MIT-002: "Patch SQL injection"
    timeline: "Within 24 hours"
    owner: "Security Team"

  short_term:                   # P1 - This week
    - MIT-003: "Implement rate limiting"
    - MIT-004: "Add input validation"
    timeline: "7 days"
    owner: "Backend Team"

  medium_term:                  # P2 - This month
    - MIT-005: "Add MFA support"
    - MIT-006: "Implement audit logging"
    timeline: "30 days"
    owner: "Platform Team"

  long_term:                    # P3 - Backlog
    - MIT-007: "Security architecture review"
    - MIT-008: "Penetration testing program"
    timeline: "Q2 planning"
    owner: "Security Team"
```

---

## Report Template

```markdown
# P7: Mitigation Planning

## Executive Summary

| Priority | Count | Timeline |
|----------|-------|----------|
| P0 (Critical) | N | Immediate |
| P1 (High) | N | 24-48h |
| P2 (Medium) | N | 7 days |
| P3 (Low) | N | 30 days |

## Immediate Actions (P0)

### MIT-001: Enable JWT Signature Verification

**Risk**: VR-001 - JWT Bypass (CVSS 9.8)
**Effort**: LOW
**Timeline**: 2 hours

**Current Implementation**:
```python
jwt.decode(token, options={"verify_signature": False})
```

**Recommended Fix**:
```python
secret_key = os.environ.get('JWT_SECRET_KEY')
jwt.decode(token, secret_key, algorithms=['HS256'])
```

**Implementation Steps**:
1. Generate secure secret key
2. Store in environment variables
3. Update verify_token function
4. Add unit tests

**Verification**:
- [ ] Valid tokens accepted
- [ ] Invalid signatures rejected
- [ ] ASVS V3.5.3 compliance

## Short-Term Actions (P1)

### MIT-002: ...

## Implementation Roadmap

| Timeline | Mitigations | Owner |
|----------|-------------|-------|
| Immediate | MIT-001, MIT-002 | Security Team |
| 7 days | MIT-003, MIT-004 | Backend Team |
| 30 days | MIT-005, MIT-006 | Platform Team |

## Mitigation Plan

[yaml:mitigation_plan block]
```

---

## Quality Requirements

### Every Mitigation Must Include:

1. **risk_refs[]**: Link to VR-xxx from Phase 6
2. **Priority**: P0/P1/P2/P3
3. **Implementation Steps**: Actionable code/config changes
4. **Verification**: How to confirm fix works
5. **ASVS/WSTG References**: Compliance mapping

### Avoid Generic Recommendations

**Bad Example**:
```
"Implement proper input validation"
```

**Good Example**:
```python
# src/api/routes.py line 120
# Before:
query = f"SELECT * FROM users WHERE name = '{user_input}'"

# After:
query = "SELECT * FROM users WHERE name = %s"
cursor.execute(query, (user_input,))
```

---

## Validation Gates

| Check | Severity |
|-------|----------|
| yaml:mitigation_plan block present | BLOCKING |
| Every validated risk has mitigation | BLOCKING |
| Implementation steps are specific | WARNING |
| Verification tests defined | WARNING |
| ASVS/WSTG references provided | WARNING |

---

## Completion Checklist

Before marking Phase 7 complete:

- [ ] Every VR-xxx has corresponding MIT-xxx
- [ ] yaml:mitigation_plan present
- [ ] Roadmap with timeline defined
- [ ] Implementation steps are specific (not generic)
- [ ] Code examples provided for code fixes
- [ ] Verification steps defined
- [ ] Validation passed

---

**End of Phase 7 Instructions** (~640 lines, ~5K tokens)
