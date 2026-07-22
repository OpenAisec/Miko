<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Phase 3: Trust Boundary Evaluation

**Type**: Evaluative
**Executor**: LLM
**Knowledge**: Security Principles (ZT, SOD, LP), security-design.yaml

---

## ⚠️ 4-Phase Gating Protocol — THINKING → PLANNING → EXECUTION → REFLECTION (output each stage)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🧠 THINKING - Phase 3 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Purpose**: Identify trust boundaries based on P2 DFD, evaluate cross-boundary security posture.

**⚠️ You MUST output THINKING results in the following format:**

```
🧠 THINKING - P3 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 CORE PROBLEM
Identify all trust boundaries, evaluate security controls for cross-boundary flows

📊 UPSTREAM DATA (Read from P2 YAML)
| Metric | Value | Source |
|--------|-------|--------|
| P2 External Interactor Count | {actual_value} | P2_dfd_elements.yaml → dfd_elements.external_interactors length |
| P2 Process Count | {actual_value} | P2_dfd_elements.yaml → dfd_elements.processes length |
| P2 Data Store Count | {actual_value} | P2_dfd_elements.yaml → dfd_elements.data_stores length |
| P2 Data Flow Count | {actual_value} | P2_dfd_elements.yaml → dfd_elements.data_flows length |
| L1 Coverage Score | {actual_value} | P2_dfd_elements.yaml → l1_coverage.overall.overall_score |

❓ UNKNOWNS
- Trust boundary type distribution (Network/Process/User/Data/Service/Model/Agent)
- Security controls for cross-boundary flows
- Sensitive data node locations

⚠️ RISKS
- DFD elements not fully mapped to boundary zones
- Cross-boundary flows missing security control records
- Boundary diagram missing critical crossing points

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⛔ STOP CHECK
- P2 YAML read? [YES/NO]
- Upstream data complete (all DFD element counts have values)? [YES/NO]
- Ready to continue PLANNING? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ **STOP CONDITION**: If any STOP CHECK = NO → Read P2 data first before continuing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 📋 PLANNING - Sub-task Decomposition
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Step 1: Read Upstream Data** (BLOCKING - MUST execute)
```bash
# Read P2 YAML data
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 2 --summary --root .
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 2 --type dfd --root .

# Or read directly
cat .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
```
⛔ If P2 YAML does not exist or is invalid → STOP and return to complete P2

**Step 2: Output Sub-task Table** (MANDATORY)

**⚠️ You MUST output PLANNING results in the following format:**

```
📋 PLANNING - P3 Sub-tasks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| # | Sub-task | Expected Output |
|---|----------|-----------------|
| T1 | Read P2 DFD data, extract element inventory | Data structure |
| T2 | Identify trust boundaries (TB-xxx), determine types | Boundary inventory |
| T3 | Analyze cross-boundary data flows | Cross-boundary flow mapping |
| T4 | Evaluate interface security (authn/authz/encryption) | Security control assessment |
| T5 | Map sensitive data nodes | Sensitive data markers |
| T6 | Generate boundary diagram (ASCII + Mermaid) | Visual diagrams |
| T7 | Write final output | P3_boundary_context.yaml + MD |

⛔ PLANNING CHECK
- Sub-tasks decomposed? [YES/NO]
- Ready to execute TaskCreate? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Step 3**: ⚠️ `TaskCreate` ALL sub-tasks before implementation (MANDATORY).

**Step 4: Multi-Perspective Parallel Analysis** (RECOMMENDED)

Launch `‖` sub-agents via `Task` tool (`subagent_type: "general-purpose"`, `model: "opus"`). Each receives P2 DFD data + its perspective prompt:

**‖ Architect**: "Evaluate trust boundaries as a software architect. Focus: boundary placement correctness, zone topology design, network segmentation layering, defense-in-depth structure. Verify all DFD components assigned to correct zones and all inter-zone connections identified."

**‖ Security Expert**: "Evaluate trust boundaries as a security expert. Focus: cross-boundary control adequacy (authn/authz/encryption at each crossing), attack surface at boundary interfaces, trust assumption gaps, privilege escalation paths between zones."

**Merge**: Union of findings → deduplicate by boundary ID → keep highest severity on conflict.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### ⚡ EXECUTION — TaskUpdate(in_progress) → Execute → Verify → TaskUpdate(completed) | Fail → Retry 3x → CHECKPOINT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Output Order** (CRITICAL):
1. **Write YAML first**: `.phase_working/{SESSION_ID}/data/P3_boundary_context.yaml`
2. **Write MD second**: `.phase_working/{SESSION_ID}/reports/P3-TRUST-BOUNDARY.md`

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🔍 REFLECTION - Completion Verification
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**⚠️ After completing EXECUTION, you MUST output REFLECTION results in the following format:**

```
🔍 REFLECTION - P3 Completion Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| Check Item | Status |
|------------|--------|
| P2 YAML data read and understood? | [✅/❌] |
| P3_boundary_context.yaml exists and valid? | [✅/❌] |
| All TB-xxx boundaries identified and classified? | [✅/❌] |
| All DFD elements mapped to boundary zones? | [✅/❌] |
| All cross-boundary flows have security control records? | [✅/❌] |
| Boundary diagram (ASCII) included? | [✅/❌] |
| boundary_findings exists (even if empty)? | [✅/❌] |
| `--phase-end` validation passed (exit 0)? | [✅/❌] |

⛔ COMPLETION GATE
- All checks passed? [YES/NO]
- Ready to enter P4? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ If any check fails → Fix and re-verify until all pass

---

### ⚠️ Dual Output (YAML first → MD second)

1. **YAML** (PRIMARY): `.phase_working/{SESSION_ID}/data/P3_boundary_context.yaml`
2. **MD** (SECONDARY): `.phase_working/{SESSION_ID}/reports/P3-TRUST-BOUNDARY.md`
- **Input**: Read `P2_dfd_elements.yaml` (❌ NOT .md reports)
- ❌ Writing only .md without .yaml | ✅ .yaml is the authoritative data source

### Required Data Sections in YAML

| Section | Validation |
|---------|------------|
| `boundary_context.boundaries[]` | BLOCKING - all trust boundaries with TB-xxx IDs |
| `boundary_context.interfaces[]` | BLOCKING - cross-boundary interfaces |
| `boundary_context.data_nodes[]` | BLOCKING - sensitive data locations |
| `boundary_context.cross_boundary_flows[]` | BLOCKING - all boundary crossings |
| `boundary_findings` | WARNING - security observations from boundary analysis |

### Validation Gate

Phase 3 CANNOT complete until:
1. `.phase_working/{SESSION_ID}/data/P3_boundary_context.yaml` exists and is valid YAML
2. Every DFD element mapped to a trust boundary zone
3. All cross-boundary flows have security controls documented
4. `.phase_working/{SESSION_ID}/reports/P3-TRUST-BOUNDARY.md` exists

---

## Input Context

← P2: `dfd_elements` from `.phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml`

### ⚠️ MANDATORY: Query P2 Data Before Analysis

**Before starting P3 analysis**, LLM MUST execute these queries to obtain P2 data:

```bash
# Step 1: Get P2 summary for DFD overview
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 2 --summary --root .

# Step 2: Get detailed DFD elements (REQUIRED for boundary mapping)
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 2 --type dfd --root .

# Step 3: Get data flows (REQUIRED for cross-boundary analysis)
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 2 --type flows --root .
```

**Or read YAML directly**:
```bash
# PRIMARY source - REQUIRED
cat .phase_working/{SESSION_ID}/data/P2_dfd_elements.yaml
```

**CRITICAL**: Do NOT generate P3 trust boundaries from memory. MUST read P2 DFD data first!

## Output Context

→ P4: `boundary_context` {boundaries[], interfaces[], data_nodes[], cross_boundary_flows[]}

---

## Core Analysis Goal

Based on DFD, identify trust boundaries, key interfaces, and data nodes; evaluate security posture at boundary crossings.

---

## Knowledge Reference

**Security Principles**:
- Zero Trust (ZT): Never trust, always verify
- Separation of Duties (SOD): Critical ops require multiple parties
- Least Privilege (LP): Minimum permissions required
- Least Agency (LA): Limit AI agent autonomy

**Security Domains**: AUTHN, AUTHZ, DATA from `security-design.yaml`

---

## Error Handling

| Error | Cause | Recovery Action |
|-------|-------|-----------------|
| P2 YAML not found | P2 not completed | Return to P2, complete DFD analysis |
| DFD elements incomplete | Missing flows or stores | Return to P2 for supplemental analysis |
| Boundary mapping failure | Complex architecture | Break into smaller zones, consult architect |
| Cross-boundary flow gaps | Incomplete P2 data | Document gaps, flag for manual review |

**Fallback Strategy**: If boundary analysis cannot complete due to data gaps, document known boundaries and mark incomplete zones with `status: partial` and `gaps: ["description"]`.

---

## Trust Boundary Types

| Type | Description | Example |
|------|-------------|---------|
| Network | Network segment boundaries | Internet/DMZ, DMZ/Internal |
| Process | Process isolation boundaries | Container, VM, Sandbox |
| User | User privilege boundaries | Anonymous/Authenticated, User/Admin |
| Data | Data sensitivity boundaries | Public/Internal/Confidential |
| Service | Service trust boundaries | Internal/External services |
| **Model** | AI/LLM model boundaries | User/Model, Model/Tool, Model/Data |
| **Agent** | AI agent autonomy boundaries | Human/Agent, Agent/External API |

---

## Analysis Tasks

### 1. Identify Trust Boundaries

For each boundary:
- Assign ID: TB-xxx
- Determine type (Network/Process/User/Data/Service)
- Define scope (which elements are inside)
- Identify crossing points

### 2. Analyze Cross-Boundary Flows

For each data flow crossing a boundary:
- Source boundary zone
- Destination boundary zone
- Security controls at crossing
- Risk assessment

### 3. Evaluate Interface Security

For each cross-boundary interface:
- Authentication mechanism
- Authorization checks
- Data validation
- Encryption status

### 4. Map Sensitive Data Nodes

Identify where sensitive data resides relative to boundaries:
- Which boundary zone
- Access controls
- Encryption status

---

## Output Structure

```yaml
boundary_context:
  boundaries:
    - id: TB-001
      name: "Internet Boundary"
      type: Network
      description: "Boundary between internet and DMZ"
      inside: [P-001]           # Elements inside
      outside: [EI-001, EI-002] # Elements outside
      crossing_points:
        - flow_id: DF-001
          direction: inbound
          controls: [TLS, WAF, Rate-Limit]

  interfaces:
    - id: IF-001
      boundary: TB-001
      entry_side: "Internet"
      exit_side: "DMZ"
      protocol: HTTPS
      authentication: "None (public endpoint)"
      authorization: "N/A"
      validation: "Input sanitization"
      encryption: "TLS 1.3"
      risk_level: HIGH

  data_nodes:
    - id: DN-001
      data_store: DS-001
      data_types: ["User PII", "Credentials"]
      sensitivity: CRITICAL
      boundary_zone: "Internal Network"
      access_controls: ["Role-based", "MFA required"]
      encryption:
        at_rest: true
        in_transit: true

  cross_boundary_flows:
    - flow_id: DF-001
      source_zone: "Internet"
      dest_zone: "DMZ"
      boundaries_crossed: [TB-001]
      data_sensitivity: MEDIUM
      security_controls:
        authentication: "Session token"
        encryption: "TLS 1.3"
        validation: "Input sanitization"
      risk_assessment:
        level: MEDIUM
        concerns: ["Public exposure", "Credential handling"]
```

---

## Boundary Diagram Template

```
┌─────────────────────────────────────────────────────────────────┐
│                     Trust Boundary Diagram                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ╔══════════════════════════════════════════════════════════╗   │
│  ║ TB-001: Internet Boundary                                 ║   │
│  ╠══════════════════════════════════════════════════════════╣   │
│  ║                                                           ║   │
│  ║  ┌─────────┐                                             ║   │
│  ║  │ EI-001  │                                             ║   │
│  ║  │Web User │──────────┐                                  ║   │
│  ║  └─────────┘          │ DF-001                           ║   │
│  ║                       │ [TLS, WAF]                       ║   │
│  ╚═══════════════════════╪══════════════════════════════════╝   │
│                          │                                       │
│  ╔═══════════════════════╪══════════════════════════════════╗   │
│  ║ TB-002: DMZ          ▼                                    ║   │
│  ╠══════════════════════════════════════════════════════════╣   │
│  ║  ┌─────────┐        ┌─────────┐                          ║   │
│  ║  │  P-001  │───────▶│  P-002  │                          ║   │
│  ║  │API Gate │ DF-002 │Auth Svc │                          ║   │
│  ║  └─────────┘        └────┬────┘                          ║   │
│  ╚═══════════════════════════╪══════════════════════════════╝   │
│                              │                                   │
│  ╔═══════════════════════════╪══════════════════════════════╗   │
│  ║ TB-003: Internal Network  │ DF-003                        ║   │
│  ╠═══════════════════════════╪══════════════════════════════╣   │
│  ║                           ▼                               ║   │
│  ║                     ┌─────────┐                           ║   │
│  ║                     │ DS-001  │                           ║   │
│  ║                     │User DB  │                           ║   │
│  ║                     └─────────┘                           ║   │
│  ╚══════════════════════════════════════════════════════════╝   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Assessment Matrix

| Boundary | Crossing Flows | Auth | Encryption | Validation | Risk |
|----------|----------------|------|------------|------------|------|
| TB-001 | DF-001, DF-010 | Token | TLS 1.3 | Input sanitization | Medium |
| TB-002 | DF-002, DF-003 | mTLS | TLS 1.3 | Schema validation | Low |
| TB-003 | DF-003 | DB Auth | TLS 1.3 | Parameterized queries | Low |

---

## Boundary Issues to Identify

1. **Missing Controls**: Boundaries without adequate authentication
2. **Weak Encryption**: Unencrypted or weak encryption at crossings
3. **Excessive Permissions**: Cross-boundary access with excessive privileges
4. **Missing Validation**: Input not validated at boundary crossings
5. **Sensitive Data Exposure**: Sensitive data crossing to lower-trust zones

---

## Report Template

```markdown
# P3: Trust Boundary Evaluation

## Boundary Summary

| Boundary | Type | Elements Inside | Crossing Flows |
|----------|------|-----------------|----------------|
| TB-001 | Network | P-001 | DF-001 |
| TB-002 | Network | P-001, P-002 | DF-002, DF-003 |

## Trust Boundary Diagram

[ASCII diagram]

## Cross-Boundary Flow Analysis

### DF-001: User Request (Internet → DMZ)
- **Source Zone**: Internet
- **Dest Zone**: DMZ
- **Security Controls**: TLS 1.3, WAF, Rate Limiting
- **Risk Level**: Medium
- **Concerns**: Public exposure

## Interface Security Assessment

[Assessment matrix]

## Sensitive Data Mapping

| Data Node | Location | Sensitivity | Protection |
|-----------|----------|-------------|------------|
| DN-001 | Internal | CRITICAL | Encrypted, RBAC |

## Boundary Findings

[yaml:boundary_findings block - see below]

```yaml:boundary_findings
findings:
  - id: F-P3-001
    type: boundary
    title: "Finding title"
    description: "Detailed description"
    severity: HIGH      # CRITICAL|HIGH|MEDIUM|LOW|INFO
    category: missing_control|weak_encryption|excessive_permission|unprotected_crossing
    location:
      boundary_id: TB-xxx
      interface_id: IF-xxx
      flow_id: DF-xxx
    affected_elements:
      - type: trust_boundary
        id: TB-xxx
      - type: cross_boundary_flow
        id: DF-xxx
    security_relevance: "Why this matters for security"
    crossing_risk: HIGH  # Risk level of boundary crossing
    recommended_action: "What to investigate in later phases"

summary:
  total: 0
  by_severity:
    critical: 0
    high: 0
    medium: 0
    low: 0
    info: 0
  by_category:
    missing_control: 0
    weak_encryption: 0
    excessive_permission: 0
    unprotected_crossing: 0
```

**Finding Categories**:
- `missing_control`: Boundary crossing without security control
- `weak_encryption`: Inadequate encryption at boundary
- `excessive_permission`: Cross-boundary access with excessive privileges
- `unprotected_crossing`: Input not validated at boundary

## Recommendations

1. ...
2. ...
```

---

## Completion Checklist

Before marking Phase 3 complete:

- [ ] All trust boundaries identified (TB-xxx)
- [ ] All cross-boundary flows analyzed
- [ ] Interface security assessed
- [ ] Sensitive data nodes mapped
- [ ] Trust boundary diagram included
- [ ] yaml:boundary_findings present (even if empty)
- [ ] Boundary issues documented
- [ ] Validation passed

---

**End of Phase 3 Instructions** (~510 lines, ~4K tokens)
