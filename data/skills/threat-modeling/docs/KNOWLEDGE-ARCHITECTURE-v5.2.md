<!-- Threat Modeling Skill | Version 3.1.0 (20260313a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# STRIDE Skill Set - Knowledge Architecture v5.2

**Version**: 5.2.1
**Date**: 2026-01-04 (updated 2026-03-13)
**Status**: Production - v3.1.0

---

## 1. Vision Statement

> **"Code-First Automated Application Security Risk Assessment and Threat Modeling Toolkit"**
>
> An LLM-driven automated system for:
> - **Security Design Assessment**
> - **Threat Modeling Assessment**
> - **Infrastructure Security Assessment**
>
> With specialized extensions for:
> - **Cloud-Native Applications**
> - **LLM/AI Applications**

---

## 2. Knowledge System Architecture

### 2.1 Dual-Track Knowledge System

The knowledge system consists of two parallel sets that work together:

```
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                              Security Knowledge Architecture                                   │
├───────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                │
│                       ┌───────────────────────────────────────────┐                           │
│                       │         Security Principles               │                           │
│                       │    (Foundation - Guides All Phases)       │                           │
│                       │  DID │ LP │ ZT │ FS │ SOD │ SBD │ CM │ EOM │ OD │ IV                 │
│                       └───────────────────────────────────────────┘                           │
│                                           │                                                    │
│                 ┌─────────────────────────┴─────────────────────────┐                         │
│                 │                                                    │                         │
│                 ▼                                                    ▼                         │
│  ┌─────────────────────────────────────┐      ┌─────────────────────────────────────┐        │
│  │      Security Control Set          │      │      Threat Pattern Set             │        │
│  │      (What to do & How to do)      │      │      (What to know & Validate)      │        │
│  ├─────────────────────────────────────┤      ├─────────────────────────────────────┤        │
│  │                                     │      │                                     │        │
│  │  Security Domains (16)              │      │  CWE Weakness Types (974)           │        │
│  │      │                              │      │      │                              │        │
│  │      ▼                              │      │      ▼                              │        │
│  │  Control Sets (18 files, 107)       │      │  CAPEC Attack Patterns (615)        │        │
│  │      │                              │      │      │                              │        │
│  │      ▼                              │      │      ▼                              │        │
│  │  OWASP References (73)              │      │  ATT&CK Techniques (835)            │        │
│  │      │                              │      │      │                              │        │
│  │      ▼                              │      │      ▼                              │        │
│  │  Compliance Frameworks (14)         │      │  CVE/KEV Vulnerabilities (323K+)    │        │
│  │                                     │      │                                     │        │
│  └──────────────┬──────────────────────┘      └──────────────┬──────────────────────┘        │
│                 │                                             │                               │
│                 │      ┌─────────────────────────────┐        │                               │
│                 │      │    Verification Set         │        │                               │
│                 │      │  (How to verify & test)     │        │                               │
│                 │      ├─────────────────────────────┤        │                               │
│                 │      │                             │        │                               │
│                 └─────▶│  WSTG Tests (121)           │◀───────┘                               │
│                        │      │                      │                                        │
│                        │      ▼                      │                                        │
│                        │  MASTG Tests (206)          │                                        │
│                        │      │                      │                                        │
│                        │      ▼                      │                                        │
│                        │  ASVS Requirements (345)    │                                        │
│                        │                             │                                        │
│                        └─────────────────────────────┘                                        │
│                                     │                                                          │
│                                     ▼                                                          │
│                        Used in: Phase 6 (Validation) / Phase 7 (Mitigation) / Phase 8 (Report)│
│                                                                                                │
│  Cross-Set Mappings:                                                                          │
│  ├── STRIDE → Security Domains ←→ CWE Weakness Types                                         │
│  ├── Control Sets ←→ CWE Mitigations                                                         │
│  ├── CAPEC → ATT&CK Techniques                                                                │
│  ├── Compliance ←→ CWE Compliance Mappings                                                   │
│  ├── stride_verification → WSTG/MASTG/ASVS (STRIDE to Verification)                          │
│  └── cwe_verification → WSTG/MASTG/ASVS (CWE to Verification)                                │
│                                                                                                │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Security Principles (Foundation Layer)

Security Principles serve as the foundation that guides all phases of the threat modeling process.

| Code | Principle | Definition | Application in Security Control | Application in Threat Analysis |
|------|-----------|------------|--------------------------------|-------------------------------|
| **DID** | Defense in Depth | 纵深防御 | Multiple independent security controls | Identify single points of failure |
| **LP** | Least Privilege | 最小权限 | Permission control design | Detect over-privileged access |
| **ZT** | Zero Trust | 零信任 | Continuous verification mechanisms | Identify implicit trust risks |
| **FS** | Fail Securely | 安全失败 | Deny/degrade on failure | Detect error handling leaks |
| **SOD** | Separation of Duties | 职责分离 | Multi-role collaboration | Identify privilege concentration |
| **SBD** | Security by Design | 安全设计 | Built-in security | Identify retrofit vulnerabilities |
| **CM** | Continuous Monitoring | 持续监控 | Real-time detection and alerting | Identify detection blind spots |
| **EOM** | Economy of Mechanism | 机制简化 | Simple and verifiable | Identify complexity risks |
| **OD** | Open Design | 开放设计 | No security by obscurity | Identify obscurity dependencies |
| **IV** | Input Validation | 输入验证 | Boundary validation | Identify injection surfaces |

### 2.3 Security Control Set

```
Security Domains ──▶ Control Sets ──▶ OWASP References ──▶ Compliance Frameworks
       │                  │                  │                      │
       │                  │                  │                      │
   security-         control-set-       reference-set-          YAML + SQLite
   design.yaml         *.md               *.md              (compliance tables)
```

**Security Domains (16 total)**:

| Seq | Code | Name | STRIDE | Description |
|-----|------|------|--------|-------------|
| 01 | AUTHN | 认证与会话 | S | Identity verification and session lifecycle |
| 02 | AUTHZ | 授权访问控制 | E | Access permission enforcement |
| 03 | INPUT | 输入验证 | T | External input validation and sanitization |
| 04 | OUTPUT | 输出编码 | T,I | Context-aware output encoding |
| 05 | CLIENT | 客户端安全 | S,T,I | Browser and client-side security |
| 06 | CRYPTO | 加密与传输安全 | I | Data encryption in transit and at rest |
| 07 | LOG | 日志与监控 | R | Security event logging and audit |
| 08 | ERROR | 错误处理 | I | Secure error handling and information control |
| 09 | API | API与服务安全 | S,T,I,D,E | API endpoint and service communication security |
| 10 | DATA | 数据保护 | I | Sensitive data and credential protection |
| ext-11 | INFRA | 基础设施安全 | - | Container and orchestration security |
| ext-12 | SUPPLY | 供应链安全 | - | Dependency and pipeline security |
| ext-13 | AI | AI/LLM安全 | - | LLM-specific threats (OWASP LLM Top 10) |
| ext-14 | MOBILE | 移动端安全 | - | Mobile app security |
| ext-15 | CLOUD | 云服务安全 | - | Cloud-native security controls |
| ext-16 | AGENT | Agent安全 | S,T,R,I,D,E | Agent system and agentic component security (OWASP ASI) |

### 2.4 Threat Pattern Set

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              Threat Intelligence Chain                                    │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  L1: STRIDE       L2: 威胁情报知识层                          L3/L4: 验证与实时         │
│  ───────────      ────────────────────────────────────        ─────────────────         │
│                                                                                          │
│  ┌─────────┐      ┌───────┐      ┌───────┐      ┌─────────┐      ┌───────────────┐     │
│  │ STRIDE  │─────▶│  CWE  │─────▶│ CAPEC │─────▶│ ATT&CK  │─────▶│ CVE/KEV       │     │
│  │ 6类别   │      │ 弱点  │      │ 攻击  │      │  技术   │      │ 漏洞/已利用   │     │
│  └─────────┘      └───────┘      └───────┘      └─────────┘      └───────────────┘     │
│       │               │              │               │                  │               │
│  stride-         SQLite:cwe    SQLite:capec   SQLite:attack_*    SQLite:cve + API      │
│  library.yaml    (974条)       (615条)        (835条)            (323K+)               │
│                                                                                          │
│  映射表: stride_cwe → capec_cwe → capec_attack → cve_cwe                               │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

#### L1: STRIDE 威胁分类模型

STRIDE 是威胁情报体系的基础层，定义6大威胁类别：

| STRIDE | 英文名 | 中文 | 违反的安全属性 | 存储位置 |
|--------|--------|------|----------------|----------|
| **S** | Spoofing | 身份伪造 | 认证 (Authentication) | stride-library.yaml |
| **T** | Tampering | 数据篡改 | 完整性 (Integrity) | stride-library.yaml |
| **R** | Repudiation | 抵赖 | 不可否认性 (Non-repudiation) | stride-library.yaml |
| **I** | Information Disclosure | 信息泄露 | 机密性 (Confidentiality) | stride-library.yaml |
| **D** | Denial of Service | 拒绝服务 | 可用性 (Availability) | stride-library.yaml |
| **E** | Elevation of Privilege | 权限提升 | 授权 (Authorization) | stride-library.yaml |

#### L1→L2 映射关系

```
L1 STRIDE 类别 → L2 威胁情报知识:
─────────────────────────────────────────────────────────────────────────────
S(身份伪造) → CWE-287/290/307 → CAPEC-151/194/600 → T1078/T1110 → CVE-*
T(数据篡改) → CWE-20/77/89    → CAPEC-66/88/248   → T1190/T1059 → CVE-*
R(抵赖)     → CWE-117/223/778 → CAPEC-93/268      → T1070/T1562 → CVE-*
I(信息泄露) → CWE-200/209/311 → CAPEC-116/157/497 → T1552/T1213 → CVE-*
D(拒绝服务) → CWE-400/770/918 → CAPEC-125/227/469 → T1498/T1499 → CVE-*
E(权限提升) → CWE-269/284/862 → CAPEC-122/233/17  → T1068/T1548 → CVE-*
```

#### L2: 威胁情报知识层

**STRIDE to CWE Mapping Chain**:

| STRIDE | OWASP Top 10 | Primary CWEs | Typical Attack Patterns |
|--------|--------------|--------------|------------------------|
| S (Spoofing) | A07 Auth Failures | CWE-287, 290, 307 | CAPEC-151, 194, 600 |
| T (Tampering) | A03 Injection | CWE-20, 77, 78, 89 | CAPEC-66, 88, 248 |
| R (Repudiation) | A09 Logging Failures | CWE-117, 223, 778 | CAPEC-93 |
| I (Info Disclosure) | A02 Crypto Failures | CWE-200, 209, 311 | CAPEC-116, 157 |
| D (DoS) | A10 SSRF | CWE-400, 770, 918 | CAPEC-125, 227 |
| E (Elevation) | A01 Access Control | CWE-269, 284, 862 | CAPEC-122, 233 |

### 2.5 Verification Set (Cross-Cutting)

The Verification Set bridges both Security Control Set and Threat Pattern Set, providing test procedures to validate controls and verify threats.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              Verification Set Structure                                  │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ WSTG (Web Security Testing Guide) - 121 Tests                                    │   │
│  │     Categories: INFO, CONF, IDNT, ATHN, AUTHZ, SESS, INPV, ERRH, CRYP, BUSL,    │   │
│  │                 CLNT, APIT                                                       │   │
│  │     Storage: SQLite (wstg_test table)                                           │   │
│  │     Mappings: stride_verification, cwe_verification                              │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                              │                                           │
│                                              ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ MASTG (Mobile App Security Testing Guide) - 206 Tests                            │   │
│  │     Categories: MASVS-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK,          │   │
│  │                 MASVS-PLATFORM, MASVS-CODE, MASVS-RESILIENCE                     │   │
│  │     Storage: SQLite (mastg_test table)                                          │   │
│  │     Mappings: stride_verification, cwe_verification                              │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                              │                                           │
│                                              ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ ASVS (Application Security Verification Standard) - 345 Requirements             │   │
│  │     Levels: L1 (Essential), L2 (Standard), L3 (Advanced)                         │   │
│  │     Chapters: V1-V14 (Architecture to API, Config, Storage, Crypto, etc.)       │   │
│  │     Storage: SQLite (asvs_requirement table)                                     │   │
│  │     Mappings: stride_verification, cwe_verification                              │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

**STRIDE to Verification Mapping**:

| STRIDE | Verification Categories | Test Count |
|--------|------------------------|------------|
| S (Spoofing) | WSTG-IDNT, WSTG-ATHN, WSTG-SESS, MASTG-AUTH | 27 |
| T (Tampering) | WSTG-INPV, WSTG-CONF, MASTG-PLATFORM | 34 |
| R (Repudiation) | WSTG-BUSL, ASVS-V7 (Error/Logging) | 11 |
| I (Info Disclosure) | WSTG-INFO, WSTG-ERRH, WSTG-CRYP, MASTG-STORAGE | 31 |
| D (DoS) | WSTG-BUSL, WSTG-APIT | 15 |
| E (Elevation) | WSTG-AUTHZ, MASTG-AUTH, ASVS-V4 (Access) | 16 |

**SQLite Verification Tables**:

| Table | Content | Records | Purpose |
|-------|---------|---------|---------|
| `wstg_test` | Web security test procedures | 121 | Web application testing |
| `mastg_test` | Mobile security test procedures | 206 | Mobile app testing |
| `asvs_requirement` | Security verification requirements | 345 | Compliance verification |
| `stride_verification` | STRIDE → Test mappings | - | Phase 6 validation |
| `cwe_verification` | CWE → Test mappings | - | CWE-based testing |
| `verification_procedure` | Detailed test procedures | - | POC/Test case generation |

**Query Commands**:

```bash
# Get verification tests for STRIDE category
unified_kb_query.py --stride-tests S

# Get verification tests for CWE
unified_kb_query.py --cwe-tests CWE-89

# Get ASVS requirements for compliance
unified_kb_query.py --asvs-level L2 --chapter V4

# Get WSTG tests for specific category
unified_kb_query.py --wstg-category ATHN
```

**Phase Usage**:

| Phase | Verification Set Usage |
|-------|----------------------|
| Phase 6 | `stride_verification` + `cwe_verification` → Generate test cases for each risk |
| Phase 7 | `asvs_requirement` → Verify mitigation meets security requirements |
| Phase 8 | `asvs_requirement` + Compliance mapping → Report compliance status |

---

## 3. Eight-Phase Workflow with Data Flow

### 3.1 Phase Overview

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              8-Phase Deep Threat Modeling Workflow                                │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                   │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│  │ Phase 1 │──▶│ Phase 2 │──▶│ Phase 3 │──▶│ Phase 4 │──▶│ Phase 5 │──▶│ Phase 6 │──▶│ Phase 7 │──▶│ Phase 8 │
│  │ Project │   │  DFD    │   │ Trust   │   │Security │   │ STRIDE  │   │  Risk   │   │Mitigate │   │ Report  │
│  │   Ctx   │   │ Analysis│   │Boundary │   │ Design  │   │Analysis │   │Validate │   │  Plan   │   │Generate │
│  └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘
│       │             │             │             │             │             │             │             │
│       ▼             ▼             ▼             ▼             ▼             ▼             ▼             ▼
│   findings_1    findings_2    findings_3    findings_4    findings_5  validated_    mitigation_   final_
│   [project_ctx] [dfd_issues]  [boundary_   [design_gaps] [threat_inv] risks        plan         report
│                               issues]
│                                                                                                   │
│  ════════════════════════════════════════════════════════════════════════════════════════════════│
│  Execution Mode: Strictly Sequential (Phase N must complete before Phase N+1)                    │
│  Parallel Support: Phase 5/6/7 can spawn parallel sub-agents for individual risk items           │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Phase Data Flow Specification

#### Phase 1: Project Understanding

| Attribute | Value |
|-----------|-------|
| **Type** | Exploratory |
| **Input** | Project code tree |
| **Knowledge** | Security Principles |
| **Script** | `list_files.py --detect-type` |
| **Output** | `findings_1`: Project context, tech stack, entry points, dependencies |

```yaml
findings_1:
  project_type: web|api|microservice|ai|mobile
  tech_stack: [framework, language, database, ...]
  entry_points: [routes, handlers, main, ...]
  dependencies: [packages, external_services, ...]
  initial_concerns: [potential_issues, ...]
```

---

#### Phase 2: Call Flow & DFD Analysis

| Attribute | Value |
|-----------|-------|
| **Type** | Constructive |
| **Input** | `findings_1` + Source code |
| **Knowledge** | Security Principles + `security-design.yaml` (for security-relevant flow identification) |
| **Script** | - (Claude native capability) |
| **Output** | `findings_2`: DFD elements, data flow issues |

```yaml
findings_2:
  dfd_elements:
    processes: [{id, name, description, security_aspects}, ...]
    data_stores: [{id, name, data_types, sensitivity}, ...]
    data_flows: [{id, source, target, data_type, protocol}, ...]
    external_entities: [{id, name, trust_level}, ...]
  dfd_issues:  # Issues discovered during DFD analysis
    - {id: "DFD-001", category: "data_flow", description: "...", severity: "..."}
```

**Knowledge Reference**: `security-design.yaml` provides security domains context for identifying security-relevant data flows (authentication flows, authorization checkpoints, sensitive data paths).

---

#### Phase 3: Trust Boundaries

| Attribute | Value |
|-----------|-------|
| **Type** | Evaluative |
| **Input** | `findings_1` + `findings_2` + Source code |
| **Knowledge** | Security Principles + `security-design.yaml` (for boundary placement criteria) |
| **Script** | - (Claude native capability) |
| **Output** | `findings_3`: Trust boundaries, boundary crossing issues |

```yaml
findings_3:
  trust_boundaries:
    - {id: "TB-1", name: "Internet/DMZ", elements: [...], controls_expected: [...]}
    - {id: "TB-2", name: "DMZ/Internal", elements: [...], controls_expected: [...]}
  boundary_crossings:
    - {flow_id, boundary_id, direction, authentication_required, current_state}
  boundary_issues:  # Issues discovered during boundary analysis
    - {id: "TB-001", category: "trust_boundary", description: "...", severity: "..."}
```

**Knowledge Reference**: `security-design.yaml` core domains (AUTHN, AUTHZ, API) provide expected controls at trust boundaries.

---

#### Phase 4: Security Design Assessment

| Attribute | Value |
|-----------|-------|
| **Type** | Evaluative |
| **Input** | `findings_1` + `findings_2` + `findings_3` (cumulative context) |
| **Knowledge** | `security-design.yaml` + `security-controls/*.md` + `references/*.md` (progressive loading) |
| **Script** | `--control {domain}`, `--stride-controls {category}` |
| **Output** | `findings_4`: Security design gaps |

**Knowledge Loading Strategy**:
1. Load `security-design.yaml` - Get all 16 domains with core requirements
2. For each relevant domain, load corresponding `control-set-*.md`
3. When specific implementation details needed, load `reference-set-*.md`

```yaml
findings_4:
  assessed_domains:
    - domain: AUTHN
      status: partial|missing|implemented
      gaps: [{control_id, description, severity}, ...]
      evidence: [code_locations, ...]
    - domain: AUTHZ
      status: ...
  design_issues:  # Issues discovered during design assessment
    - {id: "SD-001", domain: "AUTHN", control: "MFA", description: "...", severity: "..."}
```

---

#### Phase 5: STRIDE Analysis

| Attribute | Value |
|-----------|-------|
| **Type** | Enumerative |
| **Input** | `findings_2` (DFD elements) + `findings_3` (boundaries) |
| **Knowledge** | CWE → CAPEC mapping (Threat Pattern Set) |
| **Script** | `unified_kb_query.py --stride`, `--full-chain CWE-XXX`, `--all-llm` |
| **Output** | `findings_5`: Threat inventory |

**STRIDE per Element Matrix**:

| Element Type | Applicable STRIDE |
|--------------|-------------------|
| Process | S, T, R, I, D, E (all 6) |
| Data Store | T, R, I, D |
| Data Flow | T, I, D |
| External Entity (as source) | S, R |

```yaml
findings_5:
  threat_inventory:
    - id: "T-S-P001-001"
      element: {type: process, id: P001, name: "AuthService"}
      stride_category: S
      description: "..."
      cwe_ids: [CWE-287, CWE-290]
      capec_ids: [CAPEC-151]
      severity: high|medium|low
      likelihood: high|medium|low
    - ...
```

---

#### Phase 6: Risk Validation

| Attribute | Value |
|-----------|-------|
| **Type** | Verification |
| **Input** | **ALL previous findings consolidated**: `findings_1` + `findings_2` + `findings_3` + `findings_4` + `findings_5` |
| **Knowledge** | Threat Pattern Set (CAPEC → ATT&CK → CVE/KEV) + **Verification Set** (WSTG/MASTG/ASVS) |
| **Script** | `--capec`, `--attack-technique`, `--cve-for-cwe`, `--check-kev`, `--stride-tests`, `--cwe-tests` |
| **Output** | `validated_risks`: Comprehensive validated risk analysis |

**Verification Set Integration**:
- Use `stride_verification` to get STRIDE-specific test procedures
- Use `cwe_verification` to get CWE-specific test cases
- Generate POC/test cases from `verification_procedure` table

**Consolidation Process**:
1. Merge all findings from P1-P5 into unified issue list
2. Deduplicate and group related issues
3. Perform detailed validation for each unique risk

**Output Structure**:
```yaml
validated_risks:
  # Part 1: Validated Risk List with Assessment Summary
  risk_summary:
    total_identified: 45
    validated_high: 12
    validated_medium: 18
    validated_low: 10
    dismissed: 5
    risk_by_stride: {S: 8, T: 12, R: 3, I: 10, D: 4, E: 8}
    risk_by_domain: {AUTHN: 10, INPUT: 15, ...}

  # Part 2: Detailed Risk Analysis per Item
  risk_details:
    - risk_id: "VR-001"
      original_refs: ["T-S-P001-001", "SD-001", "DFD-002"]  # Consolidated from multiple phases

      # 2.1 Issue Location
      location:
        files: ["src/auth/login.py:45-67", "src/api/handlers.py:120"]
        elements: ["P1:AuthService", "DF-3:UserCredentials"]
        trust_boundary: "TB-1:Internet/DMZ"

      # 2.2 Detailed Analysis
      detailed_analysis:
        vulnerability_type: "CWE-287 Improper Authentication"
        description: "Authentication bypass possible via..."
        technical_details: "The login function at line 45..."
        attack_surface: "External, unauthenticated"
        affected_data: ["user_credentials", "session_tokens"]
        impact: "Complete authentication bypass..."

      # 2.3 Root Cause Analysis
      root_cause:
        primary_cause: "Missing authentication check on alternative endpoint"
        contributing_factors:
          - "No centralized authentication middleware"
          - "Inconsistent route protection patterns"
        design_flaw: true
        implementation_flaw: true
        cwe_chain: [CWE-287, CWE-863]

      # 2.4 Test Cases / POC Analysis
      validation:
        test_cases:
          - name: "TC-001: Direct endpoint access"
            method: "GET /api/v2/user/profile without token"
            expected: "401 Unauthorized"
            actual: "200 OK with user data"
            result: FAIL
          - name: "TC-002: Token tampering"
            method: "Modify JWT payload, skip signature"
            expected: "401 Unauthorized"
            actual: "200 OK"
            result: FAIL
        poc_available: true
        poc_complexity: low
        cvss_score: 9.1
        kev_status: false

  # Part 3: Attack Path Analysis
  attack_paths:
    - path_id: "AP-001"
      name: "Authentication Bypass to Data Exfiltration"
      risk_refs: ["VR-001", "VR-005", "VR-012"]
      description: "Attacker chains authentication bypass with..."

      # 3.1 Attack Path Design
      attack_chain:
        entry_point: "External:Internet"
        target: "DataStore:UserDatabase"
        trust_boundaries_crossed: ["TB-1", "TB-2"]
        techniques_used:
          - capec: CAPEC-151
            attack: T1078
            description: "Identity Spoofing via authentication bypass"
          - capec: CAPEC-116
            attack: T1552
            description: "Credential extraction from memory"

      # Part 4: Step-by-Step Attack Flow
      detailed_steps:
        - step: 1
          phase: "Reconnaissance"
          action: "Enumerate API endpoints via /swagger.json"
          technique: T1592.002
          tools: ["curl", "burpsuite"]
          commands: |
            curl -s https://target.com/swagger.json | jq '.paths | keys'
          expected_result: "List of all API endpoints"

        - step: 2
          phase: "Initial Access"
          action: "Access unprotected /api/v2/user endpoint"
          technique: T1190
          tools: ["curl"]
          commands: |
            curl -s https://target.com/api/v2/user/profile \
              -H "X-Forwarded-For: 127.0.0.1"
          expected_result: "User profile data returned without authentication"

        - step: 3
          phase: "Credential Access"
          action: "Extract session tokens from response"
          technique: T1552.001
          tools: ["jq", "python"]
          poc_code: |
            import requests
            resp = requests.get("https://target.com/api/v2/user/profile")
            tokens = resp.json().get("active_sessions", [])
            print(f"Extracted {len(tokens)} session tokens")
          expected_result: "Valid session tokens extracted"

        - step: 4
          phase: "Lateral Movement"
          action: "Use extracted tokens to access other user accounts"
          technique: T1550.001
          commands: |
            for token in $TOKENS; do
              curl -s https://target.com/api/v1/admin \
                -H "Authorization: Bearer $token"
            done
          expected_result: "Access to admin functionality"

      overall_complexity: medium
      detection_difficulty: high
      business_impact: critical
```

---

#### Phase 7: Mitigation Planning

| Attribute | Value |
|-----------|-------|
| **Type** | Prescriptive |
| **Input** | `validated_risks` (complete Phase 6 output) |
| **Knowledge** | Security Control Set (Control Sets + OWASP References) + CWE Mitigations + **Verification Set** (ASVS) |
| **Script** | `--cwe --mitigations`, `--control {domain}`, `--asvs-level`, `--asvs-chapter` |
| **Output** | `mitigation_plan`: Risk-by-risk mitigation strategy |

**Verification Set Integration**:
- Use `asvs_requirement` to ensure mitigations meet ASVS security requirements
- Map each mitigation to specific ASVS levels (L1/L2/L3) for compliance tracking
- Include ASVS verification method in mitigation verification criteria

**Processing**: For each validated risk in `validated_risks.risk_details`, design specific mitigations.

```yaml
mitigation_plan:
  - risk_id: "VR-001"
    risk_summary: "Authentication bypass via unprotected endpoint"
    severity: critical

    immediate_actions:  # Quick fixes (hours)
      - action: "Block unprotected endpoint at WAF/gateway level"
        implementation: |
          # nginx configuration
          location /api/v2/user {
            auth_request /auth/verify;
          }
        effort: 1h
        risk_reduction: 80%

    short_term_fixes:  # Code changes (days)
      - action: "Add authentication middleware to all /api/v2 routes"
        control_ref: "control-set-01-authentication.md#centralized-auth"
        implementation_guide: "reference-set-01-authentication.md"
        code_changes:
          - file: "src/middleware/auth.py"
            change_type: create
            content: |
              from functools import wraps
              def require_auth(f):
                  @wraps(f)
                  def decorated(*args, **kwargs):
                      token = request.headers.get('Authorization')
                      if not validate_token(token):
                          abort(401)
                      return f(*args, **kwargs)
                  return decorated
          - file: "src/api/v2/routes.py"
            change_type: modify
            diff: |
              - @app.route('/api/v2/user/profile')
              + @app.route('/api/v2/user/profile')
              + @require_auth
        effort: 2d
        test_verification:
          - "Verify all v2 endpoints return 401 without valid token"
          - "Run TC-001, TC-002 from validation - expect PASS"

    long_term_improvements:  # Architectural (weeks)
      - action: "Implement centralized API gateway with built-in auth"
        control_ref: "control-set-09-api-security.md#gateway-pattern"
        architecture_change: true
        effort: 2w

    verification_criteria:
      - "All test cases from VR-001 validation pass"
      - "Security scan shows no auth bypass vulnerabilities"
      - "Penetration test confirms fix effectiveness"
```

---

#### Phase 8: Report Generation

| Attribute | Value |
|-----------|-------|
| **Type** | Comprehensive |
| **Input** | **ALL phase outputs**: `findings_1` through `mitigation_plan` |
| **Knowledge** | Compliance Frameworks + **Verification Set** (ASVS for compliance verification) |
| **Script** | `--compliance {framework}`, `--asvs-level`, `--asvs-chapter` |
| **Output** | `final_report`: Complete threat model report |

**Verification Set Integration**:
- Use `asvs_requirement` to generate ASVS compliance status per chapter
- Map validated risks to ASVS requirements for gap analysis
- Include ASVS level (L1/L2/L3) compliance matrix in report

**Report Structure**:

```yaml
final_report:
  # Executive Summary
  executive_summary:
    project: "..."
    assessment_date: "2026-01-03"
    risk_posture: critical|high|medium|low
    key_findings:
      - "12 critical risks identified, 8 require immediate action"
      - "Authentication subsystem has fundamental design flaws"
    recommended_priority:
      - "VR-001: Authentication bypass (Critical)"
      - "VR-005: SQL injection in search (Critical)"

  # Section 1: Project Context (from findings_1)
  project_context:
    # ... (Phase 1 output)

  # Section 2: Architecture Analysis (from findings_2, findings_3)
  architecture:
    dfd_diagram: "..."  # Mermaid/ASCII diagram
    trust_boundaries: [...]
    data_flow_summary: [...]

  # Section 3: Security Design Gaps (from findings_4)
  security_design:
    assessed_domains: [...]
    gap_summary: [...]

  # Section 4: Threat Inventory (from findings_5)
  threats:
    by_stride: {...}
    by_severity: {...}
    full_inventory: [...]

  # Section 5: Validated Risks - FULL DETAIL (from validated_risks)
  # CRITICAL: This section must include ALL content from Phase 6
  validated_risks:
    risk_summary: {...}
    risk_details: [...]  # Complete detailed analysis
    attack_paths: [...]  # Complete attack path analysis with POCs

  # Section 6: Mitigation Plan - FULL DETAIL (from mitigation_plan)
  # CRITICAL: This section must include ALL mitigations
  mitigation:
    prioritized_actions: [...]
    implementation_roadmap: [...]
    resource_requirements: {...}

  # Section 7: Compliance Mapping
  compliance:
    frameworks_assessed: ["OWASP ASVS", "NIST 800-53", ...]
    gap_analysis: [...]
    recommendations: [...]

  # Appendices
  appendices:
    a_full_threat_list: [...]
    b_poc_scripts: [...]
    c_test_cases: [...]
    d_references: [...]
```

---

## 4. Phase to Knowledge Mapping

### 4.1 Complete Mapping Table

| Phase | Name | Type | Security Control Set | Threat Pattern Set | Verification Set | Script Support |
|-------|------|------|----------------------|---------------------|------------------|----------------|
| 1 | Project Understanding | Exploratory | - | - | - | `list_files.py` |
| 2 | Call Flow & DFD | Constructive | `security-design.yaml` | - | - | - |
| 3 | Trust Boundaries | Evaluative | `security-design.yaml` | - | - | - |
| 4 | Security Design | Evaluative | `security-design.yaml` → `control-set-*.md` → `reference-set-*.md` | - | - | `--control`, `--stride-controls` |
| 5 | STRIDE Analysis | Enumerative | - | CWE → CAPEC | - | `--stride`, `--full-chain`, `--all-llm` |
| 6 | Risk Validation | Verification | - | CAPEC → ATT&CK → CVE/KEV | **WSTG + MASTG** (test generation) | `--capec`, `--attack-technique`, `--stride-tests`, `--cwe-tests` |
| 7 | Mitigation | Prescriptive | `control-set-*.md` → `reference-set-*.md` | CWE Mitigations | **ASVS** (requirement verification) | `--cwe --mitigations`, `--control`, `--asvs-level` |
| 8 | Report | Comprehensive | Compliance Frameworks | - | **ASVS** (compliance status) | `--compliance`, `--asvs-chapter` |

### 4.2 Data Flow Visualization

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              Phase Data Flow Architecture                                            │
├─────────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                      │
│  Phase 1          Phase 2          Phase 3          Phase 4          Phase 5                        │
│  ┌─────┐          ┌─────┐          ┌─────┐          ┌─────┐          ┌─────┐                        │
│  │ P1  │─findings1─▶│ P2  │─findings2─▶│ P3  │─findings3─▶│ P4  │─findings4─▶│ P5  │                        │
│  │     │          │     │          │     │          │     │          │     │                        │
│  └──┬──┘          └──┬──┘          └──┬──┘          └──┬──┘          └──┬──┘                        │
│     │                │                │                │                │                           │
│     │                ▼                ▼                │                │                           │
│     │           security-        security-             │                │                           │
│     │           design.yaml      design.yaml           │                │                           │
│     │                                                  ▼                │                           │
│     │                                          control-set-*.md         │                           │
│     │                                          reference-set-*.md       │                           │
│     │                                                                   │                           │
│     │                                                                   ▼                           │
│     │                                                              CWE → CAPEC                      │
│     │                                                                   │                           │
│     ▼                                                                   ▼                           │
│  ┌────────────────────────────────────────────────────────────────────────────────────────┐        │
│  │                              Phase 6: Risk Validation                                  │        │
│  │  INPUT: findings_1 + findings_2 + findings_3 + findings_4 + findings_5                │        │
│  │         (ALL issues consolidated and deduplicated)                                     │        │
│  │                                                                                        │        │
│  │  KNOWLEDGE: CAPEC → ATT&CK → CVE/KEV                                                  │        │
│  │                                                                                        │        │
│  │  OUTPUT: validated_risks                                                              │        │
│  │    ├── risk_summary (counts, categorization)                                          │        │
│  │    ├── risk_details (per-item: location, analysis, root cause, test cases/POC)       │        │
│  │    └── attack_paths (chains, step-by-step flow with commands/POC)                    │        │
│  └───────────────────────────────────────────────────────────────────────────────────────┘        │
│                                             │                                                       │
│                                             ▼                                                       │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐        │
│  │                              Phase 7: Mitigation Planning                              │        │
│  │  INPUT: validated_risks (complete Phase 6 output)                                     │        │
│  │                                                                                        │        │
│  │  KNOWLEDGE: Control Sets + OWASP References + CWE Mitigations                         │        │
│  │                                                                                        │        │
│  │  OUTPUT: mitigation_plan                                                              │        │
│  │    ├── Per-risk: immediate_actions, short_term_fixes, long_term_improvements         │        │
│  │    └── verification_criteria                                                          │        │
│  └───────────────────────────────────────────────────────────────────────────────────────┘        │
│                                             │                                                       │
│                                             ▼                                                       │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐        │
│  │                              Phase 8: Report Generation                                │        │
│  │  INPUT: ALL phase outputs (findings_1 → mitigation_plan)                              │        │
│  │                                                                                        │        │
│  │  CRITICAL SECTIONS (must include full detail, no omission):                           │        │
│  │    ├── Section 5: Validated Risks (complete from Phase 6)                            │        │
│  │    └── Section 6: Mitigation Plan (complete from Phase 7)                            │        │
│  └───────────────────────────────────────────────────────────────────────────────────────┘        │
│                                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Data Storage Architecture

### 5.1 Storage Layers

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           Data Access Layers                                             │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ Layer 4: Live API (Real-time)                                                    │   │
│  │     ├── NVD API → Real-time CVE details, CVSS scores                            │   │
│  │     └── KEV API → Known Exploited Vulnerabilities check                         │   │
│  │     Query: --nvd-cve CVE-XXXX, --check-kev CVE-XXXX                             │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                              ↑                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ Layer 3: CVE Extension (security_kb_extension.sqlite - 304MB)                    │   │
│  │     ├── cve: 323,830+ CVE records                                               │   │
│  │     ├── cve_cwe: CVE → CWE mappings                                             │   │
│  │     Query: --cve, --cve-for-cwe, --stride-cve                                   │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                              ↑                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ Layer 2: SQLite Main (security_kb.sqlite - 18MB)                                 │   │
│  │                                                                                   │   │
│  │     Core Tables:                                                                  │   │
│  │     ├── cwe (974) - CWE weakness details                                        │   │
│  │     ├── capec (615) - CAPEC attack patterns                                     │   │
│  │     ├── attack_technique (835) - ATT&CK techniques                              │   │
│  │     ├── stride_category (6) - STRIDE categories                                 │   │
│  │     └── owasp_top10 (10) - OWASP Top 10 2021                                    │   │
│  │                                                                                   │   │
│  │     Mapping Tables:                                                               │   │
│  │     ├── stride_cwe - STRIDE → CWE                                               │   │
│  │     ├── capec_cwe - CAPEC → CWE                                                 │   │
│  │     ├── capec_attack - CAPEC → ATT&CK                                           │   │
│  │     └── cwe_mitigation - CWE mitigations                                        │   │
│  │                                                                                   │   │
│  │     Query: --stride, --cwe, --capec, --full-chain, --semantic-search            │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                              ↑                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ Layer 1: Curated YAML + Markdown (On-demand, ~550KB)                             │   │
│  │                                                                                   │   │
│  │     YAML:                                                                         │   │
│  │     ├── stride-library.yaml (5KB) - STRIDE definitions + generation rules       │   │
│  │     ├── security-design.yaml (17KB) - Security domains + control references     │   │
│  │     ├── llm-threats.yaml (31KB) - OWASP LLM Top 10                              │   │
│  │     ├── cloud-services.yaml (20KB) - Multi-cloud threat mappings               │   │
│  │     ├── compliance-mappings.yaml (26KB) - Compliance framework mappings        │   │
│  │     └── verification-mappings.yaml (25KB) - Verification test mappings         │   │
│  │                                                                                   │   │
│  │     Markdown:                                                                     │   │
│  │     ├── security-controls/control-set-*.md (18 files)                           │   │
│  │     └── security-controls/references/reference-set-*.md (74 files)              │   │
│  │                                                                                   │   │
│  │     Query: --control, --llm, --cloud                                            │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Query Routing

| Query Parameter | Data Source | Returns |
|-----------------|-------------|---------|
| `--stride S` | YAML + SQLite | STRIDE details + CWE list |
| `--cwe CWE-89` | SQLite (cwe) | CWE details |
| `--cwe CWE-89 --mitigations` | SQLite | CWE + cwe_mitigation |
| `--full-chain CWE-89` | SQLite (multi-table) | CWE → CAPEC → ATT&CK chain |
| `--capec CAPEC-66` | SQLite (capec) | CAPEC details + CWE mapping |
| `--attack-technique T1190` | SQLite | ATT&CK technique details |
| `--control authentication` | YAML + Markdown | Domain + control set content |
| `--llm LLM01` | YAML (llm-threats) | LLM threat details |
| `--cloud aws` | YAML (cloud-services) | Cloud service threats |
| `--cve CVE-2024-XXXX` | SQLite (extension) | CVE details + CVSS |
| `--check-kev CVE-XXXX` | Live API | KEV check result |
| `--compliance nist-csf` | YAML + SQLite | Compliance framework controls |

---

## 6. Key Statistics

### 6.1 Security Control Set

| Component | Count | Storage |
|-----------|-------|---------|
| Security Principles | 11 | SKILL.md |
| Security Domains | 16 (10 core + 6 extended) | security-design.yaml |
| Control Sets | 18 files / 107 controls | Markdown |
| OWASP References | 74 | Markdown |
| Compliance Frameworks | 14 | YAML + SQLite |
| Verification Tests | 475 (WSTG + MASTG + ASVS) | YAML + SQLite |

### 6.2 Threat Pattern Set

| Component | Count | Storage |
|-----------|-------|---------|
| CWE Weaknesses | 974 | SQLite |
| OWASP Top 10 | 10 (248 CWE mappings) | SQLite |
| CAPEC Attack Patterns | 615 | SQLite |
| ATT&CK Techniques | 835 | SQLite |
| CVE Vulnerabilities | 323,830+ | SQLite Extension |
| Semantic Vectors | 3,278 x 384-dim | SQLite |

### 6.3 Special Extensions

| Extension | Content | Count | Storage |
|-----------|---------|-------|---------|
| LLM Threats | OWASP LLM Top 10 | 10 threats / 5 architectures | YAML |
| Cloud Services | Multi-cloud threat mapping | 5 providers / 8 categories | YAML |
| AI Compliance | ISO 42001 / NIST AI RMF / EU AI Act | 3 frameworks | YAML |

---

## 7. Design Principles

### 7.1 "Scripts are Black Boxes" Principle

- Script execution does not consume context, only output does
- Complex computations (knowledge base queries) handled by scripts
- Claude focuses on tasks requiring understanding and reasoning

### 7.2 "Dual-Set Parallel" Principle

- **Security Control Set**: Defines "what to do" and "how to do it" (defensive perspective)
- **Threat Pattern Set**: Defines "what to know" and "what to validate" (offensive perspective)
- Two sets work independently but collaborate through mapping relationships

### 7.3 "Progressive Disclosure" Principle

- Phase 1-3: Pure Claude capability, reference Security Principles only
- Phase 4: On-demand loading of Security Control Set (domains → controls → references)
- Phase 5-6: On-demand loading of Threat Pattern Set (CWE → CAPEC → ATT&CK → CVE)
- Phase 7: Cross-reference both sets (controls + CWE mitigations)
- Phase 8: On-demand loading of compliance frameworks

### 7.4 "Complete Context Propagation" Principle

- Each phase receives cumulative context from all previous phases
- Phase 6 consolidates ALL findings (P1-P5) for unified validation
- Phase 8 must include COMPLETE Phase 6 and Phase 7 outputs without omission

---

## 8. Version History

| Version | Date | Changes |
|---------|------|---------|
| v5.1 | 2025-12-30 | Neutral descriptions, optimized workflow data flow, complete Phase 6/7/8 specifications |
| v5.0 | 2025-12-30 | L0 principles design + dual-track architecture + YAML/SQLite mapping |
| v4.0 | 2025-12-30 | OUTPUT/CLIENT separation + strict naming conventions |
| v3.2 | 2025-12-30 | Extended domain control sets + unified naming |

---

**Document Generated**: Code-First Deep Risk Analysis Skill - Ultrathink Critical Thinking v5.1
