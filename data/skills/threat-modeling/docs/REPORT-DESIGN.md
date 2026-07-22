<!-- Threat Modeling Skill | Version 3.1.0 (20260313a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# v3.0.3 Report Enhancement Design Document

**Version**: 3.1.0
**Date**: 2026-02-09 (updated 2026-03-12)
**Status**: Approved

---

## 1. Problem Diagnosis

### 1.1 Structural Problems
- Main report has only 9 sections, missing a high-level risk posture overview (dashboard view)
- No per-risk detailed analysis reports — all risks condensed into summary tables
- No HTML output — only Markdown, which is hard to read on screen

### 1.2 Content Quality Problems
- §1 Executive Summary: Only Top-3 critical risks, only 5 key findings → insufficient
- §2 System Architecture Overview: Missing dependency graph, tech stack security context, entry point quantification, criticality notation
- §3 Security Design Assessment: Missing security scorecard, domain evaluation detail, threat-gap traceability matrix, gap categorization
- §5 Risk Validation: POC content sometimes summarized despite prohibition
- §6 Attack Path Analysis: ASCII diagrams only, no Mermaid for complex flows
- §8 Mitigation: Missing implementation difficulty and effort breakdown

### 1.3 Readability Problems
- Monotonous text formatting, no visual hierarchy
- No diagram support beyond ASCII art
- Large tables without color-coding for severity
- No navigation or cross-reference structure

---

## 2. Three-Layer Enhancement Plan

### Layer 1: Main Report Optimization (10-Section Template)

Expand from 9 sections to 10 sections. Optimize ALL existing sections.

#### §0 Risk Posture Overview (NEW)
- **Top-10 Risk Cards**: Each card shows VR-ID, title, CVSS, STRIDE type, priority, affected modules
- **STRIDE × Severity Heatmap Matrix**: 6×4 grid (S/T/R/I/D/E × CRITICAL/HIGH/MEDIUM/LOW)
- **Key Metrics Dashboard**:
  - Total risks by priority (P0/P1/P2/P3)
  - Average CVSS score
  - Attack surface breadth (entry points × boundaries)
  - Mitigation coverage ratio

#### §1 Executive Summary (ENHANCED)
- **10 Key Findings** (was 5)
- **Immediate Action Items**: Top-3 P0 with responsible team and deadline
- **Assessment Scope Summary**: project path, tech stack, module count, analysis duration

#### §2 System Architecture Overview (ENHANCED)
- **Dependency Graph**: Module dependency visualization (ASCII in .md, Mermaid in HTML)
- **Tech Stack Security Context**: Framework versions with known CVE status
- **Entry Point Quantification**: Count by type (API/UI/CLI/WebSocket/gRPC), with auth status
- **Trust Boundary Mechanisms**: Summary of controls at each boundary crossing
- **Criticality Notation**: Mark security-critical modules with ⚠️ in component table
- **Security Observations from P1-P3**: Inline findings with F-xxx references

#### §3 Security Design Assessment (ENHANCED)
- **Security Scorecard**: Standardized X/100 score per domain (16 domains)
- **Domain Evaluation Detail**: For each domain: checks performed, checks passed, gaps found, coverage %
- **Threat-Gap Traceability Matrix**: GAP-xxx → T-xxx → VR-xxx cross-reference table
- **Gap Categorization**: G-ARCH (architecture redesign), G-IMPL (code/config fix), G-PROC (policy/process)
- **Control Flow Diagram**: Security control assessment workflow (ASCII)
- **Priority Matrix**: Gap severity × effort matrix for remediation planning

#### §4 STRIDE Threat Analysis (MAINTAINED)
- Keep current structure, no changes needed

#### §5 Risk Validation & POC Design (ENHANCED)
- **Complete POC Content**: Enforce verbatim copy with code blocks
- **Verification Status Badges**: ✅ Verified | ⚠️ Theoretical | ❓ Pending | ❌ Excluded
- **POC Execution Environment**: Required tools, environment setup instructions

#### §6 Attack Path Analysis (ENHANCED)
- **DFD Report**: ASCII + Mermaid diagrams **side-by-side** in .md
- **Other .md reports**: ASCII diagrams only
- **HTML reports**: Rendered Mermaid via CDN

#### §7 Threat Priority Matrix (MAINTAINED)
- Keep current structure, no changes needed

#### §8 Mitigation Recommendations (ENHANCED)
- **Implementation Difficulty Rating**: LOW/MEDIUM/HIGH per mitigation
- **Effort Breakdown**: Estimated hours/days per mitigation
- **Before/After Code Comparison**: Side-by-side diff format
- **Dependency Chain**: MIT-xxx prerequisite relationships

#### §9 Compliance Mapping (MAINTAINED)
- Keep current structure, no changes needed

### Layer 2: P8R Detailed Risk Reports (NEW)

Optional post-P8 phase generating per-VR detailed analysis reports.

#### Trigger Conditions
1. P8 completion prompt: "Generate detailed risk analysis? [Y/N]"
2. `--detailed` flag at session start

#### Output Structure
```
Risk_Assessment_Report/
└── detailed/
    ├── VR-001-{title-slug}.md
    ├── VR-002-{title-slug}.md
    └── ...
```

#### 12 Analysis Elements Per VR Report

| # | Element | Description |
|---|---------|-------------|
| 1 | Risk Overview | VR-ID, title, CVSS, CWE, priority, STRIDE, affected assets (table) |
| 2 | Entry Points | All attack entry points with conditions and triggers |
| 3 | Data Flow Analysis | Complete data flow from entry to vulnerable point (ASCII diagram) |
| 4 | Root Cause Analysis | Why the vulnerability exists, code-level root cause with file:line |
| 5 | Exploit Scenario | Step-by-step exploitation procedure |
| 6 | POC Code | Complete executable POC (verbatim from P6) |
| 7 | Impact Analysis | Business impact, data sensitivity, blast radius |
| 8 | Attack Chain Context | Which AC-xxx chains include this VR, position in chain |
| 9 | Related Vulnerabilities | CWE details, related CVEs, CAPEC attack patterns |
| 10 | Mitigation Strategy | Complete MIT-xxx details with before/after code |
| 11 | Verification Method | Test cases (TC-xxx), ASVS/WSTG references |
| 12 | References & Traceability | F-xxx → GAP-xxx → T-xxx → VR-xxx → MIT-xxx chain |

#### Reference Standard
- VR-Analysis samples at `~/STRIDE/test/e/EDA代码文件/Risk_Assessment_Report/VR-Analysis/*.md`
- 20 VR reports (VR-001 through VR-020), each 4K-30K characters

### Layer 3: HTML Output Support (NEW)

#### HTML Report Generator (`scripts/report_generator.py`)

**Batch MD→HTML converter** with:
- Terminal aesthetic CSS (reuse from md_to_html.py)
- CJK font stack (Sarasa Term SC, Noto Sans Mono CJK SC, PingFang SC)
- Mermaid CDN rendering (client-side via `<script src="mermaid.min.js">`)
- Severity color coding (CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue)
- Navigation sidebar with report index
- Index page (index.html) with links to all reports
- Print-friendly media queries

**Output Structure**:
```
Risk_Assessment_Report/
└── html/
    ├── index.html                    ← Report index page
    ├── RISK-ASSESSMENT-REPORT.html   ← Main report
    ├── RISK-INVENTORY.html
    ├── MITIGATION-MEASURES.html
    ├── PENETRATION-TEST-PLAN.html
    ├── ARCHITECTURE-ANALYSIS.html
    ├── DFD-DIAGRAM.html
    ├── COMPLIANCE-REPORT.html
    ├── ATTACK-PATH-VALIDATION.html
    └── detailed/                     ← If P8R was executed
        ├── VR-001-{slug}.html
        └── ...
```

**Mermaid Rendering Strategy**:
- In .md files: ASCII diagrams (always readable)
- In DFD .md: ASCII + Mermaid source side-by-side
- In HTML: Mermaid source rendered via client-side JS
- Mermaid CDN: `https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js`

---

## 3. Implementation File List

| # | File | Action | Description |
|---|------|--------|-------------|
| T1 | docs/REPORT-DESIGN.md | CREATE | This design document |
| T2 | phases/P8-REPORT-GENERATION.md | MODIFY | Expand to 10-section template |
| T3 | phases/P8R-DETAILED-REPORT.md | CREATE | New P8R phase instructions |
| T4 | assets/contracts/data-model.yaml | MODIFY | Add DetailedRiskReport + P8R manifest |
| T5 | scripts/report_generator.py | CREATE | MD→HTML batch converter |
| T6 | SKILL.md | MODIFY | Add --detailed flag, update directory structure |
| T7 | WORKFLOW.md | MODIFY | Add P8R optional phase |

---

## 4. Design Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Top-10 risk cards (not Top-5) | Better coverage for comprehensive assessments |
| D2 | 10 key findings (not 5) | More thorough executive summary |
| D3 | DFD: ASCII + Mermaid side-by-side in .md | Maximum compatibility + visual richness |
| D4 | Other .md: ASCII only | Keeps non-DFD reports simple and portable |
| D5 | HTML: Mermaid via CDN | Client-side rendering, no server dependency |
| D6 | Reuse md_to_html.py CSS aesthetic | Consistent visual identity across reports |
| D7 | P8R as optional post-P8 phase | Doesn't break existing P1-P8 workflow |
| D8 | Gap categorization: G-ARCH/G-IMPL/G-PROC | Clear remediation responsibility assignment |
| D9 | Security scorecard X/100 per domain | Quantifiable, comparable across projects |
| D10 | 12 analysis elements per VR | Matches reference VR-Analysis samples |

---

## 5. Backward Compatibility

- Existing P1-P8 workflow unchanged
- P8R is optional (only triggered by --detailed flag or user confirmation)
- HTML output is additive (generated alongside existing .md reports)
- No changes to phase-end validation behavior
- No changes to phase_data.py validation logic

---

**End of Report Enhancement Design Document**
