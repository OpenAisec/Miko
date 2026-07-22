<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Changelog

All notable changes to the Threat Modeling Skill will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - 2026-03-13

### Comprehensive Security Audit (60 fixes across 6 scripts)

**phase_data.py** (30 fixes):
- **P0 CRITICAL**: Schema version validator tolerance — `startswith()` instead of `==` to accept both bare `"3.1.0"` and date-suffixed `"3.2.0 (20260512a)"` formats
- **HIGH (4)**: Regex DoS protection, deepcopy for YAML data isolation, data-first/markdown-first bridge with `dict.get("blocks", dict_itself)`, correct P5 coverage denominator
- **HIGH-Robustness (4)**: P1 `None` guard, safe `.get()` for optional fields, FSM bounds check on phase numbers, zero-division guard in P2 percentages
- **HIGH-Performance (7)**: Regex precompilation (22 patterns), knowledge path caching, glob caching for P8 reports, YAML safe_load verification, DFD element extraction optimization
- **MEDIUM (6)**: P5 required field validation, FSM completion gating (`mark_complete` parameter), CP1 overlap detection (set algebra), narrow `except Exception` (8 locations), status casing convention documented, P8 glob cached
- **LOW (9)**: P3 cross-boundary flow validation, entity regex `\d{3}` → `\d{3,}`, dual-write design documented, single-user file locking documented, FSM state transition documented, `--phases` bounds check, `--root` directory check, `Risk_Assessment_Report/` auto-creation, complexity estimator correction

**unified_kb_query.py** (4 fixes):
- **MEDIUM**: FTS5 query sanitization (`_sanitize_fts5_query()` strips operators, quotes terms)
- **MEDIUM**: NVD API key from `NVD_API_KEY` env var (CLI arg as fallback with deprecation warning)
- **MEDIUM**: Narrow 7 `except Exception` → specific types (JSONDecodeError, sqlite3.Error, yaml.YAMLError, OSError)
- **MEDIUM**: Schema version design documented on `_get_sqlite_connection()`

**module_discovery.py** (3 fixes):
- **HIGH**: Symlink boundary check in `list_files()` — prevent path traversal escape from project root
- **MEDIUM**: Path canonicalization with `root.resolve()` at entry
- **MEDIUM**: `ext_to_lang` mapping expanded from 5 to 11 pattern groups

**report_generator.py** (3 fixes):
- **HIGH**: HTML escape for title/project_name via `html.escape()` (XSS prevention in 3 locations)
- **MEDIUM**: Sidebar + index page href/display escaping (6 locations)
- **MEDIUM**: Narrow `except Exception` → `(OSError, ValueError, UnicodeDecodeError)`

**stride_matrix.py** (2 fixes):
- **MEDIUM**: Numeric validation + strip for `sequence` parameter in `generate_threat_id()`
- **LOW**: `sys.exit(1)` on error result in `main()`

**build_knowledge_base.py** (4 fixes, dev-only):
- Added standard version header
- Removed unused imports (re, datetime, Set, Tuple)
- Added `encoding="utf-8"` to 3 `open()` calls
- Added defusedxml decision comment

### Additional Changes
- `extract_title()` double-escape prevention — `html.unescape()` at extraction point
- `data-model.yaml`: TrustBoundary.type expanded (Model, Agent), ArchitectureFinding.category expanded (dynamic_route)
- P8R language adaptation instruction added
- Hook version updated 3.0.0 → 3.1.0
- All 137 files synced to date suffix `20260313a`
- Documentation and version consistency audit across all files

## [3.0.5] - 2026-03-12

### Audit Fix Release (47/67 issues resolved)
- **CRITICAL**: Fixed 5 phantom CLI flags (`--capec CWE`→`--full-chain`, `--stride-mapping`→`--stride-controls`, `--p8r`, `--session`→`--session-id`)
- **HIGH**: KBQueryContract phantom flags removed, codeguard→control-set mapping (56 refs), FSM precondition check (方案A), SKILL.md frontmatter compliance, version string unification
- **MEDIUM**: Data contract fixes (P2 blocks, P4 findings, P6 risk_details), path traversal validation, token budget accuracy, count conservation documentation
- **Knowledge Base**: SQLite rebuilt (7.96 MB), 0 codeguard references remaining
- **Infrastructure**: PostToolUse hook system removed (D7:A), build_knowledge_base.py restored from archive

### Changed Files
- 8 phase files, 5 scripts, 18 control-set files, 75 reference files, data-model.yaml, SKILL.md, WORKFLOW.md

## [3.0.3] - 2026-02-09

### Report System Enhancement (3-Layer)
- **Layer 1 - Main Report Optimization**: Expanded from 9 to 10 sections
  - New §0 Risk Posture Overview: Top-10 risk cards, STRIDE×Severity heatmap, key metrics dashboard
  - Enhanced §1 Executive Summary: 10 key findings (was 5), immediate action items
  - Enhanced §2 System Architecture: Dependency graph, tech stack security context, entry point quantification
  - Enhanced §3 Security Design Assessment: Security scorecard (X/100 per domain), gap categorization (G-ARCH/G-IMPL/G-PROC)
  - Enhanced §5 Risk Validation: Verification status badges, POC execution environment
  - Enhanced §6 Attack Path: ASCII + Mermaid side-by-side for DFD
  - Enhanced §8 Mitigation: Difficulty rating, effort breakdown, before/after code
- **Layer 2 - P8R Detailed Risk Reports**: Optional post-P8 phase with 12 analysis elements per VR
  - New `phases/P8R-DETAILED-REPORT.md` phase file
  - New `--detailed` flag for auto-triggering P8R
  - Per-VR reports: Risk overview, entry points, data flow, root cause, exploit scenario, POC, impact, attack chains, related vulns, mitigation, verification, traceability
- **Layer 3 - HTML Output Support**: Batch MD→HTML converter
  - New `scripts/report_generator.py` with Mermaid CDN rendering
  - Severity color coding (CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue)
  - Navigation sidebar, index page, print-friendly media queries

### New Files
- `phases/P8R-DETAILED-REPORT.md` - Optional detailed risk analysis phase
- `scripts/report_generator.py` - MD→HTML batch converter
- `docs/REPORT-DESIGN.md` - v3.0.3 report enhancement design document

### Schema Changes
- Added `DetailedRiskReport` entity and `P8RManifest` schema to `data-model.yaml`
- FSM extended with P8R state: δ(P8, p8_complete ∧ detailed) → P8R → DONE

## [3.0.2] - 2026-02-04

### Localization & Usability
- **English Localization**: All phase instructions (P1-P8) translated to English for better LLM compatibility
- **Extended Trigger Words**: Added security analysis, security audit, security check (EN/CN)
- **Removed**: compliance/合规检查 (out of core scope)

### Bug Fixes
- Fixed residual Chinese in P4 (L116-117, L145) and P5 (L126-128)

## [3.0.1] - 2026-02-03

### Architecture Optimization
- **File Responsibility Separation**: SKILL.md (WHAT & WHY) vs WORKFLOW.md (HOW & WHEN)
- **FSM Formalization**: 8-phase state machine with formal verification properties (Safety S1-S4, Liveness L1-L2)
- **4-Gate Sub-FSM**: Per-phase execution protocol (ENTRY → THINKING → PLANNING → EXECUTING → REFLECTING → EXIT)
- **Token Optimization**: 26.4% reduction (12,000 → 8,832 tokens) through de-duplication and cross-references
- **Cross-Reference Convention**: "See SKILL.md §X" pattern to maintain single source of truth

### Technical Changes
- Added `docs/SKILL-ARCHITECTURE-DESIGN.md` with FSM specification (§0, §0.1, §0.2)
- Simplified SKILL.md §10, §11 to constraint declarations
- Added WORKFLOW.md §1 Workflow State Machine definition
- Simplified WORKFLOW.md §3 data contracts (summary table instead of full schemas)
- Added `MEMORY.md` for project memory across sessions

## [3.0.0] - 2026-01-31

### Core Improvements
- **Context Efficiency**: Restructured for improved context completeness and execution efficiency
- **Systematic Analysis**: Enhanced attack path analysis with better coverage
- **Session History**: Multi-session version tracking for incremental analysis
- **CI/CD Integration**: Structured YAML phase output for external tool integration

### Technical Changes
- Separate phase instruction files (8 files, on-demand loading)
- Dual output model: YAML data (machine) + Markdown reports (human)
- PostToolUse hooks for automatic validation
- Extended security domains: AI/LLM, Mobile, Cloud, Agentic
- Chinese documentation (README-cn.md)

## [2.2.2] - 2026-01-29

### Added
- Session management with unique session IDs
- Data protocols for phase handoff
- Complete discovery validation

### Changed
- Improved validation integration
- Enhanced YAML block extraction

## [2.2.0] - 2026-01-28

### Added
- Phase output YAML blocks
- Validation integration framework

## [2.1.3] - 2026-01-20

### Added
- Phase 2 knowledge enhancement
- DFD methodology research

## [2.0.0] - 2025-12-30

### Added
- 8-phase workflow structure
- Knowledge base with CWE/CAPEC/ATT&CK
- Security control domains (10 core)

## [1.0.6] - 2025-12-30

### Added
- Initial release
- Basic STRIDE analysis capability
- Core knowledge base
