<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Phase 1: Project Understanding

**Type**: Exploratory
**Executor**: Script + LLM
**Knowledge**: Security Principles

---

## ⚠️ 4-Phase Gating Protocol — THINKING → PLANNING → EXECUTION → REFLECTION (output each stage)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🧠 THINKING - Phase 1 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Purpose**: Phase 1 is the first phase with no upstream data dependencies. Focus on project discovery.

**⚠️ You MUST output THINKING results in the following format:**

```
🧠 THINKING - P1 Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 CORE PROBLEM
Comprehensively discover project architecture, modules, and entry points to establish the threat modeling foundation

📊 KNOWN CONTEXT
| Metric | Value | Source |
|--------|-------|--------|
| Project Path | {actual_path} | User Input |
| Project Type | [to be discovered] | Requires scan |
| Tech Stack | [to be discovered] | package.json/requirements.txt |

❓ UNKNOWNS
- Module organization structure
- Entry point distribution (14 types require scanning)
- Dynamic route indicators
- Documentation quality grade

⚠️ RISKS
- Incomplete entry point type scanning (all 14 types MUST be scanned)
- Missing dynamic route indicators (Layer 3 coverage)
- coverage_confidence too low (<0.70)
- Module security_level not assigned

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⛔ STOP CHECK
- Project path accessible? [YES/NO]
- Ready to continue PLANNING? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ **STOP CONDITION**: If any STOP CHECK = NO → Resolve the issue before continuing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 📋 PLANNING - Sub-task Decomposition
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Step 1: Validate Project Path** (BLOCKING - MUST execute)
```bash
# Verify project exists (execute in project root directory)
ls .

# Check if .phase_working directory exists
ls ./Risk_Assessment_Report/.phase_working/ 2>/dev/null || echo "Will create"
```

**Step 2: Output Sub-task Table** (MANDATORY)

**⚠️ You MUST output PLANNING results in the following format:**

```
📋 PLANNING - P1 Sub-tasks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| # | Sub-task | Expected Output |
|---|----------|-----------------|
| T1 | Execute P1.0 three-layer static discovery | P1_static_discovery.yaml |
| T2 | Decide P1.1 doc analysis based on quality_grade | yaml:doc_analysis (conditional) |
| T3 | P1.2 code analysis | 3 YAML blocks |
| T4 | P1.3 dynamic route detection | Layer 3 indicators |
| T5 | P1.4 three-source alignment validation | P1_source_alignment.yaml |
| T6 | P1.5 validation and confidence calculation | coverage_confidence |
| T7 | Write final output | P1_project_context.yaml + MD |

⛔ PLANNING CHECK
- Sub-tasks decomposed? [YES/NO]
- Ready to execute TaskCreate? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Step 3**: ⚠️ `TaskCreate` ALL sub-tasks before implementation (MANDATORY).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### ⚡ EXECUTION — TaskUpdate(in_progress) → Execute → Verify → TaskUpdate(completed) | Fail → Retry 3x → CHECKPOINT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Output Order** (CRITICAL):
1. **Write YAML first**: `.phase_working/{SESSION_ID}/data/P1_project_context.yaml`
2. **Write MD second**: `.phase_working/{SESSION_ID}/reports/P1-PROJECT-UNDERSTANDING.md`

**Key Commands**:
```bash
# P1.0 Three-layer discovery (path is positional argument, not --project-root)
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/module_discovery.py . --p1-discovery --output-yaml \
  > .phase_working/{SESSION_ID}/data/P1_static_discovery.yaml
# Note: "." means current project directory, can also use absolute path like /path/to/project

# P1.5 Validation
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --validate --phase 1 --root .
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🔍 REFLECTION - Completion Verification
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**⚠️ After completing EXECUTION, you MUST output REFLECTION results in the following format:**

```
🔍 REFLECTION - P1 Completion Check
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| Check Item | Status |
|------------|--------|
| P1.0 three-layer discovery executed? (P1_static_discovery.yaml exists) | [✅/❌] |
| P1_project_context.yaml exists and valid? | [✅/❌] |
| discovery_checklist all 14 entry types scanned:true? | [✅/❌] |
| Every module has security_level assigned? | [✅/❌] |
| Every entry point has unique ID (EP-xxx format)? | [✅/❌] |
| coverage_confidence.overall_confidence ≥ 0.70? | [✅/❌] |
| `--phase-end` validation passed (exit 0)? | [✅/❌] |

⛔ COMPLETION GATE
- All checks passed? [YES/NO]
- Ready to enter P2? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ If any check fails → Fix and re-verify until all pass

---

### ⚠️ Dual Output (YAML first → MD second)

1. **YAML** (PRIMARY): `.phase_working/{SESSION_ID}/data/P1_project_context.yaml`
2. **MD** (SECONDARY): `.phase_working/{SESSION_ID}/reports/P1-PROJECT-UNDERSTANDING.md`
- ❌ Writing only .md without .yaml | ✅ .yaml is the authoritative data source

### Required Data Sections in YAML

| Section | Validation |
|---------|------------|
| `project_context` | BLOCKING - project_type, tech_stack required |
| `module_inventory` | BLOCKING - all modules with security_level |
| `entry_point_inventory` | BLOCKING - all entry points with unique IDs |
| `discovery_checklist` | BLOCKING - all 14 entry types with scanned:true |
| `doc_analysis` | CONDITIONAL - if quality_grade != "none" |
| `architecture_findings` | WARNING - security observations discovered during analysis |

### Validation Gate

Phase 1 CANNOT complete until:
1. `.phase_working/{SESSION_ID}/data/P1_project_context.yaml` exists and is valid YAML
2. `discovery_checklist` has all 14 entry types with `scanned: true`
3. Every module has `security_level` assigned
4. Every entry point has unique ID (EP-xxx format)
5. `.phase_working/{SESSION_ID}/reports/P1-PROJECT-UNDERSTANDING.md` exists

---

## Input Context

None (first phase)

## Output Context

→ P2: `project_context` {project_type, modules[], entry_points[], security_design{}}

---

## Sub-Phase Architecture

> **Terminology Note**: "P1.x" refers to sub-phases within Phase 1. "Layer 1/2/3" refers to
> the three-layer discovery strategy (deterministic/heuristic/dynamic). These are orthogonal concepts.

```
P1.0 (Script)        Three-Layer Static Discovery (Layer 1 + Layer 2 + Layer 3)
        ↓
P1.1 (LLM)           Doc-Guided Analysis (conditional)
        ↓
P1.2 (LLM)           Code Analysis & Module Inventory
        ↓
P1.3 (Script)        Dynamic Route Detection (Layer 3 refinement)
        ↓
P1.4 (Script)        Three-Source Alignment
        ↓
P1.5 (Script+LLM)    Validation & Coverage Confidence
```

| Sub-Phase | Executor | Mandatory | Output |
|-----------|----------|-----------|--------|
| P1.0 | Script | Yes | P1_static_discovery.yaml (three-layer) |
| P1.1 | LLM | Conditional* | yaml:doc_analysis |
| P1.2 | LLM | Yes | 3 YAML blocks |
| P1.3 | Script | Yes | Layer 3 dynamic indicators |
| P1.4 | Script | Yes | P1_source_alignment.yaml |
| P1.5 | Script+LLM | Yes | validation + coverage_confidence |

*P1.1 required if `documentation.quality_grade != "none"`

### Three-Layer Discovery Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│               THREE-LAYER DISCOVERY ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  LAYER 1: Deterministic Discovery (95%+ Confidence)                          │
│  ─────────────────────────────────────────────────                            │
│  • Static code patterns: @app.route, @router.get, @RequestMapping            │
│  • Config file parsing: openapi.yaml, routes.yaml, serverless.yml            │
│  • Framework-specific: Django URLconf, Spring controllers                    │
│  Output: Verified routes with exact file:line locations                      │
│                                                                              │
│  LAYER 2: Heuristic Discovery (70-90% Confidence)                            │
│  ─────────────────────────────────────────────────                            │
│  • Directory patterns: routes/, handlers/, api/, controllers/                │
│  • Import analysis: flask, fastapi, express, spring detection                │
│  • Code pattern matching: request/response handling functions                │
│  Output: Probable route locations for LLM analysis                          │
│                                                                              │
│  LAYER 3: Dynamic Route Indicators (30-60% Confidence)                       │
│  ─────────────────────────────────────────────────────                        │
│  • Conditional registration: if config.ENABLE_* + add_route                  │
│  • Plugin systems: plugin.register, loader.load_module                       │
│  • Reflection calls: getattr, eval, exec                                     │
│  • Runtime registration: def register_routes() patterns                      │
│  Output: Uncertainty markers for human review                               │
│                                                                              │
│  COVERAGE CONFIDENCE FORMULA:                                                │
│  ────────────────────────────                                                 │
│  final = base_confidence - uncertainty_penalty + tool_boost                  │
│                                                                              │
│  Where:                                                                      │
│    l1_contribution = max(l1_route_conf, l1_config_conf) * 0.6               │
│    l2_contribution = max(l2_dir_conf, l2_import_conf) * 0.3                 │
│    base_confidence = min(0.95, l1_contribution + l2_contribution + 0.05)    │
│    uncertainty_penalty = min(0.20, dynamic_count * 0.02 + high_risk * 0.03) │
│    tool_boost = sum(available_tools.boost), capped at 0.15                  │
│                                                                              │
│  Weight Distribution:                                                        │
│    • Layer 1 (Deterministic): 60% weight                                    │
│    • Layer 2 (Heuristic): 30% weight                                        │
│    • Baseline: +5% minimum confidence                                        │
│                                                                              │
│  Enhanced Tools (when available):                                            │
│    • Semgrep: +0.10 confidence boost (framework-native detection)           │
│    • OWASP Noir: +0.15 confidence boost (LLM-enhanced discovery)            │
│    • CodeQL: +0.12 confidence boost (deep dataflow analysis)                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## P1.0 Three-Layer Static Discovery (Script)

**Run first, before any manual analysis**:

```bash
# NEW: Full three-layer P1 discovery with YAML output
# Usage: module_discovery.py <path> [options]  (path is positional argument)
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/module_discovery.py . --p1-discovery --output-yaml \
  > .phase_working/{SESSION_ID}/data/P1_static_discovery.yaml
```

### Error Handling

| Error | Cause | Recovery Action |
|-------|-------|-----------------|
| Script not found | Missing module_discovery.py | Use `${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/module_discovery.py` with correct path |
| Python error | Missing dependencies | Install: `pip install pyyaml` |
| Empty output | No files found | Verify project path, check permissions |
| Timeout | Large project | Add `--summary-only` flag, increase timeout |

**Fallback Strategy**: If script fails after 2 retries, proceed to P1.2 with manual discovery and set `coverage_confidence.overall_confidence: 0.50` with note `"script_fallback": true`.

### Discovery Outputs

The three-layer discovery produces:

| Layer | Confidence | Output Section |
|-------|------------|----------------|
| Layer 1 | 95%+ | `layer1_deterministic.routes`, `layer1_deterministic.configs` |
| Layer 2 | 70-90% | `layer2_heuristic.directories`, `layer2_heuristic.frameworks` |
| Layer 3 | 30-60% | `layer3_dynamic_indicators` |
| Summary | - | `coverage_confidence`, `summary` |

### ⚠️ JSON/YAML Output Handling Rules

| ❌ FORBIDDEN | ✅ CORRECT |
|--------------|------------|
| `script.py \| python -c "yaml.load()"` | `script.py --output-yaml > file.yaml` |
| `head -N file.json \| parse` | `jq '.field' file.json` |
| `--categorize` (large output) | `--p1-discovery --summary-only` (compact output) |

**Why**: Large output through pipes may corrupt. `head` truncates structures mid-way.

**Correct Pattern**:
```bash
# Step 1: Run full P1 discovery (path is the first positional argument)
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/module_discovery.py . --p1-discovery --output-yaml \
  > .phase_working/{SESSION_ID}/data/P1_static_discovery.yaml

# Step 2: Check coverage confidence
grep "overall_confidence" .phase_working/{SESSION_ID}/data/P1_static_discovery.yaml
```

**Record from output**:

| Metric | Value |
|--------|-------|
| total_files | _____ |
| total_directories | _____ |
| coverage_confidence.overall_confidence | 0.0-1.0 |
| coverage_confidence.recommendation | HIGH/MEDIUM/LOW |
| documentation.quality_grade | high/medium/low/none |
| layer3_dynamic_indicators.total_count | _____ |

**Decision Gate**:

| quality_grade | Action |
|---------------|--------|
| "none" (< 10) | Skip P1.1, go to P1.2 |
| "low" (10-39) | Execute P1.1 (README only) |
| "medium" (40-69) | Execute P1.1 (standard) |
| "high" (>= 70) | Execute P1.1 (full) |

**Coverage Confidence Decision**:

| Confidence | Action |
|------------|--------|
| >= 0.85 | HIGH_CONFIDENCE - proceed normally |
| 0.70-0.84 | MEDIUM_CONFIDENCE - review Layer 3 indicators |
| < 0.70 | LOW_CONFIDENCE - investigate uncertainty sources before P1.2 |

---

## P1.0+ Enhanced Tool Discovery (LLM Decision + Execution)

> **IMPORTANT**: Script DETECTS tools and SUGGESTS commands. LLM DECIDES and CALLS.

### When to Execute

Check `enhanced_tools._summary` in P1_static_discovery.yaml output:

```yaml
# Example output from module_discovery.py
enhanced_tools:
  _summary:
    available_count: 2
    available_tools: ["semgrep", "noir"]
    llm_action_required: true
    instruction: "Enhanced tools detected. LLM should execute..."
  semgrep:
    available: true
    version: "1.55.0"
    suggested_action: "RUN_FOR_ENHANCED_DISCOVERY"
    recommended_commands:
      - purpose: "route_discovery"
        command: "semgrep --config auto --json --output semgrep_routes.json {project_path}"
      - purpose: "security_patterns"
        command: "semgrep --config p/security-audit --json --output semgrep_security.json {project_path}"
```

### LLM Decision Matrix

| Condition | Action |
|-----------|--------|
| `_summary.llm_action_required == false` | Skip enhanced discovery, proceed to P1.1 |
| `suggested_action == "RUN_FOR_ENHANCED_DISCOVERY"` | Execute recommended_commands for this tool |
| `suggested_action == "SKIP"` | Tool not available, skip |

### LLM Execution Protocol

When `llm_action_required == true`:

```bash
# Step 1: LLM executes recommended commands (replace {project_path} with actual path)
# For Semgrep:
semgrep --config auto --json --output .phase_working/{SESSION_ID}/data/semgrep_routes.json {project_path}

# For OWASP Noir:
noir -b {project_path} -f json -o .phase_working/{SESSION_ID}/data/noir_endpoints.json
```

### Result Integration

LLM should merge enhanced discovery results into P1.2 analysis:

```yaml
# Add to yaml:entry_point_inventory
enhanced_discovery_results:
  tools_executed: ["semgrep", "noir"]
  semgrep_findings:
    routes_discovered: 12
    security_patterns: 5
    source_file: "semgrep_routes.json"
  noir_findings:
    endpoints_discovered: 18
    source_file: "noir_endpoints.json"
  merged_entry_points:
    - id: EP-ENH-001
      path: "/api/internal/sync"
      source: "semgrep"
      confidence: 0.95
```

### Confidence Boost Application

When enhanced tools successfully execute:
- Add tool_boost to coverage_confidence
- Update `coverage_confidence.confidence_breakdown.tool_boost`

---

## P1.1 Documentation Analysis (LLM)

**Skip if**: quality_grade == "none"

**Document Priority**:
1. README.md
2. docs/ARCHITECTURE*, DESIGN*
3. docs/API*, openapi.yaml
4. CONTRIBUTING*
5. Other docs/*.md

**Output**: `yaml:doc_analysis`

```yaml:doc_analysis
schema_version: "3.2.0 (20260512a)"
phase: 1
sub_phase: "P1.1"
analyzed_at: "ISO8601"
documents_analyzed:
  - path: "README.md"
    category: "readme"
    size_bytes: 12500

project_intent:
  summary: "One-paragraph summary"
  target_users: ["developers", "enterprises"]
  key_features: ["Feature 1", "Feature 2"]

architecture_overview:
  type: "monolith|microservices|serverless|hybrid"
  frontend:
    framework: "React/Vue/Svelte"
  backend:
    framework: "FastAPI/Express/Spring"
  database:
    type: "relational/nosql/mixed"
    systems: ["PostgreSQL", "Redis"]

documented_modules:
  - name: "Authentication Module"
    description: "Handles OAuth2 and local auth"
    source: "docs/ARCHITECTURE.md"

security_mentions:
  - topic: "authentication"
    details: "OAuth2 with PKCE support"
    source: "README.md"

notes_for_analysis:
  - "Documentation mentions webhook integration not yet implemented"
```

---

## P1.2 Code Analysis (LLM)

**Core Goal**: Comprehensively understand project architecture by verifying documented claims and discovering undocumented components.

### Entry Point Types (All Must Be Scanned)

| Type | Pattern Examples | Security Sensitivity |
|------|------------------|---------------------|
| rest_api | `@app.route`, `@router.get` | HIGH |
| internal_api | Internal service calls | MEDIUM |
| graphql | `@strawberry.type` | HIGH |
| websocket | `@socketio.on` | HIGH |
| cron_jobs | `@scheduler` | MEDIUM |
| message_queue | `@celery.task` | MEDIUM |
| webhooks | `/webhook/` | HIGH |
| file_upload | `multipart` | HIGH |
| health_endpoints | `/health` | LOW |
| debug_endpoints | `/debug` | CRITICAL |
| **llm_gateway** | `ChatCompletion`, `/chat`, `/generate` | **CRITICAL** |
| **model_endpoint** | `model.predict`, `/inference` | **HIGH** |
| **rag_pipeline** | `VectorStore.query`, `retriever.get` | **HIGH** |
| **agent_tool** | `@tool`, `function_call` | **CRITICAL** |

### Required Output Blocks

**Block 1**: `yaml:module_inventory`

```yaml:module_inventory
modules:
  - id: M-001              # Format: M-{Seq:03d}
    name: "Authentication Module"
    path: "src/auth"
    type: Authentication
    security_level: HIGH   # HIGH|MEDIUM|LOW
    files: 12
    loc: 1500
    entry_types: [API, UI]
    submodules:
      - id: M-001-001      # Parent-Child: M-{Parent}-{Seq:03d}
        name: "Auth Handlers"
        path: "src/auth/handlers"
        files: 4
        loc: 600
```

**Block 2**: `yaml:entry_point_inventory`

```yaml:entry_point_inventory
api_entries:
  - id: EP-API-001
    path: "/api/v1/auth/login"
    methods: [POST]
    module: auth
    handler: "src/auth/handlers/login.py:45"
    auth_required: false
    exposure: EXTERNAL

ui_entries:
  - id: EP-UI-001
    type: WebForm
    path: "/login"
    component: "LoginForm"

system_entries:
  - id: EP-SYS-001
    type: CronJob
    trigger: "0 * * * *"

hidden_entries:
  - id: EP-HID-001
    path: "/health"
```

**Block 3**: `yaml:discovery_checklist`

```yaml:discovery_checklist
checklist:
  rest_api:
    scanned: true
    count: 45
    source_patterns: ["routes/*.py", "@app.route"]
    status: COMPLETED
  internal_api:
    scanned: true
    count: 8
    status: COMPLETED
  graphql:
    scanned: true
    count: 0
    status: NOT_APPLICABLE
    reason: "Project does not use GraphQL"
  websocket:
    scanned: true
    count: 2
    status: COMPLETED
  cron_jobs:
    scanned: true
    count: 3
    status: COMPLETED
  message_queue:
    scanned: true
    count: 0
    status: NOT_APPLICABLE
  webhooks:
    scanned: true
    count: 2
    status: COMPLETED
  file_upload:
    scanned: true
    count: 3
    status: COMPLETED
  health_endpoints:
    scanned: true
    count: 3
    status: COMPLETED
  debug_endpoints:
    scanned: true
    count: 1
    status: COMPLETED
  # AI/LLM Entry Types (when applicable)
  llm_gateway:
    scanned: true
    count: 0
    status: NOT_APPLICABLE
    reason: "Project is not an AI/LLM application"
  model_endpoint:
    scanned: true
    count: 0
    status: NOT_APPLICABLE
  rag_pipeline:
    scanned: true
    count: 0
    status: NOT_APPLICABLE
  agent_tool:
    scanned: true
    count: 0
    status: NOT_APPLICABLE

summary:
  total_entry_points: 72
  coverage: "100%"
  ai_llm_detected: false  # Set to true if any AI entry types found
```

### Scenario Detection

| Scenario | Trigger | Extension |
|----------|---------|-----------|
| Standard Web/API | No AI/No Cloud-Native | Standard flow |
| AI/LLM Application | Model calls/RAG detected | `--all-llm` |
| Cloud-Native | AWS/Azure/GCP/K8s | `--cloud {provider}` |
| Microservices | Multi-service/Docker | Cross-service analysis |

### Non-Typical Project Escape Hatch (P1-GAP-14)

For projects that don't fit standard patterns (SDK/libraries, data pipelines, batch processors):

| Project Type | Approach | Discovery Checklist Adjustment |
|--------------|----------|-------------------------------|
| **SDK/Library** | No user-facing entry points | Mark all entry types as `NOT_APPLICABLE` with reason |
| **Data Pipeline** | No HTTP endpoints | Focus on `cron_jobs`, `message_queue` entry types |
| **Batch Processor** | No real-time API | Mark `rest_api`, `websocket` as `NOT_APPLICABLE` |
| **CLI Tool** | Command-line interface only | Create custom `cli_commands` entry type |
| **Infrastructure Code** | Terraform/Pulumi | Focus on `deploy` category, skip endpoint discovery |

**Escape Hatch Protocol**:
1. If `total_entry_points == 0` after P1.0, check if project is non-typical
2. Add `project_category: "non_typical"` to P1_project_context.yaml
3. Document justification in `discovery_checklist.escape_hatch_reason`
4. Proceed to P1.2 with adapted focus

---

## P1.3 Dynamic Route Detection (Script)

> **Note**: P1.0 `--p1-discovery` already includes Layer 3 analysis. P1.3 is a **refinement step**
> that runs ONLY if `layer3_dynamic_indicators.total_count > 0` in P1.0 output, requiring deeper analysis.

**Run after P1.2 LLM analysis** (OPTIONAL - only if P1.0 found dynamic indicators):

```bash
# Skip if P1.0 layer3_dynamic_indicators.total_count == 0
# Run only for deeper analysis of HIGH risk indicators
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/module_discovery.py . --detect-dynamic --pretty
```

### Layer 3 Indicator Types

| Indicator Type | Risk Level | Description |
|----------------|------------|-------------|
| conditional_registration | HIGH | Routes registered based on config flags |
| plugin_system | MEDIUM | Routes may be added by plugins at runtime |
| reflection_calls | HIGH | getattr/eval/exec used for route creation |
| dynamic_url_construction | MEDIUM | URL paths built from variables |
| runtime_registration | MEDIUM | Routes added via function calls |

### Handling Dynamic Indicators

If `layer3_dynamic_indicators.total_count > 0`:

1. Review each indicator in the output
2. For HIGH risk indicators: Document in `architecture_findings` with F-P1-xxx ID
3. For MEDIUM risk indicators: Note in `discovery_checklist.notes`
4. Add to `coverage_confidence.uncertainty_sources` in final output

---

## P1.4 Three-Source Alignment (Script)

**Run to validate alignment between discovery sources**:

```bash
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --p1-source-alignment --root .
```

### Three Sources Compared

| Source | File | Content | Priority |
|--------|------|---------|----------|
| Source A | P1_static_discovery.yaml | Script-discovered routes/configs | Primary (deterministic) |
| Source B | P1_static_discovery.yaml → `documentation` section | Extracted from doc analysis | Secondary (doc-based) |
| Source C | P1_project_context.yaml | LLM-synthesized inventory | Tertiary (semantic) |

> **Note**: Source B is extracted from the `documentation` section of P1_static_discovery.yaml
> (generated by `module_discovery.py --p1-discovery`). If P1.1 was executed, doc_analysis
> data is also included. There is NO separate P1_doc_inventory.yaml file.

### Alignment Score Interpretation

| Score Range | Interpretation | Action |
|-------------|----------------|--------|
| >= 0.85 | HIGH_CONFIDENCE | Proceed to P1.5 validation |
| 0.70-0.84 | MEDIUM_CONFIDENCE | Review items only in one source |
| < 0.70 | LOW_CONFIDENCE | Investigate discrepancies before proceeding |

### Output: P1_source_alignment.yaml

```yaml
schema_version: "3.2.0 (20260512a)"
overall_alignment_score: 0.82
alignment_by_category:
  entry_points:
    total_items: 45
    in_all_three_sources: ["api/login", "api/register"]
    in_two_sources: ["api/webhook"]
    only_in_static: ["api/internal"]
    only_in_docs: []
    only_in_llm: ["api/admin"]
    needs_review: true
```

---

## P1.5 Validation & Coverage Confidence (Script+LLM)

**Run after completing P1.4**:

```bash
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --validate --phase 1 --root .
```

**Validation Rules**:

| Rule | Severity |
|------|----------|
| All code files analyzed | BLOCKING |
| All documented modules verified | BLOCKING |
| All 14 entry types scanned | WARNING |
| Entry point ID uniqueness | BLOCKING |
| Module count consistency | WARNING |
| Coverage confidence >= 0.70 | WARNING |
| Source alignment score >= 0.70 | WARNING |

**If BLOCKING fails**: Fix issues, do not proceed
**If WARNING only**: Acknowledge and continue

### Coverage Confidence Output

The final `P1_project_context.yaml` MUST include:

```yaml
coverage_confidence:
  overall_confidence: 0.82
  confidence_breakdown:
    layer1_contribution: 0.57
    layer2_contribution: 0.24
    base_confidence: 0.86
    uncertainty_penalty: 0.08
    tool_boost: 0.04
  uncertainty_sources:
    - type: conditional_registration
      impact: HIGH
      count: 2
      description: "Routes registered based on configuration flags"
    - type: no_openapi_spec
      impact: LOW
      count: 1
      description: "No OpenAPI specification found for validation"
  has_uncertainty: true
  recommendation: "MEDIUM_CONFIDENCE_REVIEW_RECOMMENDED"
```

---

## Report Template

```markdown
# P1: Project Understanding

## Sub-Phase Progress Tracker

| Sub-Phase | Status | Output | Notes |
|-----------|--------|--------|-------|
| P1.0 Three-Layer Discovery | □ Done | P1_static_discovery.yaml | coverage_confidence: _____ |
| P1.1 Doc Analysis | □ Done / □ Skipped | yaml:doc_analysis | Skip reason: _____ |
| P1.2 Code Analysis | □ Done | 3 YAML blocks | |
| P1.3 Dynamic Indicators | □ Done | Layer 3 count: _____ | HIGH risk: _____ |
| P1.4 Source Alignment | □ Done | alignment_score: _____ | |
| P1.5 Validation | □ Done | PASSED/FAILED | |

## P1.0 Three-Layer Discovery Summary

| Metric | Value |
|--------|-------|
| total_files | _____ |
| total_directories | _____ |
| Layer 1 routes discovered | _____ |
| Layer 2 directories found | _____ |
| Layer 3 dynamic indicators | _____ |
| coverage_confidence | _____ |
| recommendation | HIGH/MEDIUM/LOW |

## P1.1 Decision
- quality_grade: `{grade}` (score: {score})
- Decision: **Execute P1.1** / **Skip P1.1**
- Reason: _____

[yaml:doc_analysis block if P1.1 executed]

## Module Inventory

[yaml:module_inventory block]

## Entry Point Inventory

[yaml:entry_point_inventory block]

## Discovery Checklist

[yaml:discovery_checklist block]

## Layer 3 Dynamic Indicators (Uncertainty Sources)

| Indicator Type | Count | Risk | Files |
|----------------|-------|------|-------|
| conditional_registration | _____ | HIGH | _____ |
| plugin_system | _____ | MEDIUM | _____ |
| reflection_calls | _____ | HIGH | _____ |

## Source Alignment Summary

| Category | 3-Source | 2-Source | 1-Source | Needs Review |
|----------|----------|----------|----------|--------------|
| entry_points | _____ | _____ | _____ | _____ |
| modules | _____ | _____ | _____ | _____ |
| frameworks | _____ | _____ | _____ | _____ |

**Alignment Score**: _____
**Recommendation**: _____

## Architecture Findings

```yaml:architecture_findings
findings:
  - id: F-P1-001
    type: architecture
    title: "Finding title"
    description: "Detailed description"
    severity: HIGH      # CRITICAL|HIGH|MEDIUM|LOW|INFO
    category: entry_point|module_structure|dependency|configuration|dynamic_route
    location:
      module_id: M-xxx
      file: "path/to/file.py"
      line: 123
    security_relevance: "Why this matters for security"
    related_elements:
      - type: entry_point
        id: EP-xxx
      - type: module
        id: M-xxx
    recommended_action: "What to investigate in later phases"

summary:
  total: 0
  by_severity:
    critical: 0
    high: 0
    medium: 0
    low: 0
    info: 0
```

**Finding Categories**:
- `entry_point`: Unusual or sensitive entry points discovered
- `module_structure`: Architectural concerns or anti-patterns
- `dependency`: Risky or outdated dependencies
- `configuration`: Security-relevant configuration issues
- `dynamic_route`: Routes that may be registered dynamically (uncertainty source)

## Coverage Confidence

```yaml:coverage_confidence
overall_confidence: 0.82
confidence_breakdown:
  layer1_contribution: 0.57
  layer2_contribution: 0.24
  base_confidence: 0.86
  uncertainty_penalty: 0.08
  tool_boost: 0.04
uncertainty_sources:
  - type: conditional_registration
    impact: HIGH
    count: 2
has_uncertainty: true
recommendation: "MEDIUM_CONFIDENCE_REVIEW_RECOMMENDED"
```
```

---

## Tool-Assisted Discovery (Optional)

When the target project is large (>100 files) or has complex architecture, supplement `module_discovery.py` with code analysis tools. Load `@references/tool-integration-guide.md` for full tool catalog.

**Pre-requisite**: Index the target repo first:
```bash
luoshu_status(repo="<target>")                    # Check if indexed
luoshu_index(repo="<target>", languages=["python"], parallel=4)  # Index if needed
```

**Architecture discovery**:
- `luoshu_query_dfd(repo="<target>")` — system-level DFD candidates (processes, stores, external entities)
- `luoshu_query_chain(symbol="<main>", edge_kind="IMPORTS", max_depth=2)` — module dependency tree
- `luoshu_diagnose(symbol="<critical_func>")` — full diagnostic on key entry points

**Binary targets** (when source is unavailable): Load `@references/binary-analysis.md`:
- `luoshu_auto_binary(binary="<path>")` — fast binary recon into knowledge graph
- `import_binary(binary_path="<path>")` + `list_exports()` — Ghidra MCP for detailed analysis

**Integration**: Tool-discovered modules supplement `module_discovery.py` output. Cross-reference both sources for completeness before finalizing M-NNN inventory.

---

## Completion Checklist

Before marking Phase 1 complete:

- [ ] P1.0 three-layer discovery executed (P1_static_discovery.yaml)
- [ ] P1.1 executed OR skipped (with valid reason)
- [ ] P1.2 LLM analysis complete:
  - [ ] yaml:module_inventory present
  - [ ] yaml:entry_point_inventory present
  - [ ] yaml:discovery_checklist present with all scanned:true
  - [ ] yaml:architecture_findings present (even if empty)
- [ ] P1.3 dynamic indicators reviewed (if any)
- [ ] P1.4 source alignment validated (P1_source_alignment.yaml)
- [ ] P1.5 validation passed:
  - [ ] coverage_confidence included in output
  - [ ] uncertainty_sources documented (if any)

---

**End of Phase 1 Instructions** (~930 lines, ~7K tokens)
