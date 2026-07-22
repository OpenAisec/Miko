<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Phase 8R: Detailed Risk Analysis Reports (Optional)

**Type**: Deep Analysis
**Executor**: LLM
**Knowledge**: All P1-P8 data, CWE/CAPEC/ATT&CK, ASVS/WSTG
**Prerequisite**: P8 completed successfully

---

## ⚠️ Trigger Conditions

P8R activates through ANY of:

1. **Post-P8 prompt**: After P8 completion, ask: "Generate detailed per-risk analysis reports? [Y/N]"
2. **`--detailed` flag**: Set at session start → auto-trigger after P8
3. **Standalone invocation**: After P8 completion, user requests detailed reports

> **P8R is OPTIONAL** — skipping does NOT affect main P8 reports. The P1-P8 workflow remains unchanged.

---

## ⚠️ MANDATORY: 4-Phase Gating Protocol (BLOCKING)

> **CRITICAL**: You MUST complete the following four stages in sequence and **output the result of each stage**. Skipping any stage will degrade analysis quality!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🧠 THINKING - Phase 8R Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Purpose**: Generate per-VR detailed analysis reports with 12 analysis elements each. Every VR from P6 gets its own dedicated report.

**⚠️ You MUST output THINKING results in the following format:**

```
🧠 THINKING - P8R Entry Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📌 CORE PROBLEM
Generate {VR_count} detailed risk analysis reports, each with 12 analysis elements

📊 UPSTREAM DATA (from P8 manifest)
| Metric | Value | Source |
|--------|-------|--------|
| Total VR Count | {actual} | P6_validated_risks.yaml |
| P0 Risks | {count} | Priority breakdown |
| P1 Risks | {count} | Priority breakdown |
| P2 Risks | {count} | Priority breakdown |
| P3 Risks | {count} | Priority breakdown |
| POC Count | {count} | P6 poc_details |
| Attack Chain Count | {count} | P6 attack_chains |
| Mitigation Count | {count} | P7 mitigations |

❓ UNKNOWNS
- Source code availability for root cause analysis
- Related CVE details for cross-referencing

⚠️ RISKS
- POC code truncated or summarized
- Missing attack chain cross-references
- Incomplete traceability chains

💡 APPROACH
1. Read P6_validated_risks.yaml for all VR entities
2. Read P7_mitigation_plan.yaml for MIT cross-references
3. Read P8_report_manifest.yaml for report structure context
4. Generate one VR-xxx-{title-slug}.md per validated risk
5. Write P8R_manifest.yaml with generation metadata
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 📋 PLANNING - Phase 8R Execution Plan
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**⚠️ You MUST output PLANNING results in the following format:**

```
📋 PLANNING - P8R Execution Plan
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 EXECUTION PLAN
| Step | Action | Input | Output |
|------|--------|-------|--------|
| 1 | Load upstream data | P6+P7+P8 YAML | VR list with cross-refs |
| 2 | Generate VR reports | Each VR entity | VR-xxx-{slug}.md per VR |
| 3 | Write P8R manifest | Generation results | P8R_manifest.yaml |

📊 RESOURCE ESTIMATE
- VR reports to generate: {count}
- Estimated tokens per report: 2K-6K
- Total estimated output: {count * 4K} tokens

🔗 CROSS-REFERENCE MAP
VR-xxx → POC-xxx (from P6)
VR-xxx → MIT-xxx (from P7)
VR-xxx → AC-xxx (from P6 attack_chains)
VR-xxx → T-xxx (from P5 via P6)
VR-xxx → GAP-xxx (from P4 via P5)
VR-xxx → F-xxx (from P1-P3)
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### ⚡ EXECUTION - Phase 8R Report Generation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

---

## §1 Data Loading

### 1.1 Load Upstream YAML

```bash
# Load all VR data with cross-references
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 6 --session-id {SESSION_ID}

# Load mitigation mappings
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 7 --session-id {SESSION_ID}

# Load P8 manifest for report structure
python ${SKILL_PATH:-$CLAUDE_SKILL_DIR}/scripts/phase_data.py --query --phase 8 --session-id {SESSION_ID}
```

### 1.2 Build VR Index

Construct a master index from P6 validated risks:

| VR-ID | Title | CVSS | Priority | STRIDE | POC-IDs | MIT-IDs | AC-IDs |
|-------|-------|------|----------|--------|---------|---------|--------|
| VR-001 | {title} | {score} | P{n} | {type} | POC-xxx | MIT-xxx | AC-xxx |
| ... | ... | ... | ... | ... | ... | ... | ... |

---

## §2 Per-VR Report Template (12 Analysis Elements)

> **MANDATORY**: Generate one report per VR using the following 12-element template.
> Each report file: `Risk_Assessment_Report/detailed/VR-{NNN}-{title-slug}.md`

> **LANGUAGE ADAPTATION**: The template below uses Chinese headings with English in parentheses
> as the reference format. **Adapt all headings and field labels to match the session language**
> (from session metadata `language` field). For English sessions, use only English headings
> (e.g., "## 1. Risk Overview" instead of "## 1. 风险概述 (Risk Overview)").
> For other languages, translate headings accordingly while preserving the 12-element structure.

### Report Template

```markdown
# VR-{NNN}: {Title}

## 1. 风险概述 (Risk Overview)

| 属性 | 值 |
|------|-----|
| **风险ID** | VR-{NNN} |
| **标题** | {title} |
| **CVSS评分** | {score} ({severity}) |
| **CWE** | CWE-{id} ({name}) |
| **优先级** | P{n} - {priority_label} |
| **STRIDE分类** | {stride_type} ({chinese_name}) |
| **影响资产** | {affected_modules, entry_points} |

## 2. 攻击入口 (Entry Points)

### 2.1 主要入口: {primary_entry}

- **路径**: {entry_path_or_url}
- **入口条件**: {conditions_for_access}
- **触发条件**: {trigger_mechanism}

### 2.2 次要入口: {secondary_entry}
(Repeat for each additional entry point)

## 3. 数据流分析 (Data Flow Analysis)

{ASCII diagram showing complete data flow from entry point to vulnerable point}

```
{caller} → {function} → {vulnerable_point} → {impact}
```

### 数据流中的敏感数据传递

| 阶段 | 数据 | 保护状态 |
|------|------|---------:|
| {stage_1} | {data} | {protection_status} |
| ... | ... | ... |

## 4. 根因分析 (Root Cause Analysis)

### 直接原因
{Direct technical cause with file:line references}

### 深层原因
1. {Systemic cause 1}
2. {Systemic cause 2}
3. {Systemic cause 3}

## 5. 利用场景 (Exploit Scenario)

### 攻击步骤

**步骤1: {step_title}**
{Detailed description of attacker action}

**步骤2: {step_title}**
{Detailed description}

(Continue for all steps)

### 攻击链示例
```
{step_1} → {step_2} → {step_3} → {impact}
```

## 6. POC代码 (POC Code)

> ⚠️ MANDATORY: Copy POC VERBATIM from P6 data. Do NOT summarize or truncate.
> Verification Status: {✅ Verified | ⚠️ Theoretical | ❓ Pending | ❌ Excluded}

### POC {N}: {poc_title}

```{language}
{COMPLETE POC CODE - VERBATIM FROM P6}
```

**执行环境**:
- 前提条件: {prerequisites}
- 所需工具: {tools_required}
- 环境配置: {environment_setup}

## 7. 影响分析 (Impact Analysis)

### 受影响系统

| 系统/组件 | 影响描述 |
|-----------|---------:|
| {system_1} | {impact_description} |
| ... | ... |

### 受影响用户
- {user_group_1}: {impact}
- {user_group_2}: {impact}

### 数据暴露面
- {exposed_data_1}
- {exposed_data_2}

## 8. 攻击链关联 (Attack Chain Context)

### 所属攻击链

| 攻击链ID | 链名称 | 本VR位置 | 链中总步骤 |
|----------|--------|---------|-----------|
| AC-{xxx} | {chain_name} | 第{n}步/{total} | {total_steps} |

### 与其他VR的关系

| 关联VR | 关系类型 | 说明 |
|--------|---------|------:|
| VR-{xxx} | {前置/后续/并行} | {relationship_description} |

## 9. 关联漏洞 (Related Vulnerabilities)

### CWE详情
- **CWE-{id}**: {name}
- **描述**: {description}
- **常见影响**: {common_consequences}

### 相关CVE
| CVE编号 | 描述 | CVSS | 关联度 |
|---------|------|------|-------|
| CVE-{yyyy}-{nnnnn} | {description} | {score} | {relevance} |

### CAPEC攻击模式
| CAPEC编号 | 名称 | 攻击步骤 |
|----------|------|---------|
| CAPEC-{nnn} | {name} | {attack_steps_summary} |

## 10. 缓解策略 (Mitigation Strategy)

### MIT-{xxx}: {mitigation_title}

| 属性 | 值 |
|------|-----|
| **实施难度** | {LOW/MEDIUM/HIGH} |
| **预估工作量** | {hours/days} |
| **优先级** | {priority} |

### 修复前代码 (Before)
```{language}
{vulnerable_code}
```

### 修复后代码 (After)
```{language}
{fixed_code}
```

### 依赖关系
- 前置MIT: {prerequisite_MIT_ids or "无"}
- 后续MIT: {dependent_MIT_ids or "无"}

## 11. 验证方法 (Verification Method)

### 测试用例

| TC-ID | 测试步骤 | 预期结果 | 验证标准 |
|-------|---------|---------|---------|
| TC-{xxx} | {test_steps} | {expected_result} | {verification_criteria} |

### 安全标准参考
- **ASVS**: {asvs_requirement_ids}
- **WSTG**: {wstg_test_ids}
- **OWASP Top 10**: {owasp_category}

## 12. 引用与追溯 (References & Traceability)

### 完整追溯链

```
F-P{n}-{xxx} (发现) → GAP-{xxx} (安全缺口) → T-{S}-{E}-{xxx} (威胁)
    → VR-{xxx} (验证风险) → MIT-{xxx} (缓解措施)
```

### 引用来源

| 引用ID | 类型 | 来源阶段 | 描述 |
|--------|------|---------|------|
| F-P{n}-{xxx} | Finding | P{n} | {finding_description} |
| GAP-{xxx} | SecurityGap | P4 | {gap_description} |
| T-{S}-{E}-{xxx} | Threat | P5 | {threat_description} |
| MIT-{xxx} | Mitigation | P7 | {mitigation_description} |
```

---

## §3 Generation Rules

### 3.1 Content Integrity Rules

| Rule | Enforcement |
|------|-------------|
| **POC Verbatim** | Copy POC code blocks EXACTLY from P6 data — NO summarization, NO truncation |
| **Code References** | All file:line references MUST match actual source code locations from P1 |
| **ID Consistency** | Entity IDs (VR-xxx, MIT-xxx, etc.) MUST match across P1-P8 data |
| **Cross-Reference Completeness** | Every VR MUST have: ≥1 entry point, ≥1 POC or justification, ≥1 MIT |
| **Traceability Chain** | §12 MUST show complete F→GAP→T→VR→MIT chain |
| **Attack Chain Coverage** | §8 MUST list ALL AC-xxx chains that include this VR |

### 3.2 Language Convention

- Report body: Chinese (zh-CN) — matches reference standard
- Technical terms: English preserved (CVSS, CWE, STRIDE, etc.)
- Code blocks and entity IDs: English
- If `--lang=en` flag set at session start: Generate in English instead

### 3.3 Output Sizing Guidelines

| VR Priority | Target Length | Min Elements |
|-------------|--------------|--------------|
| P0 (Critical) | 6K-30K chars | All 12 elements mandatory |
| P1 (High) | 4K-20K chars | All 12 elements mandatory |
| P2 (Medium) | 3K-10K chars | All 12 elements, §9 CVE/CAPEC may be brief |
| P3 (Low) | 2K-6K chars | All 12 elements, §5/§6 may note "低风险,POC省略" |

### 3.4 Generation Order

Generate VR reports in **priority order** (P0 first, then P1, P2, P3):

```
P0 risks → P1 risks → P2 risks → P3 risks
```

Within the same priority level, order by CVSS score (highest first).

---

## §4 Output Structure

### 4.1 File Naming Convention

```
Risk_Assessment_Report/
└── detailed/
    ├── VR-001-{title-slug}.md
    ├── VR-002-{title-slug}.md
    ├── VR-003-{title-slug}.md
    └── ...
```

**Title slug rules**:
- Convert title to lowercase ASCII or pinyin
- Replace spaces/special chars with hyphens
- Max 40 characters
- Example: VR-001 "VNC密码明文日志记录" → `VR-001-vnc-password-plaintext-logging.md`

### 4.2 P8R Manifest (YAML Output)

Write to `.phase_working/{SESSION_ID}/data/P8R_manifest.yaml`:

```yaml
schema_version: "3.2.0 (20260512a)"
phase: "P8R"
session_id: "{SESSION_ID}"
generated_at: "{ISO_8601_TIMESTAMP}"

summary:
  total_vr_count: {count}
  reports_generated: {count}
  total_characters: {sum_of_all_report_chars}
  generation_order: [VR-001, VR-002, ...]

reports:
  - vr_id: "VR-001"
    title: "{title}"
    filename: "VR-001-{slug}.md"
    priority: "P0"
    cvss: {score}
    character_count: {count}
    elements_completed: 12
    poc_included: true
    mitigation_included: true
    traceability_complete: true

  - vr_id: "VR-002"
    # ...repeat for each VR

cross_reference_integrity:
  all_vr_covered: true
  all_poc_verbatim: true
  all_mit_linked: true
  all_chains_mapped: true
  traceability_complete: true

# Count conservation check
count_check:
  p6_vr_count: {from_P6}
  p8r_report_count: {generated}
  match: true  # MUST be true
```

---

## §5 Validation Gates

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 🔍 REFLECTION - Phase 8R Completion Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**⚠️ You MUST output REFLECTION results in the following format:**

```
🔍 REFLECTION - P8R Completion Gate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ VALIDATION CHECKLIST
[ ] Report count matches P6 VR count (count conservation)
[ ] All 12 elements present in every report
[ ] All POC code verbatim (not summarized)
[ ] All MIT cross-references valid
[ ] All attack chain mappings complete
[ ] All traceability chains (F→GAP→T→VR→MIT) complete
[ ] File naming convention followed
[ ] P8R_manifest.yaml written and valid
[ ] Reports ordered by priority then CVSS

📊 GENERATION METRICS
| Metric | Value |
|--------|-------|
| Total VR Reports | {count} |
| P0 Reports | {count} |
| P1 Reports | {count} |
| P2 Reports | {count} |
| P3 Reports | {count} |
| Total Characters | {sum} |
| Avg Report Length | {avg} chars |
| POC Coverage | {pct}% |
| MIT Coverage | {pct}% |

⚠️ ISSUES FOUND
- {any issues or "None"}

🎯 OUTPUT CONFIDENCE: {HIGH/MEDIUM/LOW}

⛔ COMPLETION GATE
- All checks passed? [YES/NO]
- Ready to finalize P8R? [YES/NO]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

⛔ Any check fails → Fix and re-verify until all pass

### Validation Rules

| Check | Condition | Severity |
|-------|-----------|----------|
| **Count Conservation** | P8R report count == P6 VR count | BLOCKING |
| **Element Completeness** | All 12 elements in every P0/P1 report | BLOCKING |
| **POC Verbatim** | POC code identical to P6 source | BLOCKING |
| **MIT Linkage** | Every VR links to ≥1 MIT-xxx | WARNING |
| **Chain Coverage** | Every VR in ≥1 AC-xxx shows mapping | WARNING |
| **Traceability** | §12 has complete F→GAP→T→VR→MIT chain | WARNING |
| **File Naming** | Follows VR-{NNN}-{slug}.md convention | WARNING |
| **Manifest Valid** | P8R_manifest.yaml passes schema check | BLOCKING |

---

## §6 Reference Standard

The following VR-Analysis samples serve as quality benchmarks:

```
~/STRIDE/test/e/EDA代码文件/Risk_Assessment_Report/VR-Analysis/
├── VR-001-VNC密码明文日志.md          (9.1 CVSS, ~8K chars)
├── VR-002-alertApi未授权访问.md
├── VR-003-CTLD-IP白名单绕过.md
├── ...
└── VR-020-{title}.md
```

**Quality benchmarks from reference samples**:
- Each report: 4K-30K characters
- All 12 analysis elements populated
- ASCII data flow diagrams with code call chains
- Complete POC code blocks (bash, python, etc.)
- Impact analysis with affected systems table
- Attack chain cross-references with position notation
- Before/after code comparisons in §10
- Complete traceability chains in §12

---

## §7 Integration with HTML Output

If HTML output is enabled (via `scripts/report_generator.py`):

- Detailed VR reports are converted to HTML alongside main reports
- Output path: `Risk_Assessment_Report/html/detailed/VR-{NNN}-{slug}.html`
- HTML index page includes links to all detailed reports
- Severity color coding applies to VR report headers

---

## §8 Error Handling

| Error | Recovery |
|-------|----------|
| P6 data unavailable | ABORT — P8R requires completed P6 |
| P7 data unavailable | WARN — Generate reports without §10 mitigation details |
| VR has no POC | Note in §6: "POC未设计 — 参见P6排除原因" |
| VR has no MIT | Note in §10: "缓解措施待定 — 参见P7遗留项" |
| Source code unavailable | §4 root cause uses architectural reasoning instead of file:line |
| Attack chain not mapped | §8 notes: "未纳入已知攻击链" |
