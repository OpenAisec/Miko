---
category: audit
name: code-audit
description: |
  Professional code security audit skill covering 55+ vulnerability types.
  Enhanced with WooYun 88,636 real-world vulnerability cases (2010-2016).
  This skill should be used when performing security audits, vulnerability scanning,
  penetration testing preparation, or code review for security issues.
  Supports 9 languages: Java, Python, Go, PHP, JavaScript/Node.js, C/C++, .NET/C#, Ruby, Rust.
  Includes 143 mandatory detection items across all languages with language-specific checklists.
  Covers SQL injection, XSS, RCE, deserialization, SSRF, JNDI injection, JDBC protocol injection,
  authentication bypass, business logic flaws, race conditions, and modern security domains (LLM, Serverless, Android).
  WooYun integration adds: statistical-driven parameter priority, bypass techniques library,
  logic vulnerability patterns, and real-case references.
  v1.0: Initial public release with Docker deployment verification framework.
tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Task
  - LSP
model: sonnet
priority: high
file_patterns:
  - "**/*.java"
  - "**/*.py"
  - "**/*.go"
  - "**/*.php"
  - "**/*.js"
  - "**/*.ts"
  - "**/*.jsx"
  - "**/*.tsx"
  - "**/*.c"
  - "**/*.cpp"
  - "**/*.h"
  - "**/*.cs"
  - "**/*.rb"
  - "**/*.rs"
  - "**/*.xml"
  - "**/*.yml"
  - "**/*.yaml"
  - "**/*.json"
  - "**/*.properties"
  - "**/Dockerfile"
  - "**/*.tf"
exclude_patterns:
  - "**/node_references/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/.git/**"
  - "**/test/**"
  - "**/tests/**"
  - "**/__pycache__/**"
---

# Code Audit Skill

> 专业代码安全审计技能 | Professional Code Security Audit
> 支持模式: quick / standard / deep

## When to Use This Skill

This skill should be used when:

- User requests **code audit**, **security audit**, or **vulnerability scanning**
- User asks to **check code security** or **find security issues**
- User mentions **/audit** or **/code-audit**
- User wants to **review code for vulnerabilities** before deployment
- User needs **penetration testing preparation** or **security assessment**

**Trigger phrases:**
- "审计这个项目" / "Audit this project"
- "检查代码安全" / "Check code security"
- "找出安全漏洞" / "Find security vulnerabilities"
- "/audit", "/code-audit"

---

## Quick Reference

### Scan Modes

| Mode | Use Case | Scope |
|------|----------|-------|
| **Quick** | CI/CD, small projects | High-risk vulns, secrets, dependency CVEs |
| **Standard** | Regular audits | OWASP Top 10, auth, crypto |
| **Deep** | Critical projects, pentests | Full coverage, attack chains, business logic |

### Core Workflow

```
1. Reconnaissance   → Identify tech stack, map attack surface
2. Vulnerability Hunt → Search patterns, trace data flow
3. Verification    → Confirm exploitability, filter false positives
4. Docker Verify   → [NEW] Dynamic verification in sandbox (optional)
5. Report          → Document findings with PoC and fixes
```

### Docker部署验证

对于深度审计，可使用Docker沙箱进行**动态验证**:

```bash
# 生成验证环境
code-audit --generate-docker-env

# 启动并验证
docker-compose up -d
docker exec -it sandbox python /workspace/poc/verify_all.py
```

详见: `references/core/docker_verification.md`

---

## Execution Controller（执行控制器 — 必经路径）

> ⚠️ 以下步骤是审计执行的必经路径，不是参考建议。
> 每步有必须产出的输出，后续步骤依赖前序输出。不产出 = 用户可见缺失。

### Step 1: 模式判定

根据用户指令确定审计模式：

| 用户指令关键词 | 模式 |
|--------------|------|
| "快速扫描" "quick" "CI检查" | quick |
| "审计" "扫描" "安全检查"（无特殊说明） | standard |
| "深度审计" "deep" "渗透测试准备" "全面审计" | deep |
| 无法判定 | **问用户，不得自行假设** |

**反降级规则**: 用户指定的模式不可自行降级。项目规模大不是降级理由，而是启用 Multi-Agent 的理由。降级需用户明确确认。

**必须输出**:
```
[MODE] {quick|standard|deep}
```

### Step 2: 文档加载

按模式加载必要文档（用 Read 工具实际读取，不是"知道有这个文件"）：

| 模式 | 必须 Read 的文档 |
|------|-----------------|
| quick | 当前 SKILL.md 已加载，无需额外文档 |
| standard | + `references/checklists/coverage_matrix.md` + 对应语言 checklist |
| deep | + **`agent.md`（完整读取，不可跳过）** + `coverage_matrix.md` + 对应语言 checklist |

deep 模式下 agent.md 是必读文档 — Step 4 的执行计划模板包含只有 agent.md 中才有的字段（维度权重、Agent 切分模板、门控条件、执行状态机）。

**必须输出**:
```
[LOADED] {实际 Read 的文档列表，含行数}
```

### Step 3: 侦察（Reconnaissance）

对目标项目执行攻击面测绘。

**必须输出**:
```
[RECON]
项目规模: {X files, Y directories}
技术栈: {language, framework, version}
项目类型: {CMS | 金融 | SaaS | 数据平台 | 身份认证 | IoT | 通用Web}
入口点: {Controller/Router/Handler 数量}
关键模块: {列表}
```

### Step 4: 执行计划 → STOP

基于 Step 1-3 的输出生成执行计划。**输出后暂停，等待用户确认才能继续。**

**quick/standard 模板**:
```
[PLAN]
模式: {mode}
技术栈: {from Step 3}
扫描维度: {计划覆盖的 D1-D10 维度}
已加载文档: {from Step 2}
```

**deep 模板**（全部字段必填 — 标注了信息来源文档）:
```
[PLAN]
模式: deep
项目规模: {from Step 3}
技术栈: {from Step 3}
维度权重: {from agent.md 状态机 → 项目类型维度权重，如 CMS: D5(++), D1(+), D3(+), D6(+)}
Agent 方案: {from agent.md Agent 模板 → 每个 Agent 负责的维度和 max_turns}
Agent 数量: {from agent.md 规模建议 → 小型(<10K) 2-3, 中型(10K-100K) 3-5, 大型(>100K) 5-9}
D9 覆盖策略: {若项目有后台管理/多角色/多租户 → D9 必查，D3 Agent 须同时覆盖 D9a(IDOR+权限一致性+Mass Assignment)}
轮次规划: R1 广度扫描 → R1 评估 → R2 增量补漏(按需)
门控条件: PHASE_1_RECON → ROUND_N_RUNNING → ROUND_N_EVALUATION → REPORT
预估总 turns: {Agent数 × max_turns}
已加载文档: {from Step 2}
```

**⚠️ STOP — 输出执行计划后暂停。等待用户确认后才能开始审计。**

### Step 5: 执行

用户确认后，按执行计划和已加载文档执行：

- **quick**: 高危模式匹配扫描，直接输出
- **standard**: 按 Phase 1→5 顺序执行
- **deep**: 严格按 agent.md 执行状态机
  - 启动 Multi-Agent 并行（按 Step 4 确认的 Agent 方案）
  - 遵守每个 State 的门控条件
  - 轮次评估使用 agent.md 三问法则

### Step 6: 报告门控

生成报告前验证：

| 前置条件 | quick | standard | deep |
|---------|-------|----------|------|
| 高危模式扫描完成 | ✅ | ✅ | ✅ |
| D1-D10 覆盖率标记（✅已覆盖/⚠️浅覆盖/❌未覆盖） | — | ✅ | ✅ |
| 所有 Agent 完成或超时标注 | — | — | ✅ |
| 轮次评估三问通过 | — | — | ✅ |

不满足前置条件 → 不得生成最终报告。

---

## Anti-Hallucination Rules (MUST FOLLOW)

```
⚠️ Every finding MUST be based on actual code read via tools

✗ Do NOT guess file paths based on "typical project structure"
✗ Do NOT fabricate code snippets from memory
✗ Do NOT report vulnerabilities in files you haven't read

✓ MUST use Read/Glob to verify file exists before reporting
✓ MUST quote actual code from Read tool output
✓ MUST match project's actual tech stack
```

**Core principle: Better to miss a vulnerability than report a false positive.**

---

## Anti-Confirmation-Bias Rules (MUST FOLLOW)

```
⚠️ Audit MUST be methodology-driven, NOT case-driven

✗ Do NOT say "基于之前的审计经验，我将重点关注..."
✗ Do NOT prioritize certain vuln types based on "known CVEs"
✗ Do NOT skip checklist items because they seem "less likely"

✓ MUST enumerate ALL sensitive operations, then verify EACH one
✓ MUST complete the full checklist for EACH vulnerability type
✓ MUST treat all potential vulnerabilities with equal rigor
```

**Core principle: Discover ALL potential vulnerabilities, not just familiar patterns.**

---

## Two-Layer Checklist (两层检查清单)

> **Layer 1**: `coverage_matrix.md` — Phase 2A后加载，验证10个安全维度覆盖率
> **Layer 2**: 语言语义提示 — 仅对未覆盖维度按需加载对应段落

| 文件 | 用途 |
|------|------|
| **`references/checklists/coverage_matrix.md`** | **覆盖率矩阵 (D1-D10)** |
| `references/checklists/universal.md` | 通用架构/逻辑级语义提示 |
| `references/checklists/java.md` | Java 语义提示 (10维度) |
| `references/checklists/python.md` | Python 语义提示 |
| `references/checklists/php.md` | PHP 语义提示 |
| `references/checklists/javascript.md` | JavaScript/Node.js 语义提示 |
| `references/checklists/go.md` | Go 语义提示 |
| `references/checklists/dotnet.md` | .NET/C# 语义提示 |
| `references/checklists/ruby.md` | Ruby 语义提示 |
| `references/checklists/c_cpp.md` | C/C++ 语义提示 |
| `references/checklists/rust.md` | Rust 语义提示 |

**核心原则**: Checklist 不驱动审计，而是验证覆盖。LLM 先自由审计(Phase 2A)，再用矩阵查漏(Phase 2B)。

---

## Module Reference

### Core Modules (Load First)

| Module | Path | Purpose |
|--------|------|---------|
| **Capability Baseline** | `references/core/capability_baseline.md` | **防止能力丢失的回归测试框架** |
| Anti-Hallucination | `references/core/anti_hallucination.md` | Prevent false positives |
| Audit Methodology | `references/core/comprehensive_audit_methodology.md` | Systematic framework, **coverage tracking** |
| Taint Analysis | `references/core/taint_analysis.md` | Data flow tracking, **LSP-enhanced tracking**, Slot type classification |
| PoC Generation | `references/core/poc_generation.md` | Verification templates |
| External Tools | `references/core/external_tools_guide.md` | Semgrep/Bandit integration |

### Language Modules (Load by Tech Stack)

| Language | Module | Key Vulnerabilities |
|----------|--------|---------------------|
| Java | `references/languages/java.md` | SQL injection, XXE, deserialization |
| Python | `references/languages/python.md` | Pickle, SSTI, command injection |
| Go | `references/languages/go.md` | Race conditions, SSRF |
| PHP | `references/languages/php.md` | File inclusion, deserialization |
| JavaScript | `references/languages/javascript.md` | Prototype pollution, XSS |

### Security Domain Modules (Load as Needed)

| Domain | Module | When to Load |
|--------|--------|--------------|
| API Security | `references/security/api_security.md` | REST/GraphQL APIs |
| LLM Security | `references/security/llm_security.md` | AI/ML applications |
| Serverless | `references/security/serverless.md` | AWS Lambda, Azure Functions |
| Cryptography | `references/security/cryptography.md` | Encryption, TLS, JWT |
| Race Conditions | `references/security/race_conditions.md` | Concurrent operations |

---

## Tool Priority Strategy

```
Priority 1: External Professional Tools (if available)
├─ semgrep scan --config auto          # Multi-language SAST
├─ bandit -r ./src                      # Python security
├─ gosec ./...                          # Go security
└─ gitleaks detect                      # Secret scanning

Priority 2: Built-in Analysis (always available)
├─ LSP semantic analysis                # goToDefinition, findReferences, incomingCalls
├─ Read + Grep pattern matching         # Core analysis
└─ Module knowledge base                # 55+ vuln patterns

Priority 3: Verification
├─ PoC templates from references/core/poc_generation.md
└─ Confidence scoring from references/core/verification_methodology.md
```

---

## Detailed Documentation

For complete audit methodology, vulnerability patterns, and detection rules, see:

- **Full Workflow**: `agent.md` - Complete audit process and detection commands
- **Vulnerability Details**: `references/` - Language/framework-specific patterns
- **Tool Integration**: `references/core/external_tools_guide.md`
- **Report Templates**: `references/core/taint_analysis.md`

---

## Version

- **Current**: 1.0
- **Updated**: 2026-02-13

### v1.0 (Initial Public Release)
- 9语言143项强制检测清单 (`references/checklists/`)
- 双轨并行审计框架: Sink-driven + Control-driven + Config-driven
- Docker部署验证框架 (`references/core/docker_verification.md`)
- WooYun 88,636案例库集成
- 安全控制矩阵框架
