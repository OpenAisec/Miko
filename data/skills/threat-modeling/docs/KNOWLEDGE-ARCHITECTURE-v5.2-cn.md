<!-- Threat Modeling Skill | Version 3.1.0 (20260313a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# STRIDE Skill Set - 知识架构 v5.2.2

**版本**: 5.2.2
**日期**: 2026-01-27 (updated 2026-03-13)
**状态**: Production - v3.1.0

---

## 1. 愿景声明

> **"代码优先的自动化应用安全风险评估和威胁建模工具集"**
>
> 一个 LLM 驱动的自动化系统，用于：
> - **安全设计评估**
> - **威胁建模评估**
> - **基础设施安全评估**
>
> 特别针对以下场景扩展：
> - **云原生应用**
> - **LLM/AI 应用**

---

## 2. 知识系统架构

### 2.1 双轨知识系统

知识系统由两个并行运作的知识集组成：

```
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                              安全知识架构 (Security Knowledge Architecture)                     │
├───────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                │
│                       ┌───────────────────────────────────────────┐                           │
│                       │           安全原则 (Security Principles)    │                           │
│                       │       (基础层 - 指导所有阶段)                │                           │
│                       │  DID │ LP │ ZT │ FS │ SOD │ SBD │ CM │ EOM │ OD │ IV                 │
│                       └───────────────────────────────────────────┘                           │
│                                           │                                                    │
│                 ┌─────────────────────────┴─────────────────────────┐                         │
│                 │                                                    │                         │
│                 ▼                                                    ▼                         │
│  ┌─────────────────────────────────────┐      ┌─────────────────────────────────────┐        │
│  │      安全控制集                      │      │      威胁模式集                      │        │
│  │   (做什么 & 怎么做)                  │      │   (知道什么 & 验证什么)              │        │
│  ├─────────────────────────────────────┤      ├─────────────────────────────────────┤        │
│  │                                     │      │                                     │        │
│  │  安全域 (16个)                       │      │  CWE 弱点类型 (974)                 │        │
│  │      │                              │      │      │                              │        │
│  │      ▼                              │      │      ▼                              │        │
│  │  控制集 (18文件, 107控制)            │      │  CAPEC 攻击模式 (615)               │        │
│  │      │                              │      │      │                              │        │
│  │      ▼                              │      │      ▼                              │        │
│  │  OWASP 参考 (74)                    │      │  ATT&CK 技术 (835)                  │        │
│  │      │                              │      │      │                              │        │
│  │      ▼                              │      │      ▼                              │        │
│  │  合规框架 (14)                       │      │  CVE/KEV 漏洞 (323K+)              │        │
│  │                                     │      │                                     │        │
│  └──────────────┬──────────────────────┘      └──────────────┬──────────────────────┘        │
│                 │                                             │                               │
│                 │      ┌─────────────────────────────┐        │                               │
│                 │      │       验证集                 │        │                               │
│                 │      │   (如何验证 & 测试)         │        │                               │
│                 │      ├─────────────────────────────┤        │                               │
│                 │      │                             │        │                               │
│                 └─────▶│  WSTG 测试 (121)           │◀───────┘                               │
│                        │      │                      │                                        │
│                        │      ▼                      │                                        │
│                        │  MASTG 测试 (206)          │                                        │
│                        │      │                      │                                        │
│                        │      ▼                      │                                        │
│                        │  ASVS 要求 (345)           │                                        │
│                        │                             │                                        │
│                        └─────────────────────────────┘                                        │
│                                     │                                                          │
│                                     ▼                                                          │
│                        用于: Phase 6 (验证) / Phase 7 (缓解) / Phase 8 (报告)                │
│                                                                                                │
│  跨集映射:                                                                                    │
│  ├── STRIDE → 安全域 ←→ CWE 弱点类型                                                         │
│  ├── 控制集 ←→ CWE 缓解措施                                                                  │
│  ├── CAPEC → ATT&CK 技术                                                                     │
│  ├── 合规框架 ←→ CWE 合规映射                                                                │
│  ├── stride_verification → WSTG/MASTG/ASVS (STRIDE 到验证)                                  │
│  └── cwe_verification → WSTG/MASTG/ASVS (CWE 到验证)                                        │
│                                                                                                │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 安全原则 (基础层)

安全原则作为基础，指导威胁建模过程的所有阶段。

| 代码 | 原则 | 定义 | 安全控制应用 | 威胁分析应用 |
|------|------|------|-------------|-------------|
| **DID** | 纵深防御 | Defense in Depth | 多层独立安全控制 | 识别单点故障 |
| **LP** | 最小权限 | Least Privilege | 权限控制设计 | 检测过度授权 |
| **ZT** | 零信任 | Zero Trust | 持续验证机制 | 识别隐式信任风险 |
| **FS** | 安全失败 | Fail Securely | 失败时拒绝/降级 | 检测错误处理泄露 |
| **SOD** | 职责分离 | Separation of Duties | 多角色协作 | 识别权限集中 |
| **SBD** | 安全设计 | Security by Design | 内建安全 | 识别补丁式漏洞 |
| **CM** | 持续监控 | Continuous Monitoring | 实时检测告警 | 识别检测盲区 |
| **EOM** | 机制简化 | Economy of Mechanism | 简单可验证 | 识别复杂性风险 |
| **OD** | 开放设计 | Open Design | 不依赖设计保密 | 识别隐蔽依赖 |
| **IV** | 输入验证 | Input Validation | 边界验证 | 识别注入攻击面 |

### 2.3 安全控制集

```
安全域 ──▶ 控制集 ──▶ OWASP参考 ──▶ 合规框架
   │           │           │            │
   │           │           │            │
security-   control-set-  reference-   YAML + SQLite
design.yaml    *.md        set-*.md   (合规表)
```

**安全域 (16个)**:

| 序号 | 代码 | 名称 | STRIDE | 描述 |
|-----|------|------|--------|------|
| 01 | AUTHN | 认证与会话 | S | 身份验证和会话生命周期 |
| 02 | AUTHZ | 授权访问控制 | E | 访问权限执行 |
| 03 | INPUT | 输入验证 | T | 外部输入验证和清洗 |
| 04 | OUTPUT | 输出编码 | T,I | 上下文感知输出编码 |
| 05 | CLIENT | 客户端安全 | S,T,I | 浏览器和客户端安全 |
| 06 | CRYPTO | 加密与传输安全 | I | 传输和静态数据加密 |
| 07 | LOG | 日志与监控 | R | 安全事件日志和审计 |
| 08 | ERROR | 错误处理 | I | 安全错误处理和信息控制 |
| 09 | API | API与服务安全 | S,T,I,D,E | API端点和服务通信安全 |
| 10 | DATA | 数据保护 | I | 敏感数据和凭证保护 |
| ext-11 | INFRA | 基础设施安全 | - | 容器和编排安全 |
| ext-12 | SUPPLY | 供应链安全 | - | 依赖和流水线安全 |
| ext-13 | AI | AI/LLM安全 | - | LLM特定威胁 (OWASP LLM Top 10) |
| ext-14 | MOBILE | 移动端安全 | - | 移动应用安全 |
| ext-15 | CLOUD | 云服务安全 | - | 云原生安全控制 |
| ext-16 | AGENT | Agent安全 | S,T,R,I,D,E | Agent系统和组件安全 (OWASP ASI) |

### 2.4 威胁模式集

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              威胁情报链条 (Threat Intelligence Chain)                     │
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

**STRIDE 到 CWE 映射链**:

| STRIDE | OWASP Top 10 | 主要 CWE | 典型攻击模式 |
|--------|--------------|----------|-------------|
| S (身份伪造) | A07 认证失败 | CWE-287, 290, 307 | CAPEC-151, 194, 600 |
| T (数据篡改) | A03 注入 | CWE-20, 77, 78, 89 | CAPEC-66, 88, 248 |
| R (抵赖) | A09 日志失败 | CWE-117, 223, 778 | CAPEC-93 |
| I (信息泄露) | A02 加密失败 | CWE-200, 209, 311 | CAPEC-116, 157 |
| D (拒绝服务) | A10 SSRF | CWE-400, 770, 918 | CAPEC-125, 227 |
| E (权限提升) | A01 访问控制 | CWE-269, 284, 862 | CAPEC-122, 233 |

### 2.5 验证集 (跨领域)

验证集连接安全控制集和威胁模式集，提供测试程序来验证控制和确认威胁。

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              验证集结构 (Verification Set Structure)                      │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ WSTG (Web安全测试指南) - 121 测试                                                │   │
│  │     类别: INFO, CONF, IDNT, ATHN, AUTHZ, SESS, INPV, ERRH, CRYP, BUSL,          │   │
│  │           CLNT, APIT                                                             │   │
│  │     存储: SQLite (wstg_test 表)                                                  │   │
│  │     映射: stride_verification, cwe_verification                                  │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                              │                                           │
│                                              ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ MASTG (移动应用安全测试指南) - 206 测试                                          │   │
│  │     类别: MASVS-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK,               │   │
│  │           MASVS-PLATFORM, MASVS-CODE, MASVS-RESILIENCE                          │   │
│  │     存储: SQLite (mastg_test 表)                                                 │   │
│  │     映射: stride_verification, cwe_verification                                  │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                              │                                           │
│                                              ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ ASVS (应用安全验证标准) - 345 要求                                               │   │
│  │     级别: L1 (基础), L2 (标准), L3 (高级)                                        │   │
│  │     章节: V1-V14 (架构到API、配置、存储、加密等)                                  │   │
│  │     存储: SQLite (asvs_requirement 表)                                           │   │
│  │     映射: stride_verification, cwe_verification                                  │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

**STRIDE 到验证映射**:

| STRIDE | 验证类别 | 测试数量 |
|--------|---------|---------|
| S (身份伪造) | WSTG-IDNT, WSTG-ATHN, WSTG-SESS, MASTG-AUTH | 27 |
| T (数据篡改) | WSTG-INPV, WSTG-CONF, MASTG-PLATFORM | 34 |
| R (抵赖) | WSTG-BUSL, ASVS-V7 (错误/日志) | 11 |
| I (信息泄露) | WSTG-INFO, WSTG-ERRH, WSTG-CRYP, MASTG-STORAGE | 31 |
| D (拒绝服务) | WSTG-BUSL, WSTG-APIT | 15 |
| E (权限提升) | WSTG-AUTHZ, MASTG-AUTH, ASVS-V4 (访问) | 16 |

**SQLite 验证表**:

| 表名 | 内容 | 记录数 | 用途 |
|------|------|--------|------|
| `wstg_test` | Web安全测试程序 | 121 | Web应用测试 |
| `mastg_test` | 移动安全测试程序 | 206 | 移动应用测试 |
| `asvs_requirement` | 安全验证要求 | 345 | 合规验证 |
| `stride_verification` | STRIDE → 测试映射 | - | Phase 6 验证 |
| `cwe_verification` | CWE → 测试映射 | - | 基于CWE的测试 |
| `verification_procedure` | 详细测试程序 | - | POC/测试用例生成 |

**查询命令**:

```bash
# 获取 STRIDE 类别的验证测试
unified_kb_query.py --stride-tests S

# 获取 CWE 的验证测试
unified_kb_query.py --cwe-tests CWE-89

# 获取 ASVS 合规要求
unified_kb_query.py --asvs-level L2 --chapter V4

# 获取特定类别的 WSTG 测试
unified_kb_query.py --wstg-category ATHN
```

**Phase 使用**:

| Phase | 验证集使用 |
|-------|----------|
| Phase 6 | `stride_verification` + `cwe_verification` → 为每个风险生成测试用例 |
| Phase 7 | `asvs_requirement` → 验证缓解措施符合安全要求 |
| Phase 8 | `asvs_requirement` + 合规映射 → 报告合规状态 |

---

## 3. 八阶段工作流与数据流

### 3.1 Phase 概览

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              8阶段深度威胁建模工作流                                               │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                                   │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│  │ Phase 1 │──▶│ Phase 2 │──▶│ Phase 3 │──▶│ Phase 4 │──▶│ Phase 5 │──▶│ Phase 6 │──▶│ Phase 7 │──▶│ Phase 8 │
│  │ 项目    │   │  DFD    │   │ 信任    │   │ 安全   │   │ STRIDE  │   │  风险   │   │ 缓解    │   │ 报告   │
│  │ 理解    │   │  分析   │   │ 边界   │   │ 设计   │   │ 分析   │   │  验证   │   │  计划   │   │ 生成   │
│  └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘
│       │             │             │             │             │             │             │             │
│       ▼             ▼             ▼             ▼             ▼             ▼             ▼             ▼
│   findings_1    findings_2    findings_3    findings_4    findings_5  validated_    mitigation_   final_
│   [项目上下文]  [DFD问题]    [边界问题]   [设计差距]   [威胁清单]   risks        plan         report
│                                                                                                   │
│  ════════════════════════════════════════════════════════════════════════════════════════════════│
│  执行模式: 严格串行 (Phase N 完成后才能开始 Phase N+1)                                              │
│  并行支持: Phase 5/6/7 可为单个风险项启动并行子代理                                                 │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Phase 数据流规范

#### Phase 1: 项目理解

| 属性 | 值 |
|------|---|
| **类型** | 探索性 |
| **输入** | 项目代码树 |
| **知识** | 安全原则 |
| **脚本** | `list_files.py --detect-type` |
| **输出** | `findings_1`: 项目上下文、技术栈、入口点、依赖 |

```yaml
findings_1:
  project_type: web|api|microservice|ai|mobile
  tech_stack: [framework, language, database, ...]
  entry_points: [routes, handlers, main, ...]
  dependencies: [packages, external_services, ...]
  initial_concerns: [potential_issues, ...]
```

---

#### Phase 2: 调用流与DFD分析

| 属性 | 值 |
|------|---|
| **类型** | 构建性 |
| **输入** | `findings_1` + 源代码 |
| **知识** | 安全原则 + `security-design.yaml` (识别安全相关流) + **Phase 2 知识库增强** |
| **脚本** | - (Claude 原生能力) |
| **输出** | `findings_2`: DFD元素、数据流问题 |

**Phase 2 知识库增强** (v2.2.1 新增):

| 文件 | 用途 |
|------|------|
| `phase2/framework-routing-patterns.yaml` | 框架路由模式 (含 AI/LLM 框架) |
| `phase2/data-store-patterns.yaml` | 数据存储检测模式 |
| `phase2/security-checkpoint-patterns.yaml` | 安全检查点模式 |
| `phase2/completeness-rules.yaml` | 完整性验证规则 |

```yaml
findings_2:
  dfd_elements:
    processes: [{id, name, description, security_aspects}, ...]
    data_stores: [{id, name, data_types, sensitivity}, ...]
    data_flows: [{id, source, target, data_type, protocol}, ...]
    external_entities: [{id, name, trust_level}, ...]
  dfd_issues:  # DFD 分析中发现的问题
    - {id: "DFD-001", category: "data_flow", description: "...", severity: "..."}
```

**知识引用**: `security-design.yaml` 提供安全域上下文，用于识别安全相关数据流（认证流、授权检查点、敏感数据路径）。

---

#### Phase 3: 信任边界

| 属性 | 值 |
|------|---|
| **类型** | 评估性 |
| **输入** | `findings_1` + `findings_2` + 源代码 |
| **知识** | 安全原则 + `security-design.yaml` (边界放置标准) |
| **脚本** | - (Claude 原生能力) |
| **输出** | `findings_3`: 信任边界、边界跨越问题 |

```yaml
findings_3:
  trust_boundaries:
    - {id: "TB-1", name: "Internet/DMZ", elements: [...], controls_expected: [...]}
    - {id: "TB-2", name: "DMZ/Internal", elements: [...], controls_expected: [...]}
  boundary_crossings:
    - {flow_id, boundary_id, direction, authentication_required, current_state}
  boundary_issues:  # 边界分析中发现的问题
    - {id: "TB-001", category: "trust_boundary", description: "...", severity: "..."}
```

**知识引用**: `security-design.yaml` 核心域 (AUTHN, AUTHZ, API) 提供信任边界处的预期控制。

---

#### Phase 4: 安全设计评估

| 属性 | 值 |
|------|---|
| **类型** | 评估性 |
| **输入** | `findings_1` + `findings_2` + `findings_3` (累积上下文) |
| **知识** | `security-design.yaml` + `security-controls/*.md` + `references/*.md` (渐进加载) |
| **脚本** | `--control {domain}`, `--stride-controls {category}` |
| **输出** | `findings_4`: 安全设计差距 |

**知识加载策略**:
1. 加载 `security-design.yaml` - 获取全部 16 个域的核心要求
2. 对每个相关域，加载对应的 `control-set-*.md`
3. 需要具体实现细节时，加载 `reference-set-*.md`

```yaml
findings_4:
  assessed_domains:
    - domain: AUTHN
      status: partial|missing|implemented
      gaps: [{control_id, description, severity}, ...]
      evidence: [code_locations, ...]
    - domain: AUTHZ
      status: ...
  design_issues:  # 设计评估中发现的问题
    - {id: "SD-001", domain: "AUTHN", control: "MFA", description: "...", severity: "..."}
```

---

#### Phase 5: STRIDE 分析

| 属性 | 值 |
|------|---|
| **类型** | 枚举性 |
| **输入** | `findings_2` (DFD元素) + `findings_3` (边界) |
| **知识** | CWE → CAPEC 映射 (威胁模式集) |
| **脚本** | `unified_kb_query.py --stride`, `--full-chain CWE-XXX`, `--all-llm` |
| **输出** | `findings_5`: 威胁清单 |

**STRIDE per Element 矩阵**:

| 元素类型 | 适用 STRIDE |
|----------|------------|
| Process | S, T, R, I, D, E (全部6个) |
| Data Store | T, R, I, D |
| Data Flow | T, I, D |
| External Entity (作为源) | S, R |

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

#### Phase 6: 风险验证

| 属性 | 值 |
|------|---|
| **类型** | 验证性 |
| **输入** | **所有之前的发现合并**: `findings_1` + `findings_2` + `findings_3` + `findings_4` + `findings_5` |
| **知识** | 威胁模式集 (CAPEC → ATT&CK → CVE/KEV) + **验证集** (WSTG/MASTG/ASVS) |
| **脚本** | `--capec`, `--attack-technique`, `--cve-for-cwe`, `--check-kev`, `--stride-tests`, `--cwe-tests` |
| **输出** | `validated_risks`: 全面验证的风险分析 |

**验证集集成**:
- 使用 `stride_verification` 获取 STRIDE 特定测试程序
- 使用 `cwe_verification` 获取 CWE 特定测试用例
- 从 `verification_procedure` 表生成 POC/测试用例

**合并过程**:
1. 将 P1-P5 的所有发现合并到统一问题列表
2. 去重并分组相关问题
3. 对每个唯一风险执行详细验证

**输出结构**:
```yaml
validated_risks:
  # 第1部分: 验证后的风险列表和评估摘要
  risk_summary:
    total_identified: 45
    validated_high: 12
    validated_medium: 18
    validated_low: 10
    dismissed: 5
    risk_by_stride: {S: 8, T: 12, R: 3, I: 10, D: 4, E: 8}
    risk_by_domain: {AUTHN: 10, INPUT: 15, ...}

  # 第2部分: 每个项目的详细风险分析
  risk_details:
    - risk_id: "VR-001"
      original_refs: ["T-S-P001-001", "SD-001", "DFD-002"]  # 从多个阶段合并

      # 2.1 问题位置
      location:
        files: ["src/auth/login.py:45-67", "src/api/handlers.py:120"]
        elements: ["P1:AuthService", "DF-3:UserCredentials"]
        trust_boundary: "TB-1:Internet/DMZ"

      # 2.2 详细分析
      detailed_analysis:
        vulnerability_type: "CWE-287 不当认证"
        description: "可通过...绕过认证"
        technical_details: "第45行的登录函数..."
        attack_surface: "外部, 未认证"
        affected_data: ["user_credentials", "session_tokens"]
        impact: "完全绕过认证..."

      # 2.3 根因分析
      root_cause:
        primary_cause: "备用端点缺少认证检查"
        contributing_factors:
          - "没有集中式认证中间件"
          - "路由保护模式不一致"
        design_flaw: true
        implementation_flaw: true
        cwe_chain: [CWE-287, CWE-863]

      # 2.4 测试用例 / POC 分析
      validation:
        test_cases:
          - name: "TC-001: 直接端点访问"
            method: "GET /api/v2/user/profile 无 token"
            expected: "401 Unauthorized"
            actual: "200 OK 带用户数据"
            result: FAIL
          - name: "TC-002: Token 篡改"
            method: "修改 JWT payload, 跳过签名"
            expected: "401 Unauthorized"
            actual: "200 OK"
            result: FAIL
        poc_available: true
        poc_complexity: low
        cvss_score: 9.1
        kev_status: false

  # 第3部分: 攻击路径分析
  attack_paths:
    - path_id: "AP-001"
      name: "认证绕过到数据窃取"
      risk_refs: ["VR-001", "VR-005", "VR-012"]
      description: "攻击者将认证绕过与...链接"

      # 3.1 攻击路径设计
      attack_chain:
        entry_point: "External:Internet"
        target: "DataStore:UserDatabase"
        trust_boundaries_crossed: ["TB-1", "TB-2"]
        techniques_used:
          - capec: CAPEC-151
            attack: T1078
            description: "通过认证绕过进行身份伪造"
          - capec: CAPEC-116
            attack: T1552
            description: "从内存提取凭证"

      # 第4部分: 逐步攻击流程
      detailed_steps:
        - step: 1
          phase: "侦察"
          action: "通过 /swagger.json 枚举 API 端点"
          technique: T1592.002
          tools: ["curl", "burpsuite"]
          commands: |
            curl -s https://target.com/swagger.json | jq '.paths | keys'
          expected_result: "所有 API 端点列表"

        - step: 2
          phase: "初始访问"
          action: "访问未保护的 /api/v2/user 端点"
          technique: T1190
          tools: ["curl"]
          commands: |
            curl -s https://target.com/api/v2/user/profile \
              -H "X-Forwarded-For: 127.0.0.1"
          expected_result: "无需认证返回用户配置数据"

        - step: 3
          phase: "凭证访问"
          action: "从响应中提取会话令牌"
          technique: T1552.001
          tools: ["jq", "python"]
          poc_code: |
            import requests
            resp = requests.get("https://target.com/api/v2/user/profile")
            tokens = resp.json().get("active_sessions", [])
            print(f"提取了 {len(tokens)} 个会话令牌")
          expected_result: "提取有效会话令牌"

        - step: 4
          phase: "横向移动"
          action: "使用提取的令牌访问其他用户账户"
          technique: T1550.001
          commands: |
            for token in $TOKENS; do
              curl -s https://target.com/api/v1/admin \
                -H "Authorization: Bearer $token"
            done
          expected_result: "访问管理员功能"

      overall_complexity: medium
      detection_difficulty: high
      business_impact: critical
```

---

#### Phase 7: 缓解规划

| 属性 | 值 |
|------|---|
| **类型** | 规范性 |
| **输入** | `validated_risks` (完整的 Phase 6 输出) |
| **知识** | 安全控制集 (控制集 + OWASP参考) + CWE缓解 + **验证集** (ASVS) |
| **脚本** | `--cwe --mitigations`, `--control {domain}`, `--asvs-level`, `--asvs-chapter` |
| **输出** | `mitigation_plan`: 逐风险缓解策略 |

**验证集集成**:
- 使用 `asvs_requirement` 确保缓解措施满足 ASVS 安全要求
- 将每个缓解措施映射到特定 ASVS 级别 (L1/L2/L3) 用于合规跟踪
- 在缓解验证标准中包含 ASVS 验证方法

**处理**: 对 `validated_risks.risk_details` 中的每个已验证风险，设计特定缓解措施。

```yaml
mitigation_plan:
  - risk_id: "VR-001"
    risk_summary: "通过未保护端点绕过认证"
    severity: critical

    immediate_actions:  # 快速修复 (小时级)
      - action: "在 WAF/网关层阻止未保护端点"
        implementation: |
          # nginx 配置
          location /api/v2/user {
            auth_request /auth/verify;
          }
        effort: 1h
        risk_reduction: 80%

    short_term_fixes:  # 代码修改 (天级)
      - action: "为所有 /api/v2 路由添加认证中间件"
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
          - "验证所有 v2 端点在无有效 token 时返回 401"
          - "运行验证中的 TC-001, TC-002 - 期望 PASS"

    long_term_improvements:  # 架构改进 (周级)
      - action: "实现带内置认证的集中式 API 网关"
        control_ref: "control-set-09-api-security.md#gateway-pattern"
        architecture_change: true
        effort: 2w

    verification_criteria:
      - "VR-001 验证中的所有测试用例通过"
      - "安全扫描显示无认证绕过漏洞"
      - "渗透测试确认修复有效性"
```

---

#### Phase 8: 报告生成

| 属性 | 值 |
|------|---|
| **类型** | 综合性 |
| **输入** | **所有阶段输出**: `findings_1` 到 `mitigation_plan` |
| **知识** | 合规框架 + **验证集** (ASVS 用于合规验证) |
| **脚本** | `--compliance {framework}`, `--asvs-level`, `--asvs-chapter` |
| **输出** | `final_report`: 完整威胁模型报告 |

**验证集集成**:
- 使用 `asvs_requirement` 生成每章的 ASVS 合规状态
- 将已验证风险映射到 ASVS 要求进行差距分析
- 在报告中包含 ASVS 级别 (L1/L2/L3) 合规矩阵

**报告结构**:

```yaml
final_report:
  # 执行摘要
  executive_summary:
    project: "..."
    assessment_date: "2026-01-03"
    risk_posture: critical|high|medium|low
    key_findings:
      - "识别 12 个严重风险, 8 个需要立即处理"
      - "认证子系统存在基础设计缺陷"
    recommended_priority:
      - "VR-001: 认证绕过 (严重)"
      - "VR-005: 搜索功能 SQL 注入 (严重)"

  # 第1节: 项目上下文 (来自 findings_1)
  project_context:
    # ... (Phase 1 输出)

  # 第2节: 架构分析 (来自 findings_2, findings_3)
  architecture:
    dfd_diagram: "..."  # Mermaid/ASCII 图
    trust_boundaries: [...]
    data_flow_summary: [...]

  # 第3节: 安全设计差距 (来自 findings_4)
  security_design:
    assessed_domains: [...]
    gap_summary: [...]

  # 第4节: 威胁清单 (来自 findings_5)
  threats:
    by_stride: {...}
    by_severity: {...}
    full_inventory: [...]

  # 第5节: 已验证风险 - 完整详情 (来自 validated_risks)
  # 关键: 此节必须包含 Phase 6 的所有内容
  validated_risks:
    risk_summary: {...}
    risk_details: [...]  # 完整详细分析
    attack_paths: [...]  # 带 POC 的完整攻击路径分析

  # 第6节: 缓解计划 - 完整详情 (来自 mitigation_plan)
  # 关键: 此节必须包含所有缓解措施
  mitigation:
    prioritized_actions: [...]
    implementation_roadmap: [...]
    resource_requirements: {...}

  # 第7节: 合规映射
  compliance:
    frameworks_assessed: ["OWASP ASVS", "NIST 800-53", ...]
    gap_analysis: [...]
    recommendations: [...]

  # 附录
  appendices:
    a_full_threat_list: [...]
    b_poc_scripts: [...]
    c_test_cases: [...]
    d_references: [...]
```

---

## 4. Phase 到知识映射

### 4.1 完整映射表

| Phase | 名称 | 类型 | 安全控制集 | 威胁模式集 | 验证集 | 脚本支持 |
|-------|------|------|-----------|-----------|--------|---------|
| 1 | 项目理解 | 探索性 | - | - | - | `list_files.py` |
| 2 | 调用流与DFD | 构建性 | `security-design.yaml` + **phase2/*.yaml** | - | - | - |
| 3 | 信任边界 | 评估性 | `security-design.yaml` | - | - | - |
| 4 | 安全设计 | 评估性 | `security-design.yaml` → `control-set-*.md` → `reference-set-*.md` | - | - | `--control`, `--stride-controls` |
| 5 | STRIDE分析 | 枚举性 | - | CWE → CAPEC | - | `--stride`, `--full-chain`, `--all-llm` |
| 6 | 风险验证 | 验证性 | - | CAPEC → ATT&CK → CVE/KEV | **WSTG + MASTG** (测试生成) | `--capec`, `--attack-technique`, `--stride-tests`, `--cwe-tests` |
| 7 | 缓解 | 规范性 | `control-set-*.md` → `reference-set-*.md` | CWE缓解 | **ASVS** (要求验证) | `--cwe --mitigations`, `--control`, `--asvs-level` |
| 8 | 报告 | 综合性 | 合规框架 | - | **ASVS** (合规状态) | `--compliance`, `--asvs-chapter` |

### 4.2 数据流可视化

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              Phase 数据流架构                                                        │
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
│     │           + phase2/*                             │                │                           │
│     │                                                  ▼                │                           │
│     │                                          control-set-*.md         │                           │
│     │                                          reference-set-*.md       │                           │
│     │                                                                   │                           │
│     │                                                                   ▼                           │
│     │                                                              CWE → CAPEC                      │
│     │                                                                   │                           │
│     ▼                                                                   ▼                           │
│  ┌────────────────────────────────────────────────────────────────────────────────────────┐        │
│  │                              Phase 6: 风险验证                                          │        │
│  │  INPUT: findings_1 + findings_2 + findings_3 + findings_4 + findings_5                │        │
│  │         (所有问题合并和去重)                                                            │        │
│  │                                                                                        │        │
│  │  KNOWLEDGE: CAPEC → ATT&CK → CVE/KEV                                                  │        │
│  │                                                                                        │        │
│  │  OUTPUT: validated_risks                                                              │        │
│  │    ├── risk_summary (计数, 分类)                                                      │        │
│  │    ├── risk_details (每项: 位置, 分析, 根因, 测试用例/POC)                            │        │
│  │    └── attack_paths (链, 带命令/POC的逐步流程)                                        │        │
│  └───────────────────────────────────────────────────────────────────────────────────────┘        │
│                                             │                                                       │
│                                             ▼                                                       │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐        │
│  │                              Phase 7: 缓解规划                                          │        │
│  │  INPUT: validated_risks (完整的 Phase 6 输出)                                         │        │
│  │                                                                                        │        │
│  │  KNOWLEDGE: 控制集 + OWASP 参考 + CWE 缓解                                            │        │
│  │                                                                                        │        │
│  │  OUTPUT: mitigation_plan                                                              │        │
│  │    ├── 每个风险: immediate_actions, short_term_fixes, long_term_improvements         │        │
│  │    └── verification_criteria                                                          │        │
│  └───────────────────────────────────────────────────────────────────────────────────────┘        │
│                                             │                                                       │
│                                             ▼                                                       │
│  ┌───────────────────────────────────────────────────────────────────────────────────────┐        │
│  │                              Phase 8: 报告生成                                          │        │
│  │  INPUT: 所有阶段输出 (findings_1 → mitigation_plan)                                   │        │
│  │                                                                                        │        │
│  │  关键部分 (必须包含完整详情, 不得遗漏):                                                │        │
│  │    ├── 第5节: 已验证风险 (完整来自 Phase 6)                                          │        │
│  │    └── 第6节: 缓解计划 (完整来自 Phase 7)                                            │        │
│  └───────────────────────────────────────────────────────────────────────────────────────┘        │
│                                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. 数据存储架构

### 5.1 存储层

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           数据访问层 (Data Access Layers)                                 │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ 第4层: 实时API (Live API)                                                        │   │
│  │     ├── NVD API → 实时CVE详情, CVSS分数                                         │   │
│  │     └── KEV API → 已知被利用漏洞检查                                             │   │
│  │     查询: --nvd-cve CVE-XXXX, --check-kev CVE-XXXX                              │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                              ↑                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ 第3层: CVE扩展 (security_kb_extension.sqlite - 304MB)                            │   │
│  │     ├── cve: 323,830+ CVE记录                                                   │   │
│  │     ├── cve_cwe: CVE → CWE 映射                                                 │   │
│  │     查询: --cve, --cve-for-cwe, --stride-cve                                    │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                              ↑                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ 第2层: SQLite主库 (security_kb.sqlite - 18MB)                                    │   │
│  │                                                                                   │   │
│  │     核心表:                                                                       │   │
│  │     ├── cwe (974) - CWE弱点详情                                                 │   │
│  │     ├── capec (615) - CAPEC攻击模式                                             │   │
│  │     ├── attack_technique (835) - ATT&CK技术                                     │   │
│  │     ├── stride_category (6) - STRIDE类别                                        │   │
│  │     └── owasp_top10 (10) - OWASP Top 10 2021                                    │   │
│  │                                                                                   │   │
│  │     映射表:                                                                       │   │
│  │     ├── stride_cwe - STRIDE → CWE                                               │   │
│  │     ├── capec_cwe - CAPEC → CWE                                                 │   │
│  │     ├── capec_attack - CAPEC → ATT&CK                                           │   │
│  │     └── cwe_mitigation - CWE缓解措施                                            │   │
│  │                                                                                   │   │
│  │     查询: --stride, --cwe, --capec, --full-chain, --semantic-search             │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                              ↑                                           │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ 第1层: 精选YAML + Markdown (按需加载, ~550KB)                                    │   │
│  │                                                                                   │   │
│  │     YAML:                                                                         │   │
│  │     ├── stride-library.yaml (5KB) - STRIDE定义 + 生成规则                       │   │
│  │     ├── security-design.yaml (17KB) - 安全域 + 控制引用                         │   │
│  │     ├── llm-threats.yaml (31KB) - OWASP LLM Top 10                              │   │
│  │     ├── agentic-threats.yaml (36KB) - OWASP Agentic Top 10                      │   │
│  │     ├── cloud-services.yaml (20KB) - 多云威胁映射                               │   │
│  │     ├── compliance-mappings.yaml (26KB) - 合规框架映射                          │   │
│  │     └── verification-mappings.yaml (25KB) - 验证测试映射                        │   │
│  │                                                                                   │   │
│  │     Phase 2 增强 (v2.2.1 新增):                                                  │   │
│  │     ├── phase2/framework-routing-patterns.yaml - 框架路由模式                   │   │
│  │     ├── phase2/data-store-patterns.yaml - 数据存储检测模式                      │   │
│  │     ├── phase2/security-checkpoint-patterns.yaml - 安全检查点模式               │   │
│  │     └── phase2/completeness-rules.yaml - 完整性验证规则                         │   │
│  │                                                                                   │   │
│  │     Markdown:                                                                     │   │
│  │     ├── security-controls/control-set-*.md (18文件)                             │   │
│  │     └── security-controls/references/reference-set-*.md (74文件)                │   │
│  │                                                                                   │   │
│  │     查询: --control, --llm, --cloud                                             │   │
│  └──────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 查询路由

| 查询参数 | 数据源 | 返回内容 |
|---------|--------|---------|
| `--stride S` | YAML + SQLite | STRIDE详情 + CWE列表 |
| `--cwe CWE-89` | SQLite (cwe) | CWE详情 |
| `--cwe CWE-89 --mitigations` | SQLite | CWE + cwe_mitigation |
| `--full-chain CWE-89` | SQLite (多表) | CWE → CAPEC → ATT&CK 链 |
| `--capec CAPEC-66` | SQLite (capec) | CAPEC详情 + CWE映射 |
| `--attack-technique T1190` | SQLite | ATT&CK技术详情 |
| `--control authentication` | YAML + Markdown | 域 + 控制集内容 |
| `--llm LLM01` | YAML (llm-threats) | LLM威胁详情 |
| `--agentic ASI01` | YAML (agentic-threats) | Agentic威胁详情 |
| `--cloud aws` | YAML (cloud-services) | 云服务威胁 |
| `--cve CVE-2024-XXXX` | SQLite (扩展) | CVE详情 + CVSS |
| `--check-kev CVE-XXXX` | 实时API | KEV检查结果 |
| `--compliance nist-csf` | YAML + SQLite | 合规框架控制 |

---

## 6. 关键统计

### 6.1 安全控制集

| 组件 | 数量 | 存储 |
|------|------|------|
| 安全原则 | 11 | SKILL.md |
| 安全域 | 16 (10核心 + 6扩展) | security-design.yaml |
| 控制集 | 18文件 / 107控制 | Markdown |
| OWASP参考 | 74 | Markdown |
| 合规框架 | 14 | YAML + SQLite |
| 验证测试 | 672 (WSTG + MASTG + ASVS) | YAML + SQLite |

### 6.2 威胁模式集

| 组件 | 数量 | 存储 |
|------|------|------|
| CWE弱点 | 974 | SQLite |
| OWASP Top 10 | 10 (248 CWE映射) | SQLite |
| CAPEC攻击模式 | 615 | SQLite |
| ATT&CK技术 | 835 | SQLite |
| CVE漏洞 | 323,830+ | SQLite扩展 |
| 语义向量 | 3,278 x 384-dim | SQLite |

### 6.3 特殊扩展

| 扩展 | 内容 | 数量 | 存储 |
|------|------|------|------|
| LLM威胁 | OWASP LLM Top 10 | 10威胁 / 5架构 | YAML |
| Agentic威胁 | OWASP ASI Top 10 | 10威胁 / Agent治理 | YAML |
| 云服务 | 多云威胁映射 | 5提供商 / 8类别 | YAML |
| AI合规 | ISO 42001 / NIST AI RMF / EU AI Act | 3框架 | YAML |
| Phase 2 增强 | DFD/CFD 分析知识库 | 4文件 | YAML |

---

## 7. 设计原则

### 7.1 "脚本是黑盒" 原则

- 脚本执行不消耗上下文，只有输出消耗
- 复杂计算（知识库查询）由脚本处理
- Claude 专注于需要理解和推理的任务

### 7.2 "双集并行" 原则

- **安全控制集**: 定义 "做什么" 和 "怎么做" (防御视角)
- **威胁模式集**: 定义 "知道什么" 和 "验证什么" (攻击视角)
- 两个集独立运作但通过映射关系协作

### 7.3 "渐进披露" 原则

- Phase 1-3: 纯 Claude 能力，仅引用安全原则
- Phase 4: 按需加载安全控制集 (域 → 控制 → 参考)
- Phase 5-6: 按需加载威胁模式集 (CWE → CAPEC → ATT&CK → CVE)
- Phase 7: 交叉引用两个集 (控制 + CWE缓解)
- Phase 8: 按需加载合规框架

### 7.4 "完整上下文传播" 原则

- 每个阶段接收所有之前阶段的累积上下文
- Phase 6 合并所有发现 (P1-P5) 进行统一验证
- Phase 8 必须包含完整的 Phase 6 和 Phase 7 输出，不得遗漏

---

## 8. 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| v5.2.2 | 2026-01-27 | 同步英文版完整 Phase 数据流规范，添加 Phase 2 知识库增强说明 |
| v5.2.1 | 2026-01-04 | 添加 ext-16 AGENT 安全域 (OWASP ASI)，更新统计数据 |
| v5.2 | 2025-12-30 | 添加 L1 STRIDE 层描述，完善威胁情报链条 |
| v5.1 | 2025-12-30 | 中性描述，优化工作流数据流，完整 Phase 6/7/8 规范 |
| v5.0 | 2025-12-30 | L0 原则设计 + 双轨架构 + YAML/SQLite 映射 |
| v4.0 | 2025-12-30 | OUTPUT/CLIENT 分离 + 严格命名规范 |
| v3.2 | 2025-12-30 | 扩展域控制集 + 统一命名 |

---

**文档生成**: Code-First Deep Risk Analysis Skill - Ultrathink Critical Thinking v5.2.2

[English Version](KNOWLEDGE-ARCHITECTURE-v5.2.md)
