<!-- Threat Modeling Skill | Version 3.1.0 (20260313a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# STRIDE Skill Set 综合架构与工作流指南

**版本**: 3.1.0
**日期**: 2026-01-04 (updated 2026-03-13)
**状态**: Production - v3.1.0

---

## 概览

本文档详细说明 STRIDE 威胁建模 Skill Set 的：
1. **双重四级知识体系** - 两套互补的知识架构
2. **八阶段详细工作流** - 串行执行的威胁建模流程
3. **知识体系间的关联和衔接** - 体系 A 与体系 B 的协作关系
4. **知识与工作流的关联和衔接** - 每个 Phase 如何调用知识库

---

# 第一部分：双重四级知识体系详解

## 1.1 整体架构视图

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           STRIDE 双重四级知识架构体系                                 │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  ╔═══════════════════════════════════════════════════════════════════════════════╗  │
│  ║                体系 A: SUKA v4.0 安全控制层次                                   ║  │
│  ║                (Security Control Hierarchy)                                    ║  │
│  ║                                                                                ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L1: Security Principles (11个安全原则)                                   │  ║  │
│  ║  │     位置: SKILL.md 公共段落                                              │  ║  │
│  ║  │     内容: DID, LP, ZT, FS, SOD, SBD, CM, EOM, OD, IV, LA                 │  ║  │
│  ║  │     用途: 指导所有安全设计决策                                           │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ║                                    │                                           ║  │
│  ║                                    ▼ 指导                                      ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L2: Security Design (16个安全域)                                         │  ║  │
│  ║  │     位置: knowledge/security-design.yaml                                 │  ║  │
│  ║  │     核心域(10): AUTHN, AUTHZ, INPUT, OUTPUT, CLIENT,                     │  ║  │
│  ║  │                 CRYPTO, LOG, ERROR, API, DATA                            │  ║  │
│  ║  │     扩展域(6): INFRA, SUPPLY, AI, MOBILE, CLOUD, AGENT                  │  ║  │
│  ║  │     用途: 定义安全评估的检查维度                                         │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ║                                    │                                           ║  │
│  ║                                    ▼ 实现                                      ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L3: Security Controls (18个控制集文件, 107个控制)                        │  ║  │
│  ║  │     位置: knowledge/security-controls/control-set-*.md                   │  ║  │
│  ║  │     内容: 具体安全控制要求和实施指南                                     │  ║  │
│  ║  │     用途: Phase 4 安全功能评估的检查清单                                 │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ║                                    │                                           ║  │
│  ║                                    ▼ 实践                                      ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L4: Scenario Practices (73个OWASP参考文件)                               │  ║  │
│  ║  │     位置: knowledge/security-controls/references/reference-set-*.md      │  ║  │
│  ║  │     内容: OWASP Cheat Sheet 详细实践指南                                 │  ║  │
│  ║  │     用途: Phase 7 缓解建议的技术参考                                     │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ╚═══════════════════════════════════════════════════════════════════════════════╝  │
│                                                                                      │
│  ╔═══════════════════════════════════════════════════════════════════════════════╗  │
│  ║                体系 B: 威胁情报知识层次                                        ║  │
│  ║                (Threat Intelligence Hierarchy)                                 ║  │
│  ║                                                                                ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L1: STRIDE 威胁分类模型 (STRIDE Threat Classification)                   │  ║  │
│  ║  │     位置: knowledge/stride-library.yaml                                  │  ║  │
│  ║  │     内容: 6大威胁类别 (S/T/R/I/D/E) + 元素适用矩阵                       │  ║  │
│  ║  │     用途: Phase 5 威胁分析的分类基础                                     │  ║  │
│  ║  │                                                                          │  ║  │
│  ║  │     ┌─────────────────────────────────────────────────────────────┐     │  ║  │
│  ║  │     │  STRIDE 威胁情报链条 (Threat Intelligence Chain)             │     │  ║  │
│  ║  │     │  ────────────────────────────────────────────────────────   │     │  ║  │
│  ║  │     │  STRIDE → CWE → CAPEC → ATT&CK → CVE/KEV                    │     │  ║  │
│  ║  │     │    L1      ├─────── L2 ────────┤    L3(验证) + L4(实时)     │     │  ║  │
│  ║  │     │                                                              │     │  ║  │
│  ║  │     │  S(身份伪造) → CWE-287/290/307 → CAPEC-151/600 → T1078/T1110│     │  ║  │
│  ║  │     │  T(数据篡改) → CWE-20/77/89    → CAPEC-66/88   → T1190      │     │  ║  │
│  ║  │     │  R(抵赖)     → CWE-117/223/778 → CAPEC-93      → T1070      │     │  ║  │
│  ║  │     │  I(信息泄露) → CWE-200/209/311 → CAPEC-116/157 → T1552/T1213│     │  ║  │
│  ║  │     │  D(拒绝服务) → CWE-400/770/918 → CAPEC-125/227 → T1498/T1499│     │  ║  │
│  ║  │     │  E(权限提升) → CWE-269/284/862 → CAPEC-122/233 → T1068/T1548│     │  ║  │
│  ║  │     └─────────────────────────────────────────────────────────────┘     │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ║                                    │                                           ║  │
│  ║                                    ▼ L1→L2: 威胁分类到弱点枚举                ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L2: 威胁情报知识层 (Threat Intelligence Layer)                           │  ║  │
│  ║  │     数据源: ATT&CK v18.1, CAPEC v3.9, CWE v4.19, OWASP Top 10 2025      │  ║  │
│  ║  │     记录数: 835 技术 + 615 模式 + 974 弱点 + 248 CWE映射                 │  ║  │
│  ║  │     存储: security_kb.sqlite                                             │  ║  │
│  ║  │     用途: Phase 5 STRIDE分析的威胁枚举                                   │  ║  │
│  ║  │                                                                          │  ║  │
│  ║  │     L1-L2 关系: STRIDE类别 → CWE弱点类型 → CAPEC攻击模式                 │  ║  │
│  ║  │     映射表: stride_cwe (STRIDE→CWE), capec_cwe (CAPEC→CWE)              │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ║                                    │                                           ║  │
│  ║                                    ▼ 验证                                      ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L3: 安全验证知识层 (Security Verification Layer)                         │  ║  │
│  ║  │     数据源: OWASP WSTG (121), MASTG (206), ASVS (345)                    │  ║  │
│  ║  │     存储: security_kb.sqlite (wstg_test, mastg_test, asvs_requirement)   │  ║  │
│  ║  │     用途: Phase 6 风险验证的测试方法                                     │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ║                                    │                                           ║  │
│  ║                                    ▼ 合规                                      ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L4: 合规框架知识层 (Compliance Framework Layer)                          │  ║  │
│  ║  │     框架: NIST 800-53, CIS Controls, ISO 27001, CSA CCM v4               │  ║  │
│  ║  │            GDPR, EU AI Act, PCI-DSS, SOC 2, HIPAA                        │  ║  │
│  ║  │     存储: security_kb.sqlite + compliance-mappings.yaml                  │  ║  │
│  ║  │     用途: Phase 8 合规报告的框架映射                                     │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ╚═══════════════════════════════════════════════════════════════════════════════╝  │
│                                                                                      │
│  ╔═══════════════════════════════════════════════════════════════════════════════╗  │
│  ║                数据访问层 (Query Access Layers)                                ║  │
│  ║                统一查询接口: unified_kb_query.py                              ║  │
│  ║                                                                                ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L1: YAML + Markdown (按需加载, ~550KB)                                   │  ║  │
│  ║  │     stride-library.yaml, llm-threats.yaml, cloud-services.yaml          │  ║  │
│  ║  │     security-controls/*.md                                               │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L2: SQLite Main (security_kb.sqlite, 18MB)                               │  ║  │
│  ║  │     CWE, CAPEC, ATT&CK, STRIDE, OWASP, WSTG, MASTG, ASVS, Compliance    │  ║  │
│  ║  │     FTS5全文索引, 语义向量嵌入 (3,278 x 384-dim)                         │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L3: CVE Extension (security_kb_extension.sqlite, 304MB)                  │  ║  │
│  ║  │     323,830+ CVE记录, CVE-CWE映射, CVSS分数                              │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ║  ┌─────────────────────────────────────────────────────────────────────────┐  ║  │
│  ║  │ L4: Live API (实时查询)                                                  │  ║  │
│  ║  │     NVD API: 实时CVE详情, CVSS分数                                       │  ║  │
│  ║  │     KEV API: 已知被利用漏洞检查                                          │  ║  │
│  ║  └─────────────────────────────────────────────────────────────────────────┘  ║  │
│  ╚═══════════════════════════════════════════════════════════════════════════════╝  │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1.2 体系 A 详解：SUKA v4.0 安全控制层次

### L1: Security Principles (11个安全原则)

| 编号 | Code | 原则名称 | 中文 | 定义 | 引用Phase |
|------|------|----------|------|------|-----------|
| 1 | DID | Defense in Depth | 纵深防御 | 多层独立安全控制；单点失败不妥协系统 | 1, 2, 4 |
| 2 | LP | Least Privilege | 最小权限 | 仅授予完成任务所需的最小权限 | 1, 3, 4 |
| 3 | ZT | Zero Trust | 零信任 | 永不信任，始终验证；假设网络已被入侵 | 1, 2, 3, 4 |
| 4 | FS | Fail Securely | 安全失败 | 失败时默认拒绝；不暴露敏感信息 | 4 |
| 5 | SOD | Separation of Duties | 职责分离 | 关键操作需多人/角色协作完成 | 3, 4 |
| 6 | SBD | Security by Design | 安全设计 | 安全内建于设计，而非事后修补 | 4 |
| 7 | CM | Continuous Monitoring | 持续监控 | 实时检测、告警和响应安全事件 | 4 |
| 8 | EOM | Economy of Mechanism | 机制简化 | 安全机制越简单越容易验证和维护 | 4 |
| 9 | OD | Open Design | 开放设计 | 安全不依赖于设计保密 | 4 |
| 10 | IV | Input Validation | 输入验证 | 所有外部输入都需验证和清洗 | 2, 4 |
| 11 | LA | Least Agency | 最小代理 | 限制AI Agent自主能力、工具访问和决策范围 | 1, 3, 4 |

**层级关系**: L1 原则 → 指导 L2 域设计 → 约束 L3 控制实现

### L2: Security Design (16个安全域)

#### 核心域 (01-10) 与 STRIDE 映射

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    安全域 与 STRIDE 映射关系                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  STRIDE类别        主要关联域              安全属性                          │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  S (Spoofing)  ──→ 01-AUTHN, 09-API, 05-CLIENT                              │
│     身份伪造       └── 认证机制、API认证、客户端身份                         │
│                                                                              │
│  T (Tampering) ──→ 03-INPUT, 04-OUTPUT, 09-API                              │
│     数据篡改       └── 输入验证、输出编码、API数据完整性                      │
│                                                                              │
│  R (Repudiation)──→ 07-LOG                                                  │
│     抵赖           └── 日志审计、事件追踪                                    │
│                                                                              │
│  I (Info Disc.) ──→ 06-CRYPTO, 08-ERROR, 10-DATA, 04-OUTPUT                 │
│     信息泄露       └── 加密、错误处理、数据保护、输出编码                     │
│                                                                              │
│  D (DoS)       ──→ 09-API                                                   │
│     拒绝服务       └── 速率限制、资源配额                                    │
│                                                                              │
│  E (Elevation) ──→ 02-AUTHZ                                                 │
│     权限提升       └── 授权访问控制                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 扩展域 (ext-11 to ext-16) 触发条件

| 扩展域 | Code | 触发条件 | 检测模式 |
|--------|------|----------|----------|
| ext-11 | INFRA | Dockerfile, K8s manifests, IaC | `*.yaml`, `Dockerfile`, `*.tf` |
| ext-12 | SUPPLY | package.json, requirements.txt | 依赖声明文件 |
| ext-13 | AI | openai/anthropic SDK, model files | AI库导入, `.pt`, `.onnx` |
| ext-14 | MOBILE | iOS/Android project | `*.swift`, `*.kt`, `AndroidManifest.xml` |
| ext-15 | CLOUD | terraform, AWS/Azure/GCP SDK | 云提供商SDK导入 |
| ext-16 | AGENT | Agent frameworks, MCP, Skills | `langchain`, `crewai`, `mcp.json`, Skills定义 |

### L3: Security Controls (18个控制集)

```
security-controls/
├── 核心域控制集 (10个)
│   ├── control-set-01-authentication.md        # AUTHN: 6控制
│   ├── control-set-02-authorization.md         # AUTHZ: 6控制
│   ├── control-set-03-input-validation.md      # INPUT: 6控制
│   ├── control-set-04-output-encoding.md       # OUTPUT: 6控制
│   ├── control-set-05-client-side.md           # CLIENT: 6控制
│   ├── control-set-06-cryptography.md          # CRYPTO: 6控制
│   ├── control-set-07-logging.md               # LOG: 6控制
│   ├── control-set-08-error-handling.md        # ERROR: 5控制
│   ├── control-set-09-api-security.md          # API: 6控制
│   └── control-set-10-data-protection.md       # DATA: 6控制
│
├── 域扩展控制集 (2个)
│   ├── control-set-ext-01_02-auth-patterns.md  # 认证授权交叉模式
│   └── control-set-ext-10-hardcoded-credentials.md  # 硬编码凭证
│
└── 扩展域控制集 (6个)
    ├── control-set-ext-11-infrastructure.md    # INFRA: 6控制
    ├── control-set-ext-12-supply-chain.md      # SUPPLY: 6控制
    ├── control-set-ext-13-ai-llm.md            # AI: 6控制
    ├── control-set-ext-14-mobile.md            # MOBILE: 6控制
    ├── control-set-ext-15-cloud.md             # CLOUD: 6控制
    └── control-set-ext-16-agentic.md           # AGENT: 10控制
```

### L4: Scenario Practices (73个OWASP参考)

**按域分布**:

| 域 | 参考数 | 代表性文件 |
|----|--------|-----------|
| 01-AUTHN | 11 | authentication, mfa, session, password, jwt |
| 02-AUTHZ | 4 | authorization, access-control, idor |
| 03-INPUT | 13 | sql-injection, os-command-injection, ssrf |
| 04-OUTPUT | 0 | (新域，待补充) |
| 05-CLIENT | 13 | xss, csp, csrf, clickjacking |
| 06-CRYPTO | 6 | tls, key-management, cryptographic-storage |
| 07-LOG | 2 | logging, logging-vocabulary |
| 08-ERROR | 2 | error-handling, xs-leaks |
| 09-API | 7 | rest-security, graphql, microservices |
| 10-DATA | 3 | database-security, secrets-management |
| ext-11 INFRA | 4 | docker, kubernetes, iac |
| ext-12 SUPPLY | 4 | dependency-management, npm, cicd |
| ext-13 AI | 1 | ai-agent-security |
| ext-14 MOBILE | 2 | mobile-security |
| ext-15 CLOUD | 1 | cloud-architecture |
| ext-16 AGENT | 4 | agentic-security, mcp-security, multi-agent, skill-security |

---

## 1.3 体系 B 详解：威胁情报知识层次

### L1: STRIDE 威胁分类模型

STRIDE 是威胁情报体系的基础层，提供威胁分类的六大类别框架。

#### STRIDE 类别定义

| 类别 | 英文 | 中文 | 定义 | 违反的安全属性 |
|------|------|------|------|----------------|
| **S** | Spoofing | 身份伪造 | 伪装成其他用户或系统 | 认证 (Authentication) |
| **T** | Tampering | 数据篡改 | 非法修改数据或代码 | 完整性 (Integrity) |
| **R** | Repudiation | 抵赖 | 否认执行过某操作 | 不可否认性 (Non-repudiation) |
| **I** | Information Disclosure | 信息泄露 | 未授权访问敏感信息 | 机密性 (Confidentiality) |
| **D** | Denial of Service | 拒绝服务 | 使系统或服务不可用 | 可用性 (Availability) |
| **E** | Elevation of Privilege | 权限提升 | 获取超出授权的权限 | 授权 (Authorization) |

#### STRIDE per Element 适用矩阵

| 元素类型 | S | T | R | I | D | E |
|----------|---|---|---|---|---|---|
| **Process** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Data Store** | - | ✓ | ✓ | ✓ | ✓ | - |
| **Data Flow** | - | ✓ | - | ✓ | ✓ | - |
| **External Entity (as source)** | ✓ | - | ✓ | - | - | - |

#### L1→L2 威胁情报链条 (Threat Intelligence Chain)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         STRIDE 威胁情报链条                                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  L1: STRIDE    L2: 威胁情报知识              L3: 验证      L4: 实时              │
│  ───────────   ─────────────────────────     ─────────    ─────────              │
│                                                                                  │
│  ┌─────────┐   ┌───────┐   ┌───────┐   ┌─────────┐   ┌───────┐   ┌─────────┐   │
│  │ STRIDE  │──▶│  CWE  │──▶│ CAPEC │──▶│ ATT&CK  │──▶│  CVE  │──▶│   KEV   │   │
│  │  类别   │   │ 弱点  │   │ 攻击  │   │  技术   │   │ 漏洞  │   │ 已利用  │   │
│  └────┬────┘   └───┬───┘   └───┬───┘   └────┬────┘   └───┬───┘   └────┬────┘   │
│       │            │           │            │            │            │         │
│       │            │           │            │            │            │         │
│    分类框架     弱点枚举    攻击模式     战术技术     实际漏洞    活跃威胁     │
│    (6类别)     (974条)     (615条)     (835条)    (323K+)    (实时API)    │
│                                                                                  │
│  映射关系:                                                                       │
│  ────────────────────────────────────────────────────────────────────────────   │
│  • stride_cwe: STRIDE类别 → CWE弱点 (每类别映射10-50个CWE)                       │
│  • capec_cwe: CWE弱点 → CAPEC攻击模式 (弱点如何被利用)                           │
│  • capec_attack: CAPEC模式 → ATT&CK技术 (攻击者实际使用的技术)                   │
│  • cve_cwe: CVE漏洞 → CWE弱点 (实际漏洞的弱点分类)                              │
│                                                                                  │
│  查询链示例 (SQL Injection):                                                     │
│  ────────────────────────────────────────────────────────────────────────────   │
│  T(Tampering) → CWE-89 → CAPEC-66 → T1190 → CVE-2024-* → KEV检查               │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### 各 STRIDE 类别的威胁链映射

| STRIDE | 主要 CWE | 主要 CAPEC | 主要 ATT&CK | 典型攻击场景 |
|--------|----------|------------|-------------|--------------|
| **S** | CWE-287, 290, 307 | CAPEC-151, 194, 600 | T1078, T1110 | 凭证填充、身份伪造 |
| **T** | CWE-20, 77, 78, 89 | CAPEC-66, 88, 248 | T1190, T1059 | SQL注入、命令注入 |
| **R** | CWE-117, 223, 778 | CAPEC-93, 268 | T1070, T1562 | 日志伪造、审计绕过 |
| **I** | CWE-200, 209, 311 | CAPEC-116, 157, 497 | T1552, T1213 | 敏感数据泄露、配置暴露 |
| **D** | CWE-400, 770, 918 | CAPEC-125, 227, 469 | T1498, T1499 | 资源耗尽、SSRF |
| **E** | CWE-269, 284, 862 | CAPEC-122, 233, 17 | T1068, T1548 | 权限绕过、垂直越权 |

---

### L2: 威胁情报知识层

#### 数据源详情

| 数据源 | 版本 | 表名 | 记录数 | 主要字段 |
|--------|------|------|--------|----------|
| MITRE ATT&CK | v18.1 | attack_technique | 835 | id, name, description, tactics, mitigations |
| CAPEC | v3.9 | capec | 615 | id, name, description, attack_steps, mitigations |
| CWE | v4.19 | cwe | 974 | id, name, description, mitigations, detection |
| OWASP Top 10 | 2025 | owasp_top10 | 10 | id, name, cwe_list, description |

#### 知识映射链

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        威胁情报知识映射链                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  STRIDE 类别                                                                 │
│      │                                                                       │
│      ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ OWASP Top 10 2025                                                    │    │
│  │ A01: Broken Access Control     → 26 CWEs → S, E                     │    │
│  │ A02: Cryptographic Failures    → 18 CWEs → T, I                     │    │
│  │ A03: Injection                 → 30 CWEs → T                         │    │
│  │ A04: Insecure Design           → 24 CWEs → T, E                     │    │
│  │ A05: Security Misconfiguration → 7 CWEs  → T, E                     │    │
│  │ A06: Vulnerable Components     → 13 CWEs → T, E                     │    │
│  │ A07: Auth Failures             → 22 CWEs → S                         │    │
│  │ A08: Integrity Failures        → 8 CWEs  → T                         │    │
│  │ A09: Logging Failures          → 5 CWEs  → R                         │    │
│  │ A10: SSRF                      → 45 CWEs → I, D                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│      │                                                                       │
│      ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ CWE (Common Weakness Enumeration)                                    │    │
│  │ CWE-89: SQL Injection          → CAPEC-66  → T1190                  │    │
│  │ CWE-287: Improper Auth         → CAPEC-151 → T1078                  │    │
│  │ CWE-639: Auth Bypass           → CAPEC-122 → T1087                  │    │
│  │ CWE-79: XSS                    → CAPEC-86  → T1189                  │    │
│  │ CWE-352: CSRF                  → CAPEC-62  → T1185                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│      │                                                                       │
│      ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ CAPEC (Attack Patterns)                                              │    │
│  │ CAPEC-66: SQL Injection        → T1190 (Exploit Public App)         │    │
│  │ CAPEC-600: Credential Stuffing → T1110.004                          │    │
│  │ CAPEC-122: Privilege Abuse     → T1078 (Valid Accounts)             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│      │                                                                       │
│      ▼                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ ATT&CK (Adversary Tactics & Techniques)                              │    │
│  │ T1190: Exploit Public-Facing Application                             │    │
│  │ T1078: Valid Accounts                                                │    │
│  │ T1110: Brute Force                                                   │    │
│  │ T1189: Drive-by Compromise                                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### L3: 安全验证知识层

| 验证标准 | 表名 | 记录数 | 用途 |
|----------|------|--------|------|
| OWASP WSTG | wstg_test | 121 | Web应用安全测试指南 |
| OWASP MASTG | mastg_test | 206 | 移动应用安全测试指南 |
| OWASP ASVS | asvs_requirement | 345 | 应用安全验证标准 |

**验证知识结构**:
```
wstg_test:
  - id: WSTG-INPV-05
    name: SQL Injection
    objective: "Test for SQL injection vulnerabilities"
    test_methods: ["Manual testing", "Automated scanning"]
    tools: ["sqlmap", "Burp Suite"]

asvs_requirement:
  - id: V1.1.1
    level: 1
    description: "Verify the use of a secure development lifecycle..."
    cwe: ["CWE-250", "CWE-749"]
```

### L4: 合规框架知识层

#### 支持的合规框架

| 类别 | 框架 | 控制数 |
|------|------|--------|
| SDLC Security | NIST-SSDP, OWASP SAMM, AI-Governance | 50+ |
| App Security | OWASP ASVS, CWE Top 25, OWASP Top 10 | 300+ |
| Info Security | NIST CSF 2.0, NIST 800-53, CIS Controls | 800+ |
| Cloud Security | CSA CCM v4, CIS K8s, ISO 27017/18 | 400+ |
| Regional | GDPR, EU AI Act | 100+ |

#### 合规映射结构

```yaml
compliance_mapping:
  stride_category: "Spoofing"
  security_domain: "01-AUTHN"
  frameworks:
    - framework: "NIST 800-53"
      controls: ["IA-1", "IA-2", "IA-5", "IA-8"]
    - framework: "ISO 27001"
      controls: ["A.9.2.1", "A.9.2.4", "A.9.4.2"]
    - framework: "PCI-DSS"
      controls: ["8.1", "8.2", "8.3"]
    - framework: "CIS Controls"
      controls: ["5.2", "5.3", "6.3"]
```

---

# 第二部分：八阶段详细工作流

## 2.1 工作流全局视图

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                              8-Phase Deep Threat Modeling Workflow                            │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                              │
│  ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│  │ Phase 1 │──▶│ Phase 2 │──▶│ Phase 3 │──▶│ Phase 4 │──▶│ Phase 5 │──▶│ Phase 6 │──▶│ Phase 7 │──▶│ Phase 8 │
│  │ Project │   │  DFD    │   │ Trust   │   │Security │   │ STRIDE  │   │  Risk   │   │Mitigate │   │ Report  │
│  │Understanding│ Analysis│   │Boundary │   │ Design  │   │Analysis │   │Validate │   │  Plan   │   │Generate │
│  └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘
│       │             │             │             │             │             │             │             │
│       ▼             ▼             ▼             ▼             ▼             ▼             ▼             ▼
│  project_ctx   dfd_elements  boundary_ctx  security_gaps threat_inv  valid_threats mitig_plan  report_data
│                                                                                              │
│  ═══════════════════════════════════════════════════════════════════════════════════════════ │
│                                                                                              │
│  执行模式: 严格串行 (Phase N 完成后才能开始 Phase N+1)                                          │
│  思考深度: 每个Phase使用 <ultrathink><critical thinking> 模式                                  │
│  知识查询: Phase 5/6/7 必须为每个风险查询知识库                                                 │
│  并行子代理: Phase 5/6/7 内部可为多个风险启动并行子代理                                          │
│                                                                                              │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 2.2 各 Phase 详细说明

### Phase 1: 项目理解 (Project Understanding)

| 维度 | 说明 |
|------|------|
| **目标** | 全面理解项目架构、功能模块、技术栈和安全设计 |
| **执行者** | Claude + 脚本辅助 |
| **脚本支持** | `list_files.py --categorize --detect-type` |
| **知识库** | 无需查询 |
| **输入** | 项目代码路径 |
| **输出** | `project_context` (项目类型、模块清单、集成、安全设计) |

**关键活动**:
1. 获取文件结构并分类
2. 识别项目类型 (Web/API/微服务/AI/LLM)
3. 读取关键文件 (入口点、配置、API定义)
4. 文档化架构理解
5. 记录初步安全观察

### Phase 2: 调用流/DFD 分析 (Call Flow & DFD)

| 维度 | 说明 |
|------|------|
| **目标** | 构建数据流图，追踪数据如何在系统中流动 |
| **执行者** | Claude 原生能力 |
| **脚本支持** | 无 |
| **知识库** | 无需查询 |
| **输入** | `project_context` from Phase 1 |
| **输出** | `dfd_elements` (元素清单、数据流、DFD图) |

**关键活动**:
1. 识别外部交互者 (用户、外部服务)
2. 追踪数据入口点
3. 映射处理进程
4. 识别数据存储
5. 使用 Mermaid 绘制 DFD

**DFD 元素类型**:
- **EI**: External Interactor (外部交互者)
- **P**: Process (进程)
- **DS**: Data Store (数据存储)
- **DF**: Data Flow (数据流)

### Phase 3: 信任边界评估 (Trust Boundary Evaluation)

| 维度 | 说明 |
|------|------|
| **目标** | 识别关键接口、边界、数据节点和安全态势 |
| **执行者** | Claude 原生能力 |
| **脚本支持** | 无 |
| **知识库** | 无需查询 |
| **输入** | `dfd_elements` from Phase 2 |
| **输出** | `boundary_context` (边界、接口、跨边界流) |

**关键活动**:
1. 识别网络边界 (DMZ、内网、数据层)
2. 识别进程边界 (容器、VM、Serverless)
3. 定义用户信任级别
4. 标记跨边界数据流
5. 分析每个边界的安全控制

### Phase 4: 安全设计评估 (Security Design Assessment)

| 维度 | 说明 |
|------|------|
| **目标** | 深度分析所有安全域的设计实现 |
| **执行者** | Claude + 知识库 |
| **脚本支持** | `--control {domain}` (按需) |
| **知识库** | 体系 A: L2 域定义 + L3 控制集 |
| **输入** | Phase 1-3 全部输出 |
| **输出** | `security_gaps` (差距、设计矩阵) |

**必须覆盖的 9 个安全域**:
1. 身份管理 (Identity Management)
2. 认证 (Authentication)
3. 授权/访问控制 (Authorization)
4. 加密与密钥管理 (Encryption)
5. 日志与审计 (Logging)
6. 敏感数据保护 (Data Protection)
7. 高可用性 (High Availability)
8. 输入验证 (Input Validation)
9. 会话管理 (Session Management)

### Phase 5: STRIDE 分析 (STRIDE Analysis)

| 维度 | 说明 |
|------|------|
| **目标** | 使用 STRIDE + CWE + ATT&CK + LLM威胁进行全面威胁分析 |
| **执行者** | 脚本 + Claude |
| **脚本支持** | `stride_matrix.py`, `unified_kb_query.py --full-chain` |
| **知识库** | 体系 B: L2 威胁情报 (CWE/CAPEC/ATT&CK) |
| **输入** | Phase 2-4 输出 |
| **输出** | `threat_inventory` (威胁清单，含ID/CWE/CAPEC) |

**STRIDE per Interaction 矩阵**:
```
           │ S │ T │ R │ I │ D │ E │
──────────┼───┼───┼───┼───┼───┼───┤
Process   │ ✓ │ ✓ │ ✓ │ ✓ │ ✓ │ ✓ │
Data Store│   │ ✓ │ ✓ │ ✓ │ ✓ │   │
Data Flow │   │ ✓ │   │ ✓ │ ✓ │   │
+External │ ✓ │   │ ✓ │   │   │   │
```

**威胁 ID 格式**: `T-{STRIDE}-{ElementID}-{Seq}`
- 示例: `T-S-P001-001` (身份伪造威胁，针对进程P001，第1个)

### Phase 6: 风险验证 (Risk Validation)

| 维度 | 说明 |
|------|------|
| **目标** | 深度分析每个风险的攻击路径、POC设计和验证方法 |
| **执行者** | 脚本 + Claude |
| **脚本支持** | `--capec`, `--attack-technique`, `--check-kev`, `--cve-for-cwe` |
| **知识库** | 体系 B: L2 威胁情报 + L3 验证知识 (WSTG/ASVS) |
| **输入** | `threat_inventory` from Phase 5 |
| **输出** | `validated_threats` (含攻击路径、POC方法) |

**每个风险的验证内容**:
1. 查询 CAPEC 攻击模式
2. 查询 ATT&CK 技术
3. 检查已知被利用漏洞 (KEV)
4. 构建攻击路径
5. 设计 POC 验证方法

### Phase 7: 缓解建议生成 (Mitigation Generation)

| 维度 | 说明 |
|------|------|
| **目标** | 为每个风险生成知识库增强的技术特定缓解措施 |
| **执行者** | 脚本 + Claude |
| **脚本支持** | `--cwe {id} --mitigations`, `--stride {category}` |
| **知识库** | 体系 A: L3 控制集 + L4 参考 + 体系 B: CWE缓解 |
| **输入** | Phase 5 + Phase 6 输出 |
| **输出** | `mitigation_plan` (缓解措施、代码示例、路线图) |

**每个风险的缓解内容**:
1. 查询 CWE 缓解建议
2. 查询 STRIDE 控制映射
3. 设计技术栈特定实现
4. 提供代码示例
5. 估算工作量和优先级

### Phase 8: 综合报告生成 (Comprehensive Report)

| 维度 | 说明 |
|------|------|
| **目标** | 生成完整威胁模型报告，综合所有Phase输出 |
| **执行者** | Claude |
| **脚本支持** | 无 |
| **知识库** | 体系 B: L4 合规框架 (按需) |
| **输入** | Phase 1-7 全部输出 |
| **输出** | `{PROJECT}-RISK-ASSESSMENT-REPORT.md` |

**报告结构**:
1. 执行摘要
2. 系统架构概览
3. DFD 和信任边界
4. 安全设计评估
5. 威胁清单 (按STRIDE分类)
6. 风险分析 (含攻击路径)
7. 缓解措施 (含代码示例)
8. 实施路线图
9. 合规映射 (按需)

---

# 第三部分：知识体系间的关联和衔接

## 3.1 体系 A 与体系 B 的协作关系

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                        体系 A 与 体系 B 协作关系图                                    │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│                    体系 A                           体系 B                           │
│               (安全控制层次)                     (威胁情报层次)                      │
│                                                                                      │
│  ┌─────────────────────┐                   ┌─────────────────────┐                  │
│  │ L1: Security        │                   │                     │                  │
│  │     Principles      │                   │                     │                  │
│  │     (11原则)        │                   │                     │                  │
│  └──────────┬──────────┘                   │                     │                  │
│             │                              │                     │                  │
│             ▼                              │                     │                  │
│  ┌─────────────────────┐                   │ L2: Threat          │                  │
│  │ L2: Security        │◀─────────────────▶│     Intelligence    │                  │
│  │     Design          │   STRIDE映射      │   (ATT&CK/CAPEC/CWE)│                  │
│  │     (16域)          │                   │                     │                  │
│  └──────────┬──────────┘                   └──────────┬──────────┘                  │
│             │                                         │                              │
│             ▼                                         ▼                              │
│  ┌─────────────────────┐                   ┌─────────────────────┐                  │
│  │ L3: Security        │                   │ L3: Security        │                  │
│  │     Controls        │◀─────────────────▶│     Verification    │                  │
│  │     (18控制集)      │   CWE→Control    │   (WSTG/MASTG/ASVS) │                  │
│  └──────────┬──────────┘                   └──────────┬──────────┘                  │
│             │                                         │                              │
│             ▼                                         ▼                              │
│  ┌─────────────────────┐                   ┌─────────────────────┐                  │
│  │ L4: Scenario        │                   │ L4: Compliance      │                  │
│  │     Practices       │◀─────────────────▶│     Frameworks      │                  │
│  │     (73参考)        │   Control→框架    │   (NIST/CIS/ISO)    │                  │
│  └─────────────────────┘                   └─────────────────────┘                  │
│                                                                                      │
│  ════════════════════════════════════════════════════════════════════════════════   │
│                                                                                      │
│  协作关系:                                                                           │
│  ─────────────────────────────────────────────────────────────────────────────────  │
│                                                                                      │
│  1. STRIDE → Domain 映射:                                                            │
│     体系B的STRIDE类别映射到体系A的安全域                                              │
│     例: S(Spoofing) → 01-AUTHN                                                      │
│                                                                                      │
│  2. CWE → Control 映射:                                                              │
│     体系B的CWE弱点映射到体系A的安全控制                                               │
│     例: CWE-89 → control-set-03-input-validation.md                                 │
│                                                                                      │
│  3. Control → Verification 映射:                                                     │
│     体系A的控制通过体系B的验证测试进行确认                                            │
│     例: 认证控制 → WSTG-ATHN-* 测试                                                  │
│                                                                                      │
│  4. Control → Compliance 映射:                                                       │
│     体系A的控制映射到体系B的合规框架                                                  │
│     例: MFA控制 → NIST IA-2, PCI-DSS 8.3                                            │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## 3.2 知识映射链示例

### 示例 1: 认证威胁的完整知识链

```
威胁: 凭证填充攻击

体系 B 路径:
─────────────────────────────────────────────────────────────────────────
STRIDE: S (Spoofing)
    │
    ▼
OWASP: A07 (Authentication Failures)
    │
    ▼
CWE: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
    │
    ▼
CAPEC: CAPEC-600 (Credential Stuffing)
    │
    ▼
ATT&CK: T1110.004 (Credential Stuffing)
    │
    ▼
验证: WSTG-ATHN-03 (Testing for Weak Lock Out Mechanism)
    │
    ▼
合规: NIST IA-5, PCI-DSS 8.1.6

体系 A 路径:
─────────────────────────────────────────────────────────────────────────
STRIDE: S (Spoofing)
    │
    ▼
Domain: 01-AUTHN (认证与会话)
    │
    ▼
Control: control-set-01-authentication.md
    │
    ├── 控制项: 账户锁定机制
    ├── 控制项: 速率限制
    └── 控制项: MFA实现
    │
    ▼
Reference: reference-set-01-authentication.md
    │
    ├── 具体实现: express-rate-limit
    └── 代码示例: Redis账户锁定
```

### 示例 2: SQL注入威胁的完整知识链

```
威胁: SQL注入攻击

体系 B 路径:
─────────────────────────────────────────────────────────────────────────
STRIDE: T (Tampering)
    │
    ▼
OWASP: A03 (Injection)
    │
    ▼
CWE: CWE-89 (SQL Injection)
    │
    ▼
CAPEC: CAPEC-66 (SQL Injection)
    │
    ▼
ATT&CK: T1190 (Exploit Public-Facing Application)
    │
    ▼
验证: WSTG-INPV-05 (Testing for SQL Injection)
    │
    ▼
合规: NIST SI-10, PCI-DSS 6.5.1

体系 A 路径:
─────────────────────────────────────────────────────────────────────────
STRIDE: T (Tampering)
    │
    ▼
Domain: 03-INPUT (输入验证)
    │
    ▼
Control: control-set-03-input-validation.md
    │
    ├── 控制项: 参数化查询
    ├── 控制项: 输入白名单验证
    └── 控制项: ORM使用
    │
    ▼
Reference: reference-set-03-sql-injection-prevention.md
    │
    ├── 具体实现: SQLAlchemy ORM
    └── 代码示例: Pydantic验证器
```

---

# 第四部分：知识与工作流的关联和衔接

## 4.1 Phase 与知识体系映射总表

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                        Phase → 知识体系 映射关系表                                    │
├────────┬──────────────────┬──────────────────┬──────────────────────────────────────┤
│ Phase  │ 体系 A 层级      │ 体系 B 层级      │ 查询命令示例                          │
├────────┼──────────────────┼──────────────────┼──────────────────────────────────────┤
│ P1     │ -                │ -                │ list_files.py --detect-type         │
│        │ (Claude原生)      │ (Claude原生)      │                                      │
├────────┼──────────────────┼──────────────────┼──────────────────────────────────────┤
│ P2     │ -                │ -                │ (无脚本)                             │
│        │ (Claude原生)      │ (Claude原生)      │                                      │
├────────┼──────────────────┼──────────────────┼──────────────────────────────────────┤
│ P3     │ -                │ -                │ (无脚本)                             │
│        │ (Claude原生)      │ (Claude原生)      │                                      │
├────────┼──────────────────┼──────────────────┼──────────────────────────────────────┤
│ P4     │ L1: 原则         │ -                │ --control {domain}                   │
│        │ L2: 域定义       │                  │ --stride-controls {category}         │
│        │ L3: 控制集       │                  │                                      │
├────────┼──────────────────┼──────────────────┼──────────────────────────────────────┤
│ P5     │ L2: STRIDE映射   │ L2: CWE/CAPEC    │ --stride {category}                  │
│        │                  │     ATT&CK       │ --full-chain CWE-XXX                 │
│        │                  │     OWASP Top 10 │ --all-llm (AI组件)                   │
├────────┼──────────────────┼──────────────────┼──────────────────────────────────────┤
│ P6     │ -                │ L2: CAPEC        │ --capec CAPEC-XXX --attack-chain     │
│        │                  │     ATT&CK       │ --attack-technique TXXX              │
│        │                  │ L3: WSTG/ASVS    │ --check-kev CVE-XXXX                 │
│        │                  │     CVE          │ --cve-for-cwe CWE-XXX                │
├────────┼──────────────────┼──────────────────┼──────────────────────────────────────┤
│ P7     │ L3: 控制集       │ L2: CWE缓解      │ --cwe CWE-XXX --mitigations          │
│        │ L4: OWASP参考    │                  │ --control {domain} --implementation  │
├────────┼──────────────────┼──────────────────┼──────────────────────────────────────┤
│ P8     │ -                │ L4: 合规框架     │ --compliance {framework}             │
│        │ (Claude综合)      │                  │                                      │
└────────┴──────────────────┴──────────────────┴──────────────────────────────────────┘
```

## 4.2 Phase 上下文传递协议

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           Phase 上下文传递流程图                                      │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  Phase 1                     Phase 2                      Phase 3                    │
│  ┌──────────────────┐       ┌──────────────────┐        ┌──────────────────┐        │
│  │ project_context  │──────▶│ dfd_elements     │───────▶│ boundary_context │        │
│  │                  │       │                  │        │                  │        │
│  │ - project_type   │       │ - elements[]     │        │ - boundaries[]   │        │
│  │ - modules[]      │       │   {id,type,name} │        │ - interfaces[]   │        │
│  │ - integrations[] │       │ - flows[]        │        │ - data_nodes[]   │        │
│  │ - security_design│       │   {src,tgt,data} │        │ - cross_flows[]  │        │
│  └──────────────────┘       │ - dfd_diagram    │        └────────┬─────────┘        │
│                             └──────────────────┘                 │                   │
│                                                                  │                   │
│  Phase 4                     Phase 5                      Phase 6│                   │
│  ┌──────────────────┐       ┌──────────────────┐        ┌───────▼──────────┐        │
│  │ security_gaps    │──────▶│ threat_inventory │───────▶│ validated_threats│        │
│  │                  │       │                  │        │                  │        │
│  │ - gaps[]         │       │ - threats[]      │        │ - threats[]      │        │
│  │   {domain,sev,   │       │   {id,element_id,│        │   {id,attack_path│        │
│  │    description}  │       │    stride,cwe,   │        │    capec,attck,  │        │
│  │ - design_matrix{}│       │    priority}     │        │    poc_method}   │        │
│  └──────────────────┘       └──────────────────┘        └────────┬─────────┘        │
│         ▲                           ▲                            │                   │
│         │                           │                            │                   │
│  ┌──────┴───────────────────────────┴─────────────────┐          │                   │
│  │              引用 Phase 1-3 输出                    │          │                   │
│  └────────────────────────────────────────────────────┘          │                   │
│                                                                  │                   │
│  Phase 7                     Phase 8                             │                   │
│  ┌──────────────────┐       ┌──────────────────┐                 │                   │
│  │ mitigation_plan  │──────▶│ report_data      │◀────────────────┘                   │
│  │                  │       │                  │                                     │
│  │ - mitigations[]  │       │ - all_phases     │                                     │
│  │   {threat_id,cwe,│       │ - summary        │                                     │
│  │    measures,impl,│       │ - roadmap        │                                     │
│  │    effort}       │       │ - compliance     │                                     │
│  │ - roadmap{}      │       └──────────────────┘                                     │
│  └──────────────────┘                                                                │
│                                                                                      │
│  ════════════════════════════════════════════════════════════════════════════════   │
│                                                                                      │
│  跨阶段引用规则:                                                                      │
│  ───────────────────────────────────────────────────────────────────────────────    │
│  • 威胁ID格式: T-{STRIDE}-{ElementID}-{Seq}                                          │
│  • ElementID 来自 Phase 2 的 dfd_elements                                            │
│  • Phase 5-7 的每个威胁分析必须引用其 Element ID                                      │
│  • Phase 6/7 必须引用 Phase 5 的威胁ID                                               │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## 4.3 并行子代理模式 (Phase 5/6/7)

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                        并行子代理执行模式 (Phase 5/6/7)                               │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  Phase 5: STRIDE 分析 (多威胁并行)                                                   │
│  ──────────────────────────────────────────────────────────────────────────────────  │
│                                                                                      │
│  Main Agent                                                                          │
│      │                                                                               │
│      ├──▶ DFD Element P1 ──▶ Sub-Agent ──▶ KB: --full-chain CWE-89                  │
│      │                                   ──▶ KB: --stride tampering                  │
│      │                                   ◀── 威胁分析结果                             │
│      │                                                                               │
│      ├──▶ DFD Element P2 ──▶ Sub-Agent ──▶ KB: --full-chain CWE-287                 │
│      │                                   ──▶ KB: --stride spoofing                   │
│      │                                   ◀── 威胁分析结果                             │
│      │                                                                               │
│      ├──▶ DFD Element DS1 ──▶ Sub-Agent ──▶ KB: --full-chain CWE-359                │
│      │                                    ──▶ KB: --stride info_disclosure           │
│      │                                    ◀── 威胁分析结果                            │
│      │                                                                               │
│      └──▶ AI Component ──▶ Sub-Agent ──▶ KB: --all-llm                              │
│                                       ──▶ KB: --llm LLM01                            │
│                                       ◀── LLM威胁分析结果                             │
│      │                                                                               │
│      ◀──────────────────── 聚合所有威胁 ─────────────────────                        │
│                                                                                      │
│                                                                                      │
│  Phase 6: 风险验证 (多风险并行)                                                       │
│  ──────────────────────────────────────────────────────────────────────────────────  │
│                                                                                      │
│  Main Agent                                                                          │
│      │                                                                               │
│      ├──▶ T-S-P001-001 ──▶ Sub-Agent ──▶ KB: --capec CAPEC-600 --attack-chain      │
│      │                                ──▶ KB: --attack-technique T1110.004           │
│      │                                ◀── 攻击路径 + POC方法                          │
│      │                                                                               │
│      ├──▶ T-T-DF001-001 ──▶ Sub-Agent ──▶ KB: --capec CAPEC-66 --attack-chain      │
│      │                                ──▶ KB: --cve-for-cwe CWE-89                   │
│      │                                ──▶ KB: --check-kev                            │
│      │                                ◀── 攻击路径 + KEV状态                          │
│      │                                                                               │
│      └──▶ T-E-P003-001 ──▶ Sub-Agent ──▶ KB: --capec CAPEC-122 --attack-chain      │
│                                       ◀── 攻击路径 + POC方法                          │
│      │                                                                               │
│      ◀──────────────────── 聚合验证结果 ─────────────────────                        │
│                                                                                      │
│                                                                                      │
│  Phase 7: 缓解建议 (多风险并行)                                                       │
│  ──────────────────────────────────────────────────────────────────────────────────  │
│                                                                                      │
│  Main Agent                                                                          │
│      │                                                                               │
│      ├──▶ T-S-P001-001 ──▶ Sub-Agent ──▶ KB: --cwe CWE-307 --mitigations           │
│      │                                ──▶ KB: --control authentication               │
│      │                                ◀── 缓解措施 + 代码示例                         │
│      │                                                                               │
│      ├──▶ T-T-DF001-001 ──▶ Sub-Agent ──▶ KB: --cwe CWE-89 --mitigations           │
│      │                                ──▶ KB: --control input-validation             │
│      │                                ◀── 缓解措施 + 代码示例                         │
│      │                                                                               │
│      └──▶ T-E-P003-001 ──▶ Sub-Agent ──▶ KB: --cwe CWE-639 --mitigations           │
│                                       ──▶ KB: --control authorization                │
│                                       ◀── 缓解措施 + 代码示例                         │
│      │                                                                               │
│      ◀──────────────────── 聚合缓解计划 ─────────────────────                        │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## 4.4 知识库查询决策矩阵

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           知识库查询决策矩阵                                          │
├─────────┬───────────────────────────────┬───────────────────────────────────────────┤
│ Phase   │ 查询条件                       │ 查询命令                                   │
├─────────┼───────────────────────────────┼───────────────────────────────────────────┤
│ P4      │ 评估特定安全域                  │ --control {domain}                        │
│         │ 获取STRIDE控制映射              │ --stride-controls {category}              │
│         │ 查看所有控制概览                │ --all-controls                            │
├─────────┼───────────────────────────────┼───────────────────────────────────────────┤
│ P5      │ 每个DFD元素                     │ --element {type} (获取适用STRIDE)          │
│         │ 每个STRIDE类别                  │ --stride {category}                       │
│         │ 每个识别的CWE                   │ --full-chain CWE-XXX                      │
│         │ 检测到AI/LLM组件                │ --all-llm 或 --llm LLM01                  │
│         │ 检测到云服务                    │ --cloud {provider}                        │
│         │ 语义搜索相关威胁                │ --semantic-search "query"                 │
├─────────┼───────────────────────────────┼───────────────────────────────────────────┤
│ P6      │ 每个威胁的CAPEC                 │ --capec CAPEC-XXX --attack-chain          │
│         │ 每个威胁的ATT&CK                │ --attack-technique TXXX                   │
│         │ 检查已知被利用漏洞              │ --check-kev CVE-XXXX                      │
│         │ 按CWE查找CVE                    │ --cve-for-cwe CWE-XXX                     │
│         │ 查询CVE严重性                   │ --cve CVE-XXXX --severity                 │
├─────────┼───────────────────────────────┼───────────────────────────────────────────┤
│ P7      │ 每个CWE的缓解措施               │ --cwe CWE-XXX --mitigations               │
│         │ 获取STRIDE控制映射              │ --stride {category}                       │
│         │ 获取控制实现指南                │ --control {domain} --implementation       │
│         │ CVE上下文参考                   │ --cve-for-cwe CWE-XXX --cve-severity HIGH │
├─────────┼───────────────────────────────┼───────────────────────────────────────────┤
│ P8      │ 合规框架映射(按需)              │ --compliance {framework}                  │
│         │ 全部合规概览                    │ --all-compliance                          │
└─────────┴───────────────────────────────┴───────────────────────────────────────────┘
```

---

# 第五部分：总结

## 5.1 架构设计哲学

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                           STRIDE Skill Set 设计哲学                                  │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  1. "脚本是黑盒" 原则                                                                │
│     ────────────────────────────────────────────────────────────────────────────    │
│     • 脚本执行不消耗 context，只有输出消耗                                           │
│     • 复杂计算（如知识库查询）用脚本处理                                              │
│     • Claude 专注于需要理解和推理的任务                                              │
│                                                                                      │
│  2. "关注点分离" 原则                                                                │
│     ────────────────────────────────────────────────────────────────────────────    │
│     • 体系 A (安全控制): 定义"做什么"和"怎么做"                                      │
│     • 体系 B (威胁情报): 定义"知道什么"和"验证什么"                                   │
│     • 两套体系各司其职，通过映射关系协作                                              │
│                                                                                      │
│  3. "渐进式披露" 原则                                                                │
│     ────────────────────────────────────────────────────────────────────────────    │
│     • Phase 1-3: 纯 Claude 能力，无需知识库                                          │
│     • Phase 4: 按需加载安全域控制                                                    │
│     • Phase 5-7: 每个风险独立查询知识库                                              │
│     • Phase 8: 按需加载合规框架                                                      │
│                                                                                      │
│  4. "严格串行 + 并行子代理" 执行模式                                                  │
│     ────────────────────────────────────────────────────────────────────────────    │
│     • Phase 间严格串行: 确保上下文传递完整                                            │
│     • Phase 内并行子代理: 多风险分析可并行执行                                        │
│     • 最大化效率的同时保证质量                                                       │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## 5.2 关键数据统计

| 类别 | 统计 |
|------|------|
| **体系 A** | |
| L1 安全原则 | 11 |
| L2 安全域 | 16 (10核心 + 6扩展) |
| L3 控制集文件 | 18 |
| L3 控制条目 | 107 |
| L4 OWASP参考 | 74 |
| **体系 B** | |
| ATT&CK 技术 | 835 |
| CAPEC 攻击模式 | 615 |
| CWE 弱点 | 974 |
| OWASP Top 10 CWE映射 | 248 |
| WSTG 测试 | 121 |
| MASTG 测试 | 206 |
| ASVS 要求 | 345 |
| STRIDE验证映射 | 1,269 |
| CVE 记录 | 323,830+ |
| 合规框架 | 14+ |
| **数据访问层** | |
| SQLite Main | 18 MB |
| SQLite Extension | 304 MB |
| YAML 配置 | 550 KB |
| 语义向量 | 3,278 x 384-dim |

## 5.3 文档版本信息

| 项目 | 值 |
|------|-----|
| 文档版本 | 1.0 |
| 生成日期 | 2026-01-03 |
| 分析方法 | Ultrathink 深度分析 |
| 知识库版本 | SUKA v4.0 |
| SQLite版本 | CWE v4.19, CAPEC v3.9, ATT&CK v18.1 |

---

*本文档由 Code-First Deep Risk Analysis Skill 生成*
