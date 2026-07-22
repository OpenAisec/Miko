# Code Audit - 代码安全审计技能

> 专业白盒代码安全审计技能，覆盖 55+ 漏洞类型，双轨审计模型，多 Agent 深度分析。

[English](README.md)

## 概述

Code Audit 是为 [Claude Code](https://docs.anthropic.com/en/docs/claude-code) 设计的专业安全审计技能。采用白盒静态分析方法论，系统性发现和验证源代码中的安全漏洞。

### 核心能力

- **9 种语言**: Java, Python, Go, PHP, JavaScript/Node.js, C/C++, .NET/C#, Ruby, Rust
- **14 种框架**: Spring Boot, Django, Flask, FastAPI, Express, Koa, Gin, Laravel, Rails, ASP.NET Core, Rust Web, NestJS/Fastify, MyBatis
- **55+ 漏洞类型**: SQL 注入、RCE、反序列化、SSRF、SSTI、XXE、IDOR、竞态条件、业务逻辑缺陷等
- **143 项强制检测**: 按 10 个安全维度 (D1-D10) 组织的语言级检查清单
- **双轨审计模型**: Sink-driven（注入/RCE）+ Control-driven（授权/业务逻辑）
- **多 Agent 并行**: 大型代码库并行审计（874+ Java 文件约 15 分钟）
- **WooYun 案例库**: 88,636 真实漏洞案例（2010-2016）
- **攻击链构建**: 自动将多个发现串联为可利用的攻击路径

## 安装

```bash
# 复制到 Claude Code skills 目录
cp -r code-audit ~/.claude/skills/

# 或从仓库克隆
cd ~/.claude/skills
git clone <repository-url> code-audit
```

在 Claude Code 中请求安全审计时，技能自动激活。

## 使用方法

### 触发方式

```
"审计这个项目"
"检查代码安全"
"找出安全漏洞"
"/audit" 或 "/code-audit"
```

### 扫描模式

| 模式 | 适用场景 | 范围 |
|------|---------|------|
| **Quick** | CI/CD、小项目 | 高危漏洞、敏感信息、依赖 CVE |
| **Standard** | 常规审计 | OWASP Top 10、认证授权、加密，1-2 轮 |
| **Deep** | 重要项目、渗透测试准备 | 全覆盖、攻击链、业务逻辑，2-3 轮 |

### 使用示例

```
用户: /code-audit deep /path/to/project

Claude: [MODE] deep
        [RECON] 874 文件, Spring Boot 1.5 + Shiro 1.6 + JPA + Freemarker
        [PLAN] 5 个 Agent, D1-D10 覆盖, 预估 125 turns
        ... (用户确认) ...
        [REPORT] 10 Critical, 14 High, 12 Medium, 4 Low
```

## 架构

### 双轨审计模型

不同类型的漏洞需要根本不同的检测策略：

| 轨道 | 维度 | 方法 | 发现目标 |
|------|-----|------|---------|
| **Sink-driven** | D1（注入）、D4（反序列化）、D5（文件）、D6（SSRF） | Grep 危险函数 → 追踪数据流 → 验证无防护 | **存在的**危险代码 |
| **Control-driven** | D3（授权）、D9（业务逻辑） | 枚举端点 → 验证安全控制是否存在 → 缺失=漏洞 | **缺失的**安全控制 |
| **Config-driven** | D2（认证）、D7（加密）、D8（配置）、D10（供应链） | 搜索配置 → 对比安全基线 | 错误配置 |

**关键区别**: Sink-driven 搜索"存在的危险代码"，Control-driven 搜索"应存在但缺失的安全控制"。授权缺失、IDOR 等漏洞本质上是**代码不存在**（没有权限检查），Grep 搜不到"不存在的代码"。

### 10 个安全维度

| # | 维度 | 覆盖内容 |
|---|------|---------|
| D1 | 注入 | SQL/Cmd/LDAP/SSTI/SpEL/JNDI |
| D2 | 认证 | Token/Session/JWT/Filter 链 |
| D3 | 授权 | CRUD 权限一致性、IDOR、水平越权 |
| D4 | 反序列化 | Java/Python/PHP Gadget 链 |
| D5 | 文件操作 | 上传/下载/路径遍历 |
| D6 | SSRF | URL 注入、协议限制 |
| D7 | 加密 | 密钥管理、加密模式、KDF |
| D8 | 配置 | Actuator、CORS、错误信息暴露 |
| D9 | 业务逻辑 | 竞态条件、Mass Assignment、状态机、多租户隔离 |
| D10 | 供应链 | 依赖 CVE、版本检查 |

### 多 Agent 工作流

```
Phase 1: 侦察
  → 技术栈识别
  → 攻击面测绘（五层推导）
  → 端点-权限矩阵生成
  → Agent 分配

Phase 2: Agent 并行执行 (R1)
  → Agent 1: 注入 (D1) [sink-driven]
  → Agent 2: 认证+授权+业务逻辑 (D2+D3+D9) [control-driven]
  → Agent 3: 文件+SSRF (D5+D6) [sink-driven]
  → Agent 4: 反序列化 (D4) [sink-driven]
  → Agent 5: 配置+加密+供应链 (D7+D8+D10) [config-driven]

Phase 3: 覆盖评估
  → 按轨道分别计算覆盖率（Sink 扇出率 / 端点审计率）
  → 识别缺口 → 按需启动 R2 补充 Agent

Phase 4: 报告生成
  → 严重度校准（决策树）
  → 跨 Agent 去重合并
  → 攻击链构建
```

## 文件结构

```
code-audit/
├── SKILL.md                    # 技能入口（frontmatter + 执行控制器）
├── agent.md                    # Agent 工作流（状态机 + 双轨模型）
├── README.md                   # 文档（英文）
├── README_CN.md                # 文档（中文）
└── references/
    ├── core/              (16) # 核心方法论
    │   ├── phase2_deep_methodology.md   # 双轨审计方法论
    │   ├── taint_analysis.md            # 数据流追踪
    │   ├── anti_hallucination.md        # 防误报规则
    │   └── ...
    ├── checklists/        (11) # D1-D10 覆盖矩阵 + 9 语言检查清单
    ├── languages/         (18) # 语言漏洞模式
    ├── security/          (21) # 安全域模块
    ├── frameworks/        (14) # 框架专项模块
    ├── adapters/           (5) # 语言适配器 (YAML)
    ├── wooyun/             (9) # WooYun 真实案例库
    ├── cases/              (1) # 真实漏洞案例
    └── reporting/          (1) # 报告模板
```

## 防幻觉规则

所有发现必须基于工具实际读取的代码：

- 文件路径必须通过 Glob/Read 验证后才能报告
- 代码片段必须来自 Read 工具的实际输出
- 禁止基于"典型项目结构"猜测
- **核心原则：宁可漏报，不可误报**

## 支持的技术栈

### 语言
Java, Python, Go, PHP, JavaScript/TypeScript, C/C++, C#/.NET, Ruby, Rust

### 框架
Spring Boot, Django, Flask, FastAPI, Express, Koa, Gin, Laravel, Rails, ASP.NET Core, NestJS, Fastify, Rust Web (Actix/Axum)

### 安全领域
API 安全、LLM/AI 安全、Serverless、密码学、竞态条件、OAuth/OIDC/SAML、WebSocket/gRPC、HTTP 走私、供应链/CI-CD

## 贡献

欢迎贡献新的语言模块或框架模块：

1. 在 `references/languages/{language}.md` 或 `references/frameworks/{framework}.md` 创建文件
2. 按现有模块格式编写（每个 D1-D10 维度的关键问题）
3. 包含：危险函数、检测模式、漏洞示例、安全替代方案
4. 如需更新 `agent.md` 技术栈路由表

## 参考文章

- [Code Audit Skill 详解（上）](https://mp.weixin.qq.com/s/K5yJ9nPUzwpBV5rMPPKfCg)
- [Code Audit Skill 详解（下）](https://mp.weixin.qq.com/s/yTPehTfk1ufv3RXq6gh1mA)

## 交流群

加入微信群交流讨论：

<img src="image/wechat.png" alt="微信交流群" width="300">

## 许可证

MIT License

## 免责声明

本技能仅用于**授权的安全测试**。使用者必须：
- 拥有审计目标代码的合法授权
- 负责任地披露发现的漏洞
- 遵守相关法律法规和道德规范

未经授权对他人系统进行安全测试可能违法。
