<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Threat Modeling Skill v3.2.0

AI原生的自动化软件风险分析 Skill。LLM驱动，Code-First 方法，支持完整的安全风险评估、威胁建模、安全分析、安全审计和渗透测试。

## v3.2.0 新特性

- **工具辅助分析**：集成 Luoshu（14 MCP）、Ghidra（18 MCP）、CodeQL（65 MCP）、Joern（15 CWE 查询），深度代码和二进制分析
- **复杂系统支持**：DFD 自动生成、CFG/DFG 分析、N 跳调用链追踪、语义代码搜索
- **二进制逆向工程**：Ghidra 反编译、radare2 快速侦察、调用图和交叉引用分析
- **自动化漏洞检测**：Joern CWE 查询（C/C++）、CodeQL 安全套件
- **攻击链验证**：Luoshu 调用链 + Ghidra 反编译 + Joern 污点分析
- **显式阶段验证**：以可移植的 `--phase-end` 调用替代 hook 验证机制
- **工具能力矩阵**：新增 `knowledge/tool-capabilities.yaml` 用于运行时工具发现
- 新增 3 个参考文档（`references/`）提供按需工具指导
- agentskills.io 多 Agent 平台兼容性（Claude Code、Codex CLI、IDE 扩展）

完整版本历史请参见 [CHANGELOG.md](CHANGELOG.md)。

## v3.0.2 新特性

- 大幅重构系统架构，提升安全分析的深度和路径覆盖率
- 反向移植了来自下一代AI-Native渗透测试系统 "Cobweb" 的SM2状态机确保问题求解深度
- 增加多历史版本任务记录和精确的结构化阶段输出物能力，提升CI/CD集成能力
- 优化上下文工程和数据披露，节约大约35% token消耗

完整版本历史请参见 [CHANGELOG.md](CHANGELOG.md)。

## 安装

### 方式一：全局安装（推荐）

```bash
# 克隆到全局技能目录
git clone https://github.com/fr33d3m0n/threat-modeling.git \
    ~/.claude/skills/threat-modeling
```

### 方式二：项目本地安装

```bash
# 克隆到项目的 .claude/skills 目录
mkdir -p .claude/skills
git clone https://github.com/fr33d3m0n/threat-modeling.git \
    .claude/skills/threat-modeling
```

### 依赖要求

- Claude Code CLI
- Python 3.10+
- SQLite3（用于知识库查询）

## 快速开始

1. **在目标项目目录启动 Claude Code**：
   ```bash
   cd /path/to/your/project
   claude
   ```

2. **使用简单提示词调用 Skill**：
   ```
   /threat-modeling 对 @. 执行完整的威胁建模分析
   ```
   或英文：
   ```
   /threat-modeling Perform a complete threat model analysis on @.
   ```

3. **按照8阶段工作流执行** - Claude 将引导你完成每个阶段。

## 使用模式

Skill 支持 **6 种灵活的应用模式**，不仅限于标准的8阶段工作流：

### 模式 1：完整工作流（标准）

对代码库执行完整的8阶段威胁建模。

```
/threat-modeling 对 @/path/to/project 执行完整的威胁建模分析

项目背景：
- 这是一个电商平台的后端API服务
- 使用 Django REST Framework
- 用户数据包括PII和支付信息

重点关注：认证机制、支付流程、API安全
```

### 模式 2：知识库咨询

将知识库作为安全咨询资源使用，无需执行完整工作流。

```
查询 CWE-89（SQL注入）的完整信息，包括攻击模式、测试方法和缓解措施
```

**响应包含**：CWE概述、相关CAPEC模式、WSTG测试步骤、ASVS要求、缓解示例。

### 模式 3：深度漏洞分析

对特定漏洞或代码片段进行深入分析。

```
分析这段代码的 SSRF 风险，构建攻击路径并设计 POC
[代码片段]
```

**响应包含**：漏洞机制、攻击路径、POC设计、CWE/CAPEC/ATT&CK映射。

### 模式 4：安全测试生成

基于安全标准生成测试用例。

```
为这个 API 端点生成基于 WSTG 的安全测试用例
```

**响应包含**：认证、授权、输入验证、会话管理测试用例及Payload。

### 模式 5：前向集成（设计阶段）

在设计阶段进行前置威胁建模，无需等待代码完成。

```
基于这份 API 规范（OpenAPI），进行 STRIDE 威胁分析
[OpenAPI规范]
```

**响应包含**：基于API端点的DFD、信任边界、STRIDE枚举、设计建议。

### 模式 6：后向集成（渗透测试）

为渗透测试提供攻击路径和POC设计支持。

```
我在目标系统发现了 JWT 签名验证绕过，帮我构建完整攻击链
```

**响应包含**：漏洞确认、攻击链、POC Payload、ATT&CK映射、报告模板。

## 模式选择指南

| 模式 | 输入 | 输出 | 适用阶段 |
|------|------|------|----------|
| **完整工作流** | 代码库 | 完整威胁报告 | 开发中/发布前 |
| **知识库咨询** | 问题/查询 | 知识响应 | 任何阶段 |
| **漏洞分析** | 代码/描述 | 攻击路径+POC | 代码审查/渗透测试 |
| **测试生成** | 目标描述 | 测试清单 | 测试阶段 |
| **前向集成** | 设计文档 | 设计阶段分析 | 设计阶段 |
| **后向集成** | 已发现漏洞 | 攻击链+利用方案 | 渗透测试 |

## 命令行标志

| 标志 | 描述 |
|------|------|
| `--debug` | 发布内部YAML数据文件和评估报告 |
| `--lang=xx` | 设置输出语言 (en, zh, ja, ko, es, fr, de, pt, ru) |

**示例**：
```bash
/threat-model @my-project                    # 默认模式
/threat-model @my-project --debug            # 包含内部数据
/threat-model @my-project --lang=zh --debug  # 中文输出+调试
```

## 纵深扩展分析（高级场景）

在标准8阶段工作流之外，使用以下扩展 prompt 进行更深入的安全分析：

### 场景 1：完整接口与数据流发现

全面发现和分析所有系统接口及数据流。

```
/threat-modeling @/path/to/project

执行完整的接口和数据流发现分析：

1. 全面发现所有系统接口：
   - 用户交互接口（Web UI、CLI、Mobile）
   - 外部 API（REST、GraphQL、gRPC、WebSocket）
   - 系统接口（文件系统、数据库、消息队列）
   - 内部服务（微服务间调用、RPC、事件总线）

2. 构建完整数据流图：
   - 标注所有数据入口点和出口点
   - 识别敏感数据流动路径
   - 标记信任边界穿越点

3. 针对每个接口进行风险分析：
   - 输入验证风险
   - 认证授权风险
   - 数据泄露风险
   - 注入攻击风险

输出格式：按风险等级排序的完整接口清单，包含 CWE 映射和 CVSS 评分
```

### 场景 2：攻击树、POC生成与渗透测试方案

深度攻击链分析，生成 exploit POC 和渗透测试计划。

```
/threat-modeling @/path/to/project --debug

基于已发现的安全问题，进行深度攻击分析：

1. 攻击树构建：
   - 为每个高危威胁构建攻击树
   - 分析攻击前置条件和依赖关系
   - 计算攻击成功概率和影响范围

2. 攻击链分析：
   - 识别多步攻击路径（Initial Access → Execution → Persistence → Exfiltration）
   - 映射到 MITRE ATT&CK 战术和技术
   - 标注攻击链中的关键枢纽点

3. Exploit POC 生成：
   - 为每个可利用漏洞生成 POC 代码
   - 包含 Payload 构造、触发条件、预期结果
   - 提供安全的测试方法（避免破坏性操作）

4. 渗透测试方案：
   | 问题ID | 漏洞描述 | 测试用例 | 测试步骤 | POC | 推荐工具 |
   |--------|----------|----------|----------|-----|----------|

输出：完整的渗透测试计划文档，可直接用于安全测试执行
```

### 场景 3：Docker测试环境与自动化验证

建立隔离测试环境并执行渗透测试方案。

```
/threat-modeling @/path/to/project

建立测试环境并执行渗透测试验证：

1. 环境分析：
   - 解析项目的 docker-compose.yml / Dockerfile
   - 识别所需服务依赖（数据库、缓存、消息队列）
   - 分析默认配置和环境变量

2. Docker 测试环境构建：
   - 生成独立的测试环境 docker-compose.test.yml
   - 配置网络隔离和端口映射
   - 准备测试数据和初始化脚本
   - 集成安全测试工具容器（OWASP ZAP、Nuclei、SQLMap）

3. 自动化测试执行：
   - 执行已生成的渗透测试方案
   - 收集测试结果和证据截图
   - 验证漏洞可利用性

4. 测试报告：
   - 漏洞确认状态（Confirmed / Not Exploitable / False Positive）
   - 实际风险评估调整
   - 复现步骤和证据链

输出：测试环境配置文件 + 自动化测试脚本 + 测试结果报告
```

### 场景 4：攻击链可视化与POC优化

完整攻击链分析，优化POC工具组合，输出可视化分析。

```
/threat-modeling @/path/to/project --debug

完整攻击链分析与可视化：

1. 攻击图谱构建：
   - 构建系统完整攻击图（Attack Graph）
   - 节点：资产、漏洞、攻击技术
   - 边：攻击路径、前置条件、成功概率

2. 关键路径分析：
   - 识别最短攻击路径（从入口到核心资产）
   - 识别最高成功率路径
   - 识别影响范围最大的攻击链

3. POC 优化组合：
   - 工具链组合优化（Recon → Exploit → Post-Exploit）
   - 自动化攻击脚本生成
   - 一键式漏洞验证流程

4. 可视化输出：
   - Mermaid 格式攻击树图
   - 攻击路径热力图
   - 风险-影响矩阵图
   - ATT&CK Navigator 映射图

输出格式：
- 攻击图谱 Markdown（含 Mermaid 图表）
- 优化后的 POC 工具包
- 风险可视化仪表板数据
```

### 扩展场景速查表

| 场景 | 重点 | 主要输出 |
|------|------|----------|
| **接口发现** | 全部接口 + 数据流 | 风险排序的接口清单 |
| **攻击树与POC** | 攻击链 + Exploit | 渗透测试方案 + POC代码 |
| **Docker测试环境** | 隔离测试 | 测试环境 + 自动化脚本 |
| **攻击可视化** | 可视化分析 | 攻击图谱 + 热力图 |

## 输出结构

```
{PROJECT_ROOT}/
├── Risk_Assessment_Report/           # 最终报告 (P8)
│   ├── {PROJECT}-RISK-ASSESSMENT-REPORT.md
│   ├── {PROJECT}-RISK-INVENTORY.md
│   ├── {PROJECT}-PENETRATION-TEST-PLAN.md
│   └── ...
└── .phase_working/{SESSION_ID}/      # 工作数据
    ├── data/                         # YAML阶段数据
    │   ├── P1_project_context.yaml
    │   ├── P2_dfd_elements.yaml
    │   └── ...
    └── reports/                      # Markdown报告
        ├── P1-PROJECT-UNDERSTANDING.md
        └── ...
```

## 脚本命令

### 知识库查询

```bash
# STRIDE威胁模式
python scripts/unified_kb_query.py --stride spoofing

# 安全控制
python scripts/unified_kb_query.py --control AUTHN

# CWE完整链
python scripts/unified_kb_query.py --cwe CWE-89 --full-chain

# CAPEC攻击模式
python scripts/unified_kb_query.py --capec CAPEC-66 --attack-chain

# AI/LLM特定威胁
python scripts/unified_kb_query.py --all-llm
```

### 模块发现

```bash
python scripts/module_discovery.py /path/to/project --p1-discovery
```

### 阶段数据管理

```bash
# 查询前一阶段数据
python scripts/phase_data.py --query --phase 1 --root /path/to/project

# 验证阶段输出
python scripts/phase_data.py --validate --phase 2 --root /path/to/project

# 初始化新会话
python scripts/phase_data.py --init --project "PROJECT-NAME" --path /path/to/project
```

## 8阶段工作流

```
P1 → P2 → P3 → P4 → P5 → P6 → P7 → P8
│    │    │    │    │    │    │    └── 报告生成
│    │    │    │    │    │    └── 缓解规划
│    │    │    │    │    └── 风险验证（POC、攻击路径）
│    │    │    │    └── STRIDE威胁分析（威胁矩阵）
│    │    │    └── 安全设计审查（16个领域）
│    │    └── 信任边界评估
│    └── 调用流与DFD分析（数据流、调用流）
└── 项目理解（模块、入口点）
```

## 知识库

| 类别 | 覆盖范围 |
|------|----------|
| 安全控制 | 16个领域，107个控制项 |
| 威胁模式 | CWE/CAPEC/ATT&CK（1,900+模式） |
| AI/LLM威胁 | 350+威胁 |
| 合规标准 | OWASP ASVS, WSTG, MASTG |
| SQLite索引 | ~8 MB可搜索 |

## 支持的项目类型

| 类型 | 示例技术 | 重点关注 |
|------|----------|----------|
| Web API | Django, FastAPI, Express | 认证、API安全 |
| 微服务 | K8s, Istio, Kafka | 服务网格、零信任 |
| AI/LLM应用 | Claude API, RAG, 向量数据库 | Prompt注入、模型安全 |
| 移动后端 | JWT, OAuth, Firebase | Token安全、数据隐私 |
| 遗留系统 | 单体架构, SOAP | 技术债、迁移风险 |

## 许可证

BSD-3-Clause

## 仓库

https://github.com/fr33d3m0n/threat-modeling
