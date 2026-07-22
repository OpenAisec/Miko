# Phase 2 深度审计方法论

> 本文件定义三种审计轨道的执行方法论。
> D3/D9 Agent **必须加载**本文件（非"按需"）。D7 Agent 按需加载 Phase 2.7 段。

---

## 双轨审计模型概述

审计框架支持三种执行策略，不同维度使用不同策略：

| 轨道 | 适用维度 | 核心逻辑 | 输入 |
|------|---------|---------|------|
| **Sink-driven** | D1, D4, D5, D6 | Grep 危险函数 → 追踪输入到 Sink → 验证无防护 | Sink 模式列表 |
| **Control-driven** | **D3, D9** | 枚举操作 → 逐一验证安全控制是否存在 → **缺失=漏洞** | 端点-权限矩阵 |
| **Config-driven** | D2, D7, D8, D10 | 搜索配置 → 对比安全基线 | 配置文件列表 |

**关键区别**: Sink-driven 搜索"存在的危险代码"，Control-driven 搜索"应存在但缺失的安全控制"。
D3/D9 漏洞本质上是代码缺失（没有权限检查、没有归属校验），Grep 搜不到"不存在的代码"。

---

## Phase 2.5: Control-driven 授权审计（D3 专用）

> **核心原则**: 不搜"危险代码"，而是枚举操作后验证"保护代码"是否存在。

### 执行流程

```
输入: Phase 1 产出的「端点-权限矩阵」
      {端点路径, HTTP方法, 认证要求, 权限注解, 资源归属校验}

Step 1: 端点遍历 — 权限注解验证
  对矩阵中每个端点:
    a. 检查是否有权限注解/中间件保护
    b. 无保护 → 交叉验证是否为公开接口（登录/注册/健康检查）
    c. 非公开但无保护 → D3 授权缺失候选

Step 2: CRUD 权限一致性对比
  对每个资源类型的 Controller:
    a. 枚举该 Controller 的所有 CRUD 方法 (create/read/update/delete/export/copy)
    b. 对每个方法检查: 是否存在权限校验调用
    c. 权限检查不一致 → D3 垂直越权候选
       例: read 有 @RequiresPermissions 但 delete 无
       例: list 有权限检查但 export 无

Step 3: 认证豁免路径审计
  搜索认证豁免配置:
    Grep: whitelist|permitAll|excludePath|anonymous|isPublic|@AllowAnonymous|anon
  对每个被豁免端点:
    a. 该端点是否返回/接受敏感数据？
    b. 该端点是否执行特权操作？
    c. 是 → D2/D3 候选漏洞

Step 4: 统计与输出
  记录: endpoints_audited / total_endpoints = 端点审计率
  记录: crud_types = 执行了 CRUD 一致性对比的资源类型数
```

### 判定规则

- 非公开端点无权限保护 = **High（未授权访问）**
- 同一资源 read 有权限但 delete 无 = **High（垂直越权）**
- 敏感操作端点被认证豁免 = **High（认证绕过）**
- 文件下载豁免 + 无归属校验 = **High（IDOR）**

---

## Phase 2.6: Control-driven 业务逻辑审计（D9 专用）

> **核心原则**: D9 漏洞是"缺失的安全控制"，非"可搜索的危险模式"。
> Grep/Sink 驱动的审计天然低覆盖 D9，本方法论以端点列表驱动。

### 执行流程

```
输入: Phase 1 产出的「端点-权限矩阵」+ Controller/Service 列表

Step 1: IDOR / 资源归属校验
  搜索: findById|getById|selectById|get_object_or_404|findOne
  对每个调用:
    a. 返回值是否与当前用户比对？
    b. 查询条件是否包含用户/租户标识？
    c. 无归属校验 + 端点可由普通用户访问 → IDOR 候选
  覆盖范围: 全部 CRUD 端点（不止 read，包括 delete/copy/export）

Step 2: Mass Assignment 防护
  搜索: @RequestBody|@ModelAttribute 绑定的实体类
  对每个绑定:
    a. 实体类是否有 @JsonIgnore / @JsonProperty(access=READ_ONLY) 标注敏感字段？
    b. 是否使用 DTO 隔离（而非直接绑定 Entity）？
    c. 无隔离 + 实体含 role/isAdmin/status/siteId 等字段 → Mass Assignment 候选

Step 3: 状态机完整性
  识别多步骤流程: Grep status|state|step|phase 字段
  对每个流程:
    a. 每步是否验证前置状态？
    b. 能否跳步？能否回退到已完成步骤？
    c. 状态转换是否在事务内？

Step 4: 并发安全
  4a. TOCTOU / Check-Then-Act:
    搜索: if.*exists|if.*check|if.*find → 后续紧跟写操作
    检查与操作之间是否有事务锁/行级锁/乐观锁
    无锁 + 影响业务状态 → TOCTOU 候选

  4b. Lost Update:
    搜索: save|update|put 端点
    检查是否有版本号/ETag/乐观锁(@Version)
    无版本控制 + 多用户可编辑同一资源 → Lost Update 候选

  4c. 非线程安全共享状态:
    搜索: HashMap|ArrayList|SimpleDateFormat 用于类字段
    Controller/Service 是 Spring 单例 → 多线程共享 → 线程安全候选

Step 5: 数据导出与批量操作
  搜索: export|download|batch|bulk 端点
  检查: 导出范围是否受限于当前用户/租户？
  能否通过参数篡改导出其他租户数据？

Step 6: 多租户/多站点隔离
  搜索: 查询条件是否强制包含租户/站点标识
  检查: 能否通过篡改 siteId/tenantId 参数跨站操作？

Step 7: 统计与输出
  记录: endpoints_audited（D9 维度）
  记录: crud_types（执行了 IDOR 检查的资源类型数）
```

### 判定规则

- findById 后无归属校验 + 端点可由普通用户访问 = **High（IDOR/水平越权）**
- @RequestBody 直接绑定含权限字段的实体 = **High（Mass Assignment）**
- 无锁的状态修改 + 影响业务状态 = **High（竞态条件）**
- 金额来自客户端 + 服务端未重新计算 = **Critical（支付绕过）**
- 同一资源 read 有权限但 delete 无 = **High（垂直越权）**
- 批量导出无范围限制 + 多租户场景 = **Medium（数据泄露）**
- 跨租户查询无隔离 = **High（数据泄露）**

---

## Phase 2.7: 加密与密钥管理审计（D7 深度，按需加载）

> **漏检教训**: D7 浅层审计仅发现"硬编码密钥"和"ECB模式"，遗漏密钥派生、Padding Oracle、证书校验、TLS配置等深层问题。

**检测方法（通用，非语言特定）**:

1. **密钥强度与派生**:
   - 搜索密钥生成: `KeyGenerator|SecretKeySpec|PBKDF2|scrypt|argon2|deriveKey|KDF`
   - 检查: AES密钥长度是否≥128位？PBKDF2迭代次数是否≥100,000？salt是否随机且≥16字节？
   - 无KDF直接用密码作密钥 → **High**（密码空间远小于密钥空间）

2. **加密模式与Padding**:
   - 搜索: `ECB|CBC|GCM|CTR|Cipher\.getInstance|PKCS1|PKCS5|OAEP|NoPadding`
   - ECB 任何场景 → **Medium**；CBC 无 HMAC/签名 → Padding Oracle 候选
   - RSA PKCS#1 v1.5 加密（非签名） → **High**（Bleichenbacher攻击）
   - 优选: AES-GCM（认证加密）、RSA-OAEP

3. **IV/Nonce 安全**:
   - 搜索: `IvParameterSpec|nonce|iv =|IV =|getIV`
   - 硬编码IV/Nonce → **High**；CBC模式下IV可预测 → **Medium**
   - GCM模式nonce重用 → **Critical**（密钥流恢复）

4. **证书与TLS校验**:
   - 搜索: `TrustManager|X509|SSLContext|verify.*hostname|ALLOW_ALL|InsecureSkipVerify`
   - 自定义TrustManager返回空/true → **High**（中间人攻击）
   - 禁用hostname验证 → **High**

5. **密钥存储与泄露**:
   - 搜索: 密钥/密码在日志、异常消息、HTTP响应中出现
   - 密钥以String存储（不可主动清零）vs char[]/byte[]（可清零） → **Low**
   - 密钥在配置文件明文存储且无环境变量/Vault引用 → **Medium**

> **适用模式**: standard 模式检查项 1-3（核心加密缺陷），deep 模式全量 1-5。
> **Agent 分配**: D7 通常与 D8+D10 合并在同一 Agent（三者均为配置/环境层审计）。

---

## Agent 加载规则

| Agent 类型 | 必须加载 | 按需加载 |
|-----------|---------|---------|
| D3+D9 Agent (control-driven) | **Phase 2.5 + Phase 2.6 全文** | — |
| D7+D8+D10 Agent (config-driven) | — | Phase 2.7（D7 深度审计时） |
| D1/D4/D5/D6 Agent (sink-driven) | — | 无需本文件 |
