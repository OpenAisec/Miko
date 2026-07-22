# 敏感操作安全控制矩阵

> 版本: 1.0.0
> 用途: 定义各类敏感操作及其应有的安全控制
> 使用: 审计时对照此矩阵验证控制是否存在

---

## 一、敏感操作分类速查

| 类别 | 识别特征 | 典型示例 | 风险等级 |
|------|----------|----------|----------|
| **数据修改** | POST/PUT/DELETE、insert/update/delete | 创建/修改/删除用户、订单 | 高 |
| **数据访问** | GET + ID参数、query/select | /user/{id}、/order/{id} | 中 |
| **批量操作** | export/download/batch关键词 | 导出报表、批量删除 | 高 |
| **权限变更** | role/permission/grant关键词 | 角色分配、权限授予 | 严重 |
| **资金操作** | transfer/pay/refund/balance | 转账、支付、退款 | 严重 |
| **认证操作** | login/password/token/session | 登录、密码重置 | 严重 |
| **外部请求** | http/url/request/curl | 发起HTTP请求 | 高 |
| **文件操作** | file/upload/download/path | 文件上传下载、路径操作 | 高 |
| **命令执行** | exec/system/process/shell | 执行系统命令 | 严重 |

---

## 二、安全控制矩阵详表

### 2.1 数据修改操作 (CREATE/UPDATE/DELETE)

```yaml
操作类型: 数据修改
风险等级: 高
典型端点: POST /resource, PUT /resource/{id}, DELETE /resource/{id}

必须控制:
  认证控制:
    描述: 验证用户已登录
    实现方式:
      - Java: @PreAuthorize, Filter, Interceptor
      - Python: @login_required, middleware
      - Go: middleware
      - PHP: session检查, middleware
    缺失漏洞: CWE-306 认证缺失

  授权控制:
    描述: 验证用户有权执行此操作
    实现方式:
      - 角色检查: hasRole('ADMIN')
      - 权限检查: hasPermission('user:delete')
    缺失漏洞: CWE-862 授权缺失

  资源所有权:
    描述: 验证资源属于当前用户(非管理员时)
    实现方式:
      - resource.ownerId == currentUserId
      - 或 isAdmin() 跳过检查
    缺失漏洞: CWE-639 IDOR

  输入验证:
    描述: 验证输入参数合法性
    实现方式:
      - 类型校验、格式校验、范围校验
    缺失漏洞: CWE-20 输入验证不当

可选控制:
  审计日志:
    描述: 记录操作日志
    缺失影响: 合规问题、事后追溯困难

  操作确认:
    描述: 危险操作二次确认
    适用场景: 删除、不可逆操作
```

### 2.2 数据访问操作 (READ)

```yaml
操作类型: 数据访问
风险等级: 中
典型端点: GET /resource/{id}, GET /resource/list

必须控制:
  认证控制:
    描述: 敏感数据需登录访问
    例外: 公开数据可匿名

  资源所有权/范围限制:
    描述: 只能访问自己的数据或有权限的数据
    实现方式:
      - 单条: resource.ownerId == currentUserId
      - 列表: WHERE owner_id = ?
    缺失漏洞: CWE-639 IDOR

可选控制:
  数据脱敏:
    描述: 敏感字段脱敏展示
    适用: 手机号、身份证、银行卡

  分页限制:
    描述: 限制单次返回数量
    防护: 防止大量数据泄露
```

### 2.3 批量操作

```yaml
操作类型: 批量操作
风险等级: 高
典型端点: GET /export, POST /batch-delete, GET /download

必须控制:
  认证控制:
    描述: 必须登录

  授权控制:
    描述: 需要特殊权限
    实现: hasRole('ADMIN') 或 hasPermission('export')

  范围限制:
    描述: 只能操作自己有权限的数据
    实现: 查询条件加owner过滤

  数量限制:
    描述: 限制单次操作数量
    实现: LIMIT 1000, 分批处理

可选控制:
  频率限制:
    描述: 限制调用频率
    防护: 防止滥用

  异步处理:
    描述: 大量数据异步处理
    实现: 消息队列、后台任务
```

### 2.4 权限变更操作

```yaml
操作类型: 权限变更
风险等级: 严重
典型端点: POST /role/assign, PUT /user/{id}/permission

必须控制:
  认证控制:
    描述: 必须登录

  高级授权:
    描述: 需要管理员或更高权限
    实现: hasRole('SUPER_ADMIN')

  权限边界检查:
    描述: 不能授予高于自己的权限
    实现: targetRole.level <= currentUser.role.level
    缺失漏洞: CWE-269 权限提升

  操作审计:
    描述: 记录权限变更
    要求: 必须记录

可选控制:
  审批流程:
    描述: 重要权限变更需审批
```

### 2.5 资金操作

```yaml
操作类型: 资金操作
风险等级: 严重
典型端点: POST /transfer, POST /pay, POST /refund

必须控制:
  认证控制:
    描述: 必须登录且验证身份

  授权控制:
    描述: 验证账户所有权
    实现: account.ownerId == currentUserId

  金额校验:
    描述: 验证金额合理性
    实现: amount > 0 && amount <= MAX_LIMIT

  余额检查:
    描述: 操作前检查余额
    实现: balance >= amount (在事务内)

  幂等性控制:
    描述: 防止重复提交
    实现: 唯一事务ID、token机制
    缺失漏洞: 重复扣款

  并发控制:
    描述: 防止并发透支
    实现:
      - 数据库锁: SELECT ... FOR UPDATE
      - 乐观锁: version字段
      - 原子操作: UPDATE balance = balance - ? WHERE balance >= ?
    缺失漏洞: CWE-362 竞态条件

可选控制:
  风控检查:
    描述: 异常交易检测

  二次确认:
    描述: 大额交易确认
```

### 2.6 外部HTTP请求

```yaml
操作类型: 外部HTTP请求
风险等级: 高
典型场景: 回调URL、Webhook、URL预览

必须控制:
  URL白名单:
    描述: 限制可访问的目标地址
    实现: 域名白名单、IP白名单
    缺失漏洞: CWE-918 SSRF

  协议限制:
    描述: 仅允许http/https
    禁止: file://, gopher://, dict://

  内网地址过滤:
    描述: 禁止访问内网地址
    过滤: 127.0.0.1, 10.x, 172.16-31.x, 192.168.x
    注意: 需防DNS Rebinding

可选控制:
  超时控制:
    描述: 设置请求超时

  重定向限制:
    描述: 限制重定向次数或禁止重定向
```

### 2.7 文件操作 (CRUD 完整覆盖 - v2.5.0 增强)

> ⚠️ **审计盲区警示**: 必须覆盖文件的 Create/Read/Update/Delete 全部操作！
> 常见遗漏: 只审计上传/下载，忽略删除操作 (参考: litemall GitHub #564)

```yaml
操作类型: 文件操作
风险等级: 高
典型场景: 文件上传、文件下载、文件读取、**文件删除**、文件覆盖

# ============ CRUD 操作完整覆盖 ============

文件上传 (Create):
  必须控制:
    路径校验:
      描述: 防止路径遍历写入
      实现: 规范化后检查前缀
      缺失漏洞: CWE-22 路径遍历
    文件类型校验:
      描述: 验证文件类型
      实现: 扩展名白名单 + MIME + 魔数
      缺失漏洞: CWE-434 任意文件上传
    文件大小限制:
      描述: 限制文件大小
      防护: 防止DoS

文件下载/读取 (Read):
  必须控制:
    路径校验:
      描述: 防止路径遍历读取
      实现: 规范化后检查前缀
      缺失漏洞: CWE-22 任意文件读取
    权限验证:
      描述: 验证用户有权访问该文件
      缺失漏洞: CWE-639 IDOR

文件覆盖 (Update):
  必须控制:
    路径校验:
      描述: 防止覆盖任意文件
      实现: 规范化后检查前缀
      缺失漏洞: CWE-22 任意文件覆盖
    权限验证:
      描述: 验证用户有权修改该文件
      缺失漏洞: CWE-639 IDOR

文件删除 (Delete): # ⚠️ 易遗漏！
  必须控制:
    路径校验:
      描述: 防止路径遍历删除
      实现:
        - 规范化路径 (normalize)
        - 检查是否在允许目录内
        - 禁止 ../ 和 ..\
      缺失漏洞: CWE-22 任意文件删除
    权限验证:
      描述: 验证用户有权删除该文件
      缺失漏洞: CWE-639 IDOR
    审计日志:
      描述: 记录删除操作
      要求: 删除操作必须记录

可选控制:
  病毒扫描:
    描述: 上传文件病毒扫描
  存储隔离:
    描述: 上传文件与代码分离
  软删除:
    描述: 标记删除而非物理删除，便于恢复
```

### 2.7.1 文件操作 CRUD 检测命令 (多语言)

```bash
# Java
grep -rn "MultipartFile\|transferTo" --include="*.java"           # Create
grep -rn "FileInputStream\|Files\.read" --include="*.java"        # Read
grep -rn "Files\.write.*TRUNCATE" --include="*.java"              # Update
grep -rn "Files\.delete\|FileUtils\.delete" --include="*.java"    # Delete

# Python
grep -rn "\.save\(\|open.*'w'" --include="*.py"                   # Create
grep -rn "open.*'r'\|\.read\(" --include="*.py"                   # Read
grep -rn "open.*'w'" --include="*.py"                             # Update
grep -rn "os\.remove\|os\.unlink\|shutil\.rmtree" --include="*.py" # Delete

# Go
grep -rn "os\.Create\|ioutil\.WriteFile" --include="*.go"         # Create
grep -rn "os\.Open\|ioutil\.ReadFile" --include="*.go"            # Read
grep -rn "os\.OpenFile.*O_WRONLY" --include="*.go"                # Update
grep -rn "os\.Remove\|os\.RemoveAll" --include="*.go"             # Delete

# PHP
grep -rn "move_uploaded_file\|file_put_contents" --include="*.php" # Create
grep -rn "file_get_contents\|fread" --include="*.php"             # Read
grep -rn "file_put_contents" --include="*.php"                    # Update
grep -rn "unlink\|rmdir" --include="*.php"                        # Delete

# Node.js
grep -rn "fs\.writeFile\|createWriteStream" --include="*.js"      # Create
grep -rn "fs\.readFile\|createReadStream" --include="*.js"        # Read
grep -rn "fs\.writeFile" --include="*.js"                         # Update
grep -rn "fs\.unlink\|fs\.rm\|rimraf" --include="*.js"            # Delete
```

### 2.8 命令执行

```yaml
操作类型: 命令执行
风险等级: 严重
典型场景: 系统管理功能、工具调用

必须控制:
  命令白名单:
    描述: 只允许执行预定义命令
    实现: 枚举允许的命令

  参数过滤:
    描述: 过滤危险字符
    过滤: ; | & $ ` \n \r

  参数化调用:
    描述: 使用数组传参而非字符串拼接
    实现:
      - Java: ProcessBuilder(cmd, arg1, arg2)
      - Python: subprocess.run([cmd, arg1, arg2])
    缺失漏洞: CWE-78 命令注入

可选控制:
  权限降级:
    描述: 使用低权限用户执行

  沙箱执行:
    描述: 容器/沙箱隔离
```

---

## 三、控制验证检查表模板

```markdown
## 敏感操作控制验证

### 操作信息
- 端点: _________________
- 位置: _________________
- 类型: [ ] 数据修改 [ ] 数据访问 [ ] 批量操作 [ ] 权限变更 [ ] 资金操作 [ ] 外部请求 [ ] 文件操作 [ ] 命令执行

### 控制验证

| 控制项 | 应有 | 代码中存在 | 结果 |
|--------|------|-----------|------|
| 认证控制 | [ ] 是 [ ] 否 | [ ] 是 [ ] 否 | [ ] ✅ [ ] ❌ |
| 授权控制 | [ ] 是 [ ] 否 | [ ] 是 [ ] 否 | [ ] ✅ [ ] ❌ |
| 资源所有权 | [ ] 是 [ ] 否 | [ ] 是 [ ] 否 | [ ] ✅ [ ] ❌ |
| 输入验证 | [ ] 是 [ ] 否 | [ ] 是 [ ] 否 | [ ] ✅ [ ] ❌ |
| 业务规则 | [ ] 是 [ ] 否 | [ ] 是 [ ] 否 | [ ] ✅ [ ] ❌ |
| 幂等性 | [ ] 是 [ ] 否 | [ ] 是 [ ] 否 | [ ] ✅ [ ] ❌ |
| 并发控制 | [ ] 是 [ ] 否 | [ ] 是 [ ] 否 | [ ] ✅ [ ] ❌ |
| 审计日志 | [ ] 是 [ ] 否 | [ ] 是 [ ] 否 | [ ] ✅ [ ] ❌ |

### 发现问题
_________________________________________________

### 漏洞判定
_________________________________________________
```

---

## 四、语言特定实现参考

### 4.1 Java/Spring

| 控制 | 实现方式 |
|------|----------|
| 认证 | @PreAuthorize("isAuthenticated()"), SecurityFilter |
| 授权 | @PreAuthorize("hasRole('X')"), @Secured |
| 所有权 | 代码中比对 entity.getOwnerId().equals(currentUserId) |
| 输入验证 | @Valid, @NotNull, @Size, Validator |
| 并发控制 | @Transactional + @Lock, SELECT FOR UPDATE |
| 审计 | @Audit注解, AOP, Spring Data Auditing |

### 4.2 Python/Django/Flask

| 控制 | 实现方式 |
|------|----------|
| 认证 | @login_required, Flask-Login |
| 授权 | @permission_required, Django permissions |
| 所有权 | obj.owner == request.user |
| 输入验证 | Django Forms, Marshmallow, Pydantic |
| 并发控制 | select_for_update(), F()表达式 |
| 审计 | django-auditlog, signals |

### 4.3 Go/Gin/Echo

| 控制 | 实现方式 |
|------|----------|
| 认证 | JWT middleware, session middleware |
| 授权 | Casbin, 自定义middleware |
| 所有权 | 代码中比对 |
| 输入验证 | go-playground/validator |
| 并发控制 | GORM锁, 数据库事务 |
| 审计 | 自定义middleware |

### 4.4 PHP/Laravel

| 控制 | 实现方式 |
|------|----------|
| 认证 | auth middleware, Auth::check() |
| 授权 | Gate, Policy, @can |
| 所有权 | Policy中检查 |
| 输入验证 | FormRequest, Validator |
| 并发控制 | lockForUpdate(), 数据库事务 |
| 审计 | spatie/laravel-activitylog |

---

**版本**: 1.0.0
**创建日期**: 2026-02-04
