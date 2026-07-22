# 业务逻辑安全检测模块

> 基于定时任务、配置管理等复杂业务流程的安全检测
> 针对企业级应用中的业务逻辑安全风险

## Overview

Business logic flaws exploit intended functionality to violate domain invariants: transfer money without paying, exceed limits, retain privileges after downgrade, or bypass approval workflows. Unlike injection vulnerabilities that require payloads, business logic flaws require understanding the business domain and its invariants.

**Critical**: Business logic security is the enforcement of domain invariants under adversarial sequencing, timing, and inputs. If any step trusts the client or prior steps, expect abuse.

---

## Systematic Methodology

### 1. Actor × Action × Resource Matrix

Build a comprehensive matrix to identify authorization gaps:

**Actors (Roles):**
- Unauthenticated users
- Basic/Free users
- Premium/Paid users
- Trial users
- Staff/Support
- Admin/Super-admin
- Cross-tenant actors (in multi-tenant systems)

**Actions:**
- Create, Read, Update, Delete (CRUD)
- State transitions (approve, reject, cancel, refund)
- Calculations (pricing, discounts, quotas)
- Background operations (jobs, webhooks, sagas)

**Resources:**
- User accounts, profiles, settings
- Financial entities (orders, payments, refunds, credits)
- Content (posts, files, documents)
- Configuration (settings, features, limits)
- Cross-tenant resources

**Detection Pattern:**
```java
// For each endpoint, ask:
// 1. Which actors can access this action?
// 2. Is there server-side validation for actor-resource ownership?
// 3. Can lower-privileged actors access higher-privileged actions?

@PostMapping("/admin/users/{id}/promote")
public Response promoteToAdmin(@PathVariable Long id) {
    // ❌ Missing: Who can call this?
    // ❌ Missing: Can user promote themselves?
    // ❌ Missing: Can non-admin call this endpoint?
    userService.setRole(id, "ADMIN");
}
```

### 2. State Machine Enumeration

For each critical workflow, enumerate:
- **States**: Draft, Pending, Approved, Completed, Cancelled, Refunded
- **Transitions**: Valid state change paths
- **Pre-conditions**: What must be true before a transition
- **Post-conditions**: What must be true after a transition
- **Invariants**: Rules that must always hold

**Example: Order State Machine**
```
States: Created → PendingPayment → Paid → Shipped → Delivered → [Cancelled/Refunded]

Invariants:
- Conservation of value: Sum(payments) - Sum(refunds) = Order total
- Monotonicity: Created timestamp < Paid timestamp < Shipped timestamp
- Uniqueness: One active order per cart session
- Refund constraint: Total refunds ≤ Total captured amount
```

**Detection Pattern:**
```java
// ❌ State transition without pre-condition check
public void shipOrder(Long orderId) {
    // Missing: Check if order is in "Paid" state
    // Missing: Check if order hasn't been cancelled
    // Missing: Check if inventory is still available
    orderRepo.updateStatus(orderId, OrderStatus.SHIPPED);
}

// ✓ Safe: Validate pre-conditions
public void shipOrder(Long orderId) {
    Order order = orderRepo.findByIdForUpdate(orderId);

    if (order.getStatus() != OrderStatus.PAID) {
        throw new IllegalStateException("Order not paid");
    }

    if (order.isCancelled()) {
        throw new IllegalStateException("Order cancelled");
    }

    if (!inventory.reserve(order.getItems())) {
        throw new BusinessException("Insufficient inventory");
    }

    order.setStatus(OrderStatus.SHIPPED);
    order.setShippedAt(Instant.now());
    orderRepo.save(order);
}
```

### 3. Invariant Validation

**Conservation of Value:**
```java
// Financial transactions must balance
// Detect: Ledger entries that don't sum to zero
// Detect: Refunds exceeding captured amounts

// ❌ No conservation check
public void refund(Long orderId, BigDecimal amount) {
    refundService.process(orderId, amount);
}

// ✓ Enforce conservation
public void refund(Long orderId, BigDecimal amount) {
    Order order = orderRepo.findById(orderId);
    BigDecimal totalRefunded = refundRepo.sumByOrderId(orderId);

    if (totalRefunded.add(amount).compareTo(order.getTotalPaid()) > 0) {
        throw new BusinessException("Refund exceeds paid amount");
    }

    refundService.process(orderId, amount);
}
```

**Uniqueness:**
```java
// Single-use tokens, unique coupon codes, one active subscription
// Detect: Missing unique constraints in database
// Detect: Check-then-act patterns without atomicity

// ❌ Race condition on uniqueness
if (!couponRepo.existsByCode(code)) {
    couponRepo.save(new Coupon(code));  // Race window!
}

// ✓ Database-enforced uniqueness
@Entity
public class Coupon {
    @Column(unique = true, nullable = false)
    private String code;
}
```

**Monotonicity:**
```java
// Timestamps, version numbers, sequence IDs should only increase
// Detect: Backward time travel, version rollback

// ❌ No monotonicity check
public void updateVersion(Long id, int newVersion) {
    entity.setVersion(newVersion);  // Could go backward!
}

// ✓ Enforce monotonicity
public void updateVersion(Long id, int newVersion) {
    Entity entity = repo.findById(id);
    if (newVersion <= entity.getVersion()) {
        throw new BusinessException("Version must increase");
    }
    entity.setVersion(newVersion);
}
```

### 4. Test Attack Scenarios

**Step Skipping:**
```java
// Can you call step 3 without completing steps 1 and 2?
// Example: Capture payment without authorization
// Example: Ship order without payment

// Detect: Direct API calls to finalize/complete endpoints
// Detect: Missing state validation
```

**Step Repetition:**
```java
// Can you repeat a step that should only happen once?
// Example: Apply same coupon code multiple times
// Example: Redeem gift card multiple times

// Detect: Missing idempotency controls
// Detect: No "used" flag or state tracking
```

**Step Reordering:**
```java
// Can you execute steps out of order?
// Example: Refund before capture
// Example: Cancel after shipment

// Detect: Missing precondition checks
// Detect: State machine not enforced
```

**Late Mutation:**
```java
// Can you modify inputs after validation but before commit?
// Example: Change price after approval
// Example: Swap product after inventory check

// Detect: TOCTOU (Time-of-check Time-of-use) gaps
// Detect: Validation separated from action
```

---

## High-Value Target Categories

### 1. Financial Logic

**Pricing & Discounts:**
```java
// ❌ Client-computed total accepted
@PostMapping("/checkout")
public Order checkout(@RequestBody CheckoutRequest req) {
    // Trusts req.total from client!
    return paymentService.charge(req.getTotal());
}

// ✓ Server recomputes everything
@PostMapping("/checkout")
public Order checkout(@RequestBody CheckoutRequest req) {
    BigDecimal total = pricingEngine.calculate(req.getItems());
    BigDecimal discount = discountEngine.apply(req.getCouponCode(), total);
    BigDecimal tax = taxService.calculate(total.subtract(discount), req.getAddress());
    BigDecimal finalTotal = total.subtract(discount).add(tax);

    return paymentService.charge(finalTotal);
}
```

**Discount Stacking:**
```java
// ❌ No mutual exclusivity check
public BigDecimal applyDiscount(List<String> couponCodes, BigDecimal amount) {
    BigDecimal discounted = amount;
    for (String code : couponCodes) {
        discounted = discounted.multiply(getDiscountRate(code));
    }
    return discounted;  // Could stack incompatible discounts!
}

// ✓ Enforce mutual exclusivity
public BigDecimal applyDiscount(List<String> couponCodes, BigDecimal amount) {
    if (couponCodes.size() > 1) {
        List<String> categories = couponCodes.stream()
            .map(this::getCouponCategory)
            .distinct()
            .collect(Collectors.toList());

        if (categories.size() > 1) {
            throw new BusinessException("Cannot stack coupons from different categories");
        }
    }

    // Apply best discount only
    return couponCodes.stream()
        .map(code -> calculateDiscount(code, amount))
        .min(Comparator.naturalOrder())
        .orElse(amount);
}
```

**Refund Logic:**
```java
// ❌ Multiple refund paths without coordination
// Path 1: UI refund
// Path 2: Support tool refund
// Path 3: Automated refund (chargeback)
// Result: Double refund possible

// ✓ Centralized refund ledger
public void refund(Long orderId, BigDecimal amount, RefundSource source) {
    synchronized (getLock(orderId)) {  // Or use database lock
        BigDecimal totalRefunded = refundLedger.sumByOrderId(orderId);
        BigDecimal totalCaptured = paymentLedger.sumCapturedByOrderId(orderId);

        if (totalRefunded.add(amount).compareTo(totalCaptured) > 0) {
            throw new BusinessException("Total refunds would exceed captured amount");
        }

        refundLedger.create(orderId, amount, source);
        paymentGateway.refund(orderId, amount);
    }
}
```

### 2. Quotas & Limits

```java
// ❌ Non-atomic quota check
int usage = quotaService.getUsage(userId);
if (usage < LIMIT) {
    // Race window - quota can be exceeded
    processRequest();
    quotaService.increment(userId);
}

// ✓ Atomic quota enforcement
long newUsage = quotaService.incrementAndGet(userId);
if (newUsage > LIMIT) {
    quotaService.decrement(userId);  // Rollback
    throw new QuotaExceededException();
}
processRequest();
```

**Limit Slicing:**
```java
// ❌ Per-transaction limit without total limit
// User sends 100 transactions of $99 each to bypass $100 limit

// ✓ Both per-transaction and total limits
public void transfer(Long fromUserId, Long toUserId, BigDecimal amount) {
    if (amount.compareTo(PER_TRANSACTION_LIMIT) > 0) {
        throw new BusinessException("Per-transaction limit exceeded");
    }

    BigDecimal dailyTotal = transferRepo.sumTodayByUser(fromUserId);
    if (dailyTotal.add(amount).compareTo(DAILY_LIMIT) > 0) {
        throw new BusinessException("Daily limit exceeded");
    }

    executeTransfer(fromUserId, toUserId, amount);
}
```

### 3. Subscription & Account Lifecycle

```java
// ❌ Role retention after downgrade
public void downgradeSubscription(Long userId) {
    subscriptionRepo.updateTier(userId, "FREE");
    // Missing: Remove premium features/permissions
    // User retains premium capabilities!
}

// ✓ Clean state transition
@Transactional
public void downgradeSubscription(Long userId) {
    User user = userRepo.findByIdForUpdate(userId);

    // Check pre-conditions
    if (user.getSubscription().getTier() == Tier.FREE) {
        throw new BusinessException("Already on free tier");
    }

    // Transition state
    user.getSubscription().setTier(Tier.FREE);

    // Enforce post-conditions
    user.setMaxProjects(FREE_TIER_LIMIT);
    user.getPremiumFeatures().clear();
    featureGateService.revokePremiumAccess(userId);

    // Delete excess resources
    projectService.deleteExcessProjects(userId, FREE_TIER_LIMIT);

    userRepo.save(user);
    auditLog.record("SUBSCRIPTION_DOWNGRADED", userId);
}
```

### 4. Multi-Tenant Isolation

```java
// ❌ Missing tenant boundary check
public List<Document> search(String query) {
    return documentRepo.search(query);  // Leaks across tenants!
}

// ✓ Tenant-scoped query
public List<Document> search(String query) {
    String tenantId = SecurityContext.getCurrentTenantId();
    return documentRepo.searchByTenant(tenantId, query);
}

// ❌ Aggregate operations without tenant filter
public void resetAllUserCounters() {
    userRepo.updateAll("counter", 0);  // Affects all tenants!
}

// ✓ Tenant-aware operations
public void resetTenantUserCounters(String tenantId) {
    validateTenantAdmin(tenantId);  // Authorization
    userRepo.updateByTenant(tenantId, "counter", 0);
    auditLog.record("BULK_COUNTER_RESET", tenantId);
}
```

---

## Detection Patterns

### Client-Computed Values

```bash
# Grep for endpoints accepting totals, prices, discounts from client
grep -rn "BigDecimal.*total\|Double.*price\|int.*discount" --include="*.java" -B 3

# Look for @RequestBody or @RequestParam receiving financial values
grep -rn "@Request.*total\|@Request.*price\|@Request.*amount" --include="*.java" -A 5
```

**Red Flags:**
- Request DTOs with `total`, `finalPrice`, `discountedAmount` fields
- Server not recalculating pricing
- Comments like "// TODO: validate total"

### Missing State Validation

```bash
# Find state-changing methods without state checks
grep -rn "public.*void.*(complete\|finalize\|approve\|ship\|refund)" --include="*.java" -A 10 | \
grep -v "if.*status\|if.*state\|getStatus()\|getState()"
```

### Idempotency Gaps

```bash
# Find operations that should be idempotent but lack controls
grep -rn "@Post.*charge\|@Post.*refund\|@Post.*apply\|@Post.*redeem" --include="*.java" -A 15 | \
grep -v "idempotency\|idempotent\|@Transactional.*SERIALIZABLE"
```

### Background Job Security

```bash
# Find scheduled tasks and async jobs
grep -rn "@Scheduled\|@Async\|@RabbitListener\|@KafkaListener" --include="*.java" -A 10

# Check if they bypass authorization
grep -rn "@Scheduled" --include="*.java" -A 10 | \
grep -v "checkPermission\|hasRole\|@RequiresPermissions"
```

---

## 🔍 风险模式库

### 风险模式1: 定时任务管理业务逻辑漏洞（高危）

#### 漏洞代码示例
```java
// ❌ 高危: 定时任务创建无业务逻辑验证
@PostMapping("/monitor/job/add")
public AjaxResult addSave(SysJob job) {
    // 缺少业务逻辑验证:
    // - 方法调用权限验证
    // - 参数内容安全检查
    // - 执行频率限制验证
    return toAjax(jobService.insertJobCron(job));
}

// ❌ 高危: 定时任务执行无资源限制
public class ScheduleRunnable implements Runnable {
    public void run() {
        // 无资源使用限制
        // 无执行时间限制
        // 无异常处理限制
        method.invoke(target, params);
    }
}
```

### 风险模式2: 配置管理业务逻辑漏洞（中危）

#### 漏洞代码示例
```java
// ❌ 中危: 系统配置修改无权限验证
@PostMapping("/system/config/edit")
public AjaxResult editSave(SysConfig config) {
    // 缺少配置修改的业务逻辑验证:
    // - 配置项权限验证
    // - 配置值格式验证
    // - 配置影响范围评估
    return toAjax(configService.updateConfig(config));
}
```

### 风险模式3: 数据导出业务逻辑漏洞（中危）

#### 漏洞代码示例
```java
// ❌ 中危: 数据导出无权限和范围控制
@PostMapping("/system/user/export")
public AjaxResult export(SysUser user) {
    // 缺少数据导出的业务逻辑验证:
    // - 导出数据范围控制
    // - 导出频率限制
    // - 敏感数据过滤
    List<SysUser> list = userService.selectUserList(user);
    return util.exportExcel(list, "user");
}
```

## 🔧 检测命令集

### 业务逻辑接口检测
```bash
# 1. 定时任务管理业务检测
grep -rn "@.*Mapping.*/monitor/job" --include="*.java" -A 15

# 2. 配置管理业务检测
grep -rn "@.*Mapping.*/system/config" --include="*.java" -A 15

# 3. 数据导出业务检测
grep -rn "@.*Mapping.*/export" --include="*.java" -A 15

# 4. 权限控制业务检测
grep -rn "@RequiresPermissions" --include="*.java" -B 2 -A 5

# 5. 业务逻辑验证检测
grep -rn "validate\|check\|verify" --include="*.java" -B 2 -A 2
```

### 业务数据流检测
```bash
# 1. 用户输入到业务逻辑的完整路径
grep -rn "@.*Mapping" --include="*.java" | head -20

# 2. 业务逻辑处理链条检测
grep -rn "Service\." --include="*.java" | grep -E "save|update|delete|execute"

# 3. 数据库操作业务逻辑检测
grep -rn "Mapper\." --include="*.java" -B 3 -A 3
```

## 🛡️ 安全修复方案

### 修复方案1: 业务逻辑权限验证

```java
// ✓ 安全: 业务逻辑权限验证
@RequiresPermissions("monitor:job:add")
@PostMapping("/monitor/job/add")
public AjaxResult addSave(SysJob job) {
    // 业务逻辑权限验证
    if (!hasJobCreationPermission(job)) {
        return error("No permission to create this job");
    }

    // 业务逻辑参数验证
    if (!isValidJobConfiguration(job)) {
        return error("Invalid job configuration");
    }

    // 业务逻辑资源限制验证
    if (!hasSufficientResources(job)) {
        return error("Insufficient resources for this job");
    }

    return toAjax(jobService.insertJobCron(job));
}

private boolean hasJobCreationPermission(SysJob job) {
    // 细粒度业务权限控制
    return SecurityUtils.getSubject().isPermitted("job:create:" + job.getJobGroup());
}

private boolean isValidJobConfiguration(SysJob job) {
    // 业务逻辑配置验证
    return job.getCronExpression() != null &&
           job.getMethodName() != null &&
           isAllowedMethod(job.getMethodName());
}
```

### 修复方案2: 业务数据范围控制

```java
// ✓ 安全: 业务数据范围控制
@PostMapping("/system/user/export")
public AjaxResult export(SysUser user) {
    // 业务数据范围控制
    if (!hasDataExportPermission(user)) {
        return error("No permission to export this data");
    }

    // 业务数据过滤
    user = filterSensitiveData(user);

    // 业务频率限制
    if (!checkExportFrequency()) {
        return error("Export frequency limit exceeded");
    }

    List<SysUser> list = userService.selectUserList(user);
    return util.exportExcel(list, "user");
}

private boolean hasDataExportPermission(SysUser user) {
    // 业务数据权限控制
    User currentUser = SecurityUtils.getCurrentUser();
    return currentUser.hasPermission("data:export:" + user.getDeptId());
}
```

### 修复方案3: 业务资源限制控制

```java
// ✓ 安全: 业务资源限制控制
public class ScheduleRunnable implements Runnable {
    private static final long MAX_EXECUTION_TIME = 30000; // 30秒
    private static final int MAX_MEMORY_USAGE = 1024; // 1GB

    public void run() {
        long startTime = System.currentTimeMillis();

        try {
            // 执行时间限制
            if (System.currentTimeMillis() - startTime > MAX_EXECUTION_TIME) {
                throw new TimeoutException("Execution time exceeded");
            }

            // 内存使用限制
            if (getMemoryUsage() > MAX_MEMORY_USAGE) {
                throw new MemoryLimitException("Memory usage exceeded");
            }

            method.invoke(target, params);

        } catch (Exception e) {
            log.error("Task execution failed", e);
        }
    }
}
```

## 📊 风险评级矩阵

| 风险类型 | 严重性 | 利用难度 | 检测难度 | 修复优先级 |
|----------|--------|----------|----------|------------|
| 定时任务业务逻辑 | 🔴 高危 | 中 | 高 | 立即修复 |
| 配置管理业务逻辑 | 🟡 中危 | 中 | 中 | 计划修复 |
| 数据导出业务逻辑 | 🟡 中危 | 高 | 中 | 计划修复 |
| 权限控制业务逻辑 | 🟡 中危 | 低 | 低 | 计划修复 |

## ⚠️ 安全最佳实践

1. **业务权限控制**: 实现细粒度的业务逻辑权限验证
2. **数据范围控制**: 严格限制业务数据的访问和操作范围
3. **资源使用限制**: 对业务操作的资源使用进行限制
4. **异常处理机制**: 完善的业务异常处理和日志记录
5. **业务流程审计**: 完整的业务流程操作审计追踪

## 🎯 检测优先级

### 高危检测项（立即执行）
- [ ] 定时任务业务逻辑安全检测
- [ ] 方法调用权限验证缺失检测
- [ ] 资源使用限制缺失检测

### 中危检测项（计划执行）
- [ ] 配置管理业务逻辑检测
- [ ] 数据导出业务逻辑检测
- [ ] 权限控制业务逻辑检测

### 基础检测项（常规执行）
- [ ] 业务流程数据流追踪
- [ ] 业务异常处理机制检测
- [ ] 业务操作审计日志检测

---

## 📊 真实案例：若依管理系统数据权限过滤

### 案例背景
**项目**: RuoYi v3.1
**模块**: 数据权限过滤（Data Scope）
**风险**: MyBatis动态SQL拼接安全风险
**CVSS**: 6.5 (Medium)

### 漏洞代码分析

#### Mapper XML配置
```xml
<!-- SysDeptMapper.xml:38-52 -->
<select id="selectDeptList" parameterType="SysDept" resultMap="SysDeptResult">
    <include refid="selectDeptVo"/>
    where d.del_flag = '0'
    <if test="parentId != null and parentId != 0">
        AND parent_id = #{parentId}
    </if>
    <if test="deptName != null and deptName != ''">
        AND dept_name like concat('%', #{deptName}, '%')  <!-- ✓ 安全的参数化 -->
    </if>
    <!-- ❌ 关键风险点: 使用${}进行SQL拼接 -->
    ${params.dataScope}
</select>
```

#### AOP切面实现
```java
// DataScopeAspect.java:74-105
@Aspect
@Component
public class DataScopeAspect {

    @Before("dataScopePointCut()")
    public void doBefore(JoinPoint point) throws Throwable {
        handleDataScope(point);
    }

    protected void handleDataScope(final JoinPoint joinPoint) {
        // 获得注解
        DataScope controllerDataScope = getAnnotationLog(joinPoint);
        if (controllerDataScope == null) {
            return;
        }

        // 获取当前的用户
        SysUser currentUser = ShiroUtils.getSysUser();
        if (currentUser != null && !currentUser.isAdmin()) {
            // ❌ 非管理员需要数据权限过滤
            dataScopeFilter(joinPoint, currentUser, controllerDataScope.tableAlias());
        }
    }

    public static void dataScopeFilter(JoinPoint joinPoint, SysUser user, String alias) {
        StringBuilder sqlString = new StringBuilder();

        for (SysRole role : user.getRoles()) {
            String dataScope = role.getDataScope();

            if (DATA_SCOPE_ALL.equals(dataScope)) {
                // 全部数据权限 - 清空过滤条件
                sqlString = new StringBuilder();
                break;
            }
            else if (DATA_SCOPE_CUSTOM.equals(dataScope)) {
                // ❌ 关键问题: 使用字符串格式化拼接SQL
                sqlString.append(StringUtils.format(
                    " OR {}.dept_id IN ( SELECT dept_id FROM sys_role_dept WHERE role_id = {} ) ",
                    alias,           // ❌ 虽然来自注解，但设计不安全
                    role.getRoleId() // ❌ 来自数据库，但仍是字符串拼接
                ));
            }
            else if (DATA_SCOPE_DEPT.equals(dataScope)) {
                sqlString.append(StringUtils.format(
                    " OR {}.dept_id = {} ",
                    alias, user.getDeptId()
                ));
            }
        }

        if (StringUtils.isNotBlank(sqlString.toString())) {
            BaseEntity baseEntity = (BaseEntity) joinPoint.getArgs()[0];
            // ❌ 将拼接的SQL片段放入params，然后在XML中用${}
            baseEntity.getParams().put(DATA_SCOPE, " AND (" + sqlString.substring(4) + ")");
        }
    }
}
```

#### StringUtils.format实现
```java
// StrFormatter.java:30-91
public static String format(final String strPattern, final Object... argArray) {
    // ❌ 简单的字符串替换，没有SQL安全处理
    final int strPatternLength = strPattern.length();
    StringBuilder sbuf = new StringBuilder(strPatternLength + 50);

    int handledPosition = 0;
    int delimIndex;

    for (int argIndex = 0; argIndex < argArray.length; argIndex++) {
        delimIndex = strPattern.indexOf(EMPTY_JSON, handledPosition);  // 查找 {}
        if (delimIndex == -1) {
            if (handledPosition == 0) {
                return strPattern;
            } else {
                sbuf.append(strPattern, handledPosition, strPatternLength);
                return sbuf.toString();
            }
        } else {
            sbuf.append(strPattern, handledPosition, delimIndex);
            sbuf.append(Convert.utf8Str(argArray[argIndex]));  // ❌ 直接拼接
            handledPosition = delimIndex + 2;
        }
    }

    sbuf.append(strPattern, handledPosition, strPattern.length());
    return sbuf.toString();
}
```

### 审计发现过程

```bash
# 1. 搜索MyBatis ${}用法
grep -rn '\$\{' --include="*.xml"
# 发现: ${params.dataScope} 在多个Mapper中出现

# 2. 追踪dataScope来源
grep -rn "dataScope" --include="*.java"
# 发现: DataScopeAspect.java

# 3. 分析@DataScope注解使用
grep -rn "@DataScope" --include="*.java"
# 发现: 在Service层广泛使用

# 4. 检查StringUtils.format实现
grep -rn "public.*format" --include="*.java" -A 20 | grep -i "sql"

# 5. 对比安全的concat用法
grep -rn "concat\(" --include="*.xml"
# 发现: 大部分地方正确使用concat('%', #{param}, '%')
```

### 风险分析

虽然这不是直接的SQL注入（因为数据源相对可信），但存在以下问题：

#### 1. 设计缺陷
```
违反"所有SQL必须参数化"的基本安全原则
使用字符串拼接而非MyBatis的#{}参数化
```

#### 2. 潜在风险
```
如果注解配置可被篡改（配置注入）
如果存在其他代码注入点影响alias
如果数据库数据被污染（roleId被篡改）
```

#### 3. 维护风险
```
后续开发可能错误地将用户输入注入到params中
代码审查时容易忽视这种"内部"SQL拼接
增加了漏洞的攻击面
```

### 安全修复方案

#### 方案1: 完全消除${}（推荐）

```java
// ✓ Mapper接口增加参数
List<SysDept> selectDeptList(@Param("dept") SysDept dept,
                              @Param("dataScopeSql") String dataScopeSql,
                              @Param("dataScopeIds") List<Long> dataScopeIds);

// ✓ XML改为完全参数化
<select id="selectDeptList" resultMap="SysDeptResult">
    <include refid="selectDeptVo"/>
    where d.del_flag = '0'
    <if test="deptName != null and deptName != ''">
        AND dept_name like concat('%', #{deptName}, '%')
    </if>

    <!-- ✓ 使用foreach处理数据权限过滤 -->
    <if test="dataScopeIds != null and dataScopeIds.size() > 0">
        AND d.dept_id IN
        <foreach collection="dataScopeIds" item="id" open="(" close=")" separator=",">
            #{id}
        </foreach>
    </if>
</select>

// ✓ Aspect改为传递ID列表
public static void dataScopeFilter(JoinPoint joinPoint, SysUser user, String alias) {
    List<Long> allowedDeptIds = new ArrayList<>();

    for (SysRole role : user.getRoles()) {
        String dataScope = role.getDataScope();

        if (DATA_SCOPE_ALL.equals(dataScope)) {
            allowedDeptIds.clear();  // 清空表示不过滤
            break;
        }
        else if (DATA_SCOPE_CUSTOM.equals(dataScope)) {
            // ✓ 查询角色允许的部门ID列表
            List<Long> roleDeptIds = deptMapper.selectDeptIdsByRoleId(role.getRoleId());
            allowedDeptIds.addAll(roleDeptIds);
        }
        else if (DATA_SCOPE_DEPT.equals(dataScope)) {
            allowedDeptIds.add(user.getDeptId());
        }
    }

    BaseEntity baseEntity = (BaseEntity) joinPoint.getArgs()[0];
    baseEntity.getParams().put("dataScopeIds", allowedDeptIds);
}
```

#### 方案2: alias白名单验证（次优）

```java
// ✓ 如果必须使用${}，至少验证alias
private static final Set<String> ALLOWED_ALIASES = new HashSet<>(
    Arrays.asList("d", "u", "r", "dept", "user", "role")
);

public static void dataScopeFilter(JoinPoint joinPoint, SysUser user, String alias) {
    // ✓ 白名单验证alias
    if (!ALLOWED_ALIASES.contains(alias)) {
        throw new SecurityException("Invalid table alias: " + alias);
    }

    // ✓ 使用PreparedStatement风格
    StringBuilder sqlString = new StringBuilder();
    List<Object> params = new ArrayList<>();

    for (SysRole role : user.getRoles()) {
        if (DATA_SCOPE_CUSTOM.equals(role.getDataScope())) {
            sqlString.append(" OR ").append(alias)
                     .append(".dept_id IN (SELECT dept_id FROM sys_role_dept WHERE role_id = ?)");
            params.add(role.getRoleId());
        }
    }

    // 注: 这种方式仍然不够理想，但比直接拼接好
}
```

### 业务逻辑检测清单

#### 数据权限控制检测
- [ ] 检查@DataScope注解使用是否正确
- [ ] 验证数据权限过滤SQL是否参数化
- [ ] 确认角色权限配置的安全性
- [ ] 测试越权访问场景
- [ ] 检查管理员权限绕过逻辑

#### AOP切面安全检测
- [ ] 检查切面中的SQL拼接操作
- [ ] 验证切面参数来源的安全性
- [ ] 确认切面异常处理的完整性
- [ ] 测试切面在各种场景下的行为

### 关键教训

1. **内部数据也需参数化**
   - 即使数据来自数据库，也应使用参数化查询
   - 字符串拼接永远是不安全的

2. **AOP切面是安全盲区**
   - AOP逻辑容易被忽视
   - 切面中的SQL操作需要特别关注

3. **业务逻辑复杂度增加风险**
   - 复杂的数据权限逻辑更容易出错
   - 需要完整的安全测试覆盖

4. **代码审查要深入**
   - 不能只看表面的CRUD操作
   - 需要追踪完整的数据流

---

## 最小 PoC 示例
```bash
# 越权访问（IDOR）
curl -H "Authorization: Bearer USER" https://app.example.com/api/orders/2
curl -H "Authorization: Bearer USER" https://app.example.com/api/orders/3

# 数据权限 AOP SQL 拼接
rg -n "DataScope|dataScope" --glob "*.{java,kt}"

# 流程跳过/重放
curl -X POST https://app.example.com/api/checkout -d "step=3"  # 跳过前置步骤
```

---

通过本模块的检测规则和若依数据权限案例，能够有效识别企业级应用中的业务逻辑安全风险，特别是复杂的业务流程和后台系统操作的安全问题。
