# 定时任务安全检测模块

> 基于RuoYi定时任务任意文件写入漏洞的安全检测规则
> 针对定时任务调度系统的反射执行安全风险

## 🔍 风险模式库

### 风险模式1: 定时任务反射执行任意方法（高危）

#### 漏洞代码示例
```java
// ❌ 高危: ScheduleRunnable中的反射执行漏洞
public class ScheduleRunnable implements Runnable {
    public ScheduleRunnable(String beanName, String methodName, String params) {
        this.target = SpringContextUtil.getBean(beanName);  // ❌ 用户可控Bean
        this.method = target.getClass().getDeclaredMethod(methodName, String.class);  // ❌ 用户可控方法
    }

    public void run() {
        method.invoke(target, params);  // ❌ 任意方法执行
    }
}

// ❌ 高危: 定时任务管理接口
@PostMapping("/monitor/job/add")
public AjaxResult addSave(SysJob job) {
    return toAjax(jobService.insertJobCron(job));  // ❌ 无安全验证
}
```

#### 攻击向量
```json
{
    "jobName": "ruoYiConfig.setProfile",
    "invokeTarget": "ruoYiConfig.setProfile('C://windows/win.ini')",
    "jobGroup": "DEFAULT",
    "cronExpression": "0/10 * * * * ?",
    "status": "1"
}
```

### 风险模式2: 定时任务管理权限控制缺失（中危）

#### 漏洞代码示例
```java
// ❌ 中危: 权限控制不足
@RequiresPermissions("monitor:job:add")  // ❌ 权限粒度不够细
@PostMapping("/monitor/job/add")
public AjaxResult addSave(SysJob job) {
    // 缺少业务逻辑权限验证
    return toAjax(jobService.insertJobCron(job));
}
```

### 风险模式3: 定时任务参数验证缺失（高危）

#### 漏洞代码示例
```java
// ❌ 高危: 参数无安全验证
public ScheduleRunnable(String beanName, String methodName, String params) {
    // 缺少参数安全检查
    this.target = SpringContextUtil.getBean(beanName);
    this.params = params;  // ❌ 直接使用用户输入
    this.method = target.getClass().getDeclaredMethod(methodName, String.class);
}
```

## 🔧 检测命令集

### 定时任务接口检测
```bash
# 1. 定时任务管理接口检测
grep -rn "@.*Mapping.*/monitor/job" --include="*.java"

# 2. 定时任务业务逻辑检测
grep -rn "ScheduleRunnable\|QuartzJobBean" --include="*.java"

# 3. 反射调用上下文检测
grep -rn "SpringContextUtil\\.getBean" --include="*.java" -B 5 -A 5

# 4. 定时任务服务检测
grep -rn "ISysJobService\|SysJobServiceImpl" --include="*.java"

# 5. 定时任务实体检测
grep -rn "class SysJob" --include="*.java" -A 20
```

### 新增检测命令（基于RuoYi深度审计经验）
```bash
# 6. 反射调用方法检测（高危）
grep -rn "method\\.invoke" --include="*.java" -B 10 -A 5

# 7. 定时任务立即执行接口检测
grep -rn "@PostMapping.*run" --include="*.java" -B 5 -A 5

# 8. 方法参数控制检测
grep -rn "getMethodParams\\|methodParams" --include="*.java" -B 5 -A 5

# 9. 定时任务调用链完整分析
grep -rn "ScheduleUtils\\.run" --include="*.java" -B 5 -A 5

# 10. 多层调用链追踪
grep -rn "SysJobController\\.run" --include="*.java" -A 20 | grep -E "jobService|ScheduleUtils"
```

### 组合检测模式（新规则）
```bash
# 11. 高危组合检测：定时任务接口 + 反射调用
检测条件：
- 存在 @PostMapping("/monitor/job/*")
- 存在 method.invoke(target, params)
- 存在用户可控的 methodParams

风险等级：🔴 高危（远程代码执行）

# 12. 权限上下文组合检测
检测条件：
- 存在 @RequiresPermissions("monitor:job:*")
- 存在危险的反射调用
- 缺少方法白名单验证

风险等级：🔴 高危（权限绕过 + RCE）
```

## 🛡️ 安全修复方案

### 修复方案1: 方法调用白名单验证

```java
// ✓ 安全: 方法调用白名单验证
public ScheduleRunnable(String beanName, String methodName, String params) {
    // 白名单验证
    if (!isAllowedMethod(beanName, methodName)) {
        throw new SecurityException("Method not allowed: " + beanName + "." + methodName);
    }

    this.target = SpringContextUtil.getBean(beanName);
    this.params = params;

    if (StringUtils.isNotEmpty(params)) {
        this.method = target.getClass().getDeclaredMethod(methodName, String.class);
    } else {
        this.method = target.getClass().getDeclaredMethod(methodName);
    }
}

private boolean isAllowedMethod(String beanName, String methodName) {
    // 白名单配置
    return ALLOWED_METHODS.contains(beanName + "." + methodName);
}
```

### 修复方案2: 参数内容安全验证

```java
// ✓ 安全: 参数内容安全检查
public ScheduleRunnable(String beanName, String methodName, String params) {
    // 参数安全检查
    if (StringUtils.isNotEmpty(params) && !isSafeParams(params)) {
        throw new SecurityException("Unsafe parameters detected");
    }

    this.target = SpringContextUtil.getBean(beanName);
    this.params = params;

    if (StringUtils.isNotEmpty(params)) {
        this.method = target.getClass().getDeclaredMethod(methodName, String.class);
    } else {
        this.method = target.getClass().getDeclaredMethod(methodName);
    }
}

private boolean isSafeParams(String params) {
    // 禁止危险字符和路径遍历
    return !params.matches(".*[./\\\\\.\$\{\}].*");
}
```

### 修复方案3: 业务逻辑权限增强

```java
// ✓ 安全: 业务逻辑权限验证
@RequiresPermissions("monitor:job:add")
@PostMapping("/monitor/job/add")
public AjaxResult addSave(SysJob job) {
    // 业务逻辑权限验证
    if (!hasJobCreationPermission(job)) {
        return error("No permission to create this job");
    }

    // 参数安全验证
    if (!isValidJobConfiguration(job)) {
        return error("Invalid job configuration");
    }

    return toAjax(jobService.insertJobCron(job));
}

private boolean hasJobCreationPermission(SysJob job) {
    // 细粒度权限控制
    return SecurityUtils.getSubject().isPermitted("job:create:" + job.getJobGroup());
}
```

## 📊 风险评级矩阵

| 风险类型 | 严重性 | 利用难度 | 检测难度 | 修复优先级 |
|----------|--------|----------|----------|------------|
| 定时任务反射执行 | 🔴 高危 | 低 | 中 | 立即修复 |
| 方法调用白名单缺失 | 🔴 高危 | 低 | 中 | 立即修复 |
| 参数验证缺失 | 🔴 高危 | 低 | 中 | 立即修复 |
| 权限控制不足 | 🟡 中危 | 中 | 低 | 计划修复 |

## ⚠️ 安全最佳实践

1. **方法白名单**: 建立严格的方法调用白名单机制
2. **参数验证**: 对所有用户输入进行严格的内容验证
3. **权限控制**: 实现细粒度的业务逻辑权限控制
4. **日志审计**: 记录所有定时任务的创建和执行操作
5. **资源限制**: 限制定时任务的执行频率和资源使用

## 🎯 检测优先级

### 高危检测项（立即执行）
- [ ] 定时任务反射执行漏洞检测
- [ ] 方法调用白名单验证缺失
- [ ] 参数内容安全验证缺失

### 中危检测项（计划执行）
- [ ] 定时任务权限控制不足
- [ ] 业务逻辑权限验证缺失
- [ ] 执行日志记录不完整

通过本模块的检测规则，能够有效识别定时任务调度系统中的安全风险，特别是反射执行相关的严重漏洞。