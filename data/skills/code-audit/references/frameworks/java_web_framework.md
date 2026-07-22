# Java Web框架安全检测模块

> 基于Spring MVC、Shiro等框架的安全特性分析
> 针对框架特性的安全风险检测

## 🔍 Spring MVC安全检测

### 参数绑定风险检测

#### 风险模式1: @PathVariable直接用于敏感操作
```java
// ❌ 高危: PathVariable直接用于数据库查询
@GetMapping("/genCode/{tableName}")
public void genCode(HttpServletResponse response, @PathVariable("tableName") String tableName) {
    byte[] data = genService.generatorCode(tableName);  // ❌ 直接使用
    // ...
}

// 检测正则
- "@PathVariable.*String.*tableName"
- "@PathVariable.*String.*fileName"
- "@PathVariable.*String.*resource"
```

#### 风险模式2: 自动参数绑定风险
```java
// ❌ 中危: 自动参数绑定用于文件操作
@RequestMapping("common/download")
public void fileDownload(String fileName, Boolean delete, HttpServletResponse response) {
    String filePath = Global.getDownloadPath() + fileName;  // ❌ 路径拼接
    FileUtils.writeBytes(filePath, response.getOutputStream());
}

// 检测正则
- "public.*\(String.*fileName"
- "public.*\(String.*path"
- "public.*\(String.*resource"
```

### 响应处理风险检测

#### 风险模式3: 响应头注入
```java
// ❌ 中危: 用户输入用于响应头
public String setFileDownloadHeader(HttpServletRequest request, String fileName) {
    // ...
    response.setHeader("Content-Disposition", "attachment;fileName=" + fileName);
}

// 检测正则
- "setHeader.*\+.*fileName"
- "addHeader.*\+.*userInput"
```

## 🔍 Shiro安全检测

### 权限配置风险检测

#### 风险模式4: 匿名访问配置不当
```java
// ❌ 高危: 敏感接口配置为匿名访问
filterChainDefinitionMap.put("/common/download", "anon");  // ❌ 文件下载应认证

// 检测正则
- "filterChainDefinitionMap\.put.*download.*anon"
- "filterChainDefinitionMap\.put.*upload.*anon"
```

#### 风险模式5: Remember Me配置风险
```java
// ❌ 中危: 硬编码加密密钥
cookieRememberMeManager.setCipherKey(Base64.decode("fCq+/xW488hMTCD+cmJ3aQ=="));

// 检测正则
- "setCipherKey.*Base64\.decode"
- "rememberMe.*硬编码"
```

## 🔍 MyBatis安全检测

### SQL注入风险检测

#### 风险模式6: 数据范围过滤注入
```xml
<!-- ❌ 高危: ${params.dataScope} 直接拼接 -->
<select id="selectUserList" parameterType="SysUser" resultMap="SysUserResult">
    select * from sys_user where del_flag = '0'
    ${params.dataScope}  <!-- ❌ SQL注入风险 -->
</select>

// 检测正则
- "\\$\\{params\\.dataScope\\}"
- "\\$\\{.*dataScope.*\\}"
```

#### 风险模式7: 动态SQL拼接风险
```xml
<!-- ❌ 中危: 动态字段名拼接 -->
<select id="orderBy" resultType="User">
    SELECT * FROM users ORDER BY ${field} ${sort}  <!-- ❌ 动态排序风险 -->
</select>

// 检测正则
- "ORDER BY\\s*\\$\\{"
- "GROUP BY\\s*\\$\\{"
```

## 🛡️ 安全修复方案

### Spring MVC安全修复

#### 修复方案1: 参数白名单验证
```java
// ✓ 安全: PathVariable白名单验证
@GetMapping("/genCode/{tableName}")
public void genCode(HttpServletResponse response, @PathVariable("tableName") String tableName) {
    if (!isValidTableName(tableName)) {
        throw new SecurityException("Invalid table name");
    }
    byte[] data = genService.generatorCode(tableName);
}

private boolean isValidTableName(String name) {
    return name.matches("[a-zA-Z0-9_]+");  // ✓ 白名单验证
}
```

#### 修复方案2: 路径规范化
```java
// ✓ 安全: 路径规范化处理
@RequestMapping("common/download")
public void fileDownload(String fileName, Boolean delete, HttpServletResponse response) {
    // 路径规范化
    Path basePath = Paths.get(Global.getDownloadPath()).normalize();
    Path filePath = basePath.resolve(fileName).normalize();

    // 安全检查
    if (!filePath.startsWith(basePath)) {
        throw new SecurityException("Invalid file path");
    }

    FileUtils.writeBytes(filePath.toString(), response.getOutputStream());
}
```

### MyBatis安全修复

#### 修复方案3: 参数化数据范围
```xml
<!-- ✓ 安全: 使用#{param}替代${param} -->
<select id="selectUserList" parameterType="SysUser" resultMap="SysUserResult">
    select * from sys_user where del_flag = '0'
    AND #{params.dataScope}  <!-- ✓ 参数化查询 -->
</select>
```

#### 修复方案4: 业务逻辑层过滤
```java
// ✓ 安全: 在业务逻辑层处理数据范围
@DataScope(tableAlias = "u")
public List<SysUser> selectUserList(SysUser user) {
    // 在AOP切面中安全构造数据范围条件
    return userMapper.selectUserList(user);
}
```

## 🔧 检测命令集

### Spring MVC检测命令
```bash
# 1. 扫描所有控制器方法
grep -rn "@.*Mapping" --include="*.java" | head -20

# 2. 检查PathVariables
grep -rn "@PathVariable" --include="*.java" -A 2

# 3. 检查文件下载接口
grep -rn "download\|Download" --include="*.java" | grep -E "Mapping|RequestMapping"

# 4. 检查响应头设置
grep -rn "setHeader\|addHeader" --include="*.java" | grep -v "安全"
```

### Shiro检测命令
```bash
# 1. 检查Shiro配置
grep -rn "ShiroConfig" --include="*.java" -A 50

# 2. 检查过滤器链配置
grep -rn "filterChainDefinitionMap" --include="*.java" -A 20

# 3. 检查Remember Me配置
grep -rn "rememberMe\|setCipherKey" --include="*.java"
```

### MyBatis检测命令
```bash
# 1. 检查${}使用
grep -rn "\\$\\{" --include="*.xml" | grep -v "pom.xml"

# 2. 检查数据范围注解
grep -rn "@DataScope" --include="*.java" -B 2 -A 2

# 3. 检查动态SQL
grep -rn "ORDER BY.*\\$\|GROUP BY.*\\$" --include="*.xml"
```

## 📊 风险评级矩阵

| 风险类型 | 严重性 | 利用难度 | 检测难度 | 修复优先级 |
|----------|--------|----------|----------|------------|
| @PathVariable注入 | 🔴 高危 | 低 | 中 | 立即修复 |
| 路径遍历下载 | 🔴 高危 | 低 | 中 | 立即修复 |
| 数据范围SQL注入 | 🔴 高危 | 中 | 高 | 立即修复 |
| 响应头注入 | 🟡 中危 | 中 | 中 | 计划修复 |
| Remember Me硬编码 | 🟡 中危 | 高 | 低 | 计划修复 |
| 匿名访问配置 | 🟡 中危 | 低 | 低 | 计划修复 |

## ⚠️ 框架特性注意事项

1. **Spring Boot自动配置**: 注意默认安全配置是否足够
2. **Shiro权限继承**: 检查权限继承关系是否正确
3. **MyBatis插件**: 验证安全插件是否启用
4. **AOP切面顺序**: 检查安全切面的执行顺序

---

## 最小 PoC 示例
```bash
# 路径遍历
curl "http://localhost:8080/common/download?fileName=../../../../etc/passwd"

# 权限绕过 (匿名配置)
curl -I "http://localhost:8080/admin"

# 数据范围 SQL 注入
curl "http://localhost:8080/system/user/list?dataScope=1 or 1=1"
```

通过本模块的检测规则，能够有效识别Java Web框架中的安全风险，特别是框架特性和配置相关的隐蔽漏洞。
