# MyBatis SQL Injection Security Audit Guide

> MyBatis 框架 SQL 注入专项审计模块
> 适用于: MyBatis 3.x, MyBatis-Plus, Spring Boot + MyBatis 集成
> 来源: DataEase 审计中发现的关键差距 — `${}` 注入检测需系统化覆盖

## 核心原理: `${}` vs `#{}`

```xml
<!-- #{} = PreparedStatement 参数绑定 (安全) -->
<select id="getUser" resultType="User">
    SELECT * FROM users WHERE id = #{id}
</select>
<!-- 生成: SELECT * FROM users WHERE id = ?  ✓ -->

<!-- ${} = 字符串直接替换 (危险) -->
<select id="getUser" resultType="User">
    SELECT * FROM users WHERE id = ${id}
</select>
<!-- 生成: SELECT * FROM users WHERE id = 1 OR 1=1  ❌ -->

<!-- 核心区别:
     #{} → JDBC PreparedStatement, 参数化绑定, 防注入
     ${} → 字符串拼接, 直接替换到SQL中, 可注入
-->
```

---

## `${}` 基础检测

```xml
<!-- 危险: WHERE 条件中使用 ${} -->
<select id="findUser">
    SELECT * FROM users WHERE name = '${name}'      <!-- ❌ Critical -->
</select>

<select id="findById">
    SELECT * FROM users WHERE id = ${id}             <!-- ❌ Critical -->
</select>

<!-- 审计命令: 找出所有XML中的 ${} -->
grep -rn '\$\{' --include="*.xml" src/main/resources/mapper/

<!-- 审计正则: 精准匹配SQL中的 ${} -->
WHERE.*\$\{|AND.*\$\{|OR.*\$\{|HAVING.*\$\{|SET.*\$\{

<!-- 安全修复 -->
<select id="findUser">
    SELECT * FROM users WHERE name = #{name}         <!-- ✓ -->
</select>
```

---

## ORDER BY / LIMIT 注入 (无法使用 #{})

```xml
<!-- 问题: ORDER BY 后不能使用 #{}, 因为会被加引号变成字符串 -->
<!-- #{sort} → ORDER BY 'name' (语法错误) -->
<!-- 因此开发者常用 ${} -->

<!-- 危险: ORDER BY 注入 -->
<select id="listUsers">
    SELECT * FROM users ORDER BY ${sortColumn} ${sortOrder}  <!-- ❌ High -->
</select>
<!-- 攻击: sortColumn = (CASE WHEN (SELECT 1 FROM users WHERE name='admin'
     AND password LIKE 'a%') THEN id ELSE name END) -->

<!-- 危险: LIMIT 注入 -->
<select id="pageUsers">
    SELECT * FROM users LIMIT ${offset}, ${limit}            <!-- ❌ -->
</select>

<!-- 危险: GROUP BY 注入 -->
<select id="stats">
    SELECT count(*) FROM orders GROUP BY ${groupField}       <!-- ❌ -->
</select>

<!-- 审计正则 -->
ORDER\s+BY\s+\$\{|LIMIT\s+\$\{|GROUP\s+BY\s+\$\{|OFFSET\s+\$\{

<!-- 安全修复: Java层白名单验证 -->
```
```java
// ORDER BY 安全处理
private static final Set<String> ALLOWED_COLUMNS = Set.of("id", "name", "created_at");
private static final Set<String> ALLOWED_ORDERS = Set.of("ASC", "DESC");

public List<User> listUsers(String sortColumn, String sortOrder) {
    if (!ALLOWED_COLUMNS.contains(sortColumn)) {
        sortColumn = "id";  // ✓ 默认值
    }
    if (!ALLOWED_ORDERS.contains(sortOrder.toUpperCase())) {
        sortOrder = "ASC";  // ✓
    }
    return mapper.listUsers(sortColumn, sortOrder);
}

// LIMIT 安全处理: 强制类型转换
int offset = Integer.parseInt(offsetStr);  // ✓ 非数字会抛异常
int limit = Math.min(Integer.parseInt(limitStr), 100);  // ✓ 上限
```

---

## 表名 / 列名动态注入

```xml
<!-- 危险: 动态表名 (无法用 #{}) -->
<select id="queryTable">
    SELECT * FROM ${tableName} WHERE id = #{id}              <!-- ❌ Critical -->
</select>

<!-- 危险: 动态列名 -->
<select id="getField">
    SELECT ${columns} FROM users WHERE id = #{id}            <!-- ❌ -->
</select>

<!-- 审计正则 -->
FROM\s+\$\{|INTO\s+\$\{|UPDATE\s+\$\{|JOIN\s+\$\{
SELECT\s+\$\{|INSERT\s+INTO.*\(\s*\$\{

<!-- 安全修复: 白名单 + 正则验证 -->
```
```java
private static final Set<String> ALLOWED_TABLES = Set.of("users", "orders", "products");

public List<Map> queryTable(String tableName) {
    if (!ALLOWED_TABLES.contains(tableName)) {
        throw new IllegalArgumentException("Invalid table name");
    }
    // 额外验证: 只允许字母数字下划线
    if (!tableName.matches("^[a-zA-Z_][a-zA-Z0-9_]*$")) {  // ✓
        throw new IllegalArgumentException("Invalid table name format");
    }
    return mapper.queryTable(tableName);
}
```

---

## `${}` 在条件分支中 (隐藏注入)

```xml
<!-- 危险: <if> 条件中的 ${} — 条件触发时才注入, 审计容易遗漏 -->
<select id="search">
    SELECT * FROM users WHERE 1=1
    <if test="name != null">
        AND name LIKE '%${name}%'                            <!-- ❌ 隐藏在if中 -->
    </if>
    <if test="sortField != null">
        ORDER BY ${sortField}                                <!-- ❌ -->
    </if>
</select>

<!-- 危险: <choose>/<when> 中的 ${} -->
<select id="dynamicQuery">
    SELECT * FROM users
    <choose>
        <when test="searchType == 'name'">
            WHERE name = '${searchValue}'                    <!-- ❌ -->
        </when>
        <when test="searchType == 'email'">
            WHERE email = '${searchValue}'                   <!-- ❌ -->
        </when>
    </choose>
</select>

<!-- 危险: <foreach> 中的 ${} -->
<select id="batchQuery">
    SELECT * FROM ${tableName} WHERE id IN
    <foreach collection="ids" item="id" open="(" separator="," close=")">
        ${id}                                                <!-- ❌ -->
    </foreach>
</select>

<!-- 审计正则: 条件分支中的 ${} -->
<if\s+test=.*>\s*.*\$\{|<when\s+test=.*>\s*.*\$\{
<foreach.*\$\{

<!-- 安全修复: LIKE 查询使用 #{} + CONCAT -->
<if test="name != null">
    AND name LIKE CONCAT('%', #{name}, '%')                  <!-- ✓ -->
</if>
```

---

## MyBatis-Plus Wrapper 注入

```java
// 危险: apply() 拼接SQL片段
QueryWrapper<User> wrapper = new QueryWrapper<>();
wrapper.apply("name = '" + userInput + "'");              // ❌ Critical
wrapper.apply("date_format(create_time,'%Y') = " + year); // ❌

// 危险: last() 追加任意SQL
wrapper.last("LIMIT " + userInput);                       // ❌ Critical
wrapper.last("ORDER BY " + sortField);                    // ❌

// 危险: orderByAsc/orderByDesc 字符串
wrapper.orderByAsc(userInput);                            // ❌ High

// 危险: having() 拼接
wrapper.having("count > " + count);                       // ❌

// 危险: exists/notExists 拼接
wrapper.exists("SELECT 1 FROM admin WHERE id = " + id);  // ❌

// 审计正则
\.apply\s*\(.*\+|\.last\s*\(.*\+|\.having\s*\(.*\+
\.exists\s*\(.*\+|\.orderByAsc\s*\(.*userInput|\.orderByDesc\s*\(.*param

// 安全: apply 使用参数占位
wrapper.apply("name = {0}", userInput);                   // ✓ MyBatis-Plus参数绑定
wrapper.apply("date_format(create_time,'%Y') = {0}", year); // ✓
wrapper.last("LIMIT 10");                                 // ✓ 硬编码

// 安全: orderBy 白名单
wrapper.orderByAsc(ALLOWED_COLUMNS.contains(col) ? col : "id");  // ✓
```

---

## Provider 动态SQL注入

```java
// 危险: @SelectProvider 中拼接
public class UserSqlProvider {
    public String findUser(String name) {
        return "SELECT * FROM users WHERE name = '" + name + "'";  // ❌ Critical
    }
}

@SelectProvider(type = UserSqlProvider.class, method = "findUser")
User findUser(@Param("name") String name);

// 危险: @UpdateProvider 拼接
public class UpdateProvider {
    public String updateField(Map<String, Object> params) {
        return "UPDATE users SET " + params.get("field") +   // ❌
               " = '" + params.get("value") + "' WHERE id = " + params.get("id");
    }
}

// 审计正则
@SelectProvider|@InsertProvider|@UpdateProvider|@DeleteProvider
return\s*".*SELECT.*\+|return\s*".*UPDATE.*\+|return\s*".*DELETE.*\+

// 安全: 使用 MyBatis SQL Builder
public String findUser(@Param("name") String name) {
    return new SQL() {{
        SELECT("*");
        FROM("users");
        WHERE("name = #{name}");  // ✓ 使用 #{} 占位符
    }}.toString();
}
```

---

## 间接注入 (Java层拼接后传入MyBatis)

```java
// 危险: StringBuilder 拼接后传入
StringBuilder condition = new StringBuilder();
condition.append("name = '").append(userInput).append("'");  // ❌
mapper.queryByCondition(condition.toString());
// XML: SELECT * FROM users WHERE ${condition}

// 危险: String.format 构建条件
String filter = String.format("status = '%s' AND type = '%s'", status, type);  // ❌
mapper.queryWithFilter(filter);

// 危险: 多层调用掩盖注入 (DataEase典型模式)
// Service层
public String buildWhereClause(ChartView view) {
    return "column_name " + view.getFilterOperator() + " '" + view.getFilterValue() + "'";  // ❌
}
// 调用链: Controller → Service.buildWhereClause() → Mapper.query(${whereClause})

// 审计方法: 追踪所有 ${} 参数的数据来源
// 1. 找到XML中的 ${paramName}
// 2. 追踪到Mapper接口方法的参数
// 3. 追踪到Service层如何构建该参数
// 4. 追踪到Controller层参数来源 (是否来自用户输入)

// 审计正则 (Java层)
StringBuilder.*append\s*\(.*\+.*append|String\.format\s*\(.*SELECT|String\.format\s*\(.*WHERE
".*SELECT.*"\s*\+|".*WHERE.*"\s*\+|".*ORDER BY.*"\s*\+
```

---

## 二次注入 (存储→检索→SQL)

```java
// 阶段1: 存储恶意数据 (无注入, 正常INSERT)
// 用户输入 name = "admin' OR '1'='1"
mapper.insertUser(user);  // INSERT INTO users(name) VALUES(#{name}) — 安全存入

// 阶段2: 检索并拼接到SQL (注入触发)
String name = mapper.getUserName(userId);  // 取出: admin' OR '1'='1
// 危险: 将数据库取出的值再拼接到SQL
String sql = "SELECT * FROM orders WHERE customer = '" + name + "'";  // ❌
// 实际SQL: SELECT * FROM orders WHERE customer = 'admin' OR '1'='1'

// 审计策略:
// 1. 搜索所有 ${} 参数
// 2. 如果参数值来自数据库查询结果 (非直接用户输入), 仍然是二次注入
// 3. 特别关注: 配置表、用户自定义字段、数据源名称等

// 审计正则
// 找到从数据库取值后再拼接的模式
get.*\(\).*\+.*".*SELECT|get.*\(\).*\+.*".*WHERE
```

---

## XML Mapper 审计工作流

```bash
# Step 1: 全量扫描 ${} 使用
grep -rn '\$\{' --include="*.xml" src/main/resources/

# Step 2: 分类统计
# WHERE/AND/OR 条件中的 ${} — Critical
grep -rn 'WHERE.*\$\{' --include="*.xml" src/
grep -rn 'AND.*\$\{' --include="*.xml" src/
grep -rn 'OR.*\$\{' --include="*.xml" src/

# ORDER BY/LIMIT/GROUP BY 中的 ${} — High
grep -rn 'ORDER\s*BY.*\$\{' --include="*.xml" src/
grep -rn 'LIMIT.*\$\{' --include="*.xml" src/
grep -rn 'GROUP\s*BY.*\$\{' --include="*.xml" src/

# 表名/列名中的 ${} — High
grep -rn 'FROM\s\+\$\{' --include="*.xml" src/
grep -rn 'SELECT\s\+\$\{' --include="*.xml" src/

# LIKE 中的 ${} — High
grep -rn "LIKE.*\$\{" --include="*.xml" src/

# <if>/<when>/<foreach> 中隐藏的 ${} — Medium-High
grep -rn '<if.*>.*\$\{' --include="*.xml" src/
grep -rn '<when.*>.*\$\{' --include="*.xml" src/
grep -rn '<foreach.*\$\{' --include="*.xml" src/

# Step 3: Java层拼接检测
grep -rn 'String\.format.*SELECT\|String\.format.*WHERE' --include="*.java" src/
grep -rn '"SELECT.*"\s*+\|"WHERE.*"\s*+\|"ORDER.*"\s*+' --include="*.java" src/

# Step 4: MyBatis-Plus Wrapper
grep -rn '\.apply\s*(.*+\|\.last\s*(.*+' --include="*.java" src/

# Step 5: Provider 拼接
grep -rn '@SelectProvider\|@UpdateProvider' --include="*.java" src/
```

---

## 搜索模式汇总

```regex
# XML ${} 全量
\$\{[^}]+\}

# WHERE条件注入
(WHERE|AND|OR|HAVING|SET)\s.*\$\{

# ORDER/LIMIT注入
(ORDER\s+BY|GROUP\s+BY|LIMIT|OFFSET)\s+\$\{

# 表名/列名注入
(FROM|INTO|UPDATE|JOIN|SELECT)\s+\$\{

# LIKE注入
LIKE\s+['"]?%?\$\{

# 条件分支隐藏
<if\s+test=.*\$\{|<when\s+test=.*\$\{|<foreach.*\$\{

# MyBatis-Plus
\.apply\s*\(.*\+|\.last\s*\(.*\+|\.having\s*\(.*\+|\.exists\s*\(.*\+

# Provider
@(Select|Insert|Update|Delete)Provider

# Java层拼接
String\.format\s*\(.*"(SELECT|WHERE|ORDER|INSERT|UPDATE|DELETE)
"(SELECT|WHERE|ORDER|INSERT|UPDATE|DELETE).*"\s*\+
StringBuilder.*append.*"(SELECT|WHERE|ORDER)"
```

---

## 快速审计检查清单

```markdown
[ ] 全量扫描 XML 中所有 ${} 使用位置
[ ] 分类: WHERE条件 / ORDER BY / 表名列名 / LIKE / LIMIT
[ ] 检查 <if>/<when>/<foreach> 内隐藏的 ${}
[ ] 追踪每个 ${} 参数的数据来源 (用户输入 → Service → Mapper)
[ ] 搜索 MyBatis-Plus apply()/last()/having() 拼接
[ ] 搜索 @SelectProvider/@UpdateProvider 中的字符串拼接
[ ] 搜索 Java 层 StringBuilder/String.format 构建SQL片段
[ ] 检查二次注入: 数据库取值后再拼接到SQL
[ ] 验证 ORDER BY / 表名列名 是否有白名单
[ ] 验证 LIKE 是否使用 CONCAT('%', #{}, '%') 模式
[ ] 检查批量操作 foreach 中的参数绑定
```

---

## DataEase 审计经验补充

```markdown
关键发现模式:
1. 数据源管理: tableName/schemaName 通过 ${} 拼入SQL → 表名注入
2. 图表查询: 用户自定义字段/过滤条件通过多层Service拼接 → 间接注入
3. 排序字段: 前端传入排序列名直接用 ${} → ORDER BY 注入
4. 权限过滤: 动态拼接WHERE子句作为字符串传入 → 条件注入

审计难点:
- 调用链长 (Controller → Service → Provider → Mapper), 需完整追踪
- 条件分支中隐藏, 只在特定条件触发
- 白名单验证在Service层但不完整 (遗漏部分参数)
- 二次注入: 数据源配置存储后用于动态SQL构建
```

---

## 参考资源

- [MyBatis Official: SQL Injection Prevention](https://mybatis.org/mybatis-3/sqlmap-xml.html)
- [MyBatis-Plus Security](https://baomidou.com/pages/10c804/)
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
