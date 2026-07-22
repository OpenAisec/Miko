# Fastjson 安全审计

> Fastjson 全版本漏洞分析与检测
> 相关模块: `java_gadget_chains.md` (Gadget链) | `java_practical.md` (实战检测)

---

## 版本风险矩阵

| 版本范围 | 风险等级 | 主要漏洞 |
|----------|----------|----------|
| < 1.2.25 | 🔴 Critical | 无限制反序列化 RCE |
| 1.2.25-1.2.41 | 🔴 Critical | AutoType 绕过 |
| 1.2.42-1.2.47 | 🔴 Critical | 缓存绕过、哈希碰撞 |
| 1.2.48-1.2.67 | 🟠 High | 特定 Gadget 利用 |
| 1.2.68-1.2.82 | 🟡 Medium | expectClass 绕过 |
| >= 1.2.83 / 2.x | 🟢 Safe* | 需开启 safeMode |

---

## 快速检测

```bash
# 依赖版本检查
grep -rn "fastjson.*<version>" pom.xml build.gradle
grep -rn "fastjson.*1\\.2\\.[0-7]" pom.xml  # 高危版本

# 危险调用检测
grep -rn "JSON\.parse\|JSON\.parseObject" --include="*.java"
grep -rn "@type" --include="*.java" --include="*.json"
grep -rn "ParserConfig.*setAutoTypeSupport" --include="*.java"
```

---

## 漏洞原理

### AutoType 机制

```java
// 危险: @type 指定任意类
String json = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",...}";
JSON.parseObject(json);  // 反序列化任意类 → RCE
```

### 常见 Gadget

| Gadget | 利用方式 | 适用版本 |
|--------|----------|----------|
| JdbcRowSetImpl | JNDI注入 | < 1.2.25 |
| TemplatesImpl | 字节码执行 | < 1.2.48 |
| BasicDataSource | JNDI/BCEL | 多版本绕过 |
| C3P0 | JNDI | 配合 C3P0 依赖 |

> 📖 完整 Gadget 链: `references/languages/java_gadget_chains.md#fastjson-系列`

---

## 版本绕过技巧

### 1.2.25-1.2.41 绕过

```json
// L 前缀绕过
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://..."}

// [ 前缀绕过
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{...}]}
```

### 1.2.42-1.2.47 缓存绕过

```json
// 双写绕过
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;"}

// 哈希碰撞
{"@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory"}
```

### 1.2.68+ expectClass 绕过

```json
// AutoCloseable 子类
{"@type":"java.lang.AutoCloseable","@type":"...实际恶意类..."}
```

---

## 安全配置

```java
// ✅ 推荐: 开启 safeMode (1.2.68+)
ParserConfig.getGlobalInstance().setSafeMode(true);

// ✅ 推荐: 升级到 2.x 并开启安全模式
// Fastjson2 默认更安全，但仍需配置

// ❌ 危险: 开启 AutoType
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);

// ❌ 危险: 添加白名单但不完整
ParserConfig.getGlobalInstance().addAccept("com.myapp.");
```

---

## 审计检查清单

```
[ ] 检查 Fastjson 版本 (pom.xml / build.gradle)
[ ] 搜索 JSON.parse / JSON.parseObject 调用
[ ] 检查 AutoType 是否开启
[ ] 检查 safeMode 是否开启
[ ] 验证白名单配置是否完整
[ ] 追踪 JSON 解析的数据来源 (用户可控?)
```

---

## 修复建议

1. **升级版本**: >= 1.2.83 或迁移到 Fastjson2
2. **开启 safeMode**: `ParserConfig.getGlobalInstance().setSafeMode(true)`
3. **禁用 AutoType**: 确保 `setAutoTypeSupport(false)`
4. **输入验证**: 对外部 JSON 进行 schema 校验
5. **考虑替代方案**: Jackson (配置正确时更安全)

---

## 相关模块

- `java_gadget_chains.md` - Fastjson Gadget 链详解
- `java_practical.md` - 实战检测规则和案例
- `java_jndi_injection.md` - JNDI 注入原理
