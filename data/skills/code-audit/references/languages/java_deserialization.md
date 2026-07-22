# Java 反序列化安全

> Java 反序列化漏洞全面指南
> 相关模块: `java_gadget_chains.md` (107+ Gadget链) | `java_fastjson.md` (Fastjson专项)

---

## 反序列化入口点

### 原生 Java 序列化

```bash
# 检测 ObjectInputStream 使用
grep -rn "ObjectInputStream\|readObject\|readUnshared" --include="*.java"
grep -rn "\.readObject()" --include="*.java"
```

```java
// 危险模式
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // 🔴 反序列化任意对象
```

### JSON 反序列化

| 库 | 危险配置 | 安全配置 |
|-----|----------|----------|
| **Fastjson** | `@type` + AutoType | safeMode=true |
| **Jackson** | enableDefaultTyping | 禁用多态 |
| **Gson** | 默认安全 | - |

> 📖 详见: `java_fastjson.md`

### XML 反序列化

| 库 | 风险 |
|-----|------|
| XStream | 默认反序列化任意类 |
| XMLDecoder | 完全不安全 |
| JAXB | 相对安全 |

```bash
# 检测 XML 反序列化
grep -rn "XStream\|XMLDecoder\|fromXML" --include="*.java"
```

---

## 危险库检测

```bash
# 检查高危依赖版本
grep -rn "commons-collections.*3\\.[0-2]" pom.xml
grep -rn "commons-beanutils.*1\\.[0-8]" pom.xml
grep -rn "fastjson.*1\\.2\\.[0-6]" pom.xml
grep -rn "xstream.*1\\.[0-3]" pom.xml
```

---

## 常用 Gadget 链

| 链名称 | 依赖 | 触发条件 |
|--------|------|----------|
| CommonsCollections1-7 | commons-collections 3.x | readObject |
| CommonsBeanutils | commons-beanutils | readObject |
| Spring1/2 | spring-core | readObject |
| JDK7u21 | JDK 7u21- | readObject |
| Fastjson | fastjson | JSON.parse |
| C3P0 | c3p0 | 多种入口 |

> 📖 完整 107+ Gadget 链: `java_gadget_chains.md`

---

## 检测策略

### 1. 入口点搜索

```bash
# 所有反序列化入口
grep -rn "readObject\|fromXML\|JSON\.parse\|XMLDecoder" --include="*.java"

# 网络入口
grep -rn "ObjectInputStream.*getInputStream\|Socket.*readObject" --include="*.java"

# 文件入口
grep -rn "FileInputStream.*ObjectInputStream\|deserialize.*File" --include="*.java"
```

### 2. 依赖版本分析

```bash
# Maven
mvn dependency:tree | grep -i "commons-collections\|beanutils\|fastjson"

# Gradle
gradle dependencies | grep -i "commons-collections\|beanutils\|fastjson"
```

### 3. 污点追踪

```
Source: 用户输入 (HTTP参数、文件上传、消息队列)
    ↓
Propagation: 数据传递
    ↓
Sink: readObject() / JSON.parse() / fromXML()
```

---

## 防护措施

### 1. 输入验证

```java
// 使用 ObjectInputFilter (Java 9+)
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "java.base/*;!*"  // 只允许 java.base 包
);
ois.setObjectInputFilter(filter);
```

### 2. 禁用危险功能

```java
// Fastjson: 开启安全模式
ParserConfig.getGlobalInstance().setSafeMode(true);

// Jackson: 禁用多态反序列化
objectMapper.disableDefaultTyping();

// XStream: 设置白名单
xstream.allowTypes(new Class[] { SafeClass.class });
```

### 3. 升级依赖

```xml
<!-- 升级到安全版本 -->
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.2</version> <!-- 修复版本 -->
</dependency>
```

---

## 审计检查清单

```
[ ] 搜索所有 readObject / readUnshared 调用
[ ] 检查 Fastjson/Jackson/XStream 使用
[ ] 验证依赖版本是否包含已知漏洞
[ ] 追踪反序列化数据来源
[ ] 检查是否有输入过滤/白名单
[ ] 验证网络入口的数据校验
```

---

## 相关模块导航

| 场景 | 推荐模块 |
|------|----------|
| Gadget 链详解 | `java_gadget_chains.md` |
| Fastjson 专项 | `java_fastjson.md` |
| JNDI 注入 | `java_jndi_injection.md` |
| 实战案例 | `java_practical.md` |
| 真实漏洞 | `cases/real_world_vulns.md` |
