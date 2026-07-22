# 依赖包安全检测模块

> 第三方依赖包安全检测模块
> 针对已知CVE漏洞、版本安全、依赖配置风险

## 🔍 风险模式库

### 风险模式1: 已知CVE漏洞依赖（高危）

#### 漏洞代码示例
```xml
<!-- ❌ 高危: 存在已知CVE漏洞的依赖版本 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>  <!-- CVE-2021-44228 -->
</dependency>

<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.24</version>  <!-- 多个RCE漏洞 -->
</dependency>

<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-core</artifactId>
    <version>4.3.0.RELEASE</version>  <!-- 已知安全漏洞 -->
</dependency>
```

### 风险模式2: 过时依赖版本（中危）

#### 漏洞代码示例
```xml
<!-- ❌ 中危: 使用过时的依赖版本 -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <version>2.0.5.RELEASE</version>  <!-- 多个已知漏洞 -->
</dependency>

<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.4.0</version>  <!-- 存在安全漏洞 -->
</dependency>
```

### 风险模式4: 多语言依赖安全检测（新增）

#### Node.js依赖漏洞示例
```json
// ❌ 高危: Node.js已知漏洞依赖
{
  "dependencies": {
    "lodash": "4.17.15",  // 多个原型污染漏洞
    "hoek": "4.0.0",      // 已知安全漏洞
    "minimist": "0.0.8"   // 原型污染漏洞
  }
}
```

#### Python依赖漏洞示例
```txt
# ❌ 高危: Python已知漏洞依赖
Django==2.0.0              # 多个安全漏洞
requests==2.18.0           # 已知安全漏洞
urllib3==1.21.0            # 安全漏洞
```

#### Go依赖漏洞示例
```go
// ❌ 高危: Go已知漏洞依赖
require (
    github.com/gin-gonic/gin v1.4.0  // 存在安全漏洞
    golang.org/x/text v0.3.0         // CVE-2022-32149
)
```

#### 漏洞代码示例
```xml
<!-- ❌ 中危: 不安全的依赖配置 -->
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.13.0</version>
    <!-- 缺少安全配置: enableDefaultTyping可能导致反序列化漏洞 -->
</dependency>
```

## 🔧 检测命令集

### 依赖配置文件检测
```bash
# 1. 检测Java项目依赖配置
find . -name "pom.xml" -o -name "build.gradle" -o -name "build.gradle.kts" | head -10

# 2. 检测Node.js项目依赖配置
find . -name "package.json" | head -10

# 3. 检测Python项目依赖配置
find . -name "requirements.txt" -o -name "pyproject.toml" -o -name "setup.py" | head -10

# 4. 检测Go项目依赖配置
find . -name "go.mod" -o -name "go.sum" | head -10
```

### 已知CVE漏洞检测
```bash
# 1. 检测Log4j2漏洞版本
grep -rn "log4j-core" --include="pom.xml" --include="build.gradle" | grep -E "2\.(0|1[0-6])\."

# 2. 检测Fastjson漏洞版本
grep -rn "fastjson" --include="pom.xml" --include="build.gradle" | grep -E "1\.2\.([0-9]|[1-6][0-9]|7[0-9]|8[0-2])"

# 3. 检测Spring已知漏洞版本
grep -rn "spring-core" --include="pom.xml" --include="build.gradle" | grep -E "4\.([0-2]\.[0-9]|3\.[0-9]\.[0-9]*[^1][0-9]*)"

# 4. 检测Shiro已知漏洞版本
grep -rn "shiro-core" --include="pom.xml" --include="build.gradle" | grep -E "1\.([0-3]\.[0-9]|4\.[0-2])"
```

### 依赖版本安全分析
```bash
# 1. 提取所有依赖版本信息
grep -E "<version>|<implementation|api" pom.xml build.gradle 2>/dev/null | head -20

# 2. 检测过时的Spring Boot版本
grep -rn "spring-boot" --include="pom.xml" --include="build.gradle" | grep -E "2\.([0-4]\.[0-9])"

# 3. 检测不安全的Jackson配置
grep -rn "enableDefaultTyping" --include="*.java" --include="*.yml" --include="*.properties"

# 4. 检测XML解析器安全配置
grep -rn "disallow-doctype-decl\|external-general-entities" --include="*.java" --include="*.xml"
```

### 依赖树分析
```bash
# 1. 分析Maven依赖树（如果Maven可用）
if command -v mvn &> /dev/null; then
    mvn dependency:tree 2>/dev/null | grep -E "(log4j|fastjson|shiro|spring)" | head -10
fi

# 2. 分析Gradle依赖（如果Gradle可用）
if command -v gradle &> /dev/null; then
    gradle dependencies 2>/dev/null | grep -E "(log4j|fastjson|shiro|spring)" | head -10
fi
```

## 🛡️ 安全修复方案

### 修复方案1: 升级漏洞依赖版本
```xml
<!-- ✓ 安全: 升级到安全版本 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>  <!-- 安全版本 -->
</dependency>

<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.83</version>  <!-- 安全版本 -->
</dependency>
```

### 修复方案2: 添加安全配置
```java
// ✓ 安全: Jackson安全配置
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // 避免使用，或使用安全的白名单模式

// 使用白名单模式
mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance,
    ObjectMapper.DefaultTyping.NON_FINAL, JsonTypeInfo.As.WRAPPER_ARRAY);
```

### 修复方案3: 依赖漏洞扫描集成
```bash
# 集成OWASP Dependency Check
mvn org.owasp:dependency-check-maven:check

# 或使用snyk检测
snyk test

# 或使用trivy检测
trivy fs .
```

## 📊 风险评级矩阵

| 风险类型 | 严重性 | 利用难度 | 检测难度 | 修复优先级 |
|----------|--------|----------|----------|------------|
| 已知CVE漏洞 | 🔴 高危 | 低 | 低 | 立即修复 |
| 过时依赖版本 | 🟡 中危 | 中 | 低 | 计划修复 |
| 不安全配置 | 🟡 中危 | 中 | 中 | 计划修复 |

## ⚠️ 高风险依赖速查表

### Java高危依赖
| 依赖 | 危险版本 | CVE编号 | 风险描述 |
|------|----------|---------|----------|
| log4j-core | < 2.17.0 | CVE-2021-44228 | JNDI注入RCE |
| fastjson | < 1.2.83 | 多个CVE | 反序列化RCE |
| shiro | < 1.9.0 | CVE-2020-1957 | 权限绕过 |
| spring-core | < 5.3.0 | 多个CVE | 多个安全漏洞 |
| jackson-databind | 特定版本 | 多个CVE | 反序列化漏洞 |

### 配置安全要点
1. **禁用危险特性**: 避免enableDefaultTyping等危险配置
2. **及时更新**: 定期更新依赖到最新安全版本
3. **安全扫描**: 集成自动化依赖安全扫描工具

## 🎯 检测优先级

### 高危检测项（立即执行）
- [ ] Log4j2漏洞版本检测
- [ ] Fastjson漏洞版本检测
- [ ] Spring已知漏洞检测
- [ ] Shiro安全版本检测

### 中危检测项（计划执行）
- [ ] 依赖版本过时检测
- [ ] 不安全配置检测
- [ ] 依赖树安全分析

---

## 最小 PoC / 快速检查
```bash
# Log4j2 漏洞版本
rg -n "log4j-core" --glob "pom.xml" | rg "2\\.(0|1[0-6])\\."

# Fastjson 漏洞版本
rg -n "fastjson" --glob "pom.xml" | rg "1\\.2\\.([0-9]|[1-6][0-9]|7[0-9]|8[0-2])"

# Node postinstall
rg -n "postinstall" package.json

# Python 未 pin
rg -n "==" requirements.txt || echo "检查是否存在无锁版本"
```

---

## 📊 真实案例：若依管理系统依赖漏洞

### 项目背景
**项目**: RuoYi v3.1
**技术栈**: Spring Boot + MyBatis + Shiro + Druid
**审计时间**: 2025-12-28

### 发现的过时依赖

```xml
<!-- pom.xml -->
<properties>
    <ruoyi.version>3.1</ruoyi.version>
    <java.version>1.8</java.version>
    <shiro.version>1.4.0</shiro.version>  <!-- ❌ 2017年版本 -->
    <mybatis.boot.version>1.3.2</mybatis.boot.version>
    <druid.version>1.1.10</druid.version>  <!-- ❌ 2018年版本 -->
</properties>

<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-dependencies</artifactId>
            <version>2.0.5.RELEASE</version>  <!-- ❌ 2018年10月 -->
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

### 已知CVE清单

| 依赖 | 当前版本 | 已知CVE | 严重程度 | 影响 |
|------|---------|---------|---------|------|
| Spring Boot | 2.0.5 | CVE-2018-15758 | High | Session固定攻击 |
| Spring Boot | 2.0.5 | CVE-2018-11040 | Medium | 跨域漏洞 |
| Shiro | 1.4.0 | CVE-2020-1957 | High | 认证绕过 |
| Shiro | 1.4.0 | CVE-2020-11989 | Critical | 权限绕过 |
| Shiro | 1.4.0 | CVE-2020-13933 | High | 认证绕过 |
| Druid | 1.1.10 | SQL Wall绕过 | Medium | SQL注入防护绕过 |
| MyBatis | 1.3.2 | 性能和安全问题 | Low | 稳定性问题 |

### 检测过程

```bash
# 1. 查找依赖配置文件
find /path/to/project -name "pom.xml"

# 2. 提取依赖版本
grep -A 2 "<dependency>" pom.xml | grep -E "version|artifactId"

# 3. 检查Spring Boot版本
grep "spring-boot" pom.xml | grep "version"
# 发现: 2.0.5.RELEASE (2018年10月发布)

# 4. 检查Shiro版本
grep "shiro.version" pom.xml
# 发现: 1.4.0 (存在多个CVE)

# 5. 使用Maven依赖检查工具
mvn dependency-check:check
```

### Shiro认证绕过详细分析

#### CVE-2020-1957 (CVSS 9.8)

```java
// ❌ 漏洞原理: Spring Boot + Shiro组合的路径遍历
// Shiro 1.4.0及以下版本存在路径匹配绕过

// 配置
@Bean
public ShiroFilterFactoryBean shiroFilterFactoryBean() {
    ShiroFilterFactoryBean factoryBean = new ShiroFilterFactoryBean();
    Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
    filterChainDefinitionMap.put("/admin/**", "authc");  // 需要认证
    filterChainDefinitionMap.put("/**", "anon");  // 匿名访问
    return factoryBean;
}

// 攻击向量
// 绕过认证访问 /admin/users
GET /admin/users;.css  // ❌ 绕过认证
GET /admin/users;.js   // ❌ 绕过认证
GET /xxx/..;/admin/users  // ❌ 绕过认证
```

#### CVE-2020-11989 (CVSS 9.8)

```java
// ❌ 漏洞原理: Shiro权限绕过
// 使用URL编码绕过权限检查

// 攻击向量
GET /admin%2Fusers  // %2F = /
GET /admin%3Busers  // %3B = ;
```

### 修复建议

```xml
<!-- ✓ 升级到安全版本 -->
<properties>
    <spring-boot.version>2.7.18</spring-boot.version>  <!-- 2023年11月 -->
    <shiro.version>1.13.0</shiro.version>  <!-- 2023年8月 -->
    <druid.version>1.2.20</druid.version>  <!-- 2023年10月 -->
    <mybatis.boot.version>2.3.2</mybatis.boot.version>
</properties>

<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-dependencies</artifactId>
            <version>2.7.18</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

### 自动化检测集成

```xml
<!-- Maven依赖检查插件 -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>9.0.0</version>
    <configuration>
        <failBuildOnCVSS>7</failBuildOnCVSS>
        <suppressionFiles>
            <suppressionFile>dependency-check-suppressions.xml</suppressionFile>
        </suppressionFiles>
    </configuration>
    <executions>
        <execution>
            <goals>
                <goal>check</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

### 运行检测

```bash
# Maven依赖安全检查
mvn dependency-check:check

# 生成HTML报告
mvn dependency-check:aggregate

# CI/CD集成
mvn clean verify -P dependency-check
```

### 修复基线示例
```json
// package.json: pin 版本并移除 postinstall
"dependencies": {
  "lodash": "4.17.21"
},
"scripts": {
  "postinstall": ""  // 删除危险脚本
}
```

```xml
<!-- Maven: 固定安全版本 -->
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.17.1</version>
</dependency>
```

### 审计总结

1. **依赖过时严重**: 所有核心依赖都是2018年或更早版本
2. **安全风险高**: 存在多个Critical和High级别CVE
3. **升级建议**: 立即升级所有依赖到最新稳定版本
4. **自动化检测**: 集成dependency-check到CI/CD流程

---

通过本模块的检测规则和若依案例，能够有效识别第三方依赖包中的安全风险，特别是已知CVE漏洞和版本安全问题。
