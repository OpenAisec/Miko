# Java 审计参考

## 组件 YAML 正则匹配扫描

需要从依赖、源码、JAR/WAR、`WEB-INF/lib` 或部署目录中发现组件版本风险时，使用内置组件扫描资源。

- 脚本：`skills/audit-skills/scripts/run_component_vulnerability_scan.py`
- 规则：`skills/audit-skills/references/java-vulnerability.yaml`
- 规则机制：YAML 中按严重等级维护组件名和版本正则；脚本解析 Maven/Gradle、JAR/WAR、部署目录和依赖文件后，用这些正则匹配组件版本命中。

先校验 YAML 正则：

```bash
python3 skills/audit-skills/scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --validate-rules
```

扫描默认候选源：

```bash
python3 skills/audit-skills/scripts/run_component_vulnerability_scan.py --workspace <审计工作目录>
```

指定一个或多个扫描源：

```bash
python3 skills/audit-skills/scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --source <源码目录|依赖目录|目标.jar|目标.war|WEB-INF/lib>
python3 skills/audit-skills/scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --source <源1> --source <源2>
```

使用自定义规则文件：

```bash
python3 skills/audit-skills/scripts/run_component_vulnerability_scan.py --workspace <审计工作目录> --rules <自定义java-vulnerability.yaml>
```

组件命中只能作为线索；不能仅凭组件名、版本或 CVE 命中确认漏洞，必须继续证明入口、可控参数、传播链、可利用性、安全 Payload 和 BurpSuite 请求包。

## CFR 反编译

默认使用 CFR 0.152。

- 下载地址：`https://xget.xi-xu.me/gh/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar`
- 使用策略：有源码时优先审源码；只有 JAR/WAR/class 或缺失关键代码时再反编译。

下载命令：

```bash
mkdir -p <工具目录>
curl -L -o <工具目录>/cfr-0.152.jar https://xget.xi-xu.me/gh/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar
```

基础用法：

```bash
java -jar <工具目录>/cfr-0.152.jar <目标.jar|目标.class> --outputdir <反编译目录>/<目标名>
```

WAR 包用法：

```bash
java -jar <工具目录>/cfr-0.152.jar <目标.war> --analyseas WAR --outputdir <反编译目录>/<目标名>
```

聚焦包名或类名：

```bash
java -jar <工具目录>/cfr-0.152.jar <目标.jar> --jarfilter '<包名或类名正则>' --outputdir <反编译目录>/<目标名>
```

反编译失败、部分成功或跳过都必须记录到 manifest。
