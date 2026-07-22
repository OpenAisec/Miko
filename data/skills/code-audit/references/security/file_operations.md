# 文件操作安全检测模块

> 文件下载、上传、路径遍历等操作的安全检测
> 基于RuoYi系统审计经验的安全规则

## 🔍 文件下载安全检测（新增定时任务案例）

### 风险模式1: 定时任务间接文件写入（高危）

#### 漏洞代码示例
```java
// ❌ 高危: 通过定时任务间接写入文件
@PostMapping("/monitor/job/add")
public AjaxResult addSave(SysJob job) {
    // 攻击者可以创建定时任务执行任意文件操作
    // invokeTarget: "ruoYiConfig.setProfile('/etc/passwd')"
    return toAjax(jobService.insertJobCron(job));
}

// 实际执行
public class ScheduleRunnable implements Runnable {
    public void run() {
        method.invoke(target, params);  // ❌ 任意文件写入
    }
}
```

#### 攻击向量
```json
{
    "jobName": "ruoYiConfig.setProfile",
    "invokeTarget": "ruoYiConfig.setProfile('C://windows/win.ini')",
    "jobGroup": "DEFAULT",
    "cronExpression": "0/10 * * * * ?",
    "status": "1"
}
```

### 检测命令（新增）
```bash
# 定时任务文件操作检测
grep -rn "@.*Mapping.*/monitor/job" --include="*.java" -A 10 | grep -E "invokeTarget|methodName|methodParams"

# 反射执行文件操作检测
grep -rn "method\.invoke" --include="*.java" -B 10 -A 5 | grep -E "setProfile|writeFile|save"

# Spring Bean文件操作检测
grep -rn "SpringContextUtil\.getBean" --include="*.java" -B 5 -A 5 | grep -E "Config|File|Profile"
```

## 最小 PoC 示例
```bash
# 路径遍历下载
curl "https://app.example.com/common/download?fileName=../../../../etc/passwd"

# 上传类型绕过 (仅大小校验)
curl -F "file=@/etc/passwd;type=text/plain" https://app.example.com/upload

# 定时任务文件写/执行
curl -X POST https://app.example.com/monitor/job/add \
  -H "Content-Type: application/json" \
  -d '{"jobName":"pwn","invokeTarget":"ruoYiConfig.setProfile('/"'"'"/etc/passwd'"'"'/)","cronExpression":"0/1 * * * * ?"}'
```

## 🔍 文件下载安全检测

### 风险模式1: 路径遍历下载漏洞（基于RuoYi案例）

#### 漏洞代码示例
```java
// ❌ 高危: CommonController中的路径遍历漏洞
@RequestMapping("common/download")
public void fileDownload(String fileName, Boolean delete, HttpServletResponse response) {
    String realFileName = System.currentTimeMillis() + fileName.substring(fileName.indexOf("_") + 1);
    String filePath = Global.getDownloadPath() + fileName;  // ❌ 直接拼接路径

    response.setHeader("Content-Disposition", "attachment;fileName=" + setFileDownloadHeader(request, realFileName));
    FileUtils.writeBytes(filePath, response.getOutputStream());  // ❌ 任意文件读取
}

// 攻击向量
GET /common/download?fileName=../../../etc/passwd
GET /common/download?fileName=/Windows/system.ini
```

#### 检测正则
```bash
# 1. 文件下载接口检测
grep -rn "@.*Mapping.*download" --include="*.java"

# 2. 路径拼接模式检测（新增规则）
grep -rn "get.*Path\(\)\s*\+\s*" --include="*.java"

# 3. 文件操作检测
grep -rn "FileUtils\.writeBytes\|getOutputStream" --include="*.java"

# 4. 响应头设置检测
grep -rn "setHeader.*fileName" --include="*.java"
```

### 风险模式2: 响应头注入漏洞

#### 漏洞代码示例
```java
// ❌ 中危: 响应头注入风险
public String setFileDownloadHeader(HttpServletRequest request, String fileName) {
    final String agent = request.getHeader("USER-AGENT");
    String filename = fileName;  // ❌ 用户控制文件名

    if (agent.contains("MSIE")) {
        filename = URLEncoder.encode(filename, "utf-8");
    }
    // ... 其他浏览器处理

    return filename;  // ❌ 可能注入CRLF
}

// 攻击向量
GET /common/download?fileName=test.txt%0D%0AHeader-Injection: value
```

## 🛡️ 安全修复方案（基于RuoYi漏洞）

### 修复方案1: 路径规范化与验证

```java
// ✓ 安全: 路径规范化下载接口（RuoYi修复版本）
@RequestMapping("common/download")
public void fileDownloadSafe(String fileName, Boolean delete, HttpServletResponse response) {
    // 1. 路径规范化
    Path basePath = Paths.get(Global.getDownloadPath()).normalize();
    Path filePath = basePath.resolve(fileName).normalize();

    // 2. 安全检查
    if (!filePath.startsWith(basePath)) {
        throw new SecurityException("Invalid file path");
    }

    // 3. 文件类型白名单
    if (!isAllowedFileType(filePath)) {
        throw new SecurityException("File type not allowed");
    }

    // 4. 文件存在性检查
    if (!Files.exists(filePath) || !Files.isRegularFile(filePath)) {
        throw new FileNotFoundException("File not found");
    }

    FileUtils.writeBytes(filePath.toString(), response.getOutputStream());
}

private boolean isAllowedFileType(Path filePath) {
    String extension = getFileExtension(filePath.toString());
    return Arrays.asList("pdf", "txt", "jpg", "png").contains(extension);
}
```

### 修复方案2: 安全的文件名处理

```java
// ✓ 安全: 响应头安全处理（RuoYi修复版本）
public String setFileDownloadHeaderSafe(HttpServletRequest request, String fileName) {
    // 1. 文件名净化
    String safeFileName = sanitizeFileName(fileName);

    // 2. 编码处理
    final String agent = request.getHeader("USER-AGENT");
    String encodedName;

    if (agent.contains("MSIE") || agent.contains("Trident")) {
        encodedName = URLEncoder.encode(safeFileName, "UTF-8")
                .replace("+", "%20");
    } else if (agent.contains("Firefox")) {
        encodedName = "=?UTF-8?B?" +
                Base64.getEncoder().encodeToString(safeFileName.getBytes(StandardCharsets.UTF_8)) + "?=";
    } else {
        encodedName = URLEncoder.encode(safeFileName, "UTF-8");
    }

    return encodedName;
}

private String sanitizeFileName(String fileName) {
    // 移除路径遍历字符
    String sanitized = fileName.replaceAll("[/\\\\:]*\.\.[/\\\\:]*", "");
    // 移除控制字符
    sanitized = sanitized.replaceAll("[\\x00-\\x1F\\x7F]", "");
    return sanitized;
}
```

### 权限控制缺失 (中危)

#### 风险模式
```java
// ❌ 中危：缺少权限控制
@GetMapping("/download/{file}")
public void downloadFile(@PathVariable String file) {
    // 任何登录用户都可访问
}

// ❌ 中危：权限控制不足
@RequiresPermissions("user:view")  // 权限太宽泛
@GetMapping("/download/{file}")
public void downloadFile(@PathVariable String file) {
    // ...
}
```

#### 安全实现
```java
// ✅ 安全：细粒度权限控制
@RequiresPermissions("file:download")  // 具体权限
@GetMapping("/download/{file}")
public void downloadFile(@PathVariable String file) {
    // 业务逻辑权限验证
    if (!hasFileAccessPermission(file)) {
        throw new SecurityException("无文件访问权限");
    }
    // ...
}
```

### 文件上传风险 (高危)

#### 风险模式
```java
// ❌ 高危：类型验证不足
@PostMapping("/upload")
public String upload(MultipartFile file) {
    // 只检查后缀名，可被绕过
    if (!file.getOriginalFilename().endsWith(".jpg")) {
        return "文件类型错误";
    }
    // ...
}

// ❌ 高危：存储路径不安全
String filename = file.getOriginalFilename();
String path = "/uploads/" + filename;  // 路径遍历风险
file.transferTo(new File(path));
```

## 🔧 检测规则

### 一键检测命令

```bash
# 1. 文件下载接口检测
grep -rn "@GetMapping.*download\|@PostMapping.*download" --include="*.java"

# 2. 文件上传接口检测
grep -rn "@PostMapping.*upload\|MultipartFile" --include="*.java"

# 3. 路径拼接风险检测
grep -rn "path.*\\+.*fileName\|getPath().*\\+\|new File(.*\\.\\." --include="*.java"

# 4. 权限控制检查
grep -rn "@RequiresPermissions" --include="*.java" -A 2 | grep -E "download|upload|file"

# 5. 文件操作Sink点检测
grep -rn "new File(.*)\\|FileInputStream\|FileOutputStream\|Paths.get" --include="*.java"
```

### 框架特定检测

#### Spring Boot检测
```bash
# Spring MVC文件操作接口
grep -rn "@GetMapping.*file\|@PostMapping.*file" --include="*.java"

# 路径参数绑定风险
grep -rn "@PathVariable.*String.*file" --include="*.java"

# RequestParam文件参数
grep -rn "@RequestParam.*file" --include="*.java"
```

## 📋 审计清单

### 高危项 (Critical)
- [ ] 文件下载路径遍历防护
- [ ] 文件上传类型和内容验证
- [ ] 路径拼接操作安全性
- [ ] 文件存储路径安全性

### 中危项 (High)
- [ ] 文件操作权限控制完整性
- [ ] 文件名输入验证和转义
- [ ] 文件访问日志记录
- [ ] 文件大小和数量限制

### 配置项 (Medium)
- [ ] 文件存储目录权限配置
- [ ] 临时文件清理机制
- [ ] 文件访问速率限制
- [ ] 敏感文件访问控制

## 🛡️ 修复建议

### 路径遍历防护
```java
// 增强路径安全检查
public static boolean isSafeFilePath(String fileName, String basePath) {
    // 基本字符检查
    if (fileName == null || fileName.contains("..") ||
        fileName.contains("/") || fileName.contains("\\")) {
        return false;
    }

    // 路径规范化验证
    Path normalizedBase = Paths.get(basePath).normalize();
    Path normalizedFile = Paths.get(basePath, fileName).normalize();

    return normalizedFile.startsWith(normalizedBase);
}
```

### 文件上传安全
```java
// 安全的文件上传处理
@PostMapping("/upload")
@RequiresPermissions("file:upload")
public AjaxResult uploadFile(@Validated MultipartFile file) {
    // 1. 文件类型验证
    if (!isAllowedFileType(file)) {
        return error("文件类型不允许");
    }

    // 2. 文件大小限制
    if (file.getSize() > MAX_FILE_SIZE) {
        return error("文件大小超限");
    }

    // 3. 安全文件名生成
    String safeFileName = generateSafeFileName(file.getOriginalFilename());
    String filePath = getUploadPath() + safeFileName;

    // 4. 安全存储
    file.transferTo(new File(filePath));

    return success("上传成功");
}
```

## 🎯 经验总结与规则更新

### 从RuoYi审计中学到的关键教训（系统性盲区分析）

#### 盲区1: 路径拼接检测规则缺失
**问题**: 传统检测完全忽略`basePath + fileName`这种常见模式
**实例**: `Global.getDownloadPath() + fileName` → 路径遍历漏洞
**根本原因**: 检测规则缺少路径拼接模式的识别能力

#### 盲区2: 框架特性安全风险理解不足
**问题**: 未考虑Spring MVC自动参数绑定的安全风险
**实例**: `fileDownload(String fileName, ...)`自动绑定用户输入
**根本原因**: 对框架工作原理理解不深入

#### 盲区3: 组合攻击检测能力缺失
**问题**: 孤立检测单个漏洞，忽略路径遍历+文件下载组合
**实例**: 路径遍历可导致任意文件下载
**根本原因**: 检测缺乏关联性和上下文感知

#### 盲区4: 业务逻辑深度分析不足
**问题**: 只关注技术漏洞，忽略业务逻辑安全
**实例**: 文件下载接口的业务权限控制
**根本原因**: 缺乏对复杂业务流程的分析能力

### 更新的检测能力

#### 新增检测规则组
1. **路径拼接检测**: `basePath + userInput` → 文件操作
2. **框架特性检测**: Spring MVC参数绑定风险
3. **组合攻击检测**: 路径遍历+文件下载组合
4. **业务逻辑检测**: 文件操作权限控制

#### 增强的检测方法
- **数据流追踪**: 从用户输入到文件操作的完整路径
- **上下文感知**: 结合框架特性和业务场景分析
- **关联分析**: 识别相关漏洞的利用关系

### 持续改进方向
1. **框架知识库建设**: 深入理解主流框架的安全特性
2. **模式识别引擎**: 建立更智能的漏洞模式识别
3. **自动化验证**: 开发漏洞验证的自动化工具
4. **持续学习**: 跟进新的攻击技术和防御方法

通过本次更新，文件操作安全检测能力得到了显著提升，能够更全面地发现Java Web应用中的文件操作安全风险。

## 修复示例
- 路径遍历：`Paths.get(base, userInput).normalize()` 后检查 `startsWith(base)`
- 上传：MIME+魔术数字双重校验，写入随机文件名+隔离目录，禁止覆盖
- 下载：白名单路径/文件，禁止拼接用户输入，添加鉴权/审计
- 定时任务：白名单可调用方法，禁止反射调用任意 bean 方法

## 🔥 文件删除安全检测（v2.5.0 新增 - 基于 litemall 审计经验）

> ⚠️ **审计盲区警示**: 文件删除功能经常被遗漏！大多数审计只关注上传和下载，忽略删除操作。
> 此漏洞在 litemall 项目审计中被遗漏，后通过 CVE 研究才发现 (GitHub #564)。

### 风险模式: 任意文件删除

#### 漏洞代码示例（Java）
```java
// ❌ 高危: 直接使用用户输入删除文件
@PostMapping("/storage/delete")
public Object delete(@RequestBody String key) {
    storageService.delete(key);  // 无路径验证
    return ResponseEntity.ok();
}

// Storage 服务实现
public void delete(String filename) {
    Path file = rootLocation.resolve(filename);  // ❌ 直接拼接
    Files.delete(file);  // ❌ 任意文件删除
}

// 攻击向量
POST /admin/storage/delete
{"key": "../../../etc/important.conf"}
```

#### 漏洞代码示例（Python）
```python
# ❌ 高危: 路径遍历删除
@app.route('/delete', methods=['POST'])
def delete_file():
    filename = request.json.get('filename')
    filepath = os.path.join(UPLOAD_DIR, filename)  # ❌ 直接拼接
    os.remove(filepath)  # ❌ 任意文件删除
    return jsonify({'success': True})
```

#### 漏洞代码示例（Go）
```go
// ❌ 高危: 无路径验证的删除
func DeleteFile(c *gin.Context) {
    filename := c.PostForm("filename")
    filepath := path.Join(uploadDir, filename)  // ❌ 直接拼接
    os.Remove(filepath)  // ❌ 任意文件删除
    c.JSON(200, gin.H{"success": true})
}
```

#### 漏洞代码示例（PHP）
```php
// ❌ 高危: 直接删除用户指定文件
function deleteFile($filename) {
    $filepath = UPLOAD_DIR . '/' . $filename;  // ❌ 直接拼接
    unlink($filepath);  // ❌ 任意文件删除
}
```

#### 漏洞代码示例（Node.js）
```javascript
// ❌ 高危: 路径遍历删除
app.post('/delete', (req, res) => {
    const filename = req.body.filename;
    const filepath = path.join(uploadDir, filename);  // ❌ 直接拼接
    fs.unlinkSync(filepath);  // ❌ 任意文件删除
    res.json({ success: true });
});
```

### 多语言检测命令

```bash
# ========== Java ==========
# 文件删除接口检测
grep -rn "Files\.delete\|FileUtils\.delete\|\.delete()" --include="*.java"

# 删除API端点
grep -rn "@.*Mapping.*delete\|@DeleteMapping" --include="*.java" -A 5

# Storage/File服务删除方法
grep -rn "void\s+delete.*String\s+\(filename\|key\|path\)" --include="*.java"

# ========== Python ==========
# 文件删除操作
grep -rn "os\.remove\|os\.unlink\|shutil\.rmtree\|Path.*unlink" --include="*.py"

# Flask/Django删除端点
grep -rn "@.*route.*delete\|def delete" --include="*.py" -A 5

# ========== Go ==========
# 文件删除操作
grep -rn "os\.Remove\|os\.RemoveAll" --include="*.go"

# Gin/Echo删除端点
grep -rn "DELETE\|\.Delete(" --include="*.go" -A 5

# ========== PHP ==========
# 文件删除函数
grep -rn "unlink\|rmdir\|array_map.*unlink" --include="*.php"

# 删除接口
grep -rn "function\s+delete\|action.*delete" --include="*.php" -A 5

# ========== Node.js ==========
# 文件删除操作
grep -rn "fs\.unlink\|fs\.rm\|fs\.rmSync\|rimraf" --include="*.js" --include="*.ts"

# Express删除路由
grep -rn "\.delete\s*(\|router\.delete" --include="*.js" --include="*.ts" -A 5
```

### 安全修复方案

```java
// ✓ 安全: 路径规范化 + 白名单目录验证
public void deleteSafe(String filename) {
    // 1. 路径规范化
    Path basePath = Paths.get(rootLocation).normalize().toAbsolutePath();
    Path filePath = basePath.resolve(filename).normalize().toAbsolutePath();

    // 2. 检查是否在允许的目录内
    if (!filePath.startsWith(basePath)) {
        throw new SecurityException("Invalid file path: path traversal detected");
    }

    // 3. 检查文件存在性
    if (!Files.exists(filePath)) {
        throw new FileNotFoundException("File not found");
    }

    // 4. 可选: 检查文件类型白名单
    String extension = getFileExtension(filename);
    if (!ALLOWED_DELETE_EXTENSIONS.contains(extension)) {
        throw new SecurityException("File type not allowed for deletion");
    }

    // 5. 审计日志
    auditLog.info("File deleted: {} by user: {}", filePath, getCurrentUser());

    // 6. 执行删除
    Files.delete(filePath);
}
```

---

## 📋 文件 CRUD 完整性检查清单（v2.5.0 新增）

> ⚠️ **核心原则**: 审计文件操作时，必须覆盖 Create/Read/Update/Delete 全部操作，不可只关注上传和下载！

### CRUD 操作对照表

| 操作 | 典型函数 | 常见漏洞 | 检测优先级 |
|------|----------|----------|------------|
| **Create (上传)** | upload, save, write, create | 任意文件上传, 路径遍历写入 | ⭐⭐⭐ 高 |
| **Read (下载)** | download, read, get, fetch | 任意文件读取, 路径遍历 | ⭐⭐⭐ 高 |
| **Update (覆盖)** | update, replace, overwrite | 任意文件覆盖 | ⭐⭐ 中 |
| **Delete (删除)** | delete, remove, unlink | 任意文件删除 | ⭐⭐⭐ 高 (易遗漏!) |

### 多语言 CRUD 检测命令

```bash
# ========== 综合检测（所有语言） ==========
# 文件操作入口点枚举
grep -rn "upload\|download\|delete\|remove\|read\|write\|save" \
  --include="*.java" --include="*.py" --include="*.go" \
  --include="*.php" --include="*.js" --include="*.ts" \
  | grep -i "file\|storage\|attachment"

# ========== Java 完整检测 ==========
# Create
grep -rn "MultipartFile\|transferTo\|Files\.write\|FileOutputStream" --include="*.java"
# Read
grep -rn "FileInputStream\|Files\.read\|FileUtils\.read" --include="*.java"
# Update
grep -rn "Files\.write.*TRUNCATE\|FileWriter\|overwrite" --include="*.java"
# Delete
grep -rn "Files\.delete\|FileUtils\.delete\|\.delete()" --include="*.java"

# ========== Python 完整检测 ==========
# Create
grep -rn "\.save\(\|open.*'w'\|shutil\.copy" --include="*.py"
# Read
grep -rn "open.*'r'\|\.read\(\|Path.*read" --include="*.py"
# Update
grep -rn "open.*'w'\|\.write\(" --include="*.py"
# Delete
grep -rn "os\.remove\|os\.unlink\|shutil\.rmtree\|Path.*unlink" --include="*.py"

# ========== Go 完整检测 ==========
# Create
grep -rn "os\.Create\|ioutil\.WriteFile\|os\.OpenFile" --include="*.go"
# Read
grep -rn "os\.Open\|ioutil\.ReadFile\|os\.ReadFile" --include="*.go"
# Update
grep -rn "os\.OpenFile.*O_WRONLY\|os\.Truncate" --include="*.go"
# Delete
grep -rn "os\.Remove\|os\.RemoveAll" --include="*.go"

# ========== PHP 完整检测 ==========
# Create
grep -rn "move_uploaded_file\|file_put_contents\|fwrite" --include="*.php"
# Read
grep -rn "file_get_contents\|fread\|readfile" --include="*.php"
# Update
grep -rn "file_put_contents\|fwrite" --include="*.php"
# Delete
grep -rn "unlink\|rmdir\|array_map.*unlink" --include="*.php"

# ========== Node.js 完整检测 ==========
# Create
grep -rn "fs\.writeFile\|createWriteStream\|\.pipe(" --include="*.js" --include="*.ts"
# Read
grep -rn "fs\.readFile\|createReadStream" --include="*.js" --include="*.ts"
# Update
grep -rn "fs\.writeFile\|fs\.truncate" --include="*.js" --include="*.ts"
# Delete
grep -rn "fs\.unlink\|fs\.rm\|rimraf" --include="*.js" --include="*.ts"
```

### 审计完成检查矩阵

```markdown
## 文件操作 CRUD 覆盖验证

| 操作类型 | 发现入口点 | 已分析 | 有漏洞 | 安全 | 覆盖率 |
|----------|-----------|--------|--------|------|--------|
| Create (上传) | _ | _ | _ | _ | _% |
| Read (下载) | _ | _ | _ | _ | _% |
| Update (覆盖) | _ | _ | _ | _ | _% |
| Delete (删除) | _ | _ | _ | _ | _% |
| **总计** | _ | _ | _ | _ | _% |

⚠️ 必须达到 100% 覆盖率才算完成文件操作审计！
```

---

## 📚 参考资源

### 安全标准
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-73: External Control of File Name or Path
- **CWE-377: Insecure Temporary File** (文件删除相关)
- **CWE-379: Creation of Temporary File in Directory with Insecure Permissions**

### 工具参考
- Semgrep文件操作规则: https://semgrep.dev/r/java
- CodeQL路径遍历查询: https://codeql.github.com/codeql-query-help/java/

### 真实案例参考
- **litemall GitHub #564**: 任意文件删除漏洞 (LocalStorage.java 路径遍历)
