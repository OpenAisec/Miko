# 文件上传模块安全审计报告

审计文件：
- Controller/UploadController.php
- Service/FileService.php

## 发现的问题

### 1. 路径穿越 (FileService.php:47-56)

`saveExport()` 中 `$filename` 直接拼接到路径中，未做 `basename()` 过滤。攻击者可传入 `../../config/database.php` 覆写任意文件。

修复：使用 `basename($filename)` 剥离路径。

### 2. 文件上传绕过 (FileService.php:16-32)

`uploadAvatar()` 中校验存在多个缺陷：
- MIME 类型仅检查 `$file['type']`（客户端可控，可伪造）
- 扩展名仅检查原始文件名，不检查文件内容
- 文件名可预测

修复：使用 `finfo` 检测真实 MIME 类型，文件名加随机前缀。

### 3. 目录创建 (FileService.php:52)

`mkdir($dir, 0755, true)` 递归创建目录，可能被路径穿越利用。

## 总结

共发现 2 个主要问题：1 个高危（路径穿越），1 个中危（上传绕过）。
