# 认证模块安全审计报告

审计文件：
- Controller/AuthController.php
- Service/AuthService.php

## 发现的问题

### 1. SQL注入 (AuthService.php:20-27)

`authenticate()` 方法中使用 `addslashes()` 对 username 做转义，但数据库连接字符集为 GBK，可能导致宽字节注入。`addslashes()` 在 GBK 编码下不可靠。

修复：使用 PDO 预处理语句。

### 2. 开放重定向 (AuthService.php:39-47)

`buildRedirectUrl()` 检查了 `http://` 和 `https://` 但可以用 `//` 协议相对URL绕过。

修复：只允许相对路径或以 `/` 开头的路径。

### 3. SSO参数拼接 (AuthService.php:57)

`ssoVerify()` 中 token 和 state 直接拼接到 URL，未做 URL 编码。

修复：使用 `urlencode()` 或 `http_build_query()`。

## 总结

发现 3 个安全问题：1 个高危（SQL注入），2 个中危（开放重定向、参数注入）。
