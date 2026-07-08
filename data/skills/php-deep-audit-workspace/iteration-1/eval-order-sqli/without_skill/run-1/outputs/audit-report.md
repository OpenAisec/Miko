# 订单模块安全审计报告

## 文件概览

审计了以下文件：
- `Controller/OrderController.php` — 两个接口：`detail()` 和 `search()`
- `Service/OrderService.php` — 透传层，调用 Repository
- `Repository/OrderRepository.php` — 数据库操作层

## 发现的问题

### 问题1：SQL注入 — order_id 参数

**位置：** `OrderController.php:32` → `OrderRepository.php:21`

`$_GET['order_id']` 在经过 Controller 和 Service 两层传递后，在 `OrderRepository::findByIdAndUser()` 中直接拼接到 SQL：

```php
$sql = "SELECT * FROM orders WHERE id = {$orderId} AND user_id = {$userId}";
```

修复：使用 `(int)$_GET['order_id']` 或预处理语句。

### 问题2：ORDER BY 注入 — sort 参数

**位置：** `OrderController.php:63` → `OrderRepository.php:42`

`$_GET['sort']` 被直接拼接到 ORDER BY 子句：

```php
$sql .= " ORDER BY {$sortField} DESC";
```

修复：使用字段名白名单。

### 问题3：keyword 参数的 LIKE 通配符未转义

`$_GET['keyword']` 虽然经过了 `real_escape_string()` 转义，但 LIKE 的 `%` 和 `_` 未被处理。风险较低。

## 总结

共发现 2 个高危漏洞（SQL 注入 + ORDER BY 注入），1 个低风险问题。
