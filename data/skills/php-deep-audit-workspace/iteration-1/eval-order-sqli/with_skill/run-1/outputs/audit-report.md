# PHP 深度安全审计报告 — 订单模块

## 攻击面地图

| 入口 | 路由 | 鉴权 | 用户可控输入 | 对应 Sink |
|------|------|------|-------------|-----------|
| `detail()` | `GET /order/detail?id=123` | 需登录 | `$_GET['order_id']` | `mysqli->query()` |
| `search()` | `GET /order/search?keyword=&sort=` | 需登录 | `$_GET['keyword']`, `$_GET['sort']` | `mysqli->query()` |

**文件分布：** Controller (OrderController.php) → Service (OrderService.php) → Repository (OrderRepository.php)

---

## 漏洞 1：[高危] SQL 注入 — `findByIdAndUser()` 中 `$_GET['order_id']` 无过滤拼接

### 传播链路

```
Source:  $_GET['order_id']                                  ← OrderController.php:32 (路由: GET /order/detail)
  ↓ 直接赋值，无过滤
$orderId = $_GET['order_id'];                               ← OrderController.php:32
  ↓ 作为第二个参数传入
$this->orderService->getOrderDetail($orderId, $userId)      ← OrderController.php:41 (跨文件 → OrderService.php)
  ↓ 方法签名接收，参数保持原值
public function getOrderDetail($orderId, $userId)            ← OrderService.php:18
  ↓ 直接透传，无处理
$this->orderRepo->findByIdAndUser($orderId, $userId)        ← OrderService.php:22 (跨文件 → OrderRepository.php)
  ↓ 方法签名接收
public function findByIdAndUser($orderId, $userId)           ← OrderRepository.php:17
  ↓ 直接拼接到 SQL 字符串（双引号字符串内插值）
$sql = "SELECT * FROM orders WHERE id = {$orderId}
        AND user_id = {$userId}";                            ← OrderRepository.php:21
  ↓
$this->db->query($sql);                                     ← OrderRepository.php:22  [SINK: mysqli::query]
```

### 过滤评估

| 节点 | 操作 | 有效性 |
|------|------|--------|
| OrderController.php:34 | `empty($orderId)` | ❌ 仅检查非空，不是安全过滤 |
| OrderService.php:22 | 透传 | ❌ 无任何处理 |
| OrderRepository.php:21 | 直接拼接 | ❌ 无参数化、无转义、无类型转换 |

**结论：整条链路上 ZERO 有效过滤。** `empty()` 只阻止空字符串，无法阻止 `1 UNION SELECT ...` 等注入 payload。

### 利用场景

```
# 联合查询注入 — 窃取 users 表数据
GET /order/detail?order_id=1 UNION SELECT 1,username,password,4,5 FROM users--

# 布尔盲注 — 逐字符猜解
GET /order/detail?order_id=1 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'

# 时间盲注 — 无回显时
GET /order/detail?order_id=1 AND IF(1=1, SLEEP(5), 0)
```

### 修复建议

```php
// 方案 A（推荐 — 数字场景最简）：类型转换
// OrderController.php:32
$orderId = (int)$_GET['order_id'];

// 方案 B（更健壮）：PDO 预处理语句
// OrderRepository.php:17-22
public function findByIdAndUser($orderId, $userId)
{
    $stmt = $this->db->prepare(
        "SELECT * FROM orders WHERE id = ? AND user_id = ?"
    );
    $stmt->bind_param('ii', $orderId, $userId);
    $stmt->execute();
    return $stmt->get_result()->fetch_assoc();
}
```

---

## 漏洞 2：[高危] ORDER BY 注入 — `searchByUser()` 中 `$_GET['sort']` 无白名单校验

### 传播链路

```
Source:  $_GET['sort']                                        ← OrderController.php:63 (路由: GET /order/search)
  ↓ 直接赋值，默认值 'created_at' 但用户可覆盖
$sortField = $_GET['sort'] ?? 'created_at';                   ← OrderController.php:63
  ↓ 作为第三个参数传入
$this->orderService->searchOrders($userId, $keyword,
    $sortField)                                               ← OrderController.php:66 (跨文件 → OrderService.php)
  ↓ 方法签名接收，参数保持原值
public function searchOrders($userId, $keyword, $sortField)   ← OrderService.php:35
  ↓ 直接透传
$this->orderRepo->searchByUser($userId, $keyword,
    $sortField)                                               ← OrderService.php:38 (跨文件 → OrderRepository.php)
  ↓ 方法签名接收
public function searchByUser($userId, $keyword, $sortField)   ← OrderRepository.php:34
  ↓ 直接拼接到 ORDER BY 子句
$sql .= " ORDER BY {$sortField} DESC";                         ← OrderRepository.php:42
  ↓
$this->db->query($sql);                                       ← OrderRepository.php:44  [SINK: mysqli::query]
```

### 过滤评估

| 节点 | 操作 | 有效性 |
|------|------|--------|
| OrderController.php:63 | `$_GET['sort'] ?? 'created_at'` | ❌ 默认值仅在参数不存在时生效，用户可传入任意值 |
| OrderService.php:38 | 透传 | ❌ 无任何处理 |
| OrderRepository.php:42 | 直接拼接 | ❌ 无白名单校验 |

**关键分析：** ORDER BY / GROUP BY 子句中的字段名**不能使用参数化查询**（预处理仅支持值绑定，不支持标识符绑定）。因此即使用了 PDO 预处理，`$sortField` 依然需要白名单校验。

### 利用场景

```sql
# 基础注入 — 枚举列数
GET /order/search?sort=1

# 联合查询注入
GET /order/search?sort=(SELECT password FROM users LIMIT 1)

# 利用 CASE WHEN 实现布尔盲注
GET /order/search?sort=CASE WHEN (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a' THEN created_at ELSE id END
```

### 修复建议

```php
// OrderController.php:63 — 白名单校验
$allowedSortFields = ['id', 'created_at', 'updated_at', 'amount', 'order_no'];
$sortField = in_array($_GET['sort'] ?? '', $allowedSortFields)
    ? $_GET['sort']
    : 'created_at';  // 默认安全值
```

---

## 漏洞 3：[低] LIKE 通配符未转义 — `$_GET['keyword']`

### 传播链路

```
Source:  $_GET['keyword']                                     ← OrderController.php:62
  ↓
$keyword = $_GET['keyword'] ?? '';                            ← OrderController.php:62
  ↓ 传入 Service → 透传到 Repository
  ↓ real_escape_string 转义
$keyword = $this->db->real_escape_string($keyword);           ← OrderRepository.php:39
  ↓ 拼接到 LIKE 子句（% 和 _ 未转义）
$sql .= " AND (... LIKE '%{$keyword}%' ...)";                ← OrderRepository.php:40
  ↓
$this->db->query($sql);                                       ← OrderRepository.php:44  [SINK]
```

### 过滤评估

- `real_escape_string()` 对引号转义有效（UTF-8 编码不会触发宽字节绕过）
- 但 `%` 和 `_` 是 LIKE 通配符，未转义时可被滥用导致性能攻击（如输入 `%` 匹配所有记录）或逻辑绕过

**结论：** 风险较低，但建议转义 LIKE 通配符。

---

## 审计结论

### 已审计入口

| 入口 | 路由 | 漏洞 | 风险 |
|------|------|------|------|
| `detail()` | `GET /order/detail` | SQL 注入（$orderId 无过滤） | **高** |
| `search()` | `GET /order/search` | ORDER BY 注入（$sortField 无白名单） | **高** |
| `search()` | `GET /order/search` | LIKE 通配符未转义（$keyword） | **低** |

### 风险汇总

| 等级 | 数量 | 详情 |
|------|------|------|
| 高 | 2 | SQL 注入 (order_id), ORDER BY 注入 (sort) |
| 中 | 0 | - |
| 低 | 1 | LIKE 通配符未转义 (keyword) |
| **合计** | **3** | |

### 修复优先级

1. **P0（立即修复）：** `findByIdAndUser()` 的 `$orderId` 注入 — 加 `(int)` 转换或用预处理
2. **P0（立即修复）：** `searchByUser()` 的 `$sortField` ORDER BY 注入 — 加白名单校验
3. **P3（下个迭代）：** LIKE 通配符转义

### 安全加固建议

- 全站统一使用 PDO 预处理语句，禁止直接拼接 SQL
- Repository 层所有 `query()` 调用增加参数绑定
- 对 `ORDER BY` / `GROUP BY` 等无法参数化的子句，强制白名单校验
- 在 Service 层增加输入校验层（类型转换、格式校验），不应假设 Repository 层会处理
