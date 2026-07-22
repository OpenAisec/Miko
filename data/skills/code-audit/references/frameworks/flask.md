# Flask Security Audit

> Flask 框架安全审计模块
> 适用于: Flask, Flask-RESTful, Flask-Login, Flask-JWT-Extended

---

## 识别特征

```python
# Flask 项目识别
from flask import Flask, request, render_template
app = Flask(__name__)

# 常见目录结构
├── app/
│   ├── __init__.py      # create_app 工厂
│   ├── routes/          # 路由蓝图
│   ├── models/          # SQLAlchemy 模型
│   ├── templates/       # Jinja2 模板
│   └── static/          # 静态资源
├── config.py            # 配置
├── requirements.txt
└── run.py / wsgi.py
```

---

## Critical 漏洞

### 1. 调试模式 RCE

```python
# 危险: 生产环境开启调试
if __name__ == '__main__':
    app.run(debug=True)  # Werkzeug debugger PIN 可被计算

# 危险: 配置文件
DEBUG = True
FLASK_DEBUG = 1

# PIN 计算要素 (可用于爆破):
# - username (运行用户)
# - modname (通常 flask.app)
# - getattr(app, '__name__', app.__class__.__name__)
# - getattr(mod, '__file__', None) → app.py 路径
# - uuid.getnode() → MAC 地址
# - get_machine_id() → /etc/machine-id 或 /proc/sys/kernel/random/boot_id

# 检测
grep -rn "debug\s*=\s*True" --include="*.py"
grep -rn "FLASK_DEBUG\|DEBUG\s*=" --include="*.py" --include="*.env"
```

### 2. SECRET_KEY 泄露

```python
# 危险: 硬编码密钥
app.secret_key = 'super_secret_key'
app.config['SECRET_KEY'] = 'hardcoded'

# 危险: 弱密钥
SECRET_KEY = 'development'
SECRET_KEY = os.urandom(16)  # 每次重启变化，session 失效

# 影响:
# - Session 伪造
# - Flask-Login 令牌伪造
# - CSRF token 伪造
# - itsdangerous 签名伪造

# 安全: 从环境变量读取
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("SECRET_KEY not set")

# 检测
grep -rn "secret_key\s*=\|SECRET_KEY\s*=" --include="*.py"
```

### 3. SSTI (Server-Side Template Injection)

```python
# 危险: render_template_string 用户输入
from flask import render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    template = f'<h1>Hello {name}!</h1>'
    return render_template_string(template)

# payload: {{config.items()}}
# payload: {{''.__class__.__mro__[1].__subclasses__()}}
# RCE payload:
# {{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()}}

# 危险: 用户控制模板名
@app.route('/page/<template>')
def page(template):
    return render_template(template)  # 可能加载任意模板

# 安全: 固定模板，传递变量
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    return render_template('hello.html', name=name)

# SSTI 检测命令
grep -rn "render_template_string" --include="*.py"
grep -rn "render_template.*request\." --include="*.py"
grep -rn "Template\s*\(" --include="*.py"
```

### 4. Pickle Session 反序列化

```python
# 危险: 使用 pickle 序列化 session
# Flask 默认使用 itsdangerous 签名的 JSON
# 但某些扩展可能使用 pickle

# Flask-Session 配置
SESSION_TYPE = 'filesystem'  # 文件存储
SESSION_SERIALIZER = PickleSerializer  # 危险!

# 如果 SECRET_KEY 泄露 + pickle session = RCE

# 安全配置
SESSION_TYPE = 'redis'
SESSION_SERIALIZER = 'json'

# 检测
grep -rn "SESSION_SERIALIZER\|PickleSerializer\|pickle" --include="*.py"
```

---

## High 漏洞

### 5. SQL 注入

```python
# 危险: 原始 SQL 拼接
from flask_sqlalchemy import SQLAlchemy

@app.route('/user/<id>')
def get_user(id):
    sql = f"SELECT * FROM users WHERE id = {id}"
    result = db.engine.execute(sql)
    return jsonify(result.fetchone())

# 危险: text() 拼接
from sqlalchemy import text
db.session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))

# 安全: 参数化
db.session.execute(
    text("SELECT * FROM users WHERE name = :name"),
    {"name": name}
)

# 安全: ORM
User.query.filter_by(id=id).first()
User.query.filter(User.name == name).all()

# 检测
grep -rn "execute\s*\(.*f[\"']" --include="*.py"
grep -rn "execute\s*\(.*\+" --include="*.py"
grep -rn "text\s*\(.*f[\"']" --include="*.py"
```

### 6. 命令注入

```python
# 危险: os.system
@app.route('/ping')
def ping():
    host = request.args.get('host')
    os.system(f'ping -c 4 {host}')
    return 'Done'
# payload: ?host=127.0.0.1;id

# 危险: subprocess shell=True
import subprocess
subprocess.run(f'echo {user_input}', shell=True)

# 安全: 参数列表
subprocess.run(['ping', '-c', '4', host], shell=False)

# 更安全: 避免命令执行
import socket
socket.create_connection((host, 80), timeout=5)
```

### 7. 任意文件读取/写入

```python
# 危险: 路径拼接
@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(f'/uploads/{filename}')
# payload: ?file=../../../etc/passwd

# 危险: 文件上传未验证
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save(f'/uploads/{file.filename}')  # 危险!

# 安全: 验证和清理
from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = '/var/www/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return 'Uploaded'
    return 'Invalid file', 400

# 安全下载
@app.route('/download')
def download():
    filename = request.args.get('file')
    safe_name = secure_filename(filename)
    full_path = os.path.join(UPLOAD_FOLDER, safe_name)

    # 验证路径在允许目录内
    if not full_path.startswith(UPLOAD_FOLDER):
        abort(403)

    return send_from_directory(UPLOAD_FOLDER, safe_name)
```

### 8. SSRF

```python
# 危险: 未验证 URL
import requests

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    resp = requests.get(url)
    return resp.text
# payload: ?url=http://169.254.169.254/latest/meta-data/

# 安全: URL 白名单
from urllib.parse import urlparse

ALLOWED_HOSTS = ['api.example.com']

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    parsed = urlparse(url)

    if parsed.scheme not in ['http', 'https']:
        abort(400)

    if parsed.hostname not in ALLOWED_HOSTS:
        abort(403)

    resp = requests.get(url, timeout=5)
    return resp.text
```

---

## Medium 漏洞

### 9. XSS

```python
# 危险: Markup/safe 标记
from flask import Markup

@app.route('/comment')
def comment():
    text = request.args.get('text')
    return Markup(f'<p>{text}</p>')  # 不转义!

# 危险: |safe 过滤器
{{ user_input|safe }}

# 危险: 直接返回 HTML
@app.route('/hello')
def hello():
    name = request.args.get('name')
    return f'<h1>Hello {name}</h1>'  # 不经过模板

# 安全: 使用模板自动转义
return render_template('hello.html', name=name)
# 模板: <h1>Hello {{ name }}</h1>  # 自动转义

# 检测
grep -rn "Markup\s*\(" --include="*.py"
grep -rn "|safe" --include="*.html"
grep -rn "return.*f['\"].*<" --include="*.py"
```

### 10. CSRF 保护缺失

```python
# 危险: 未使用 CSRF 保护
@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']
    to_account = request.form['to']
    # 执行转账...

# 安全: Flask-WTF CSRF
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# 表单中添加
{{ csrf_token() }}
# 或
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

# AJAX 请求
headers: {
    'X-CSRFToken': '{{ csrf_token() }}'
}

# 检测
grep -rn "methods.*POST\|methods.*PUT\|methods.*DELETE" --include="*.py"
# 检查是否有 CSRF 保护
```

### 11. Open Redirect

```python
# 危险: 未验证重定向 URL
from flask import redirect

@app.route('/login')
def login():
    next_url = request.args.get('next')
    # 登录成功后
    return redirect(next_url)
# payload: ?next=http://evil.com

# 安全: 验证是相对路径或同域
from urllib.parse import urlparse, urljoin

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

@app.route('/login')
def login():
    next_url = request.args.get('next', '/')
    if not is_safe_url(next_url):
        next_url = '/'
    return redirect(next_url)
```

### 12. Session 配置不安全

```python
# 危险配置
SESSION_COOKIE_SECURE = False    # HTTP 传输
SESSION_COOKIE_HTTPONLY = False  # JS 可访问
SESSION_COOKIE_SAMESITE = None   # 无 SameSite

# 安全配置
app.config.update(
    SESSION_COOKIE_SECURE=True,      # 仅 HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # JS 不可访问
    SESSION_COOKIE_SAMESITE='Lax',   # 防 CSRF
    PERMANENT_SESSION_LIFETIME=3600, # 1小时过期
)
```

---

## Flask 扩展安全

### Flask-Login

```python
# 危险: remember_me 无限期
login_user(user, remember=True)  # 默认 365 天

# 安全: 设置过期时间
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

# 危险: user_loader 未验证
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)  # 可能返回已禁用用户

# 安全: 验证用户状态
@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(user_id)
    if user and user.is_active:
        return user
    return None
```

### Flask-JWT-Extended

```python
# 危险配置
JWT_SECRET_KEY = 'weak_secret'
JWT_ACCESS_TOKEN_EXPIRES = False  # 永不过期

# 安全配置
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
```

### Flask-CORS

```python
# 危险: 允许所有来源
from flask_cors import CORS
CORS(app)  # 默认允许所有

# 更危险: 允许凭证
CORS(app, supports_credentials=True, origins='*')

# 安全: 指定允许的来源
CORS(app,
     origins=['https://trusted.example.com'],
     supports_credentials=True,
     methods=['GET', 'POST'],
     allow_headers=['Content-Type', 'Authorization'])
```

---

## 检测命令

```bash
# 调试模式
grep -rn "debug\s*=\s*True" --include="*.py"
grep -rn "FLASK_DEBUG" --include="*.env" --include="*.py"

# SECRET_KEY
grep -rn "secret_key\s*=\|SECRET_KEY\s*=" --include="*.py"

# SSTI
grep -rn "render_template_string\|Markup\s*\(" --include="*.py"

# SQL 注入
grep -rn "execute\s*\(" --include="*.py" | grep -E "f['\"]|\+"
grep -rn "text\s*\(" --include="*.py" | grep -E "f['\"]|\+"

# 命令执行
grep -rn "os\.system\|subprocess\.\|popen" --include="*.py"

# 文件操作
grep -rn "send_file\|send_from_directory\|open\s*\(" --include="*.py"

# 综合扫描
bandit -r . -ll
```

---

## 审计清单

```
[ ] 检查 DEBUG 模式是否在生产环境禁用
[ ] 检查 SECRET_KEY 是否硬编码或弱密钥
[ ] 搜索 render_template_string 使用
[ ] 检查 SQL 查询是否参数化
[ ] 检查命令执行函数
[ ] 检查文件操作是否有路径遍历
[ ] 检查 HTTP 请求是否有 SSRF
[ ] 检查 CSRF 保护是否启用
[ ] 检查 Session 配置
[ ] 检查 CORS 配置
[ ] 检查 Flask 扩展配置
[ ] 运行 bandit 静态分析
```

---

## 最小 PoC 示例
```bash
# Jinja2 SSTI
curl "http://localhost:5000/hello?name={{7*7}}"

# DEBUG 模式检查
curl -I http://localhost:5000/ | grep "Werkzeug"

# SSRF
curl "http://localhost:5000/fetch?url=http://169.254.169.254/latest/meta-data/"
```

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
