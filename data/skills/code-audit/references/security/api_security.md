# REST API Security Audit

> REST API 安全审计深度模块
> 覆盖: BOLA/IDOR, Mass Assignment, 速率限制, 认证授权

---

## Overview

API 安全是现代应用的核心挑战。OWASP API Security Top 10 揭示了 API 特有的攻击向量。本模块提供系统化的 API 安全审计方法。

---

## BOLA/IDOR (Broken Object Level Authorization)

### 1. 危险模式

```python
# 危险: 未验证资源所有权
@app.route('/api/orders/<order_id>')
def get_order(order_id):
    order = Order.query.get(order_id)
    return jsonify(order.to_dict())  # 任何人可访问任何订单!

# 危险: 批量操作未验证
@app.route('/api/orders')
def get_orders():
    ids = request.args.getlist('ids')
    orders = Order.query.filter(Order.id.in_(ids)).all()
    return jsonify([o.to_dict() for o in orders])
# 攻击: ?ids=1&ids=2&ids=3...&ids=10000 枚举所有订单

# 危险: 隐藏参数覆盖
@app.route('/api/orders/<order_id>', methods=['PUT'])
def update_order(order_id):
    order = Order.query.get(order_id)
    # 攻击者可修改 user_id
    order.update(**request.json)  # {"user_id": "attacker_id"}
    return jsonify(order.to_dict())
```

### 2. 安全模式

```python
# 安全: 始终验证所有权
@app.route('/api/orders/<order_id>')
@login_required
def get_order(order_id):
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id  # 强制所有权验证
    ).first_or_404()
    return jsonify(order.to_dict())

# 安全: 批量操作限制
@app.route('/api/orders')
@login_required
def get_orders():
    ids = request.args.getlist('ids')

    # 限制数量
    if len(ids) > 50:
        return jsonify({'error': 'Too many IDs'}), 400

    orders = Order.query.filter(
        Order.id.in_(ids),
        Order.user_id == current_user.id  # 所有权验证
    ).all()
    return jsonify([o.to_dict() for o in orders])

# 安全: 使用 DTO 限制字段
class OrderUpdateDTO:
    allowed_fields = ['status', 'note']

@app.route('/api/orders/<order_id>', methods=['PUT'])
@login_required
def update_order(order_id):
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id
    ).first_or_404()

    data = request.json
    # 仅允许更新特定字段
    for field in OrderUpdateDTO.allowed_fields:
        if field in data:
            setattr(order, field, data[field])

    db.session.commit()
    return jsonify(order.to_dict())
```

### 3. 检测命令

```bash
# 查找资源访问点
grep -rn "\.get\(.*_id\)\|query\.get\|filter_by.*id" --include="*.py"

# 检查是否有所有权验证
grep -rn "current_user\|user_id\s*==" --include="*.py"
```

---

## Broken Authentication

### 1. JWT 漏洞

```python
# 危险: 不验证签名算法
import jwt

def verify_token(token):
    # 攻击者可将 alg 改为 none
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload

# 危险: 弱密钥
SECRET = "secret"  # 可被爆破

# 危险: RS256 密钥混淆
# 攻击者获取公钥后，将 alg 从 RS256 改为 HS256
# 使用公钥作为 HMAC 密钥签名

# 安全: 显式验证算法
def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],  # 显式指定算法
            options={"require": ["exp", "iat", "sub"]}  # 必须字段
        )
        return payload
    except jwt.InvalidTokenError:
        return None

# 安全: 强密钥
import secrets
SECRET_KEY = secrets.token_hex(32)  # 256 位随机密钥
```

### 2. Session 安全

```python
# 危险: 可预测 Session ID
session_id = str(user.id) + str(int(time.time()))

# 危险: Session 固定
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    session['user_id'] = user.id  # 未重新生成 session
    return redirect('/dashboard')

# 安全: 重新生成 Session
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)

    # 重新生成 Session ID 防止固定攻击
    session.clear()
    session.regenerate()

    session['user_id'] = user.id
    session.permanent = True
    return redirect('/dashboard')
```

### 3. 检测命令

```bash
# JWT 配置
grep -rn "jwt\.decode\|algorithms\|verify_signature" --include="*.py"

# Session 配置
grep -rn "session\[.*\]\|session\.regenerate\|session\.clear" --include="*.py"

# 密钥硬编码
grep -rn "SECRET\s*=\s*['\"]" --include="*.py"
```

---

## Broken Object Property Level Authorization (Mass Assignment)

### 1. 危险模式

```python
# 危险: 自动绑定所有字段
@app.route('/api/users', methods=['POST'])
def create_user():
    user = User(**request.json)  # 攻击者可设置 is_admin=True
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict())

# 危险: 更新时
@app.route('/api/users/<user_id>', methods=['PATCH'])
def update_user(user_id):
    user = User.query.get(user_id)
    user.update(request.json)  # 可修改 password_hash, role 等
    return jsonify(user.to_dict())
```

### 2. 安全模式

```python
from marshmallow import Schema, fields, validate

# 使用 Schema 白名单字段
class UserCreateSchema(Schema):
    username = fields.Str(required=True, validate=validate.Length(min=3, max=50))
    email = fields.Email(required=True)
    password = fields.Str(required=True, load_only=True)
    # is_admin 不在 Schema 中，无法被设置

class UserUpdateSchema(Schema):
    email = fields.Email()
    display_name = fields.Str()
    # 不包含 password, role 等敏感字段

@app.route('/api/users', methods=['POST'])
def create_user():
    schema = UserCreateSchema()
    data = schema.load(request.json)  # 仅允许的字段

    user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hash_password(data['password']),
        is_admin=False  # 显式设置
    )
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict())

@app.route('/api/users/<user_id>', methods=['PATCH'])
@login_required
def update_user(user_id):
    if str(current_user.id) != user_id:
        return jsonify({'error': 'Forbidden'}), 403

    schema = UserUpdateSchema()
    data = schema.load(request.json)

    user = User.query.get_or_404(user_id)
    for key, value in data.items():
        setattr(user, key, value)

    db.session.commit()
    return jsonify(user.to_dict())
```

---

## Unrestricted Resource Consumption

### 1. 速率限制缺失

```python
# 危险: 无速率限制
@app.route('/api/login', methods=['POST'])
def login():
    user = authenticate(request.json)
    if user:
        return jsonify({'token': generate_token(user)})
    return jsonify({'error': 'Invalid credentials'}), 401
# 可被暴力破解

# 安全: 添加速率限制
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")  # 每分钟 5 次
def login():
    user = authenticate(request.json)
    if user:
        return jsonify({'token': generate_token(user)})
    return jsonify({'error': 'Invalid credentials'}), 401

# 更细粒度的限制
@limiter.limit("100 per day", key_func=lambda: request.json.get('email'))
```

### 2. 分页和查询限制

```python
# 危险: 无限制的查询
@app.route('/api/users')
def list_users():
    users = User.query.all()  # 可能返回百万记录
    return jsonify([u.to_dict() for u in users])

# 安全: 强制分页
@app.route('/api/users')
def list_users():
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)  # 最大 100

    pagination = User.query.paginate(page=page, per_page=per_page)

    return jsonify({
        'items': [u.to_dict() for u in pagination.items],
        'total': pagination.total,
        'page': pagination.page,
        'pages': pagination.pages
    })

# 限制查询深度 (GraphQL 尤其重要)
MAX_QUERY_DEPTH = 5
MAX_QUERY_COMPLEXITY = 100
```

### 3. 文件上传限制

```python
# 危险: 无限制上传
@app.route('/api/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save(f'/uploads/{file.filename}')
    return jsonify({'status': 'uploaded'})

# 安全: 限制大小和类型
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/upload', methods=['POST'])
@limiter.limit("10 per hour")
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400

    file = request.files['file']

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400

    filename = secure_filename(file.filename)
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    return jsonify({'status': 'uploaded'})
```

---

## Broken Function Level Authorization

### 1. 管理功能暴露

```python
# 危险: 管理接口无权限检查
@app.route('/api/admin/users', methods=['DELETE'])
def delete_all_users():
    User.query.delete()
    return jsonify({'status': 'deleted'})

# 危险: 隐藏的管理参数
@app.route('/api/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    if request.args.get('admin_view'):  # 隐藏参数
        return jsonify(user.full_dict())  # 包含敏感信息
    return jsonify(user.to_dict())

# 安全: 显式权限检查
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'error': 'Admin required'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/api/admin/users', methods=['DELETE'])
@login_required
@admin_required
def delete_all_users():
    # 额外确认
    if not request.json.get('confirm'):
        return jsonify({'error': 'Confirmation required'}), 400

    User.query.delete()
    return jsonify({'status': 'deleted'})
```

### 2. 水平越权

```python
# 危险: 通过用户 ID 访问他人资源
@app.route('/api/users/<user_id>/documents')
@login_required
def get_documents(user_id):
    docs = Document.query.filter_by(user_id=user_id).all()
    return jsonify([d.to_dict() for d in docs])
# 攻击者可以访问任何用户的文档

# 安全: 强制使用当前用户
@app.route('/api/documents')
@login_required
def get_my_documents():
    docs = Document.query.filter_by(user_id=current_user.id).all()
    return jsonify([d.to_dict() for d in docs])

# 如果需要按用户 ID 查询，验证权限
@app.route('/api/users/<user_id>/documents')
@login_required
def get_documents(user_id):
    # 只有管理员或用户本人可以访问
    if str(current_user.id) != user_id and not current_user.is_admin:
        return jsonify({'error': 'Forbidden'}), 403

    docs = Document.query.filter_by(user_id=user_id).all()
    return jsonify([d.to_dict() for d in docs])
```

---

## Security Misconfiguration

### 1. CORS 配置

```python
# 危险: 允许所有来源
from flask_cors import CORS
CORS(app, origins='*', supports_credentials=True)  # 危险组合!

# 安全: 白名单来源
CORS(app,
     origins=['https://app.example.com'],
     methods=['GET', 'POST', 'PUT', 'DELETE'],
     allow_headers=['Content-Type', 'Authorization'],
     supports_credentials=True,
     max_age=3600)
```

### 2. 错误处理

```python
# 危险: 暴露内部错误
@app.errorhandler(Exception)
def handle_error(e):
    return jsonify({
        'error': str(e),
        'traceback': traceback.format_exc()  # 暴露堆栈!
    }), 500

# 安全: 通用错误消息
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.error(f'Unhandled exception: {e}', exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(403)
def forbidden(e):
    return jsonify({'error': 'Access denied'}), 403
```

### 3. 安全头

```python
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

---

## 检测命令

```bash
# IDOR/BOLA
grep -rn "\.get\(.*id\)\|query\.get\|filter_by.*id" --include="*.py"
grep -rn "current_user\|user_id\s*==" --include="*.py"

# Mass Assignment
grep -rn "\*\*request\.json\|\*\*request\.form\|update\(request" --include="*.py"

# 认证配置
grep -rn "jwt\|token\|session\|login" --include="*.py"

# 速率限制
grep -rn "limiter\|rate.*limit\|throttle" --include="*.py"

# CORS
grep -rn "CORS\|Access-Control" --include="*.py"
```

---

## 最小 PoC 示例
```bash
# IDOR 枚举
curl -H "Authorization: Bearer USER" https://api.example.com/orders/1
curl -H "Authorization: Bearer USER" https://api.example.com/orders/2

# Mass Assignment
curl -X PATCH -H "Content-Type: application/json" -d '{"is_admin":true}' https://api.example.com/users/123

# 速率限制
for i in {1..50}; do curl -I https://api.example.com/login?u=a&p=b; done
```

---

## 审计清单

```
[ ] 检查所有资源端点是否验证所有权 (BOLA)
[ ] 检查 JWT 配置 (算法验证、密钥强度、过期时间)
[ ] 检查 Session 管理 (重新生成、超时、存储)
[ ] 检查 Mass Assignment 防护 (白名单字段)
[ ] 检查速率限制 (登录、敏感操作)
[ ] 检查分页限制
[ ] 检查文件上传限制 (大小、类型)
[ ] 检查管理功能权限
[ ] 检查水平越权防护
[ ] 检查 CORS 配置
[ ] 检查错误处理 (不泄露内部信息)
[ ] 检查安全响应头
[ ] 检查 API 文档是否暴露敏感端点
```

---

## 参考资源

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [API Security Checklist](https://github.com/shieldfy/API-Security-Checklist)
- [REST API Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
