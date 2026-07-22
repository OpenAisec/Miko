# Django Security Audit

> Django 框架安全审计模块
> 适用于: Django, Django REST Framework

## 识别特征

```python
# Django项目识别
import django
from django.http import HttpResponse
from django.views import View

# 文件结构
├── manage.py
├── project/
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── app/
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   └── forms.py
└── templates/
```

---

## Django特定漏洞

### 1. ORM注入

```python
# 危险: raw()拼接
User.objects.raw(f"SELECT * FROM auth_user WHERE id = {user_id}")
User.objects.raw('SELECT * FROM auth_user WHERE id = %s' % str(id))  # 字符串拼接

# 危险: extra()拼接
User.objects.extra(where=[f"id = {user_id}"])
User.objects.extra(WHERE=['id=' + str(id)])  # 拼接导致注入

# 危险: RawSQL
from django.db.models.expressions import RawSQL
queryset.annotate(val=RawSQL(f"SELECT col FROM tbl WHERE id = {id}"))

# 危险: 参数名可控 (高危!)
import json
data = json.loads(request.body.decode())
Student.objects.filter(**data).first()
# payload: {"passkey__contains":"a"} 利用 lookup 语法
# 可用 lookup: __contains, __startswith, __endswith, __icontains, __regex 等

# 危险: 字典键可控
dict = {'username': user_input, 'age': 18}
User.objects.create(**dict)  # 如果 username 包含注入字符

# 二次注入
filename = request.GET.get('url')
File.objects.create(filename=filename)  # 存入: ' or '1'='1
# 后续拼接查询
cur = connection.cursor()
cur.execute("""select * from file where filename='%s'""" % filename)
# 产生注入: select * from file where filename='' or '1'='1'

# Django ORM Lookup 语法
# field__lookup = value
# __exact: 精确匹配
# __contains: 包含
# __startswith: 开始于
# __endswith: 结束于
# __regex: 正则匹配 (需注意 ReDoS)
# __iregex: 不区分大小写正则

# 安全: 参数化
User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])
User.objects.filter(id=user_id)  # ORM 标准 API
User.objects.get(id=str(id))
User.objects.extra(WHERE=['id=%s'], params=[str(id)])  # 正确的 extra 用法

# SQLite3 参数化
con = sqlite3.connect('sql.db')
c = con.cursor()
username = c.execute('SELECT name FROM users WHERE id = ?', [id]).fetchone()[0]
```

### 2. 模板XSS

```python
# 危险: mark_safe
from django.utils.safestring import mark_safe
mark_safe(f"<div>{user_input}</div>")

# 危险: |safe过滤器
{{ user_input|safe }}

# 危险: autoescape off
{% autoescape off %}{{ user_input }}{% endautoescape %}

# 危险: 直接拼接 HTML
name = request.GET.get('name')
return HttpResponse("<p>name: %s</p>" % name)

# 安全: 默认转义
{{ user_input }}  # 自动转义

# 安全: 使用 render
from django.shortcuts import render
return render(request, 'index.html', {'name': name})
```

### 2.5. SSTI / 格式化字符串注入

```python
# 危险: 双重格式化字符串
name = request.GET.get('name')
template = "<p>user:{user}, name:%s</p>" % name  # 第一次格式化
return HttpResponse(template.format(user=request.user))  # 第二次格式化
# payload: name = "{user.password}" → 泄露用户密码

# 信息泄露 payload
{user.password}  # 读取密码哈希
{user.__init__.__globals__[__builtins__][eval]}  # 获取 eval 函数

# 读取 SECRET_KEY 路径
{user.groups.model._meta.app_config.module.admin.settings.SECRET_KEY}
{user.user_permissions.model._meta.app_config.module.admin.settings.SECRET_KEY}
{user.groups.model._meta.apps.app_configs[auth].module.middleware.settings.SECRET_KEY}
{user.groups.model._meta.apps.app_configs[sessions].module.middleware.settings.SECRET_KEY}
{user.groups.model._meta.apps.app_configs[staticfiles].module.utils.settings.SECRET_KEY}

# 枚举 app_configs
{user.groups.model._meta.apps.app_configs}

# format() 限制
# 只支持点 (.) 和中括号 ([])
# 不支持括号调用，因此 RCE 困难
# 主要用于信息泄露

# 安全: 避免双重格式化
return render(request, 'template.html', {'name': name})
```

### 3. CSRF配置

```python
# 危险: 全局禁用
MIDDLEWARE = [
    # 'django.middleware.csrf.CsrfViewMiddleware',  # 被注释
]

# 危险: 视图级别禁用
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # 搜索这个装饰器
def vulnerable_view(request):
    ...

# 危险: CSRF_TRUSTED_ORIGINS过宽
CSRF_TRUSTED_ORIGINS = ['https://*.example.com']
```

### 4. Session安全

```python
# settings.py 检查项
SESSION_COOKIE_SECURE = True  # 必须为True (HTTPS)
SESSION_COOKIE_HTTPONLY = True  # 必须为True
SESSION_COOKIE_SAMESITE = 'Lax'  # 或 'Strict'
CSRF_COOKIE_SECURE = True

# Session存储
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
# 签名cookie需要强SECRET_KEY
```

### 5. 文件处理

```python
# 危险: 不安全的文件路径
def download(request, filename):
    file_path = os.path.join(UPLOAD_DIR, filename)  # 路径遍历
    return FileResponse(open(file_path, 'rb'))

# 危险: 未验证的文件类型
def upload(request):
    file = request.FILES['file']
    with open(f'/uploads/{file.name}', 'wb') as f:  # 文件名未过滤
        for chunk in file.chunks():
            f.write(chunk)

# 危险: 未验证文件大小
file = request.FILES.get('filename')
name = os.path.join(UPLOAD_DIR, file.name)
with open(name, 'wb') as f:
    f.write(file.read())  # 可能导致 DoS

# 安全: 文件类型和大小验证
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'png'}
MAX_FILE_SIZE = 2097152  # 2MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload(request):
    if request.method == 'POST':
        img = request.FILES.get('filename')
        if img.size < MAX_FILE_SIZE and allowed_file(img.name):
            # 重命名文件 (UUID)
            import uuid
            ext = img.name.rsplit('.', 1)[1]
            new_name = str(uuid.uuid5(uuid.NAMESPACE_DNS, img.name)) + "." + ext

            name = os.path.join(UPLOAD_DIR, new_name)
            with open(name, 'wb') as f:
                for chunk in img.chunks():
                    f.write(chunk)
            return render(request, 'upload.html', {'file': '上传成功'})
        else:
            return render(request, 'upload.html', {'file': "不允许的类型或大小超限"})

# 安全: 使用 FileField 验证
from django.core.validators import FileExtensionValidator

class Document(models.Model):
    file = models.FileField(
        upload_to='documents/%Y/%m/%d',  # 按日期组织
        validators=[FileExtensionValidator(allowed_extensions=['pdf', 'doc'])],
        max_length=100
    )

# 安全: 路径遍历防护
def safe_download(request, filename):
    base_dir = os.path.abspath(UPLOAD_DIR)
    file_path = os.path.abspath(os.path.join(base_dir, filename))

    if not file_path.startswith(base_dir):
        raise ValueError("Path traversal detected")

    return FileResponse(open(file_path, 'rb'))
```

### 6. 调试模式泄露

```python
# settings.py
DEBUG = True  # 生产环境必须False!!!
ALLOWED_HOSTS = ['*']  # 危险: 应指定具体域名

# 调试工具栏
INSTALLED_APPS = [
    'debug_toolbar',  # 生产环境应移除
]
```

### 7. SECRET_KEY安全

```python
# 危险: 硬编码或弱密钥
SECRET_KEY = 'django-insecure-xxx'
SECRET_KEY = 'secret'

# 安全: 环境变量
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
```

### 8. 管理后台安全

```python
# urls.py - 检查admin路径
urlpatterns = [
    path('admin/', admin.site.urls),  # 默认路径，应更改
]

# 应使用不可预测的路径
path('super-secret-admin-xyz/', admin.site.urls),

# 检查admin权限
# admin.py
@admin.register(SensitiveModel)
class SensitiveModelAdmin(admin.ModelAdmin):
    # 检查是否限制了权限
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser
```

---

## Django审计清单

```
配置检查:
- [ ] DEBUG = False (生产环境)
- [ ] SECRET_KEY 强度和存储 (避免硬编码)
- [ ] ALLOWED_HOSTS 配置 (避免 ['*'])
- [ ] SESSION_COOKIE_SECURE = True
- [ ] SESSION_COOKIE_HTTPONLY = True
- [ ] SESSION_COOKIE_SAMESITE = 'Lax'
- [ ] CSRF_COOKIE_SECURE = True
- [ ] CSRF 中间件启用
- [ ] debug_toolbar 生产环境移除

ORM 安全:
- [ ] 搜索 .raw() 调用 (字符串拼接)
- [ ] 搜索 .extra() 调用 (where 拼接)
- [ ] 搜索 RawSQL 使用 (拼接)
- [ ] 搜索 cursor.execute() 拼接
- [ ] 检查 .filter(**dict) 参数名可控
- [ ] 检查 .create(**dict) 字典键可控
- [ ] 检查 __regex/__iregex 输入
- [ ] 检查二次注入场景
- [ ] 验证 lookup 语法使用 (__contains 等)

模板安全:
- [ ] 搜索 mark_safe 使用
- [ ] 搜索 |safe 过滤器
- [ ] 搜索 autoescape off
- [ ] 搜索 HttpResponse 拼接 HTML
- [ ] 检查双重格式化 (% + format)

CSRF:
- [ ] 检查中间件配置
- [ ] 搜索 @csrf_exempt 装饰器
- [ ] 验证 AJAX 请求 CSRF 处理
- [ ] 检查 CSRF_TRUSTED_ORIGINS 配置

认证:
- [ ] 检查密码验证器配置
- [ ] 审计自定义认证后端
- [ ] 检查登录限流
- [ ] 验证密码重置流程

文件处理:
- [ ] 检查 MEDIA_ROOT 配置
- [ ] 验证上传文件类型限制
- [ ] 验证上传文件大小限制
- [ ] 检查文件下载路径验证
- [ ] 验证文件名重命名
- [ ] 检查 FileField validators

管理后台:
- [ ] 检查 admin 路径 (避免默认 /admin/)
- [ ] 验证 admin 权限配置
- [ ] 检查 ModelAdmin 权限方法
- [ ] 验证敏感模型访问控制

其他:
- [ ] 搜索 redirect() 用户输入
- [ ] 检查 is_safe_url 使用 (CVE-2017-7233)
- [ ] 验证环境变量使用 (敏感信息)
```

---

## 审计正则

```regex
# ORM 注入
\.raw\s*\(f['"']|\.raw\s*\([^)]*%\s*str\(
\.extra\s*\([^)]*WHERE\s*=\s*\[|\.extra\s*\([^)]*where\s*=
RawSQL\s*\(f['"']
cursor\.execute\s*\([^)]*['"]\s*%|execute\s*\([^)]*\+
\.filter\s*\(\*\*|\.create\s*\(\*\*

# XSS
mark_safe\s*\(|\|safe\s*}}|autoescape\s+off
HttpResponse\s*\([^)]*%|HttpResponse\s*\(f['"']

# SSTI / 格式化字符串
['"]\s*%\s*[^'"]*\.format\s*\(

# CSRF
@csrf_exempt|csrf_exempt
CsrfViewMiddleware.*#

# 配置
DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[['"]?\*['"]?\]

# SECRET_KEY
SECRET_KEY\s*=\s*['"][^'"]{0,30}['"]

# 文件操作
request\.FILES\s*\[|request\.FILES\.get\s*\(
FileResponse\s*\(open\s*\(|open\s*\([^)]*file\.name

# URL 重定向
redirect\s*\([^)]*request\.|HttpResponseRedirect\s*\([^)]*request\.
is_safe_url\s*\(
```

## 最小 PoC 示例
```bash
# DEBUG/ALLOWED_HOSTS 检查
curl -I http://localhost:8000/ | grep "X-Content-Type-Options"

# SQL 注入 (.raw)
curl "http://localhost:8000/users?q=1' OR '1'='1"

# Open Redirect
curl "http://localhost:8000/redirect?next=http://evil.com"
```
