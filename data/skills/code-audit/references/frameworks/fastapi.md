# FastAPI Security Audit

> FastAPI 框架安全审计模块
> 适用于: FastAPI, Starlette, SQLAlchemy

## 识别特征

```python
# FastAPI项目识别
from fastapi import FastAPI, Depends, HTTPException
app = FastAPI()

# 文件结构
├── main.py
├── routers/
├── models/
├── schemas/
├── crud/
└── dependencies/
```

---

## 路由与端点分析

```python
# 搜索所有路由
@app.get|post|put|delete|patch
@router.get|post|put|delete|patch

# 路径参数
@app.get("/users/{user_id}")
def get_user(user_id: int):  # 检查IDOR

# 查询参数
@app.get("/search")
def search(q: str = Query(...)):  # 检查注入
```

---

## FastAPI特定漏洞

### 1. 依赖注入安全

```python
# 危险: 未验证的依赖
def get_current_user(token: str = Header(...)):
    # 缺少token验证
    return decode_token(token)

# 安全: 完整验证
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    user = authenticate_token(token, db)
    if not user:
        raise HTTPException(status_code=401)
    return user
```

### 2. Pydantic验证绕过

```python
# 危险: 使用dict绕过验证
@app.post("/users")
def create_user(data: dict):  # 无schema验证
    db.create(User(**data))

# 安全: 强类型schema
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)

@app.post("/users")
def create_user(user: UserCreate):
    ...
```

### 3. 响应模型泄露

```python
# 危险: 返回ORM模型 (可能包含password_hash)
@app.get("/users/{id}")
def get_user(id: int):
    return db.query(User).filter(User.id == id).first()

# 安全: 使用响应模型过滤
class UserResponse(BaseModel):
    id: int
    email: str
    # 排除敏感字段

@app.get("/users/{id}", response_model=UserResponse)
def get_user(id: int):
    return db.query(User).filter(User.id == id).first()
```

### 4. 背景任务注入

```python
# 危险: 用户输入传入背景任务
@app.post("/process")
def process(cmd: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(os.system, cmd)  # RCE!

# 检查所有 BackgroundTasks.add_task 调用
```

### 5. 文件上传处理

```python
# 危险模式
@app.post("/upload")
async def upload(file: UploadFile):
    content = await file.read()
    with open(f"/uploads/{file.filename}", "wb") as f:  # 路径遍历
        f.write(content)

# 安全模式
import uuid
import os

@app.post("/upload")
async def upload(file: UploadFile):
    # 验证文件类型
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(400)
    # 使用安全文件名
    safe_name = f"{uuid.uuid4()}{os.path.splitext(file.filename)[1]}"
    # 限制文件大小
    content = await file.read(MAX_SIZE)
    ...
```

### 6. SQLAlchemy ORM注入

```python
# 危险: 原始SQL
@app.get("/search")
def search(q: str, db: Session = Depends(get_db)):
    return db.execute(f"SELECT * FROM items WHERE name LIKE '%{q}%'")

# 危险: text()拼接
from sqlalchemy import text
db.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))

# 安全: 参数化
db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
```

---

## FastAPI审计清单

```
认证与授权:
- [ ] 检查OAuth2/JWT实现 (Depends)
- [ ] 验证所有端点有适当的认证装饰器
- [ ] 检查IDOR (路径参数未验证所有权)
- [ ] 审计权限检查逻辑

输入验证:
- [ ] 检查是否使用Pydantic schema
- [ ] 搜索 dict 类型参数 (绕过验证)
- [ ] 验证Query/Path/Body参数验证
- [ ] 检查文件上传处理

输出安全:
- [ ] 检查response_model使用
- [ ] 验证敏感字段排除
- [ ] 检查错误响应信息

数据库:
- [ ] 搜索原始SQL执行
- [ ] 检查SQLAlchemy text()使用
- [ ] 验证ORM查询安全

CORS:
- [ ] 检查CORSMiddleware配置
- [ ] 验证allow_origins设置
- [ ] 检查allow_credentials=True风险
```

---

## 审计正则

```regex
# 路由搜索
@(app|router)\.(get|post|put|delete|patch)\s*\(

# Pydantic绕过
def\s+\w+\([^)]*:\s*dict[^)]*\)

# 背景任务
BackgroundTasks\.add_task

# SQL注入
db\.execute\s*\(f['"']|text\s*\(f['"']

# 文件上传
UploadFile.*file\.filename
```

## 最小 PoC 示例
```bash
# SQL 注入
curl "http://localhost:8000/users?q=1' OR '1'='1"

# SSRF
curl "http://localhost:8000/fetch?url=http://169.254.169.254/latest/meta-data/"

# 路径遍历上传文件名
curl -F "file=@/etc/passwd;filename=../../etc/passwd" http://localhost:8000/upload
```
