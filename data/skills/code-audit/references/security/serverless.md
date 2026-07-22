# Serverless Security Audit

> Serverless 应用安全审计模块
> 覆盖: AWS Lambda, Azure Functions, GCP Cloud Functions, Event Injection

---

## Overview

Serverless 架构引入独特的安全挑战：事件注入、权限过宽、冷启动数据残留、第三方依赖风险。本模块覆盖主流 Serverless 平台的安全审计要点。

---

## AWS Lambda 安全

### 1. 事件注入

```python
# 危险: 未验证事件数据
def handler(event, context):
    # API Gateway 事件
    user_id = event['queryStringParameters']['id']
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL 注入!
    return db.execute(query)

# 危险: S3 事件注入
def handler(event, context):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']

    # key 可被攻击者控制 (文件名)
    # payload: ../../../etc/passwd 或 malicious.txt; rm -rf /
    local_path = f"/tmp/{key}"
    s3.download_file(bucket, key, local_path)

    # 命令注入
    os.system(f"process_file {local_path}")  # 危险!

# 安全: 验证和清理
def handler(event, context):
    user_id = event.get('queryStringParameters', {}).get('id')

    # 类型验证
    if not user_id or not user_id.isdigit():
        return {'statusCode': 400, 'body': 'Invalid ID'}

    # 参数化查询
    query = "SELECT * FROM users WHERE id = %s"
    return db.execute(query, (int(user_id),))

# S3 安全处理
def handler(event, context):
    key = event['Records'][0]['s3']['object']['key']

    # 路径清理
    safe_key = os.path.basename(key)
    if '..' in key or not safe_key:
        raise ValueError("Invalid key")

    local_path = os.path.join('/tmp', safe_key)
    s3.download_file(bucket, key, local_path)

    # 避免命令执行
    process_file_safely(local_path)
```

### 2. IAM 权限过宽

```yaml
# 危险: 过宽权限
Resources:
  MyFunction:
    Type: AWS::Lambda::Function
    Properties:
      Role: !GetAtt LambdaRole.Arn

  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      Policies:
        - PolicyName: FullAccess
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: "*"           # 危险: 全部权限!
                Resource: "*"

# 安全: 最小权限
  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      Policies:
        - PolicyName: MinimalAccess
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:PutObject
                Resource:
                  - !Sub "arn:aws:s3:::${BucketName}/*"
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !Sub "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:*"
```

### 3. 环境变量泄露

```python
# 危险: 敏感信息在环境变量
# serverless.yml
environment:
  DB_PASSWORD: "hardcoded_password"  # 危险!
  API_KEY: "sk-xxxx"                 # 危险!

# 代码中打印环境
def handler(event, context):
    print(os.environ)  # 日志泄露!
    return {"statusCode": 200}

# 安全: 使用 Secrets Manager
import boto3

def get_secret():
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId='my-secret')
    return json.loads(response['SecretString'])

def handler(event, context):
    secrets = get_secret()
    db_password = secrets['db_password']
    # ...
```

### 4. 冷启动数据残留

```python
# 危险: 全局变量存储敏感数据
user_data = {}  # Lambda 实例复用时保留

def handler(event, context):
    user_id = event['user_id']

    # 前一个请求的数据可能泄露给下一个用户
    if user_id in user_data:
        return user_data[user_id]

    # 存储当前用户数据
    user_data[user_id] = fetch_sensitive_data(user_id)
    return user_data[user_id]

# 安全: 避免全局敏感数据缓存
def handler(event, context):
    user_id = event['user_id']

    # 每次请求获取新数据
    data = fetch_sensitive_data(user_id)

    # 处理完毕清理
    try:
        return process_data(data)
    finally:
        del data  # 显式清理
```

### 5. /tmp 目录风险

```python
# 危险: /tmp 数据可能被复用
def handler(event, context):
    # Lambda 实例复用时 /tmp 保留
    with open('/tmp/sensitive.txt', 'w') as f:
        f.write(sensitive_data)

    process_file('/tmp/sensitive.txt')
    # 未清理! 下次调用可能读取

# 安全: 使用唯一文件名并清理
import uuid

def handler(event, context):
    temp_file = f'/tmp/{uuid.uuid4()}.txt'

    try:
        with open(temp_file, 'w') as f:
            f.write(sensitive_data)
        process_file(temp_file)
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
```

---

## Azure Functions 安全

### 1. HTTP 触发器注入

```python
# 危险: 未验证输入
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    name = req.params.get('name')
    return func.HttpResponse(f"Hello {name}")  # XSS!

# 安全: 转义输出
from html import escape

def main(req: func.HttpRequest) -> func.HttpResponse:
    name = req.params.get('name', '')

    # 输入验证
    if not name.isalnum():
        return func.HttpResponse("Invalid name", status_code=400)

    # 转义输出
    return func.HttpResponse(f"Hello {escape(name)}")
```

### 2. 绑定注入

```json
// function.json - 危险: 动态绑定路径
{
  "bindings": [
    {
      "name": "inputBlob",
      "type": "blobTrigger",
      "path": "container/{name}",  // name 来自请求
      "connection": "AzureWebJobsStorage"
    }
  ]
}

// 攻击: name=../sensitive/secrets.json
```

### 3. 托管身份权限

```json
// 危险: 过宽的 RBAC
{
  "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/...",
  "principalId": "function-identity",
  "scope": "/subscriptions/xxx"  // 整个订阅!
}

// 安全: 最小范围
{
  "scope": "/subscriptions/xxx/resourceGroups/myRG/providers/Microsoft.Storage/storageAccounts/myStorage"
}
```

---

## GCP Cloud Functions 安全

### 1. Pub/Sub 注入

```python
# 危险: 未验证消息
def pubsub_handler(event, context):
    import base64
    message = base64.b64decode(event['data']).decode('utf-8')

    # 消息可能被恶意发布者控制
    command = json.loads(message)['command']
    os.system(command)  # RCE!

# 安全: 验证和白名单
ALLOWED_COMMANDS = {'process', 'analyze', 'report'}

def pubsub_handler(event, context):
    message = base64.b64decode(event['data']).decode('utf-8')
    data = json.loads(message)

    command = data.get('command')
    if command not in ALLOWED_COMMANDS:
        logging.warning(f"Invalid command: {command}")
        return

    if command == 'process':
        process_data(data.get('input'))
    # ...
```

### 2. 服务账户权限

```yaml
# 危险: 使用默认计算服务账户
# 通常有过宽权限

# 安全: 创建专用服务账户
resource "google_service_account" "function_sa" {
  account_id   = "my-function-sa"
  display_name = "My Function Service Account"
}

resource "google_project_iam_member" "function_sa_roles" {
  project = var.project_id
  role    = "roles/storage.objectViewer"  # 仅需要的权限
  member  = "serviceAccount:${google_service_account.function_sa.email}"
}
```

---

## 通用安全问题

### 1. 依赖漏洞

```python
# requirements.txt
requests==2.25.0  # 可能有已知漏洞

# 检测
pip-audit
safety check -r requirements.txt

# 安全: 定期更新
pip install --upgrade pip-audit
pip-audit --fix
```

### 2. 日志安全

```python
# 危险: 记录敏感数据
def handler(event, context):
    print(f"Processing request: {event}")  # 可能包含密码、token

    user = authenticate(event['password'])
    print(f"User authenticated: {user}")  # 敏感信息

# 安全: 脱敏日志
def handler(event, context):
    safe_event = {k: v for k, v in event.items() if k not in ['password', 'token']}
    logger.info(f"Processing request: {safe_event}")

    user = authenticate(event['password'])
    logger.info(f"User authenticated: {user.id}")  # 仅 ID
```

### 3. 超时和资源限制

```yaml
# serverless.yml
functions:
  myFunction:
    handler: handler.main
    timeout: 900  # 15 分钟 - 可能被滥用于长时间攻击
    memorySize: 3008  # 高内存 = 高成本攻击

# 安全: 合理限制
functions:
  myFunction:
    handler: handler.main
    timeout: 30  # 合理超时
    memorySize: 256  # 最小所需
    reservedConcurrency: 10  # 限制并发
```

### 4. VPC 配置

```yaml
# 危险: Lambda 可访问公网
# 默认 Lambda 在 AWS 管理的网络中，可访问公网

# 安全: VPC 内运行 (访问内部资源时)
functions:
  myFunction:
    vpc:
      securityGroupIds:
        - sg-xxx
      subnetIds:
        - subnet-xxx
        - subnet-yyy

# 注意: VPC Lambda 默认无法访问公网
# 需要 NAT Gateway 或 VPC Endpoint
```

---

## 检测命令

```bash
# 事件注入
grep -rn "event\[" --include="*.py" | grep -E "system\(|exec\(|eval\("

# 环境变量泄露
grep -rn "os\.environ\|print.*environ" --include="*.py"

# 过宽权限
grep -rn '"Action":\s*"\*"\|"Resource":\s*"\*"' --include="*.yaml" --include="*.json"

# /tmp 使用
grep -rn "/tmp/" --include="*.py"

# 依赖检查
pip-audit -r requirements.txt
npm audit
```

---

## 审计清单

```
[ ] 检查事件数据验证 (API Gateway, S3, Pub/Sub 等)
[ ] 检查 IAM/RBAC 权限是否最小化
[ ] 检查敏感信息存储方式 (Secrets Manager vs 环境变量)
[ ] 检查全局变量是否存储敏感数据
[ ] 检查 /tmp 目录使用和清理
[ ] 检查依赖包漏洞
[ ] 检查日志是否泄露敏感信息
[ ] 检查超时和内存配置
[ ] 检查 VPC 配置 (如适用)
[ ] 检查并发限制
[ ] 检查函数 URL/API Gateway 认证
[ ] 检查跨账户访问配置
```

---

## 最小 PoC 示例
```bash
# 事件注入 (S3 -> Lambda)
aws s3 cp test.txt s3://target-bucket/pwn.txt

# API Gateway 路径绕过
curl -i "https://api.example.com/prod/admin;/"

# IAM 权限模拟（需凭证）
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123:role/lambda-role --action-names s3:ListAllMyBuckets
```

---

## 参考资源

- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/)
- [AWS Lambda Security Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/security.html)
- [Serverless Security Handbook](https://www.puresec.io/hubfs/SLS-Top10.pdf)

---

**最后更新**: 2026-01-23
**版本**: 1.0.0
