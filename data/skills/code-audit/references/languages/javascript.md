# JavaScript/Node.js Security Audit Guide

> JavaScript/Node.js 代码安全审计模块 | **双轨并行完整覆盖**
> 适用于: ES5/ES6+, Node.js, TypeScript, Deno

---

## 审计方法论

### 双轨并行框架

```
                  JavaScript/Node.js 代码安全审计
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
         ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  轨道A (50%)    │ │  轨道B (40%)    │ │  补充 (10%)     │
│  控制建模法     │ │  数据流分析法   │ │  配置+依赖审计  │
│                 │ │                 │ │                 │
│ 缺失类漏洞:     │ │ 注入类漏洞:     │ │ • 硬编码凭据    │
│ • 认证缺失      │ │ • 代码注入      │ │ • npm audit     │
│ • 授权缺失      │ │ • 原型污染      │ │ • CVE依赖       │
│ • IDOR          │ │ • 命令注入      │ │                 │
│ • 竞态条件      │ │ • 路径遍历      │ │                 │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### 两轨核心公式

```
轨道A: 缺失类漏洞 = 敏感操作 - 应有控制
轨道B: 注入类漏洞 = Source → [无净化] → Sink
```

**参考文档**: `references/core/security_controls_methodology.md`, `references/core/data_flow_methodology.md`

---

# 轨道A: 控制建模法 (缺失类漏洞)

## A1. 敏感操作枚举

### 1.1 快速识别命令

```bash
# Express路由 - 数据修改操作
grep -rn "app\.post\|app\.put\|app\.delete\|app\.patch\|router\.post\|router\.delete" --include="*.js" --include="*.ts"

# NestJS控制器
grep -rn "@Post\|@Put\|@Delete\|@Patch" --include="*.ts"

# 数据访问操作 (带参数)
grep -rn "app\.get.*:\|router\.get.*:\|@Get.*:" --include="*.js" --include="*.ts"

# 批量操作
grep -rn "export.*=\|download\|batch" --include="*.js" --include="*.ts"

# 资金操作
grep -rn "transfer\|payment\|refund\|balance" --include="*.js" --include="*.ts"

# 外部HTTP请求
grep -rn "axios\.\|fetch(\|http\.request\|got\(" --include="*.js" --include="*.ts"

# 文件操作
grep -rn "fs\.readFile\|fs\.writeFile\|fs\.unlink\|multer" --include="*.js" --include="*.ts"

# 命令执行
grep -rn "child_process\|exec(\|spawn(\|execSync" --include="*.js" --include="*.ts"
```

### 1.2 输出模板

```markdown
## Node.js敏感操作清单

| # | 端点/函数 | HTTP方法 | 敏感类型 | 位置 | 风险等级 |
|---|-----------|----------|----------|------|----------|
| 1 | /api/user/:id | DELETE | 数据修改 | userController.js:45 | 高 |
| 2 | /api/user/:id | GET | 数据访问 | userController.js:32 | 中 |
| 3 | /api/transfer | POST | 资金操作 | paymentController.js:56 | 严重 |
```

---

## A2. 安全控制建模

### 2.1 Node.js安全控制实现方式

| 控制类型 | Express | NestJS | Koa |
|----------|---------|--------|-----|
| **认证控制** | passport, express-jwt | `@UseGuards(AuthGuard)` | koa-passport |
| **授权控制** | CASL, 自定义middleware | `@Roles()`, Guards | 自定义middleware |
| **资源所有权** | middleware检查 | Guards | middleware检查 |
| **输入验证** | express-validator, Joi | class-validator, Pipes | joi, yup |
| **并发控制** | 数据库事务 | TypeORM事务 | Sequelize事务 |
| **审计日志** | morgan, winston | Interceptors | koa-logger |

### 2.2 控制矩阵模板 (Node.js)

```yaml
敏感操作: DELETE /api/user/:id
位置: userController.js:45
类型: 数据修改

应有控制:
  认证控制:
    要求: 必须登录
    Express: passport.authenticate() 或 jwt middleware
    NestJS: @UseGuards(AuthGuard('jwt'))

  授权控制:
    要求: 管理员或本人
    Express: CASL ability.can() 或自定义middleware
    NestJS: @Roles('admin') + RolesGuard

  资源所有权:
    要求: 非管理员只能删除自己的数据
    验证: req.user.id === resource.userId
```

---

## A3. 控制存在性验证

### 3.1 数据修改操作验证清单

```markdown
## 控制验证: [端点名称]

| 控制项 | 应有 | Express实现 | NestJS实现 | 结果 |
|--------|------|-------------|------------|------|
| 认证控制 | 必须 | passport middleware | @UseGuards | ✅/❌ |
| 授权控制 | 必须 | CASL/middleware | @Roles Guard | ✅/❌ |
| 资源所有权 | 必须 | req.user.id比对 | Guard检查 | ✅/❌ |
| 输入验证 | 必须 | express-validator | ValidationPipe | ✅/❌ |

### 验证命令
```bash
# 检查路由中间件
grep -B 5 "router\.delete\|app\.delete" [路由文件] | grep "authenticate\|isAuth\|jwt"

# 检查资源所有权
grep -A 15 "delete.*async" [controller文件] | grep "userId\|ownerId\|req\.user"
```
```

### 3.2 常见缺失模式 → 漏洞映射

| 缺失控制 | 漏洞类型 | CWE | Node.js检测方法 |
|----------|----------|-----|-----------------|
| 无jwt middleware | 认证缺失 | CWE-306 | 检查路由中间件链 |
| 无CASL/Guards | 授权缺失 | CWE-862 | 检查ability检查 |
| 无userId比对 | IDOR | CWE-639 | 检查查询条件 |
| 无事务锁 | 竞态条件 | CWE-362 | 检查资金操作 |

---

# 轨道B: 数据流分析法 (注入类漏洞)

> **核心公式**: Source → [无净化] → Sink = 注入类漏洞

## B1. Node.js Source

```javascript
// Express
req.query.name        // GET参数
req.body.name         // POST body
req.params.id         // 路径参数
req.headers['x-header']
req.cookies.session
req.files             // 文件上传
```

## B2. Node.js Sink

| Sink类型 | 漏洞 | CWE | 危险函数 |
|----------|------|-----|----------|
| 代码执行 | 代码注入 | 94 | eval, Function, vm.run |
| 命令执行 | 命令注入 | 78 | child_process.exec |
| SQL执行 | SQL注入 | 89 | connection.query |
| 文件操作 | 路径遍历 | 22 | fs.readFile, fs.writeFile |
| 原型污染 | 原型污染 | 1321 | Object.assign, _.merge |

## B3. Sink检测命令

## 核心危险面

JavaScript 的动态特性、原型链机制和异步编程模型带来独特的安全挑战。关键攻击面：代码注入、原型污染、ReDoS、路径遍历、不安全反序列化。

---

## 补充检测命令 (grep驱动)

### 代码注入检测

```javascript
// 高危函数清单
eval(code)                           // 执行任意代码
Function(code)()                     // 动态函数构造
setTimeout(code_string, delay)       // 字符串形式超时回调
setInterval(code_string, delay)      // 字符串形式间隔回调
new Function('return ' + code)()     // 构造函数注入
vm.runInNewContext(code)             // VM模块执行
vm.runInThisContext(code)            // 当前上下文执行
require('child_process').exec(cmd)   // 命令执行

// 审计正则
\beval\s*\(|\bFunction\s*\(|setTimeout\s*\([^,)]*?[\+\`]|setInterval\s*\([^,)]*?[\+\`]
vm\.run|child_process|exec\s*\(|spawn\s*\(

// 漏洞示例
const userCode = req.query.code;
eval(userCode);  // ❌ Critical: 任意代码执行

// 安全替代
const vm = require('vm');
const sandbox = Object.create(null);
vm.runInNewContext(code, sandbox, { timeout: 1000 });  // 有限沙箱
```

---

## 原型污染检测

```javascript
// 原型污染向量
Object.assign(target, source)        // 递归合并对象
_.merge(target, source)              // Lodash合并
_.mergeWith(target, source)          // 自定义合并
$.extend(true, target, source)       // jQuery深拷贝
hoek.merge(target, source)           // Hoek合并

// 危险属性
__proto__
constructor.prototype
prototype

// 审计正则
(Object\.assign|_\.merge|_\.set|_\.defaults|\$\.extend)\s*\(
__proto__|constructor\.prototype

// 漏洞示例
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];  // ❌ High: 原型污染
        }
    }
    return target;
}

// 攻击载荷
POST /api/merge
{
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  }
}

// 安全措施
function safeMerge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // ✓ 过滤危险属性
        }
        if (Object.prototype.hasOwnProperty.call(source, key)) {
            target[key] = source[key];
        }
    }
}

// 使用 Object.create(null) 创建无原型对象
const safeObj = Object.create(null);
```

---

## 命令注入检测

```javascript
// 高危模块和函数
child_process.exec(cmd)              // Shell执行
child_process.execSync(cmd)          // 同步Shell执行
child_process.spawn(cmd, {shell:true}) // shell=true时危险
child_process.execFile(file, args)   // 文件执行
require('shelljs').exec(cmd)         // ShellJS

// 审计正则
child_process\.(exec|spawn|execSync|execFile|fork)
shelljs.*exec|sh\.exec

// 漏洞示例
const { exec } = require('child_process');
const filename = req.query.file;
exec(`cat ${filename}`, (err, stdout) => {  // ❌ Critical
    res.send(stdout);
});

// 攻击载荷
GET /api/file?file=test.txt;id;whoami

// 安全替代
const { execFile } = require('child_process');
execFile('cat', [filename], (err, stdout) => {  // ✓ 使用参数数组
    res.send(stdout);
});

// 或使用 spawn 不带 shell
const { spawn } = require('child_process');
const child = spawn('cat', [filename]);  // ✓ shell=false (默认)
```

---

## 路径遍历检测

```javascript
// 危险操作
fs.readFile(userPath)                // 文件读取
fs.writeFile(userPath)               // 文件写入
fs.createReadStream(userPath)        // 流读取
require(userModule)                  // 动态加载模块
res.sendFile(userPath)               // Express发送文件
res.download(userPath)               // Express下载

// 审计正则
fs\.(readFile|writeFile|readFileSync|createReadStream|createWriteStream|unlink)
res\.(sendFile|download)\s*\(|require\s*\(.*?req\.(query|body|params)

// 漏洞示例
app.get('/download', (req, res) => {
    const file = req.query.file;
    res.sendFile(__dirname + '/files/' + file);  // ❌ High: 路径遍历
});

// 攻击载荷
GET /download?file=../../../etc/passwd

// 安全修复
const path = require('path');
const file = req.query.file;
const safePath = path.normalize(file).replace(/^(\.\.(\/|\\|$))+/, '');
const fullPath = path.join(__dirname, 'files', safePath);

if (!fullPath.startsWith(path.join(__dirname, 'files'))) {
    return res.status(403).send('Forbidden');
}
res.sendFile(fullPath);  // ✓
```

---

## 正则表达式拒绝服务 (ReDoS)

```javascript
// 危险正则模式
(a+)+                                // 嵌套量词
(a|a)*                               // 重复的选择
(a|ab)*                              // 重叠选择
(\w+\s?)*                            // 字符类+空格量词

// 审计正则
/\([^)]*[\+\*]\)\+/                  // 检测嵌套量词

// 漏洞示例
const emailRegex = /^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]{2,}$/;
if (emailRegex.test(userInput)) {    // ❌ Medium: ReDoS
    // ...
}

// 攻击载荷
"aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"  // 不匹配但导致指数级回溯

// 安全修复
const emailRegex = /^[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]{2,}$/;  // ✓ 移除嵌套量词

// 使用 safe-regex 检测
const safe = require('safe-regex');
if (!safe(regex)) {
    console.warn('Unsafe regex detected!');
}
```

---

## JSON 注入和反序列化

```javascript
// 不安全反序列化
JSON.parse(userInput)                // 通常安全，但注意原型污染
eval('(' + jsonString + ')')         // ❌ 极度危险
node-serialize.unserialize()         // 可执行代码
cryo.parse()                         // 可还原函数

// 审计正则
eval\s*\(.*JSON|serialize\.unserialize|cryo\.(parse|hydrate)

// 漏洞示例 - node-serialize
const serialize = require('node-serialize');
const userCookie = req.cookies.profile;
const obj = serialize.unserialize(userCookie);  // ❌ Critical

// 攻击载荷
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('calc')}()"}

// 安全措施
const data = JSON.parse(userInput);  // ✓ 仅使用 JSON.parse
// 验证反序列化后的对象结构
if (!isValidUser(data)) {
    throw new Error('Invalid data structure');
}
```

---

## XSS 检测 (服务端渲染)

```javascript
// 危险的模板引擎配置
// EJS
<%= userInput %>                     // ❌ 不转义输出
<%- userInput %>                     // ❌ 原始HTML

// Pug/Jade
!= userInput                         // ❌ 不转义
div!= userInput                      // ❌ 不转义

// Handlebars
{{{ userInput }}}                    // ❌ 三重大括号不转义

// 审计关键字
res.send|res.write|innerHTML|dangerouslySetInnerHTML
<%=|<%-|!{|{{{

// 漏洞示例
app.get('/greet', (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello ${name}</h1>`);  // ❌ High: XSS
});

// 安全修复
const escapeHtml = require('escape-html');
res.send(`<h1>Hello ${escapeHtml(name)}</h1>`);  // ✓

// React/Vue 组件
<div dangerouslySetInnerHTML={{__html: userInput}} />  // ❌ High
<div v-html="userInput"></div>                          // ❌ High
```

---

## SQL 注入检测 (Node.js ORM)

```javascript
// 危险操作
// Sequelize
User.findAll({ where: sequelize.literal(userInput) })  // ❌
sequelize.query(`SELECT * FROM users WHERE id=${id}`)  // ❌

// Knex
knex.raw(`SELECT * FROM users WHERE name='${name}'`)   // ❌

// TypeORM
manager.query(`SELECT * FROM users WHERE id=${id}`)    // ❌

// 审计正则
sequelize\.(literal|query)|knex\.raw|manager\.query.*\$\{

// 漏洞示例
app.get('/users', async (req, res) => {
    const id = req.query.id;
    const query = `SELECT * FROM users WHERE id = ${id}`;
    const users = await sequelize.query(query);  // ❌ Critical
    res.json(users);
});

// 安全修复
const users = await sequelize.query(
    'SELECT * FROM users WHERE id = ?',
    { replacements: [id], type: QueryTypes.SELECT }  // ✓ 参数化查询
);

// ORM 安全方式
const user = await User.findByPk(id);  // ✓
const users = await User.findAll({ where: { status: userStatus } });  // ✓
```

---

## NoSQL 注入检测 (MongoDB)

```javascript
// 危险操作
db.collection.find(JSON.parse(userInput))         // ❌
db.collection.find({ $where: userCondition })     // ❌
User.find(req.query)                              // ❌ Mongoose直接传递查询

// 审计正则
\$where|JSON\.parse.*req\.(query|body)|\.find\(req\.(query|body)\)

// 漏洞示例
app.get('/users', async (req, res) => {
    const filter = req.query;
    const users = await User.find(filter);  // ❌ High: NoSQL注入
    res.json(users);
});

// 攻击载荷
GET /users?username[$ne]=null&password[$ne]=null  // 绕过认证
GET /users?$where=this.password.length<20         // $where注入

// 安全修复
const { username } = req.query;
if (typeof username !== 'string') {
    return res.status(400).send('Invalid input');
}
const users = await User.find({ username: username });  // ✓ 明确字段

// 使用白名单
const allowedFields = ['username', 'email', 'status'];
const filter = {};
for (let key in req.query) {
    if (allowedFields.includes(key) && typeof req.query[key] === 'string') {
        filter[key] = req.query[key];
    }
}
```

---

## SSRF 检测

```javascript
// 危险函数
http.get(url)                        // HTTP请求
https.request(url)                   // HTTPS请求
axios.get(url)                       // Axios
fetch(url)                           // Fetch API
request(url)                         // Request库
got(url)                             // Got库

// 审计正则
(http|https|axios|fetch|request|got)\.(get|post|request)\s*\(.*?req\.(query|body|params)

// 漏洞示例
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    const response = await axios.get(url);  // ❌ High: SSRF
    res.send(response.data);
});

// 攻击载荷
GET /fetch?url=http://169.254.169.254/latest/meta-data/  // AWS元数据
GET /fetch?url=http://localhost:6379/                    // 内网Redis
GET /fetch?url=file:///etc/passwd                        // 文件读取

// 安全修复
const url = require('url');
const targetUrl = req.query.url;
const parsed = new URL(targetUrl);

// 黑名单检查
const blockedHosts = ['169.254.169.254', 'localhost', '127.0.0.1', '0.0.0.0'];
const blockedSchemes = ['file', 'gopher', 'dict'];

if (blockedSchemes.includes(parsed.protocol.replace(':', ''))) {
    return res.status(403).send('Forbidden protocol');
}

if (blockedHosts.includes(parsed.hostname)) {
    return res.status(403).send('Forbidden host');
}

// 白名单更安全
const allowedHosts = ['api.example.com', 'cdn.example.com'];
if (!allowedHosts.includes(parsed.hostname)) {
    return res.status(403).send('Unauthorized host');
}
```

---

## JWT 安全检测

```javascript
// 常见漏洞
jwt.verify(token, secret, { algorithms: ['HS256', 'none'] })  // ❌ 允许none算法
jwt.decode(token)                                              // ❌ 不验证签名
jwt.sign(payload, null)                                        // ❌ 空密钥

// 审计正则
jwt\.decode\s*\((?!.*verify)|algorithms.*none|jwt\.sign.*null

// 漏洞示例
app.get('/admin', (req, res) => {
    const token = req.headers.authorization;
    const decoded = jwt.decode(token);  // ❌ High: 未验证签名
    if (decoded.role === 'admin') {
        res.send('Admin panel');
    }
});

// 攻击载荷 - none算法绕过
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4ifQ.

// 安全修复
const secret = process.env.JWT_SECRET;
try {
    const decoded = jwt.verify(token, secret, {
        algorithms: ['HS256']  // ✓ 明确指定算法
    });
    if (decoded.role === 'admin') {
        res.send('Admin panel');
    }
} catch (err) {
    res.status(401).send('Invalid token');
}

// 密钥安全
// ❌ 硬编码密钥
const SECRET = 'my-secret-key-123';

// ✓ 环境变量 + 强密钥
const SECRET = process.env.JWT_SECRET;  // 至少32字节随机
```

---

## 开放重定向检测

```javascript
// 危险操作
res.redirect(req.query.url)          // ❌ 直接重定向
res.redirect(301, req.body.next)     // ❌ 用户控制的目标

// 审计正则
res\.redirect\s*\(.*?req\.(query|body|params)

// 漏洞示例
app.get('/logout', (req, res) => {
    const returnUrl = req.query.return;
    res.clearCookie('session');
    res.redirect(returnUrl);  // ❌ Medium: 开放重定向
});

// 攻击载荷
GET /logout?return=https://evil.com/phishing

// 安全修复
const allowedDomains = ['example.com', 'app.example.com'];
const url = new URL(returnUrl, 'http://example.com');

if (!allowedDomains.includes(url.hostname)) {
    return res.redirect('/');  // 默认安全路径
}
res.redirect(returnUrl);

// 或仅允许相对路径
if (returnUrl.startsWith('/') && !returnUrl.startsWith('//')) {
    res.redirect(returnUrl);  // ✓
}
```

---

## 竞态条件检测

```javascript
// TOCTOU (Time-of-check to Time-of-use)
if (await canWithdraw(user, amount)) {  // Check
    await withdraw(user, amount);        // Use - ❌ 竞态窗口
}

// 漏洞示例 - 余额检查
async function transfer(from, to, amount) {
    const balance = await getBalance(from);
    if (balance >= amount) {            // ❌ 竞态条件
        await deduct(from, amount);
        await credit(to, amount);
    }
}

// 攻击场景：同时发送多个转账请求

// 安全修复 - 原子操作
async function transfer(from, to, amount) {
    const session = await db.startSession();
    session.startTransaction();
    try {
        await Account.updateOne(
            { _id: from, balance: { $gte: amount } },
            { $inc: { balance: -amount } },
            { session }
        );  // ✓ 原子更新
        await Account.updateOne(
            { _id: to },
            { $inc: { balance: amount } },
            { session }
        );
        await session.commitTransaction();
    } catch (err) {
        await session.abortTransaction();
        throw err;
    } finally {
        session.endSession();
    }
}

// Redis 分布式锁
const Redlock = require('redlock');
const lock = await redlock.lock('transfer:' + userId, 1000);
try {
    // 执行转账
} finally {
    await lock.unlock();
}
```

---

## 敏感信息泄露检测

```javascript
// 危险模式
console.log(req.body.password)       // 日志泄露密码
console.error(err.stack)             // 详细堆栈
res.send(err)                        // 错误对象直接返回
process.env                          // 环境变量泄露

// 审计正则
console\.(log|error|info).*password|res\.(send|json)\(err\)|JSON\.stringify\(process\.env\)
app\.use\(express\.errorHandler\(\)\)

// 漏洞示例
app.post('/login', async (req, res) => {
    try {
        const user = await authenticate(req.body);
        console.log('Login:', req.body);  // ❌ Low: 密码记录到日志
        res.json({ token: user.token });
    } catch (err) {
        res.status(500).json({ error: err.stack });  // ❌ Medium: 堆栈泄露
    }
});

// 安全修复
const sanitized = { ...req.body };
delete sanitized.password;
logger.info('Login attempt', sanitized);  // ✓

// 统一错误处理
app.use((err, req, res, next) => {
    logger.error(err);  // 后端记录完整错误
    res.status(500).json({
        error: process.env.NODE_ENV === 'production'
            ? 'Internal server error'  // ✓ 生产环境隐藏细节
            : err.message
    });
});
```

---

## package.json 依赖审计

```bash
# 检查已知漏洞
npm audit
yarn audit

# 常见脆弱依赖
lodash < 4.17.21                     # 原型污染
minimist < 1.2.6                     # 原型污染
node-serialize                       # RCE
js-yaml < 3.13.1                     # 代码执行
handlebars < 4.7.7                   # RCE
express < 4.17.3                     # 开放重定向
jsonwebtoken < 9.0.0                 # 算法混淆

# 审计正则 (在package.json中)
"lodash":\s*"[<^~]?[0-3]\.|"^4\.(0|1[0-6])\."
"minimist":\s*"[<^~]?[01]\."
```

---

## TypeScript 特定安全

```typescript
// 类型断言绕过
const userInput = req.query.data as string;  // ❌ 不安全，可能不是string
executeQuery(userInput);

// 安全验证
function isString(value: unknown): value is string {
    return typeof value === 'string';
}

if (isString(req.query.data)) {
    executeQuery(req.query.data);  // ✓ 类型守卫
}

// any 类型滥用
function process(data: any) {  // ❌ 绕过类型检查
    eval(data.code);
}

// 使用 unknown 代替
function process(data: unknown) {
    if (typeof data === 'object' && data !== null && 'code' in data) {
        // 运行时验证
    }
}
```

---

## 环境变量和密钥管理

```javascript
// 危险配置
const config = {
    dbPassword: 'hardcoded123',      // ❌ 硬编码密码
    apiKey: 'sk-1234567890',         // ❌ 硬编码API密钥
    jwtSecret: 'secret'              // ❌ 弱密钥
};

// .env 文件泄露
app.use(express.static('public'));   // ❌ 如果public包含.env

// 审计正则
password\s*[:=]\s*['"][^'"]+['"]|api[_-]?key\s*[:=]\s*['"]
git add \.env

// 安全措施
// .env 文件
DB_PASSWORD=use_strong_random_password
JWT_SECRET=at_least_32_bytes_random_string

// .gitignore
.env
.env.local
config/secrets.js

// 代码中
require('dotenv').config();
const dbPassword = process.env.DB_PASSWORD;

// 验证环境变量
const requiredEnvVars = ['DB_PASSWORD', 'JWT_SECRET', 'API_KEY'];
for (const varName of requiredEnvVars) {
    if (!process.env[varName]) {
        throw new Error(`Missing required env var: ${varName}`);
    }
}
```

---

## 搜索模式汇总

```regex
# 代码注入
\beval\s*\(|\bFunction\s*\(|vm\.run.*context|setTimeout.*[\+\`]

# 命令注入
child_process\.(exec|spawn).*shell.*true|exec\s*\(.*\$\{

# 原型污染
__proto__|constructor\.prototype|Object\.assign|_\.merge

# SQL注入
sequelize\.(literal|query).*\$\{|knex\.raw.*\$\{|\.query\(.*\+

# NoSQL注入
\$where|\.find\(req\.(query|body)\)|JSON\.parse.*req\.

# SSRF
(axios|fetch|http|https|request|got)\.(get|post).*req\.

# 路径遍历
res\.(sendFile|download).*req\.|fs\.read.*\+.*req\.|require\(.*req\.

# XSS
res\.send.*\$\{|dangerouslySetInnerHTML|v-html=|<%=.*req\.

# JWT
jwt\.decode\((?!.*verify)|algorithms.*none

# 敏感信息
console\.log.*password|res\.(send|json)\(err\)|\.stack

# 硬编码密钥
password\s*[:=]\s*['"]|api[_-]?key\s*[:=]\s*['"]|secret.*=.*['"][^'"]{8,}
```

---

## 快速审计检查清单

```markdown
[ ] 检查 package.json 已知CVE (npm audit)
[ ] 搜索 eval/Function/vm.run (代码注入)
[ ] 搜索 child_process.exec (命令注入)
[ ] 搜索 __proto__/Object.assign (原型污染)
[ ] 检查 JWT 验证逻辑 (算法、密钥)
[ ] 检查文件操作的路径拼接 (路径遍历)
[ ] 检查 HTTP 请求函数 (SSRF)
[ ] 检查数据库查询的字符串拼接 (注入)
[ ] 检查模板引擎的不转义输出 (XSS)
[ ] 检查重定向目标来源 (开放重定向)
[ ] 检查 .env 文件是否在 .gitignore
[ ] 检查错误处理是否泄露堆栈信息
[ ] 检查正则表达式是否存在 ReDoS
[ ] 检查竞态条件 (余额、库存等)
```

---

## 最小 PoC 示例
```bash
# Prototype Pollution
node -e "const a={}; const b=JSON.parse('{\"__proto__\":{\"polluted\":true}}'); Object.assign(a,b); console.log({}.polluted)"

# SSRF
curl "http://localhost:3000/fetch?url=http://169.254.169.254/latest/meta-data/"

# 路径遍历
curl "http://localhost:3000/download?file=../../etc/passwd"
```

---

---

## 授权漏洞检测 (Authorization Gap) - v1.7.1

> **核心问题**: 授权漏洞是"代码缺失"，grep 无法检测"应该有但没有"的代码
> **解决方案**: 授权矩阵方法 - 从"应该是什么"出发，而非"存在什么"

### 方法论

```
❌ 旧思路 (被动检测 - 局限性大):
   搜索中间件调用 → 检查是否存在
   问题: 存在中间件不等于正确，可能配置错误或遗漏

✅ 新思路 (主动建模 - 系统性):
   1. 枚举所有敏感操作 (DELETE/PUT handler)
   2. 定义应有的权限 (谁可以操作什么)
   3. 对比实际代码，检测缺失或不一致
```

### Express 授权检测

```bash
# 步骤1: 找到所有敏感路由
grep -rn "\.delete\|\.put\|\.patch" --include="*.js" --include="*.ts"
grep -rn "router\.\(delete\|put\|patch\)" --include="*.js" --include="*.ts"

# 步骤2: 检查路由是否有认证中间件
grep -rn "router\.delete" --include="*.js" -B 2 -A 2 | grep -E "isAuthenticated|requireAuth|passport\.authenticate|verifyToken"

# 步骤3: 检查handler中是否有权限检查
grep -rn "async.*delete\|function.*delete" --include="*.js" -A 20 | grep -E "userId|ownerId|req\.user\.\|checkPermission"
```

### 漏洞模式

```javascript
// ❌ 漏洞: delete 路由缺失认证中间件
router.delete('/files/:id', async (req, res) => {
    // 未检查用户登录状态
    await File.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

// ❌ 漏洞: 有认证但无授权 (水平越权)
router.delete('/files/:id', isAuthenticated, async (req, res) => {
    // 只验证登录，未验证是否是文件所有者
    await File.findByIdAndDelete(req.params.id);  // 可删除他人文件!
    res.json({ success: true });
});

// ✅ 安全: 认证 + 授权 + 资源所有权验证
router.delete('/files/:id', isAuthenticated, async (req, res) => {
    const file = await File.findOne({
        _id: req.params.id,
        owner: req.user._id  // 验证资源所有权
    });

    if (!file) {
        return res.status(403).json({ error: 'Not authorized' });
    }

    await file.remove();
    res.json({ success: true });
});
```

### NestJS 授权检测

```bash
# 检查 Controller 的 Guard 配置
grep -rn "@Delete\|@Put\|@Patch" --include="*.ts" -B 5 | grep -E "@UseGuards|@Roles|AuthGuard"

# 检查全局 Guard 配置
grep -rn "APP_GUARD\|useGlobalGuards" --include="*.ts"
```

### 漏洞模式 (NestJS)

```typescript
// ❌ 漏洞: Controller 缺失 Guard
@Controller('files')
export class FileController {
    @Delete(':id')
    async delete(@Param('id') id: string) {
        // 任何人都可访问
        return this.fileService.delete(id);
    }
}

// ❌ 漏洞: 有 AuthGuard 但无资源所有权验证
@Controller('files')
@UseGuards(AuthGuard('jwt'))
export class FileController {
    @Delete(':id')
    async delete(@Param('id') id: string, @Request() req) {
        // 未验证是否是文件所有者
        return this.fileService.delete(id);
    }
}

// ✅ 安全: AuthGuard + 资源所有权验证
@Controller('files')
@UseGuards(AuthGuard('jwt'))
export class FileController {
    @Delete(':id')
    async delete(@Param('id') id: string, @Request() req) {
        const file = await this.fileService.findOne({
            _id: id,
            owner: req.user.id
        });
        if (!file) {
            throw new ForbiddenException('Not authorized');
        }
        return this.fileService.delete(id);
    }
}
```

### Koa 授权检测

```bash
# 检查路由定义
grep -rn "router\.delete\|router\.put\|router\.patch" --include="*.js"

# 检查中间件
grep -rn "router\.use\|app\.use" --include="*.js" -A 2 | grep -E "auth\|jwt\|session"
```

### 授权一致性检测脚本

```bash
#!/bin/bash
# check_auth_consistency_js.sh

echo "=== JavaScript 授权一致性检测 ==="

# 找所有路由文件
ROUTE_FILES=$(find . -name "*.js" -o -name "*.ts" | xargs grep -l "router\.\|@Delete\|@Put" 2>/dev/null)

for routefile in $ROUTE_FILES; do
    echo ""
    echo "检查: $routefile"

    # Express 风格检测
    DELETE_ROUTES=$(grep -n "\.delete\s*(" "$routefile" 2>/dev/null)
    PUT_ROUTES=$(grep -n "\.put\s*(" "$routefile" 2>/dev/null)

    if [ -n "$DELETE_ROUTES" ]; then
        echo "$DELETE_ROUTES" | while read line; do
            line_num=$(echo "$line" | cut -d: -f1)
            route=$(echo "$line" | cut -d: -f2-)

            # 检查是否有认证中间件
            has_auth=$(echo "$route" | grep -c "isAuthenticated\|requireAuth\|verifyToken\|passport")

            if [ "$has_auth" -eq 0 ]; then
                echo "  ⚠️  第${line_num}行: DELETE 路由可能缺少认证中间件"
                echo "      $route"
            else
                echo "  ✅ 第${line_num}行: DELETE 路由有认证检查"
            fi
        done
    fi

    # NestJS 风格检测
    NEST_DELETES=$(grep -n "@Delete" "$routefile" 2>/dev/null)
    if [ -n "$NEST_DELETES" ]; then
        echo "$NEST_DELETES" | while read line; do
            line_num=$(echo "$line" | cut -d: -f1)

            # 检查前10行是否有 Guard
            start=$((line_num - 10))
            [ $start -lt 1 ] && start=1

            has_guard=$(sed -n "${start},${line_num}p" "$routefile" | grep -c "@UseGuards\|@Roles")

            if [ "$has_guard" -eq 0 ]; then
                echo "  ⚠️  第${line_num}行: @Delete 可能缺少 @UseGuards"
            else
                echo "  ✅ 第${line_num}行: @Delete 有 Guard 保护"
            fi
        done
    fi
done
```

### 间接SSRF检测 (配置驱动)

```javascript
// ❌ 漏洞: 配置驱动的间接SSRF
// config.js
const config = {
    apiBaseUrl: process.env.API_URL || 'http://internal-api'
};

// service.js
async function fetchData(endpoint) {
    const url = config.apiBaseUrl + endpoint;  // 间接SSRF
    return axios.get(url);
}

// 检测命令
grep -rn "process\.env\.\w*URL\|process\.env\.\w*HOST" --include="*.js" --include="*.ts"
grep -rn "config\.\w*[Uu]rl\|config\.\w*[Hh]ost" --include="*.js" --include="*.ts"
grep -rn "\`.*\${.*}.*http\|\`http.*\${" --include="*.js" --include="*.ts"
```

### 审计清单 (授权专项)

```
授权矩阵建模:
- [ ] 列出所有敏感路由 (DELETE/PUT/PATCH)
- [ ] 定义每个路由的预期权限
- [ ] 检查实际中间件配置是否匹配预期

Express 专项:
- [ ] 检查敏感路由是否有认证中间件
- [ ] 验证 DELETE 路由的资源所有权检查
- [ ] 检查 app.use() 全局中间件配置顺序

NestJS 专项:
- [ ] 检查 Controller 级别的 @UseGuards
- [ ] 检查方法级别的 @Roles/@Permissions
- [ ] 验证 Guard 中的资源所有权逻辑

水平越权防护:
- [ ] 验证所有资源操作都检查 owner/userId
- [ ] 检查数据库查询是否包含用户过滤条件
- [ ] 验证批量操作的权限检查 (如批量删除)

中间件配置:
- [ ] 检查中间件顺序 (认证 → 授权 → 路由)
- [ ] 验证 JWT 密钥强度
- [ ] 检查 CORS 配置

间接注入:
- [ ] 检查 process.env 中的 URL 配置
- [ ] 追踪 config 对象中的可控值
- [ ] 验证模板字符串构造的URL
```

---

## CSRF 安全 (CWE-352)

### 危险模式

```javascript
// Express - 未启用 CSRF 保护
const app = express();
app.use(express.json());
// 🔴 缺少 csrf 中间件

app.post('/api/transfer', (req, res) => {
    // 状态变更操作无 CSRF 保护
    transferMoney(req.body.to, req.body.amount);
});
```

### 安全配置

```javascript
// Express + csurf
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.use(cookieParser());
app.use(csrfProtection);

app.get('/form', (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
});

app.post('/api/transfer', csrfProtection, (req, res) => {
    // CSRF token 自动验证
    transferMoney(req.body.to, req.body.amount);
});

// NestJS
import { CsrfModule } from '@tekuconcept/nestjs-csrf';
@Module({
    imports: [CsrfModule.forRoot({ cookie: true })],
})
export class AppModule {}
```

### 检测命令

```bash
# 查找 POST/PUT/DELETE 路由无 CSRF
rg -n "app\.(post|put|delete|patch)\(" --glob "*.{js,ts}" | grep -v "csrf\|CSRF"

# 查找敏感操作
rg -n "transfer|delete|update|create" --glob "*.{js,ts}" | grep "app\.\|router\."
```

---

## 文件上传安全 (CWE-434)

### 危险模式

```javascript
// 🔴 无类型验证
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('file'), (req, res) => {
    res.json({ filename: req.file.filename });  // 任意文件类型
});

// 🔴 仅前端验证
// <input type="file" accept=".jpg,.png">  // 可绕过
```

### 安全配置

```javascript
const multer = require('multer');
const path = require('path');

const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif'];
const MAX_SIZE = 5 * 1024 * 1024;  // 5MB

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, '/uploads/');
    },
    filename: (req, file, cb) => {
        // 生成安全文件名
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname).toLowerCase();
        if (!['.jpg', '.jpeg', '.png', '.gif'].includes(ext)) {
            return cb(new Error('Invalid extension'));
        }
        cb(null, uniqueSuffix + ext);
    }
});

const fileFilter = (req, file, cb) => {
    if (!ALLOWED_TYPES.includes(file.mimetype)) {
        return cb(new Error('Invalid file type'), false);
    }
    cb(null, true);
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: MAX_SIZE }
});

app.post('/upload', upload.single('file'), (req, res) => {
    // 额外: 使用 file-type 库验证实际内容
    const FileType = require('file-type');
    const type = await FileType.fromFile(req.file.path);
    if (!type || !ALLOWED_TYPES.includes(type.mime)) {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ error: 'Invalid file content' });
    }
    res.json({ filename: req.file.filename });
});
```

### 检测命令

```bash
# 查找 multer 配置
rg -n "multer\(|upload\.(single|array|fields)" --glob "*.{js,ts}"

# 查找缺少 fileFilter 的配置
rg -A10 "multer\(" --glob "*.{js,ts}" | grep -v "fileFilter"
```

---

## 参考资源

- [OWASP NodeGoat](https://github.com/OWASP/NodeGoat)
- [Node.js Security Checklist](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [npm Security Best Practices](https://docs.npmjs.com/packages-and-references/securing-your-code)
- [Prototype Pollution Attack](https://portswigger.net/daily-swig/prototype-pollution)
